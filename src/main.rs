use anyhow::Result;
use futures_util::stream::StreamExt;
use quinn::Endpoint;
use sha2::{Digest, Sha256};
use std::net::{SocketAddr, ToSocketAddrs};
use std::sync::Arc;
use std::time::Duration;
use structopt::StructOpt;
use tokio::io::{copy, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_io_timeout::TimeoutReader;

mod config;
use config::{client_config, server_config};
use std::convert::TryInto;

#[derive(StructOpt, Debug)]
#[structopt(name = "quic-tun")]
enum Opt {
    Client(ClientOpt),
    Server(ServerOpt),
    #[structopt(name = "gencert")]
    GenCert,
}

#[derive(StructOpt, Debug)]
struct ClientOpt {
    #[structopt(short = "l", long = "local-addr")]
    local_addr: SocketAddr,
    #[structopt(short = "r", long = "remote-addr")]
    remote_addr: String,
    #[structopt(short = "p", long = "fingerprint")]
    fingerprint: Option<String>,
    #[structopt(short = "e", long = "psk")]
    psk: Option<String>,
    #[structopt(skip = [0;32])]
    auth_key: Option<[u8; 32]>,
    #[structopt(short = "d", long = "daemonize")]
    daemonize: bool,
}

#[derive(StructOpt, Debug)]
struct ServerOpt {
    #[structopt(short = "l", long = "local-addr")]
    local_addr: SocketAddr,
    #[structopt(short = "f", long = "forward-addr")]
    forward_addr: String,
    #[structopt(short = "c", long = "cert-file")]
    cert_file: Option<String>,
    #[structopt(short = "e", long = "psk")]
    psk: Option<String>,
    #[structopt(skip = [0;32])]
    auth_key: Option<[u8; 32]>,
    #[structopt(short = "d", long = "daemonize")]
    daemonize: bool,
}

const READ_TIMEOUT: Duration = Duration::from_secs(30);

fn main() {
    let opt: Opt = StructOpt::from_args();

    env_logger::init_from_env(
        env_logger::Env::default().filter_or(env_logger::DEFAULT_FILTER_ENV, "info"),
    );

    run(opt).unwrap();
}

fn run(opt: Opt) -> Result<()> {
    match opt {
        Opt::Client(opt) => {
            if opt.daemonize {
                daemonize();
            }
            run_client(opt)
        }
        Opt::Server(opt) => {
            if opt.daemonize {
                daemonize();
            }
            run_server(opt)
        }
        Opt::GenCert => gen_cert(),
    }
}

fn daemonize() {
    daemonize::Daemonize::new() /*.user("nobody")*/
        .start()
        .unwrap();
}

#[tokio::main]
async fn run_client(mut opt: ClientOpt) -> Result<()> {
    if let Some(psk) = &opt.psk {
        opt.auth_key = Some(auth_key(&psk));
    }

    let ln = TcpListener::bind(opt.local_addr).await?;

    log::info!("local:{}, remote:{}", ln.local_addr()?, opt.remote_addr,);

    let mut builder = Endpoint::builder();

    builder.default_client_config(client_config());

    let remote_addr = opt.remote_addr.to_socket_addrs()?.next().unwrap();

    let bind_addr = match remote_addr {
        SocketAddr::V4(_) => "0.0.0.0:0",
        SocketAddr::V6(_) => "[::]:0",
    };

    let (endpoint, _incoming) = builder.bind(&bind_addr.parse()?)?;

    let conn_remote = || async {
        let conn = endpoint
            .connect(&remote_addr, "what-ever-name")
            .unwrap()
            .await;

        match conn {
            Ok(c) => {
                let fp = fingerprint(
                    c.connection
                        .peer_identity()
                        .unwrap()
                        .iter()
                        .next()
                        .unwrap()
                        .as_ref(),
                );
                log::info!("connected to remote server, fingerprint {}", fp);

                if let Some(fp0) = &opt.fingerprint {
                    if *fp0 != fp {
                        panic!("remote fingprint not match!");
                    }
                }

                let c = c.connection;

                if let Some(auth_key) = &opt.auth_key {
                    match c.open_bi().await {
                        Ok(mut s) => {
                            let _ = s.0.write(auth_key).await;
                            Ok(())
                        }
                        Err(_) => Err("auth fail"),
                    }?;
                }

                Ok(c)
            }

            Err(_) => Err("connect to remote fail"),
        }
    };

    let mut conn1 = Some(conn_remote().await.unwrap());

    while let Ok((mut stream0, src)) = ln.accept().await {
        log::trace!("new connection, {:?}", src);

        let mut retry = false;

        let stream1 = loop {
            if conn1.is_none() {
                log::debug!("reconnect remote");
                conn1 = match conn_remote().await {
                    Ok(c) => Some(c),
                    Err(_) => None,
                };
            }

            if let Some(c) = conn1.as_ref() {
                match c.open_bi().await {
                    Ok(s) => break Some(s),
                    Err(e) => {
                        log::trace!("open bi fail, {:?}", e);
                        conn1 = None;
                    }
                };
            }

            if !retry {
                retry = true;
            } else {
                break None;
            }
        };

        let stream1 = match stream1 {
            Some(s) => s,
            None => continue,
        };

        tokio::spawn(async move {
            let (recv0, mut send0) = stream0.split();
            let (mut send1, recv1) = stream1;

            let mut recv0 = TimeoutReader::new(recv0);
            recv0.set_timeout(Some(READ_TIMEOUT));

            let mut recv1 = TimeoutReader::new(recv1);
            recv1.set_timeout(Some(READ_TIMEOUT));

            let a = async {
                let _ = copy(&mut Box::pin(recv0), &mut send1).await;
                let _ = send1.finish().await;
            };
            let b = async {
                let _ = copy(&mut Box::pin(recv1), &mut send0).await;
                let _ = send0.shutdown().await;
            };

            let _ = tokio::join!(a, b);

            log::trace!("finish connection");
        });
    }

    Ok(())
}

#[tokio::main]
async fn run_server(mut opt: ServerOpt) -> Result<()> {
    if let Some(psk) = &opt.psk {
        opt.auth_key = Some(auth_key(&psk));
    }

    let mut builder = Endpoint::builder();

    let (cfg, cert) = server_config(&opt.cert_file)?;
    builder.listen(cfg);

    let (endpoint, mut incoming) = builder.bind(&opt.local_addr)?;
    log::info!(
        "local:{}, forward:{}, fingerprint: {}",
        endpoint.local_addr()?,
        opt.forward_addr,
        fingerprint(&cert),
    );

    let opt = Arc::new(opt);
    while let Some(conn) = incoming.next().await {
        log::trace!("new connection {:?}", conn.remote_address());

        let mut bi_streams = match conn.await {
            Ok(c) => c.bi_streams,
            Err(e) => {
                log::trace!("wait incomming fail, {:?}", e);
                continue;
            }
        };

        let opt = opt.clone();
        tokio::spawn(async move {
            let mut auth = false;

            while let Some(stream) = bi_streams.next().await {
                let mut stream0 = match stream {
                    Err(e) => {
                        log::trace!("next bi stream fail, {:?}", e);
                        return;
                    }
                    Ok(s) => s,
                };

                log::trace!("new stream");

                if !auth && opt.auth_key.is_some() {
                    let mut buf = [0; 32];
                    let _ = stream0.1.read_exact(&mut buf[..]).await;
                    if buf == *opt.auth_key.as_ref().unwrap() {
                        log::trace!("authenticate pass!");
                        auth = true;
                        continue;
                    } else {
                        log::trace!("authenticate fail!");
                        break;
                    }
                }

                let opt = opt.clone();
                tokio::spawn(async move {
                    log::trace!("connecting {:?}", opt.forward_addr);
                    let mut stream1 = match TcpStream::connect(&opt.forward_addr).await {
                        Ok(s) => s,
                        Err(e) => {
                            log::warn!("connect to forward_addr fail, {:?}", e);
                            return;
                        }
                    };

                    log::trace!("{:?} connected", &opt.forward_addr);

                    let (mut send0, recv0) = stream0;
                    let (recv1, mut send1) = stream1.split();

                    let mut recv0 = TimeoutReader::new(recv0);
                    recv0.set_timeout(Some(READ_TIMEOUT));

                    let mut recv1 = TimeoutReader::new(recv1);
                    recv1.set_timeout(Some(READ_TIMEOUT));

                    let a = async {
                        let _ = copy(&mut Box::pin(recv0), &mut send1).await;
                        let _ = send1.shutdown().await;
                    };

                    let b = async {
                        let _ = copy(&mut Box::pin(recv1), &mut send0).await;
                        let _ = send0.finish().await;
                    };

                    let _ = tokio::join!(a, b);

                    log::trace!("finish stream");
                });
            }
        });
    }

    Ok(())
}

fn fingerprint(cert: &[u8]) -> String {
    let mut hs = Sha256::new();
    hs.update(cert);
    hex::encode(hs.finalize())[..10].to_string()
}

fn gen_cert() -> Result<()> {
    let cert = rcgen::generate_simple_self_signed(vec!["what-ever-host".into()]).unwrap();
    println!(
        "{}\n{}",
        cert.serialize_pem().unwrap(),
        cert.serialize_private_key_pem()
    );

    Ok(())
}

fn auth_key(psk: &String) -> [u8; 32] {
    let mut hs = Sha256::new();
    hs.update(psk);
    (*hs.finalize()).try_into().unwrap()
}
