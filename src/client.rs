use crate::common::concat_stream;
use crate::common::{auth_key, fingerprint};
use crate::config::client_config;
use anyhow::{anyhow, Result};
use futures_util::stream::StreamExt;
use quinn::Endpoint;
use rndz::udp::Client as rndz;
use std::net::{SocketAddr, ToSocketAddrs};
use std::time::Duration;
use structopt::StructOpt;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::net::{TcpListener, TcpStream};

#[derive(StructOpt, Debug)]
pub(crate) struct ClientOpt {
    #[structopt(short = "r", long = "remote-addr", required_unless = "remote-id")]
    remote_addr: Option<String>,
    #[structopt(long = "rndz-server", required_unless = "remote-addr")]
    rndz_server: Option<String>,
    #[structopt(long = "remote-id", required_unless = "remote-addr")]
    remote_id: Option<String>,
    #[structopt(long = "id")]
    id: Option<String>,
    #[structopt(
        short = "l",
        long = "local-addr",
        required_unless("open-port"),
        conflicts_with("open-port")
    )]
    local_addr: Option<SocketAddr>,
    #[structopt(short = "f", long = "forward-addr", required_unless("local-addr"))]
    forward_addr: Option<String>,
    #[structopt(short = "o", long = "open-port", required_unless("local-addr"))]
    open_port: Option<u16>,
    #[structopt(short = "p", long = "fingerprint")]
    fingerprint: Option<String>,
    #[structopt(short = "e", long = "psk")]
    psk: Option<String>,
    #[structopt(skip = [0;32])]
    auth_key: Option<[u8; 32]>,
    #[structopt(short = "t", long = "read-timeout", default_value = "10")]
    read_timeout: u64,
    #[structopt(short = "d", long = "daemonize")]
    pub(crate) daemonize: bool,
}

fn new_ep(opt: &ClientOpt) -> Result<(quinn::Endpoint, SocketAddr)> {
    let mut builder = Endpoint::builder();

    builder.default_client_config(client_config());

    if let Some(remote_addr) = opt.remote_addr.as_ref() {
        let remote_addr = remote_addr
            .to_socket_addrs()?
            .next()
            .ok_or(anyhow!("no addr"))?;

        let bind_addr = match remote_addr {
            SocketAddr::V4(_) => "0.0.0.0:0",
            SocketAddr::V6(_) => "[::]:0",
        };

        let (endpoint, _incoming) = builder.bind(&bind_addr.parse()?)?;

        Ok((endpoint, remote_addr))
    } else {
        let rndz_server = opt
            .rndz_server
            .as_ref()
            .ok_or(anyhow!("rndz server not set"))?;

        let remote_id = opt.remote_id.as_ref().ok_or(anyhow!("remote id not set"))?;

        let mut c = rndz::new(
            rndz_server,
            opt.id.as_ref().ok_or(anyhow!("local id not set"))?,
        )?;
        let (socket, remote_addr) = c.connect(remote_id)?;

        let (endpoint, _incoming) = builder.with_socket(socket)?;

        Ok((endpoint, remote_addr))
    }
}

#[tokio::main]
pub(crate) async fn run_client(mut opt: ClientOpt) -> Result<()> {
    if let Some(psk) = &opt.psk {
        opt.auth_key = Some(auth_key(&psk));
    }

    let rto = Duration::from_secs(opt.read_timeout);

    log::info!(
        "remote: {}",
        opt.remote_addr.as_ref().or(opt.remote_id.as_ref()).unwrap()
    );

    if opt.local_addr.is_none() {
        log::info!("forward:{}", opt.forward_addr.as_ref().unwrap(),);

        local_forward(&opt, rto).await
    } else {
        log::info!("listen:{}", opt.local_addr.as_ref().unwrap(),);

        remote_forward(&opt, rto).await
    }
}

async fn local_forward(opt: &ClientOpt, rto: Duration) -> Result<()> {
    loop {
        let mut conn = match conn_remote(opt).await {
            Ok(c) => c,
            Err(_) => {
                std::thread::sleep(Duration::from_secs(30));
                continue;
            }
        };

        let ok = match conn.connection.open_bi().await {
            Ok(mut s) => {
                if s.0
                    .write(format!("open {}\n", opt.open_port.unwrap()).as_bytes())
                    .await
                    .is_ok()
                {
                    let mut reader = BufReader::new(s.1);
                    let mut resp = String::new();
                    match reader.read_line(&mut resp).await {
                        Ok(_) => match resp.trim() {
                            "success" => {
                                log::info!("open port success");
                                true
                            }
                            reason => {
                                log::error!("open port fail, {}", reason);
                                break;
                            }
                        },
                        Err(_) => false,
                    }
                } else {
                    false
                }
            }
            Err(_) => false,
        };

        if !ok {
            log::trace!("open port fail, retry later");
            std::thread::sleep(Duration::from_secs(30));
            continue;
        }

        log::trace!("wait for stream");

        while let Some(stream) = conn.bi_streams.next().await {
            let s = match stream {
                Err(e) => {
                    log::trace!("next bi stream fail, {:?}", e);
                    break;
                }
                Ok(s) => s,
            };
            log::trace!("new stream");

            let fw_addr = opt.forward_addr.clone().unwrap();
            tokio::spawn(handle_forward(s, fw_addr, rto));
        }
    }

    Err(anyhow!("internal fail"))
}

async fn conn_remote(opt: &ClientOpt) -> Result<quinn::NewConnection> {
    let (endpoint, remote_addr) = new_ep(opt)?;

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

            if let Some(auth_key) = &opt.auth_key {
                match c.connection.open_bi().await {
                    Ok(mut s) => {
                        let _ = s.0.write(auth_key).await;
                    }
                    Err(_) => {
                        return Err(anyhow!("auth fail"));
                    }
                };
            }

            Ok(c)
        }

        Err(_) => Err(anyhow!("connect to remote fail")),
    }
}

async fn handle_forward(
    s0: (quinn::SendStream, quinn::RecvStream),
    fw_addr: String,
    rto: Duration,
) -> Result<()> {
    let s1 = TcpStream::connect(fw_addr.clone()).await.map_err(|e| {
        log::warn!("connect {} fail, {:?}", fw_addr, e);
        e
    })?;

    log::trace!("connect to {} success", fw_addr);

    concat_stream(s0, s1, rto).await;

    Ok(())
}

async fn remote_forward(opt: &ClientOpt, rto: Duration) -> Result<()> {
    let ln = TcpListener::bind(opt.local_addr.unwrap()).await?;

    let mut conn1 = Some(conn_remote(opt).await.unwrap());

    while let Ok((stream0, src)) = ln.accept().await {
        log::trace!("new connection, {:?}", src);

        let mut retry = false;

        let stream1 = loop {
            if conn1.is_none() {
                log::debug!("reconnect remote");
                conn1 = match conn_remote(opt).await {
                    Ok(c) => Some(c),
                    Err(_) => None,
                };
            }

            if let Some(c) = conn1.as_ref() {
                match c.connection.open_bi().await {
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
            concat_stream(stream1, stream0, rto).await;

            log::trace!("finish connection");
        });
    }

    Ok(())
}
