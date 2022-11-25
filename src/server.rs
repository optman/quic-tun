use crate::common::concat_stream;
use crate::common::{auth_key, fingerprint};
use crate::config::server_config;
use anyhow::Result;
use futures_util::stream::StreamExt;
use quinn::Endpoint;
use rndz::udp::Client as rndz;
use std::marker::Unpin;
use std::net::SocketAddr;
use std::os::unix::{io::AsRawFd, prelude::RawFd};
use std::sync::Arc;
use std::time::Duration;
use structopt::StructOpt;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

#[derive(StructOpt, Debug)]
pub(crate) struct ServerOpt {
    #[structopt(short = "l", long = "local-addr", required_unless = "id")]
    local_addr: Option<SocketAddr>,
    #[structopt(short = "f", long = "forward-addr")]
    forward_addr: Option<String>,
    #[structopt(short = "c", long = "cert-file")]
    cert_file: Option<String>,
    #[structopt(short = "e", long = "psk")]
    psk: Option<String>,
    #[structopt(skip = [0;32])]
    auth_key: Option<[u8; 32]>,
    #[structopt(short = "t", long = "read-timeout", default_value = "10")]
    read_timeout: u64,
    #[structopt(short = "d", long = "daemonize")]
    pub(crate) daemonize: bool,
    #[structopt(long = "rndz-server", required_unless = "local-addr")]
    rndz_server: Option<String>,
    #[structopt(long = "id", required_unless = "local-addr")]
    id: Option<String>,
}

#[tokio::main]
pub(crate) async fn run_server(mut opt: ServerOpt) -> Result<()> {
    if let Some(psk) = &opt.psk {
        opt.auth_key = Some(auth_key(psk));
    }

    let (cfg, cert) = server_config(&opt.cert_file)?;
    log::info!("fingerprint: {}", fingerprint(&cert),);

    let mut builder = Endpoint::builder();
    builder.listen(cfg);

    let remote_forward = opt.forward_addr.is_none();
    if !remote_forward {
        log::info!("forward:{}", opt.forward_addr.as_ref().unwrap());
    }

    let opt = Arc::new(opt);

    match opt.rndz_server.as_ref() {
        None => {
            let (endpoint, incoming) = builder.bind(opt.local_addr.as_ref().unwrap())?;

            log::info!("local:{}", endpoint.local_addr().unwrap());

            handle_incoming(incoming, opt).await?;
        }
        Some(rndz_server) => {
            let mut c = rndz::new(rndz_server, opt.id.as_ref().unwrap(), opt.local_addr)?;
            c.listen()?;

            log::info!("local: {}", c.local_addr().unwrap());

            let (_, incoming) = builder
                .with_socket(c.as_socket().try_clone().unwrap())
                .unwrap();

            handle_incoming(incoming, opt).await?;
        }
    }

    Ok(())
}

async fn handle_incoming(mut incoming: quinn::Incoming, opt: Arc<ServerOpt>) -> Result<()> {
    let rto = Duration::from_secs(opt.read_timeout);

    while let Some(conn) = incoming.next().await {
        log::trace!("new connection {:?}", conn.remote_address());

        let mut conn = match conn.await {
            Ok(c) => c,
            Err(e) => {
                log::trace!("wait incomming fail, {:?}", e);
                continue;
            }
        };

        let opt = opt.clone();
        tokio::spawn(async move {
            let mut auth = false;
            let mut listener: Option<RawFd> = None;

            while let Some(stream) = conn.bi_streams.next().await {
                let mut stream0 = match stream {
                    Err(e) => {
                        log::trace!("next bi stream fail, {:?}", e);
                        if let Some(fd) = listener {
                            unsafe {
                                libc::shutdown(fd, libc::SHUT_RD);
                            }
                        }
                        break;
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

                if let Some(fw_addr) = &opt.forward_addr {
                    let fw_addr = fw_addr.clone();
                    tokio::spawn(async move {
                        let _ = local_forward(stream0, &fw_addr, rto).await;
                    });
                } else if let Some(fd) =
                    handle_cmd(stream0.1, stream0.0, conn.connection.clone(), rto).await
                {
                    log::info!("open port success");
                    listener = Some(fd);
                }
            }
        });
    }
    Ok(())
}

async fn handle_cmd<R: AsyncRead + Unpin, W: AsyncWrite + Unpin>(
    r: R,
    mut w: W,
    c: quinn::Connection,
    rto: Duration,
) -> Option<RawFd> {
    let mut reader = BufReader::new(r);
    let mut req = String::new();
    match reader.read_line(&mut req).await {
        Ok(_) => {
            let parts: Vec<&str> = req.trim().splitn(2, ' ').collect();
            if parts.len() != 2 {
                return None;
            }
            let (resp, result) = match (parts[0], parts[1]) {
                ("open", port) => {
                    log::info!("open port {}", port);
                    match open_port(port, c.clone(), rto).await {
                        Ok(fd) => ("success".to_string(), Some(fd)),
                        Err(e) => (e.to_string(), None),
                    }
                }
                (cmd, _) => {
                    log::trace!("invalid cmd {}", cmd);
                    ("invalid cmd".to_string(), None)
                }
            };

            let _ = w.write(resp.as_bytes()).await;
            let _ = w.write(b"\n").await;

            result
        }
        Err(_) => None,
    }
}

async fn open_port(port: &str, conn: quinn::Connection, rto: Duration) -> Result<RawFd> {
    let ln = TcpListener::bind(format!("0.0.0.0:{}", port)).await?;
    let fd = ln.as_raw_fd();
    let port = port.to_owned();
    tokio::spawn(async move {
        while let Ok(s) = ln.accept().await {
            tokio::spawn(handle_client(s.0, conn.clone(), rto));
        }

        log::info!("close port {}", port);
    });

    Ok(fd)
}

async fn handle_client(s0: TcpStream, conn1: quinn::Connection, rto: Duration) -> Result<()> {
    let s1 = conn1.open_bi().await.map_err(|e| {
        log::trace!("open bi fail, {:?}", e);
        e
    })?;

    log::trace!("open stream success");

    concat_stream(s1, s0, rto).await;

    Ok(())
}

async fn local_forward(
    stream0: (quinn::SendStream, quinn::RecvStream),
    forward_addr: &String,
    rto: Duration,
) -> Result<()> {
    log::trace!("connecting {:?}", forward_addr);
    let stream1 = match TcpStream::connect(forward_addr).await {
        Ok(s) => s,
        Err(e) => {
            log::warn!("connect to forward_addr fail, {:?}", e);
            return Ok(());
        }
    };

    log::trace!("{:?} connected", forward_addr);

    concat_stream(stream0, stream1, rto).await;

    log::trace!("finish stream");

    Ok(())
}
