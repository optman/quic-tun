use anyhow::Result;
use sha2::{Digest, Sha256};
use std::convert::TryInto;
use std::time::Duration;
use tokio::io::{copy, AsyncWriteExt};
use tokio_io_timeout::TimeoutReader;

pub(crate) fn daemonize() {
    daemonize::Daemonize::new() /*.user("nobody")*/
        .start()
        .unwrap();
}

pub(crate) fn fingerprint(cert: &[u8]) -> String {
    let mut hs = Sha256::new();
    hs.update(cert);
    hex::encode(hs.finalize())[..10].to_string()
}

pub(crate) fn gen_cert() -> Result<()> {
    let cert = rcgen::generate_simple_self_signed(vec!["what-ever-host".into()]).unwrap();
    println!(
        "{}\n{}",
        cert.serialize_pem().unwrap(),
        cert.serialize_private_key_pem()
    );

    Ok(())
}

pub(crate) fn auth_key(psk: &String) -> [u8; 32] {
    let mut hs = Sha256::new();
    hs.update(psk);
    (*hs.finalize()).try_into().unwrap()
}

pub(crate) async fn concat_stream(
    s0: (quinn::SendStream, quinn::RecvStream),
    mut s1: tokio::net::TcpStream,
    rto: Duration,
) {
    let (mut send0, recv0) = s0;
    let (recv1, mut send1) = s1.split();

    let mut recv0 = TimeoutReader::new(recv0);
    recv0.set_timeout(Some(rto));

    let mut recv1 = TimeoutReader::new(recv1);
    recv1.set_timeout(Some(rto));

    let a = async {
        let _ = copy(&mut Box::pin(recv0), &mut send1).await;
        let _ = send1.shutdown().await;
    };

    let b = async {
        let _ = copy(&mut Box::pin(recv1), &mut send0).await;
        let _ = send0.finish().await;
    };

    let _ = tokio::join!(a, b);
}
