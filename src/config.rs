use anyhow::{Context, Result};
use quinn::{Certificate, CertificateChain, ClientConfig, PrivateKey, ServerConfig};
use std::convert::TryInto;
use std::fs;
use std::sync::Arc;
use std::time::Duration;

struct SkipServerVerification;

impl SkipServerVerification {
    fn new() -> Arc<Self> {
        Arc::new(Self)
    }
}

impl rustls::ServerCertVerifier for SkipServerVerification {
    fn verify_server_cert(
        &self,
        _roots: &rustls::RootCertStore,
        _presented_certs: &[rustls::Certificate],
        _dns_name: webpki::DNSNameRef,
        _ocsp_response: &[u8],
    ) -> Result<rustls::ServerCertVerified, rustls::TLSError> {
        Ok(rustls::ServerCertVerified::assertion())
    }
}

pub(crate) fn client_config() -> ClientConfig {
    let mut cfg = ClientConfig::with_root_certificates(vec![]).unwrap();

    let tp_cfg = Arc::get_mut(&mut cfg.transport).unwrap();
    tp_cfg.keep_alive_interval(Some(Duration::from_secs(10)));
    tp_cfg.max_idle_timeout(Some(Duration::from_secs(60).try_into().unwrap()));

    let tls_cfg = Arc::get_mut(&mut cfg.crypto).unwrap();
    tls_cfg
        .dangerous()
        .set_certificate_verifier(SkipServerVerification::new());

    cfg
}

pub(crate) fn server_config(cert_file: &Option<String>) -> Result<(ServerConfig, Vec<u8>)> {
    let (cert, priv_key) = match cert_file {
        Some(cert_file) => {
            let f = fs::read(cert_file).context("read cert file")?;
            let cert = Certificate::from_pem(&f)?;
            let priv_key = PrivateKey::from_pem(&f)?;
            (cert, priv_key)
        }
        None => {
            let cert = rcgen::generate_simple_self_signed(vec!["what-ever-host".into()])?;
            let cert_der = cert.serialize_der()?;
            let priv_der = cert.serialize_private_key_der();
            let cert = Certificate::from_der(&cert_der)?;
            let priv_key = PrivateKey::from_der(&priv_der)?;
            (cert, priv_key)
        }
    };

    let cert_der = cert.as_der().to_vec();

    let cert_chain = CertificateChain::from_certs(vec![cert]);

    let mut cfg = ServerConfig::with_single_cert(cert_chain, priv_key)?;

    let tp_cfg = Arc::get_mut(&mut cfg.transport).unwrap();
    tp_cfg.max_idle_timeout(Some(Duration::from_secs(60).try_into().unwrap()));

    Ok((cfg, cert_der))
}
