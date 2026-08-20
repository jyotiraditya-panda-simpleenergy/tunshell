use crate::Config;
use anyhow::{bail, Context as AnyhowContext, Result};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{ClientConfig, DigitallySignedStruct, RootCertStore, SignatureScheme};
use std::{
    convert::TryFrom,
    io,
    net::ToSocketAddrs,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
    time::Duration,
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf},
    net::TcpStream,
};
use tokio_rustls::{client::TlsStream, TlsConnector};

pub struct TlsServerStream {
    inner: TlsStream<TcpStream>,
}

impl TlsServerStream {
    pub async fn connect(config: &Config, port: u16) -> Result<Self> {
        let mut root_store = RootCertStore::empty();
        root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let tls_config_builder =
            ClientConfig::builder_with_provider(Arc::clone(&provider))
                .with_safe_default_protocol_versions()
                .context("failed to build tls config")?
                .with_root_certificates(root_store);

        let mut tls_config = tls_config_builder.with_no_client_auth();

        if config.dangerous_disable_relay_server_verification() {
            log::warn!("disabling TLS verification");
            tls_config
                .dangerous()
                .set_certificate_verifier(Arc::new(NullCertVerifier { provider }));
        }

        let connector = TlsConnector::from(Arc::new(tls_config));

        let server_name = ServerName::try_from(config.relay_host().to_owned())?;

        let network_stream = if let Ok(http_proxy) = std::env::var("HTTP_PROXY") {
            log::info!("Connecting to relay server via http proxy {}", http_proxy);

            connect_via_http_proxy(config, port, http_proxy).await?
        } else {
            log::info!("Connecting to relay server over TCP");
            let relay_addr = (config.relay_host(), port)
                .to_socket_addrs()?
                .next()
                .unwrap();

            TcpStream::connect(relay_addr).await?
        };

        let keepalive = socket2::TcpKeepalive::new().with_time(Duration::from_secs(30));
        if let Err(err) = socket2::SockRef::from(&network_stream).set_tcp_keepalive(&keepalive) {
            log::warn!("failed to set tcp keepalive: {}", err);
        }

        let transport_stream = connector.connect(server_name, network_stream).await?;

        Ok(Self {
            inner: transport_stream,
        })
    }
}

/// Skips certificate verification entirely; used only when the caller has
/// explicitly opted in via `dangerous_disable_relay_server_verification`.
#[derive(Debug)]
struct NullCertVerifier {
    provider: Arc<rustls::crypto::CryptoProvider>,
}

impl ServerCertVerifier for NullCertVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

async fn connect_via_http_proxy(
    config: &Config,
    port: u16,
    http_proxy: String,
) -> Result<TcpStream> {
    let proxy_addr = http_proxy.to_socket_addrs()?.next().unwrap();
    let mut proxy_stream = TcpStream::connect(proxy_addr).await?;

    proxy_stream
        .write_all(format!("CONNECT {}:{} HTTP/1.1\n\n", config.relay_host(), port).as_bytes())
        .await?;
    let mut read_buff = [0u8; 1024];

    let read = match proxy_stream.read(&mut read_buff).await? {
        0 => bail!("Failed to read response from http proxy"),
        read @ _ => read,
    };

    let response =
        String::from_utf8(read_buff[..read].to_vec()).context("failed to parse proxy response")?;
    if !response.contains("HTTP/1.1 200") && !response.contains("HTTP/1.0 200") {
        bail!(format!(
            "invalid response returned from http proxy: {}",
            response
        ));
    }

    Ok(proxy_stream)
}

impl AsyncRead for TlsServerStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl AsyncWrite for TlsServerStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<Result<usize, io::Error>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), io::Error>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), io::Error>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

impl super::AsyncIO for TlsServerStream {}
