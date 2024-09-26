use argh::FromArgs;
use http_body_util::BodyExt;
use hyper::{Request, StatusCode};
use hyper_util::rt::tokio::{TokioExecutor, TokioIo};
use rustls::ClientConfig;
use rustls::{pki_types::ServerName, RootCertStore};
use std::error::Error;
use std::sync::Arc;
use tokio::net::TcpStream;
use tokio::pin;
use tokio_rustls::{rustls, TlsConnector};
use tokio_util::either::Either;

#[derive(FromArgs)]
/// Arguments
pub struct Args {
    #[argh(option)]
    /// HTTP CONNECT proxy to use
    proxy: Option<hyper::Uri>,
    /// HTTP URL to do a GET request to
    #[argh(positional)]
    target: hyper::Uri,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    // Fetch proxy and target from command-line arguments
    let args: Args = argh::from_env();
    let target_uri = args.target;

    let target_port = target_uri
        .port_u16()
        .unwrap_or_else(|| match target_uri.scheme_str() {
            Some("https") => 443,
            _ => 80,
        });
    let target_host = target_uri.host().expect("uri has no host").to_string();
    let host_addr = format!("{target_host}:{target_port}");

    let tcp_stream = if let Some(proxy_uri) = args.proxy {
        // XXX: We don't support HTTPS proxy but that woudln't be too hard.
        let proxy_addr = format!(
            "{}:{}",
            proxy_uri.host().expect("proxy uri needs host"),
            proxy_uri.port_u16().expect("proxy uri needs port")
        );

        let stream = TcpStream::connect(proxy_addr).await.unwrap();
        let (mut sender, conn) =
            hyper::client::conn::http1::handshake(TokioIo::new(stream)).await?;

        // use the http proxy CONNECT request method
        let request =
            Request::connect(format!("{}:{}", target_host, target_port)).body(String::new())?;
        let response_future = sender.send_request(request);
        pin!(response_future);

        let (proxy_response, conn_parts) = tokio::join!(response_future, conn.without_shutdown());

        if proxy_response?.status() != StatusCode::OK {
            panic!("Failed to negotioate with proxy");
        }

        conn_parts?.io.into_inner()
    } else {
        TcpStream::connect(host_addr).await?
    };

    let (io, http2) = if target_uri.scheme_str() == Some("https") {
        let mut root_cert_store = RootCertStore::empty();
        root_cert_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        let mut config = ClientConfig::builder()
            .with_root_certificates(root_cert_store)
            .with_no_client_auth();

        config.alpn_protocols = vec!["http/1.1".into(), "h2".into()];

        let connector = TlsConnector::from(Arc::new(config));
        let dnsname = ServerName::try_from(target_host.clone()).unwrap();
        let tls_stream = connector.connect(dnsname, tcp_stream).await.unwrap();
        let http2 = tls_stream.get_ref().1.alpn_protocol() == Some(b"h2");
        // 🤬: It's annoying to Box<dyn ..> these because you need multiple traits and for some
        // reason rust doesn't support that. You have to make your own trait which requires the other traits and I cbf...
        (Either::Left(tls_stream), http2)
    } else {
        (Either::Right(tcp_stream), false)
    };

    let mut request = Request::builder()
        // 🤬: Sometimes this works without being explicitly set
        .version(if http2 {
            hyper::Version::HTTP_2
        } else {
            hyper::Version::HTTP_11
        })
        .method("GET")
        .header(hyper::header::USER_AGENT, "llfourn-hyper")
        .header(hyper::header::ACCEPT, "*/*")
        // 🤬: Must be different between http 1 and 2!
        .uri(if http2 {
            target_uri.to_string()
        } else {
            target_uri.path().to_string()
        })
        .body(String::new())?;

    dbg!(&request);

    let res = if http2 {
        eprintln!("=== using HTTP 2 ===");

        let (mut request_sender, conn) =
            hyper::client::conn::http2::handshake(TokioExecutor::new(), TokioIo::new(io)).await?;
        tokio::task::spawn(async move {
            if let Err(err) = conn.await {
                eprintln!("Connection failed: {:?}", err);
            }
        });
        dbg!(request_sender.send_request(request).await).unwrap()
    } else {
        eprintln!("=== using HTTP 1 ===");
        // 🤬: setting this header in http2 sometimes kills you
        request.headers_mut().insert(
            hyper::header::HOST,
            hyper::header::HeaderValue::from_str(target_uri.authority().unwrap().as_str()).unwrap(),
        );
        let (mut request_sender, conn) =
            hyper::client::conn::http1::handshake(TokioIo::new(io)).await?;
        tokio::task::spawn(async move {
            if let Err(err) = conn.await {
                println!("Connection failed: {:?}", err);
            }
        });

        request_sender.send_request(request).await.unwrap()
    };

    eprintln!("status: {}", res.status());
    eprintln!("Headers: {:#?}\n", res.headers());

    let body = res.into_body();
    let data = body.collect().await?.to_bytes();
    use std::io::Write;
    std::io::stdout().write_all(&data).unwrap();

    Ok(())
}
