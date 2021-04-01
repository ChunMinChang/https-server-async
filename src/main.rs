use argh::FromArgs;
use async_std::io;
use async_std::net::{TcpListener, TcpStream};
use async_std::prelude::*;
use async_std::task;
use async_tls::TlsAcceptor;
use rustls::internal::pemfile::{certs, pkcs8_private_keys};
use rustls::{Certificate, NoClientAuth, PrivateKey, ServerConfig};
use std::fs::File;
use std::io::BufReader;
use std::net::ToSocketAddrs;
use std::path::{Path, PathBuf};
use std::sync::Arc;

#[derive(FromArgs)]
#[argh(description = "HTTPS server settings")]
struct Options {
    #[argh(positional)]
    addr: String,

    #[argh(option, short = 'c')]
    #[argh(description = "the certificate file for the server")]
    cert: PathBuf,

    #[argh(option, short = 'k')]
    #[argh(description = "the private-key file for the certificate")]
    key: PathBuf,
}

fn main() -> io::Result<()> {
    let options: Options = argh::from_env();
    let addr = options
        .addr
        .to_socket_addrs()?
        .next()
        .ok_or_else(|| io::Error::from(io::ErrorKind::InvalidInput))?;
    let config = load_config(&options)?;

    let tls_acceptor = TlsAcceptor::from(Arc::new(config));

    task::block_on(async {
        let tcp_listener = TcpListener::bind(&addr).await?;
        let mut incoming = tcp_listener.incoming();

        while let Some(stream) = incoming.next().await {
            let acceptor = tls_acceptor.clone();
            let mut stream = stream?;

            task::spawn(async move {
                let res = handle_connection(&acceptor, &mut stream).await;
                match res {
                    Ok(_) => {}
                    Err(err) => {
                        eprintln!("{:?}", err);
                    }
                };
            });
        }

        Ok(())
    })
}

async fn handle_connection(
    tls_acceptor: &TlsAcceptor,
    tcp_stream: &mut TcpStream,
) -> io::Result<()> {
    let peer_addr = tcp_stream.peer_addr()?;
    println!("Connection from: {}", peer_addr);

    let handshake = tls_acceptor.accept(tcp_stream);
    let mut tls_stream = handshake.await?;

    tls_stream
        .write_all(
            &b"HTTP/1.0 200 ok\r\n\
        Connection: close\r\n\
        Content-length: 12\r\n\
        \r\n\
        Hello world!"[..],
        )
        .await?;

    tls_stream.flush().await?;

    Ok(())
}

fn load_config(options: &Options) -> io::Result<ServerConfig> {
    let certs = load_certs(&options.cert)?;
    let mut keys = load_keys(&options.key)?;

    let mut config = ServerConfig::new(NoClientAuth::new());
    config
        .set_single_cert(certs, keys.remove(0))
        .map_err(|err| io::Error::new(io::ErrorKind::InvalidInput, err))?;

    Ok(config)
}

fn load_certs(path: &Path) -> io::Result<Vec<Certificate>> {
    certs(&mut BufReader::new(File::open(path)?))
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid cert"))
}

fn load_keys(path: &Path) -> io::Result<Vec<PrivateKey>> {
    pkcs8_private_keys(&mut BufReader::new(File::open(path)?))
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid key"))
}
