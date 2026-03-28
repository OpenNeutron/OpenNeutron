use std::io::{self, Read, Write};
use std::net::TcpStream;
use std::sync::Arc;
use rustls::{ClientConfig, ClientConnection, StreamOwned};
use rustls::pki_types::ServerName;

pub enum MaybeTlsClientStream {
    Plain(TcpStream),
    Tls(StreamOwned<ClientConnection, TcpStream>),
}

impl Read for MaybeTlsClientStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match self {
            MaybeTlsClientStream::Plain(s) => s.read(buf),
            MaybeTlsClientStream::Tls(s) => s.read(buf),
        }
    }
}

impl Write for MaybeTlsClientStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        match self {
            MaybeTlsClientStream::Plain(s) => s.write(buf),
            MaybeTlsClientStream::Tls(s) => s.write(buf),
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        match self {
            MaybeTlsClientStream::Plain(s) => s.flush(),
            MaybeTlsClientStream::Tls(s) => s.flush(),
        }
    }
}

impl MaybeTlsClientStream {
    pub fn upgrade_to_tls(self, config: Arc<ClientConfig>, server_name: ServerName<'static>) -> io::Result<Self> {
        match self {
            MaybeTlsClientStream::Plain(tcp) => {
                let client_conn = ClientConnection::new(config, server_name)
                    .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("TLS client conn err: {:?}", e)))?;
                Ok(MaybeTlsClientStream::Tls(StreamOwned::new(client_conn, tcp)))
            }
            MaybeTlsClientStream::Tls(s) => Ok(MaybeTlsClientStream::Tls(s)),
        }
    }
}
