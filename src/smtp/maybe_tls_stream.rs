
use std::io::{self, Read, Write};
use std::net::TcpStream;
use std::sync::Arc;
use rustls::{ServerConfig, ServerConnection, StreamOwned};

pub enum MaybeTlsStream {
    Plain(TcpStream),
    Tls(StreamOwned<ServerConnection, TcpStream>),
}

impl Read for MaybeTlsStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match self {
            MaybeTlsStream::Plain(s) => s.read(buf),
            MaybeTlsStream::Tls(s) => s.read(buf),
        }
    }
}

impl Write for MaybeTlsStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        match self {
            MaybeTlsStream::Plain(s) => s.write(buf),
            MaybeTlsStream::Tls(s) => s.write(buf),
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        match self {
            MaybeTlsStream::Plain(s) => s.flush(),
            MaybeTlsStream::Tls(s) => s.flush(),
        }
    }
}

impl MaybeTlsStream {
    pub fn upgrade(self, config: Arc<ServerConfig>) -> io::Result<MaybeTlsStream> {
        match self {
            MaybeTlsStream::Plain(tcp) => {
                let server_conn = ServerConnection::new(config)
                    .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("TLS conn err: {:?}", e)))?;
                let mut tls_stream = StreamOwned::new(server_conn, tcp);
                tls_stream.conn.complete_io(&mut tls_stream.sock)?;
                Ok(MaybeTlsStream::Tls(tls_stream))
            }
            MaybeTlsStream::Tls(s) => Ok(MaybeTlsStream::Tls(s)),
        }
    }
}