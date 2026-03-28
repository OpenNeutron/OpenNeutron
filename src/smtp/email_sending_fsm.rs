use std::io::{self, Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::sync::Arc;
use std::time::Duration;
use rustls::ClientConfig;
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::{DigitallySignedStruct, SignatureScheme};
use crate::smtp::MaybeTlsClientStream;


#[derive(Debug)]
struct NoCertVerification;

impl ServerCertVerifier for NoCertVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp: &[u8],
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
        vec![
            SignatureScheme::RSA_PKCS1_SHA256,
            SignatureScheme::RSA_PKCS1_SHA384,
            SignatureScheme::RSA_PKCS1_SHA512,
            SignatureScheme::ECDSA_NISTP256_SHA256,
            SignatureScheme::ECDSA_NISTP384_SHA384,
            SignatureScheme::ECDSA_NISTP521_SHA512,
            SignatureScheme::RSA_PSS_SHA256,
            SignatureScheme::RSA_PSS_SHA384,
            SignatureScheme::RSA_PSS_SHA512,
            SignatureScheme::ED25519,
        ]
    }
}

fn make_client_tls_config() -> Arc<ClientConfig> {
    let config = ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(NoCertVerification))
        .with_no_client_auth();
    Arc::new(config)
}

pub struct EmailSendingFSM {
    stream: Option<MaybeTlsClientStream>,
    tls_config: Arc<ClientConfig>,
    host: String,
    ehlo_domain: String,
}

impl EmailSendingFSM {
    pub fn connect(host: &str, port: u16, ehlo_domain: &str) -> io::Result<Self> {
        let addr = (host, port)
            .to_socket_addrs()?
            .next()
            .ok_or_else(|| io::Error::new(io::ErrorKind::Other, format!("DNS resolution failed for '{}'", host)))?;
        let stream = TcpStream::connect_timeout(&addr, Duration::from_secs(30))?;
        stream.set_read_timeout(Some(Duration::from_secs(60)))?;
        stream.set_write_timeout(Some(Duration::from_secs(60)))?;
        Ok(EmailSendingFSM {
            stream: Some(MaybeTlsClientStream::Plain(stream)),
            tls_config: make_client_tls_config(),
            host: host.to_string(),
            ehlo_domain: ehlo_domain.to_string(),
        })
    }

    fn read_line(&mut self) -> io::Result<String> {
        let stream = self.stream.as_mut().unwrap();
        let mut line = Vec::new();
        let mut byte = [0u8; 1];
        loop {
            stream.read_exact(&mut byte)?;
            if byte[0] == b'\n' {
                break;
            }
            line.push(byte[0]);
        }
        if line.last() == Some(&b'\r') {
            line.pop();
        }
        let s = String::from_utf8_lossy(&line).to_string();
        log::debug!("[SMTP Client] << {}", s);
        Ok(s)
    }

    
    fn read_response(&mut self) -> io::Result<(u16, Vec<String>)> {
        let mut lines = Vec::new();
        loop {
            let line = self.read_line()?;
            if line.len() < 3 {
                return Err(io::Error::new(io::ErrorKind::Other, format!("Unexpected short SMTP response: '{}'", line)));
            }
            let code: u16 = line[..3].parse()
                .map_err(|_| io::Error::new(io::ErrorKind::Other, format!("Invalid SMTP response code: '{}'", &line[..3])))?;
            
            let is_last = line.as_bytes().get(3) != Some(&b'-');
            lines.push(line);
            if is_last {
                return Ok((code, lines));
            }
        }
    }

    fn write_cmd(&mut self, cmd: &str) -> io::Result<()> {
        log::debug!("[SMTP Client] >> {}", cmd.trim_end());
        let stream = self.stream.as_mut().unwrap();
        stream.write_all(cmd.as_bytes())?;
        stream.flush()
    }

    
    
    
    
    pub fn send(&mut self, from: &str, to: &[String], data: &[u8]) -> io::Result<()> {
        self.negotiate()?;
        self.send_envelope(from, to, data)?;
        self.quit()
    }

    pub fn send_e2ee(&mut self, from: &str, to: &[String], data: &[u8]) -> io::Result<()> {
        let caps = self.negotiate()?;
        if Self::has_opntrn(&caps) {
            self.write_cmd("OPNTRN E2EE\r\n")?;
            let (code, _) = self.read_response()?;
            if code != 250 {
                return Err(io::Error::new(io::ErrorKind::Other, format!("OPNTRN E2EE rejected with {}", code)));
            }
        }
        self.send_envelope(from, to, data)?;
        self.quit()
    }

    pub fn query_opntrn_keys(&mut self, addresses: &[String]) -> io::Result<Vec<(String, Option<(String, String)>)>> {
        let caps = self.negotiate()?;
        if !Self::has_opntrn(&caps) {
            self.quit()?;
            return Ok(addresses.iter().map(|a| (a.clone(), None)).collect());
        }

        let mut results = Vec::new();
        for addr in addresses {
            self.write_cmd(&format!("OPNTRN GETKEY {}\r\n", addr))?;
            let (code, lines) = self.read_response()?;
            if code == 250 && !lines.is_empty() {
                let line = &lines[0];
                let text = if line.len() > 4 { &line[4..] } else { "" };
                if text.starts_with("OPNTRN KEY ") {
                    let key_data = &text[11..];
                    if let Some(space_pos) = key_data.find(' ') {
                        let key_type = key_data[..space_pos].to_string();
                        let key_b64 = key_data[space_pos + 1..].trim().to_string();
                        results.push((addr.clone(), Some((key_type, key_b64))));
                        continue;
                    }
                }
            }
            results.push((addr.clone(), None));
        }

        self.quit()?;
        Ok(results)
    }

    fn has_opntrn(capabilities: &[String]) -> bool {
        capabilities.iter().any(|l| l.to_uppercase().contains("OPNTRN"))
    }

    fn negotiate(&mut self) -> io::Result<Vec<String>> {
        let (code, _) = self.read_response()?;
        if code != 220 {
            return Err(io::Error::new(io::ErrorKind::Other, format!("Expected 220 banner, got {}", code)));
        }

        self.write_cmd(&format!("EHLO {}\r\n", self.ehlo_domain))?;
        let (code, mut lines) = self.read_response()?;
        if code != 250 {
            return Err(io::Error::new(io::ErrorKind::Other, format!("EHLO failed with {}", code)));
        }

        let has_starttls = lines.iter().any(|l| l.to_uppercase().contains("STARTTLS"));
        if has_starttls {
            self.write_cmd("STARTTLS\r\n")?;
            let (code, _) = self.read_response()?;
            if code == 220 {
                let server_name = ServerName::try_from(self.host.clone())
                    .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Invalid server name '{}': {}", self.host, e)))?;
                let old_stream = self.stream.take().unwrap();
                self.stream = Some(old_stream.upgrade_to_tls(Arc::clone(&self.tls_config), server_name)?);

                self.write_cmd(&format!("EHLO {}\r\n", self.ehlo_domain))?;
                let (code, new_lines) = self.read_response()?;
                if code != 250 {
                    return Err(io::Error::new(io::ErrorKind::Other, format!("EHLO after STARTTLS failed with {}", code)));
                }
                lines = new_lines;
            }
        }

        Ok(lines)
    }

    fn send_envelope(&mut self, from: &str, to: &[String], data: &[u8]) -> io::Result<()> {
        self.write_cmd(&format!("MAIL FROM:<{}>\r\n", from))?;
        let (code, _) = self.read_response()?;
        if code != 250 {
            return Err(io::Error::new(io::ErrorKind::Other, format!("MAIL FROM rejected with {}", code)));
        }

        for recipient in to {
            self.write_cmd(&format!("RCPT TO:<{}>\r\n", recipient))?;
            let (code, _) = self.read_response()?;
            if code != 250 && code != 251 {
                return Err(io::Error::new(io::ErrorKind::Other, format!("RCPT TO rejected with {} for '{}'", code, recipient)));
            }
        }

        self.write_cmd("DATA\r\n")?;
        let (code, _) = self.read_response()?;
        if code != 354 {
            return Err(io::Error::new(io::ErrorKind::Other, format!("DATA command rejected with {}", code)));
        }

        // SMTP transparency (RFC 5321 s.4.5.2): dot-stuff any line that starts with '.'
        let stuffed = smtp_dot_stuff(data);
        let stream = self.stream.as_mut().unwrap();
        let send_data = &stuffed;

        const CHUNK_SIZE: usize = 65536;
        let mut offset = 0;
        while offset < send_data.len() {
            let end = (offset + CHUNK_SIZE).min(send_data.len());
            stream.write_all(&send_data[offset..end])?;
            offset = end;
        }
        stream.write_all(b"\r\n.\r\n")?;
        stream.flush()?;

        let (code, _) = self.read_response()?;
        if code != 250 {
            return Err(io::Error::new(io::ErrorKind::Other, format!("MESSAGE delivery rejected with {}", code)));
        }

        Ok(())
    }

    fn quit(&mut self) -> io::Result<()> {
        self.write_cmd("QUIT\r\n")?;
        let _ = self.read_response();
        Ok(())
    }
}

/// SMTP transparency (RFC 5321 s.4.5.2): any line beginning with '.' gets an extra '.' prepended.
fn smtp_dot_stuff(data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(data.len() + 64);
    let mut at_line_start = true;
    for &b in data {
        if at_line_start && b == b'.' {
            out.push(b'.');
        }
        out.push(b);
        at_line_start = b == b'\n';
    }
    out
}
