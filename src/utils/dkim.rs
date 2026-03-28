





use std::collections::HashMap;
use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use sha2::{Sha256, Digest};
use rsa::{RsaPublicKey, RsaPrivateKey, pkcs8::DecodePublicKey, pkcs8::DecodePrivateKey};
use rsa::pkcs1v15::{Signature, VerifyingKey, SigningKey};
use rsa::signature::{Verifier, Signer, SignatureEncoding};


#[derive(Debug, Clone, PartialEq)]
pub enum DkimStatus {
    
    Pass,
    
    Fail(String),
    
    None,
}

impl std::fmt::Display for DkimStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DkimStatus::Pass => write!(f, "pass"),
            DkimStatus::Fail(r) => write!(f, "fail: {}", r),
            DkimStatus::None => write!(f, "none"),
        }
    }
}





pub fn verify(raw_email: &str) -> DkimStatus {
    let (header_section, _) = split_email(raw_email);
    let raw_headers = parse_raw_headers(header_section);

    let sig_value = match raw_headers
        .iter()
        .find(|(name, _)| name.to_lowercase() == "dkim-signature")
        .map(|(_, v)| v.clone())
    {
        Some(v) => v,
        Option::None => return DkimStatus::None,
    };

    match verify_signature(raw_email, &raw_headers, &sig_value) {
        Ok(()) => DkimStatus::Pass,
        Err(e) => DkimStatus::Fail(e),
    }
}

fn verify_signature(
    raw_email: &str,
    raw_headers: &[(String, String)],
    sig_value: &str,
) -> Result<(), String> {
    let tags = parse_dkim_tags(sig_value);

    let domain = tags.get("d").ok_or("missing d= tag")?.trim().to_string();
    let selector = tags.get("s").ok_or("missing s= tag")?.trim().to_string();
    let algorithm = tags
        .get("a")
        .map(|s| s.trim().to_lowercase())
        .unwrap_or_else(|| "rsa-sha256".to_string());
    let canonicalization = tags
        .get("c")
        .map(|s| s.trim().to_lowercase())
        .unwrap_or_else(|| "simple/simple".to_string());
    let signed_headers_str = tags.get("h").ok_or("missing h= tag")?.trim().to_lowercase();
    let body_hash_b64 = strip_whitespace(tags.get("bh").ok_or("missing bh= tag")?);
    let sig_b64 = strip_whitespace(tags.get("b").ok_or("missing b= tag")?);

    if algorithm != "rsa-sha256" {
        return Err(format!("unsupported algorithm: {}", algorithm));
    }

    let canon_parts: Vec<&str> = canonicalization.splitn(2, '/').collect();
    let header_canon = canon_parts[0];
    let body_canon = if canon_parts.len() > 1 { canon_parts[1] } else { "simple" };

    
    let (_, raw_body) = split_email(raw_email);
    let canon_body = if body_canon == "relaxed" {
        canonicalize_body_relaxed(raw_body)
    } else {
        canonicalize_body_simple(raw_body)
    };

    let computed_bh = BASE64.encode(Sha256::digest(canon_body.as_bytes()));
    if computed_bh != body_hash_b64 {
        return Err("body hash mismatch".to_string());
    }

    
    let dns_name = format!("{}._domainkey.{}.", selector, domain);
    let txt_records = dns_txt_lookup(&dns_name);
    let key_der = find_dkim_public_key(&txt_records)?;

    
    let signed_fields: Vec<&str> = signed_headers_str.split(':').map(str::trim).collect();
    let mut signed_data = build_signed_header_data(&signed_fields, raw_headers, header_canon);

    
    
    let sig_value_empty_b = empty_b_tag(sig_value);
    let dkim_sig_line = if header_canon == "relaxed" {
        let mut s = canonicalize_header_relaxed("DKIM-Signature", &sig_value_empty_b);
        if s.ends_with("\r\n") {
            s.truncate(s.len() - 2);
        }
        s
    } else {
        format!("DKIM-Signature:{}", sig_value_empty_b)
    };
    signed_data.push_str(&dkim_sig_line);

    
    let sig_bytes = BASE64
        .decode(&sig_b64)
        .map_err(|e| format!("invalid signature base64: {}", e))?;

    let pub_key = RsaPublicKey::from_public_key_der(&key_der)
        .map_err(|e| format!("invalid public key DER: {}", e))?;

    let vk: VerifyingKey<Sha256> = VerifyingKey::new(pub_key);

    let sig = Signature::try_from(sig_bytes.as_slice())
        .map_err(|_| "invalid RSA signature bytes".to_string())?;

    vk.verify(signed_data.as_bytes(), &sig)
        .map_err(|_| "RSA signature verification failed".to_string())?;

    Ok(())
}



fn split_email(raw: &str) -> (&str, &str) {
    if let Some(pos) = raw.find("\r\n\r\n") {
        (&raw[..pos], &raw[pos + 4..])
    } else if let Some(pos) = raw.find("\n\n") {
        (&raw[..pos], &raw[pos + 2..])
    } else {
        (raw, "")
    }
}





fn parse_raw_headers(section: &str) -> Vec<(String, String)> {
    let mut headers: Vec<(String, String)> = Vec::new();
    let mut current: Option<(String, String)> = Option::None;

    for line in section.lines() {
        if line.starts_with(' ') || line.starts_with('\t') {
            
            if let Some((_, ref mut val)) = current {
                val.push_str("\r\n");
                val.push_str(line);
            }
        } else if let Some(colon) = line.find(':') {
            if let Some(hdr) = current.take() {
                headers.push(hdr);
            }
            current = Some((line[..colon].to_string(), line[colon + 1..].to_string()));
        }
    }
    if let Some(hdr) = current {
        headers.push(hdr);
    }
    headers
}

fn parse_dkim_tags(value: &str) -> HashMap<String, String> {
    let mut tags = HashMap::new();
    
    let unfolded = value
        .replace("\r\n\t", "")
        .replace("\r\n ", "")
        .replace("\n\t", "")
        .replace("\n ", "");
    for part in unfolded.split(';') {
        let part = part.trim();
        if let Some(eq) = part.find('=') {
            let k = part[..eq].trim().to_lowercase();
            let v = part[eq + 1..].to_string();
            if !k.is_empty() {
                tags.insert(k, v);
            }
        }
    }
    tags
}

fn strip_whitespace(s: &str) -> String {
    s.chars().filter(|c| !c.is_whitespace()).collect()
}



fn canonicalize_body_relaxed(body: &str) -> String {
    let mut lines: Vec<String> = body
        .lines()
        .map(|line| line.split_whitespace().collect::<Vec<_>>().join(" "))
        .collect();

    while lines.last().map(|l: &String| l.is_empty()).unwrap_or(false) {
        lines.pop();
    }

    if lines.is_empty() {
        return "\r\n".to_string();
    }

    let mut result = lines.join("\r\n");
    result.push_str("\r\n");
    result
}

fn canonicalize_body_simple(body: &str) -> String {
    let normalized = body.replace("\r\n", "\n").replace('\r', "\n");
    let trimmed = normalized.trim_end_matches('\n');
    if trimmed.is_empty() {
        "\r\n".to_string()
    } else {
        let with_crlf = trimmed.lines().collect::<Vec<_>>().join("\r\n");
        format!("{}\r\n", with_crlf)
    }
}



fn canonicalize_header_relaxed(name: &str, value: &str) -> String {
    let name_lower = name.to_lowercase();
    let unfolded = value
        .replace("\r\n\t", " ")
        .replace("\r\n ", " ")
        .replace("\n\t", " ")
        .replace("\n ", " ");
    let normalized = unfolded.split_whitespace().collect::<Vec<_>>().join(" ");
    format!("{}:{}\r\n", name_lower, normalized)
}


fn build_signed_header_data(
    fields: &[&str],
    raw_headers: &[(String, String)],
    canon: &str,
) -> String {
    let mut result = String::new();
    
    let mut used_count: HashMap<String, usize> = HashMap::new();

    for &field in fields {
        let field_lower = field.to_lowercase();
        let used = *used_count.get(&field_lower).unwrap_or(&0);
        used_count.insert(field_lower.clone(), used + 1);

        
        let matches: Vec<&(String, String)> = raw_headers
            .iter()
            .filter(|(n, _)| n.to_lowercase() == field_lower)
            .collect();

        if let Some(hdr) = matches.iter().rev().nth(used) {
            let line = if canon == "relaxed" {
                canonicalize_header_relaxed(&hdr.0, &hdr.1)
            } else {
                format!("{}:{}\r\n", hdr.0, hdr.1)
            };
            result.push_str(&line);
        }
    }
    result
}



fn empty_b_tag(sig_value: &str) -> String {
    sig_value
        .split(';')
        .map(|part| {
            let stripped = part.trim().to_lowercase();
            if stripped.starts_with("b=") && !stripped.starts_with("bh=") {
                " b=".to_string()
            } else {
                part.to_string()
            }
        })
        .collect::<Vec<_>>()
        .join(";")
}

fn find_dkim_public_key(txt_records: &[String]) -> Result<Vec<u8>, String> {
    for txt in txt_records {
        let tags = parse_dkim_tags(txt);
        if let Some(p) = tags.get("p") {
            let p = strip_whitespace(p);
            if p.is_empty() {
                return Err("DKIM key revoked (p= is empty)".to_string());
            }
            return BASE64
                .decode(&p)
                .map_err(|e| format!("invalid DKIM public key base64: {}", e));
        }
    }
    Err("no DKIM public key found in DNS".to_string())
}





fn dns_txt_lookup(hostname: &str) -> Vec<String> {
    use std::net::UdpSocket;
    use std::time::Duration;

    let query = build_dns_query(hostname);

    let socket = match UdpSocket::bind("0.0.0.0:0") {
        Ok(s) => s,
        Err(_) => return vec![],
    };
    let _ = socket.set_read_timeout(Some(Duration::from_secs(5)));

    if socket.send_to(&query, "8.8.8.8:53").is_err() {
        return vec![];
    }

    let mut buf = [0u8; 4096];
    let len = match socket.recv_from(&mut buf) {
        Ok((n, _)) => n,
        Err(_) => return vec![],
    };

    parse_dns_txt_response(&buf[..len])
}

fn build_dns_query(hostname: &str) -> Vec<u8> {
    let mut q = Vec::new();
    
    q.extend_from_slice(&[0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
    
    for label in hostname.trim_end_matches('.').split('.') {
        let b = label.as_bytes();
        q.push(b.len() as u8);
        q.extend_from_slice(b);
    }
    q.push(0x00); 
    q.extend_from_slice(&[0x00, 0x10, 0x00, 0x01]); 
    q
}

fn parse_dns_txt_response(data: &[u8]) -> Vec<String> {
    if data.len() < 12 {
        return vec![];
    }
    let ancount = u16::from_be_bytes([data[6], data[7]]) as usize;
    if ancount == 0 {
        return vec![];
    }

    let mut pos = 12;
    
    pos = skip_dns_name(data, pos);
    if pos + 4 > data.len() {
        return vec![];
    }
    pos += 4; 

    let mut results = Vec::new();

    for _ in 0..ancount {
        if pos >= data.len() {
            break;
        }
        pos = skip_dns_name(data, pos);
        if pos + 10 > data.len() {
            break;
        }
        let rtype = u16::from_be_bytes([data[pos], data[pos + 1]]);
        pos += 8; 
        let rdlen = u16::from_be_bytes([data[pos], data[pos + 1]]) as usize;
        pos += 2;

        if pos + rdlen > data.len() {
            break;
        }

        if rtype == 16 {
            
            let end = pos + rdlen;
            let mut txt = String::new();
            let mut p = pos;
            while p < end {
                let slen = data[p] as usize;
                p += 1;
                if p + slen <= end {
                    txt.push_str(&String::from_utf8_lossy(&data[p..p + slen]));
                    p += slen;
                } else {
                    break;
                }
            }
            if !txt.is_empty() {
                results.push(txt);
            }
        }

        pos += rdlen;
    }

    results
}

fn skip_dns_name(data: &[u8], mut pos: usize) -> usize {
    while pos < data.len() {
        let b = data[pos];
        if b == 0 {
            return pos + 1;
        }
        if b & 0xC0 == 0xC0 {
            
            return pos + 2;
        }
        pos += 1 + (b as usize);
    }
    pos
}


/// DKIM signer loaded at startup from the config's private_key_path.
pub struct DkimSigner {
    private_key: RsaPrivateKey,
    domain: String,
    selector: String,
}

impl DkimSigner {
    /// Try to load a DKIM signing key from PEM file.
    pub fn load(private_key_path: &str, domain: &str, selector: &str) -> Result<Self, String> {
        let pem = std::fs::read_to_string(private_key_path)
            .map_err(|e| format!("Failed to read DKIM private key '{}': {}", private_key_path, e))?;
        let private_key = RsaPrivateKey::from_pkcs8_pem(&pem)
            .map_err(|e| format!("Failed to parse DKIM private key: {}", e))?;
        Ok(DkimSigner {
            private_key,
            domain: domain.to_string(),
            selector: selector.to_string(),
        })
    }

    /// Sign a raw email (bytes) and return the email with a prepended DKIM-Signature header.
    pub fn sign(&self, raw_email: &[u8]) -> Result<Vec<u8>, String> {
        let email_str = String::from_utf8_lossy(raw_email);

        let (header_section, body) = split_email(&email_str);
        let raw_headers = parse_raw_headers(header_section);

        // Canonicalize body (relaxed/relaxed)
        let canon_body = canonicalize_body_relaxed(body);
        let body_hash = BASE64.encode(Sha256::digest(canon_body.as_bytes()));

        // Determine which headers to sign
        let headers_to_sign: Vec<&str> = ["from", "to", "subject", "date", "message-id", "mime-version", "content-type"]
            .iter()
            .filter(|&&h| raw_headers.iter().any(|(n, _)| n.to_lowercase() == h))
            .copied()
            .collect();

        let h_tag = headers_to_sign.join(":");

        // Build the DKIM-Signature header value without b=
        let sig_value_no_b = format!(
            " v=1; a=rsa-sha256; c=relaxed/relaxed; d={}; s={}; h={}; bh={}; b=",
            self.domain, self.selector, h_tag, body_hash
        );

        // Build signed data for header hashing
        let mut signed_data = build_signed_header_data(&headers_to_sign, &raw_headers, "relaxed");

        // Append the DKIM-Signature header itself with empty b=
        let mut dkim_line = canonicalize_header_relaxed("DKIM-Signature", &sig_value_no_b);
        if dkim_line.ends_with("\r\n") {
            dkim_line.truncate(dkim_line.len() - 2);
        }
        signed_data.push_str(&dkim_line);

        // Sign
        let signing_key: SigningKey<Sha256> = SigningKey::new(self.private_key.clone());
        let signature: Signature = signing_key.sign(signed_data.as_bytes());
        let sig_b64 = BASE64.encode(signature.to_bytes());

        // Build the full DKIM-Signature header
        let dkim_header = format!("DKIM-Signature:{} b={}\r\n", sig_value_no_b.trim_end(), sig_b64);

        // Prepend to raw email
        let mut result = dkim_header.into_bytes();
        result.extend_from_slice(raw_email);
        Ok(result)
    }
}
