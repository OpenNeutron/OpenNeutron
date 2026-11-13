//! Minimal outbound mail for server-generated messages (invites, password
//! recovery). Everything the mail client sends goes through the sending FSM so
//! it can be E2EE-wrapped; these messages are plain system notices addressed to
//! an address outside the mailbox, so they only need a correct envelope, a real
//! Date header and a DKIM signature.

use crate::smtp::EmailSendingFSM;
use crate::utils::emailutils;

fn rfc2822_now() -> String {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let days = (secs / 86400) as i64;
    let rem = secs % 86400;
    let (h, m, s) = (rem / 3600, (rem % 3600) / 60, rem % 60);

    // civil_from_days (Howard Hinnant) - no calendar crate needed.
    let z = days + 719468;
    let era = if z >= 0 { z } else { z - 146096 } / 146097;
    let doe = z - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let mo = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = if mo <= 2 { y + 1 } else { y };

    let names = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"];
    let mons = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];
    let weekday = (((days + 4) % 7 + 7) % 7) as usize;
    format!(
        "{}, {:02} {} {} {:02}:{:02}:{:02} +0000",
        names[weekday], d, mons[(mo - 1) as usize], year, h, m, s
    )
}

/// Send one plain-text message through the local MTA.
///
/// Returns Err with a human-readable reason; callers report it rather than
/// claiming delivery.
pub fn send_plain(from: &str, to: &str, subject: &str, body: &str) -> Result<(), String> {
    let msgid = crate::core::user::gen_setup_token();
    let domain = emailutils::get_server_domain();
    let raw = format!(
        "From: Sloth Lee Mail <{from}>\r\n\
         To: {to}\r\n\
         Subject: {subject}\r\n\
         Date: {date}\r\n\
         Message-ID: <{msgid}@{domain}>\r\n\
         MIME-Version: 1.0\r\n\
         Content-Type: text/plain; charset=utf-8\r\n\
         Content-Transfer-Encoding: 8bit\r\n\
         Auto-Submitted: auto-generated\r\n\
         \r\n\
         {body}\r\n",
        from = from,
        to = to,
        subject = subject,
        date = rfc2822_now(),
        msgid = msgid,
        domain = domain,
        body = body
    );

    let signed = match emailutils::get_dkim_signer() {
        Some(signer) => signer
            .sign(raw.as_bytes())
            .map_err(|e| format!("DKIM signing failed: {e}"))?,
        None => raw.into_bytes(),
    };

    let mut last_error = String::from("no candidate address");
    let mut sent = false;
    for host in mta_candidates() {
        match EmailSendingFSM::connect(&host, 25, emailutils::get_helo_domain()) {
            Ok(mut fsm) => match fsm.send(from, &[to.to_string()], &signed) {
                Ok(()) => {
                    sent = true;
                    break;
                }
                Err(e) => last_error = format!("SMTP send via {host} failed: {e}"),
            },
            Err(e) => last_error = format!("SMTP connect to {host}:25 failed: {e}"),
        }
    }
    if !sent {
        return Err(last_error);
    }
    Ok(())
}

/// Where the local MTA might be.
///
/// Inside the container nothing listens on 127.0.0.1:25 - Postfix is on the
/// host, reachable through the docker bridge gateway. Read that gateway out of
/// the routing table so a changed docker network does not silently break
/// recovery mail.
fn mta_candidates() -> Vec<String> {
    let mut hosts = vec!["127.0.0.1".to_string()];

    if let Ok(routes) = std::fs::read_to_string("/proc/net/route") {
        for line in routes.lines().skip(1) {
            let fields: Vec<&str> = line.split_whitespace().collect();
            if fields.len() > 2 && fields[1] == "00000000" {
                if let Ok(raw) = u32::from_str_radix(fields[2], 16) {
                    let octets = raw.to_le_bytes();
                    hosts.push(format!("{}.{}.{}.{}", octets[0], octets[1], octets[2], octets[3]));
                }
            }
        }
    }

    for fallback in ["172.17.0.1", "172.18.0.1"] {
        if !hosts.iter().any(|h| h == fallback) {
            hosts.push(fallback.to_string());
        }
    }
    hosts
}

#[cfg(test)]
mod tests {
    #[test]
    fn candidates_start_with_loopback() {
        assert_eq!(super::mta_candidates()[0], "127.0.0.1");
    }
}

