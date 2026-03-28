use crate::smtp::ReceivedEmail;
use crate::core::User;
use crate::utils::cryptography::Sha256Hash;
use crate::utils::emailutils;
use crate::utils::cryptography;
use std::time::{SystemTime, UNIX_EPOCH};
use serde_derive::Serialize;
use serde_derive::Deserialize;
use std::fs::File;
use std::io::{Read, Write, Result, Error, ErrorKind};
use std::path::Path;
use bincode;

#[allow(non_snake_case)]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Email {
    pub uid: u128,
    pub secure: bool,
    pub read: bool,
    #[serde(default)]
    pub starred: bool,
    #[serde(default)]
    pub e2ee: bool,
    pub userid: u128,
    pub from: String,
    pub to: Vec<String>,
    pub timestamp: u64,
    pub publicKeyHash: Sha256Hash,
    /// AES ciphertext: 'nonce (12 bytes) || ciphertext || GCM tag (16 bytes)'.
    /// When 'secure == false' this is the raw plaintext bytes (no public key was registered).
    pub raw_data: Vec<u8>,
    /// RSA-OAEP encrypted 32-byte AES-256 key. 'None' when 'secure == false'.
    #[serde(default)]
    pub message_key: Option<Vec<u8>>,
}

impl Email {
    pub fn new(received_email: ReceivedEmail, user: &User) -> Self {
        let raw_bytes = received_email.raw_data;

        // Server-side at-rest encryption using split hybrid RSA-OAEP + AES-256-GCM.
        // message_key stores the RSA-encrypted AES key; raw_data stores the AES ciphertext.
        let (message_key, encrypted_data, is_secure) = if let Some(pk) = &user.publicKey {
            match cryptography::encrypt_split(pk, &raw_bytes) {
                Ok((k, d)) => (Some(k), d, true),
                Err(e) => {
                    eprintln!("[Email] Encryption failed for user '{}': {} - storing plaintext", user.username, e);
                    (None, raw_bytes, false)
                }
            }
        } else {
            (None, raw_bytes, false)
        };

        Email {
            uid: emailutils::generate_email_uid(user),
            secure: is_secure,
            read: false,
            starred: false,
            e2ee: false,
            userid: user.uid,
            from: received_email.from,
            to: received_email.to,
            timestamp: SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs(),
            publicKeyHash: user.publicKey.as_ref()
                .map(|pk| cryptography::hash_public_key(pk))
                .unwrap_or(Sha256Hash([0u8; 32])),
            raw_data: encrypted_data,
            message_key,
        }
    }

    pub fn new_e2ee(received_email: ReceivedEmail, user: &User) -> Self {
        let raw_bytes = received_email.raw_data;
        // The sender packed the encrypted parts into the SMTP wire format.
        // Unpack them so we store message_key and raw_data separately.
        let (message_key, aes_ciphertext) = match cryptography::unpack_encrypted_email(&raw_bytes) {
            Ok((k, d)) => (Some(k), d),
            Err(e) => {
                eprintln!("[Email] Failed to unpack E2EE blob for user '{}': {} - storing as-is", user.username, e);
                (None, raw_bytes)
            }
        };
        Email {
            uid: emailutils::generate_email_uid(user),
            secure: true,
            read: false,
            starred: false,
            e2ee: true,
            userid: user.uid,
            from: received_email.from,
            to: received_email.to,
            timestamp: SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs(),
            publicKeyHash: user.publicKey.as_ref()
                .map(|pk| cryptography::hash_public_key(pk))
                .unwrap_or(Sha256Hash([0u8; 32])),
            raw_data: aes_ciphertext,
            message_key,
        }
    }

    pub fn mark_as_read(&mut self) {
        self.read = true;
    }

    pub fn mark_as_unread(&mut self) {
        self.read = false;
    }

    pub fn is_read(&self) -> bool {
        self.read
    }

    pub fn set_starred(&mut self, starred: bool) {
        self.starred = starred;
    }



    #[allow(dead_code)]
    pub fn to_string(&self) -> String {
        let read_status = if self.read { "Read" } else { "Unread" };
        format!("From: {}\nTo: {}\nDate: {}\nStatus: {}\n\n{}", 
            self.from, 
            self.to.join(", "), 
            self.timestamp, 
            read_status, 
            String::from_utf8_lossy(&self.raw_data))
    }
}

#[allow(non_snake_case)]
pub struct EmailStorage {
    storageDir: String 
}

impl EmailStorage {
    pub fn new(storage_dir: String) -> Self {
        std::fs::create_dir_all(&storage_dir).unwrap_or_default();
        EmailStorage {
            storageDir: storage_dir
        }
    }

    #[allow(dead_code)]
    #[allow(non_snake_case)]
    pub fn emailExists(&self, email_uid: u128) -> bool {
        let email_path = format!("{}/{}.bin", self.storageDir, email_uid);
        return Path::new(&email_path).exists();
    }

    pub fn read_email(&self, email_uid: u128) -> Result<Email> {
        let email_path = format!("{}/{}.bin", self.storageDir, email_uid);
        if !Path::new(&email_path).exists() {
            return Err(Error::new(ErrorKind::NotFound, "Email not found"));
        }

        let mut file = File::open(email_path)?;
        let mut buffer = Vec::new();
        file.read_to_end(&mut buffer)?;
        let email: Email = bincode::deserialize(&buffer).map_err(|e| Error::new(ErrorKind::InvalidData, e))?;
        Ok(email)
    }

    pub fn save_email(&self, email: &Email) -> Result<()> {
        let email_path = format!("{}/{}.bin", self.storageDir, email.uid);
        let mut file = File::create(email_path)?;
        let encoded: Vec<u8> = bincode::serialize(email).map_err(|e| Error::new(ErrorKind::InvalidData, e))?;
        file.write_all(&encoded)?;
        Ok(())
    }

    pub fn delete_email(&self, email_uid: u128) -> Result<()> {
        let email_path = format!("{}/{}.bin", self.storageDir, email_uid);
        if Path::new(&email_path).exists() {
            std::fs::remove_file(email_path)?;
        }
        Ok(())
    }

    pub fn get_emails_bulk(&self, email_uids: Vec<u128>) -> Result<Vec<Email>> {
        let mut emails = Vec::new();
        for uid in email_uids {
            match self.read_email(uid) {
                Ok(email) => emails.push(email),
                Err(e) => eprintln!("Error reading email with UID {}: {}", uid, e),
            }
        }
        Ok(emails)
    }

    pub fn count_unread(&self, email_ids: &[u128]) -> usize {
        email_ids.iter().filter(|&&id| {
            self.read_email(id).map(|e| !e.is_read()).unwrap_or(false)
        }).count()
    }

    pub fn delete_emails_for_user(&self, email_ids: &[u128]) {
        for &id in email_ids {
            if let Err(e) = self.delete_email(id) {
                eprintln!("Error deleting email {}: {}", id, e);
            }
        }
    }

    pub fn get_user_disk_usage(&self, email_ids: &[u128]) -> u64 {
        email_ids.iter().map(|&id| {
            let path = format!("{}/{}.bin", self.storageDir, id);
            std::fs::metadata(&path).map(|m| m.len()).unwrap_or(0)
        }).sum()
    }


}