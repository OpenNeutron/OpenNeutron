
use crate::utils::cryptography::PublicKey;
use std::time::{SystemTime, UNIX_EPOCH};
use rand;
use rand::Rng;
use crate::utils::cryptography::public_key_from_string;
use std::collections::HashMap;
use std::sync::Mutex;
use serde::{Serialize, Deserialize};
use std::fs::{File, OpenOptions};
use std::io::{Read, Write, Error, ErrorKind};
use std::io;
use bincode;




#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Group {
    pub uid: u128,
    pub title: String,
    pub email_uids: Vec<u128>,
    
    pub filter_addresses: Vec<String>,
}

impl Group {
    pub fn new(title: String, filter_addresses: Vec<String>) -> Self {
        Group {
            uid: gen_uid(),
            title,
            email_uids: Vec::new(),
            filter_addresses: filter_addresses.into_iter().map(|a| a.to_lowercase()).collect(),
        }
    }
}


#[allow(non_snake_case)]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct User {
    pub uid: u128,
    pub username: String,
    /// Password token (hashed client-side); stored as plain string and compared directly.
    pub passwordHash: Option<String>,
    pub publicKey: Option<PublicKey>,
    pub userCreated: u64,
    pub lastLogin: u64,
    pub emailIds: Vec<u128>,
    #[serde(default)]
    pub sent_emails: Vec<u128>,
    #[serde(default)]
    pub is_admin: bool,
    #[serde(default)]
    pub groups: Vec<Group>,
    /// Per-user random salt (hex string) used by the client for key derivation.
    #[serde(default = "gen_salt")]
    pub salt: String,
    /// AES-256 encrypted private key blob (encrypted client-side), stored as base64.
    #[serde(default)]
    pub encrypted_private_key: Option<String>,
}

impl User {
    #[allow(dead_code)]
    pub fn new(uid: u128, username: String, password_hash: String, public_key: PublicKey, salt: String, encrypted_private_key: Option<String>) -> Self {
        User {
            uid,
            username,
            passwordHash: Some(password_hash),
            publicKey: Some(public_key),
            userCreated: 0,
            lastLogin: 0,
            emailIds: Vec::new(),
            sent_emails: Vec::new(),
            is_admin: false,
            groups: Vec::new(),
            salt,
            encrypted_private_key,
        }
    }

    pub fn create_user(username: String, password_hash: String, public_key_str: String, encrypted_private_key: String) -> Self {
        let uid = gen_uid();
        let public_key = public_key_from_string(public_key_str);
        User {
            uid,
            username,
            passwordHash: Some(password_hash),
            publicKey: Some(public_key),
            userCreated: SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs(),
            lastLogin: 0,
            emailIds: Vec::new(),
            sent_emails: Vec::new(),
            is_admin: false,
            groups: Vec::new(),
            salt: gen_salt(),
            encrypted_private_key: Some(encrypted_private_key),
        }
    }

    pub fn create_admin_user(username: String) -> Self {
        let uid = gen_uid();
        User {
            uid,
            username,
            passwordHash: None,
            publicKey: None,
            userCreated: SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs(),
            lastLogin: 0,
            emailIds: Vec::new(),
            sent_emails: Vec::new(),
            is_admin: true,
            groups: Vec::new(),
            salt: gen_salt(),
            encrypted_private_key: None,
        }
    }

    pub fn verify_password(&self, password_hash: String) -> bool {
        match &self.passwordHash {
            Some(hash) => *hash == password_hash,
            None => true,
        }
    }

    pub fn needs_force_reset(&self) -> bool {
        self.passwordHash.is_none()
    }

}

fn gen_uid() -> u128 {
    let mut rng = rand::thread_rng();
    rng.r#gen::<u128>()
}

fn gen_salt() -> String {
    let mut rng = rand::thread_rng();
    let a: u64 = rng.r#gen();
    let b: u64 = rng.r#gen();
    format!("{:016x}{:016x}", a, b)
}





pub struct UserStorage {
    users: Mutex<HashMap<String, User>>,
    filename: String,
    pub domain: String,
}

impl UserStorage {
    pub fn new(filename: String, domain: String) -> Self {
        UserStorage {
            users: Mutex::new(HashMap::new()),
            filename,
            domain,
        }
    }

    pub fn add_user(&self, user: User) {
        let mut users = self.users.lock().unwrap();
        users.insert(user.username.clone(), user);
    }

    pub fn get_user(&self, username: &str) -> Option<User> {
        let users = self.users.lock().unwrap();
        users.get(username).cloned()
    }

    pub fn update_user(&self, user: User) {
        let mut users = self.users.lock().unwrap();
        users.insert(user.username.clone(), user);
    }

    pub fn check_user_exists(&self, username: &str) -> bool {
        let users = self.users.lock().unwrap();
        users.contains_key(username)
    }

    pub fn delete_user(&self, username: &str) -> Vec<u128> {
        let mut users = self.users.lock().unwrap();
        if let Some(user) = users.remove(username) {
            user.emailIds.clone()
        } else {
            Vec::new()
        }
    }

    pub fn get_user_count(&self) -> usize {
        let users = self.users.lock().unwrap();
        users.len()
    }

    #[allow(dead_code)]
    pub fn get_users_bulk(&self, usernames: Vec<String>) -> Vec<User> {
        let users = self.users.lock().unwrap();
        let mut result = Vec::new();
        for username in usernames {
            if let Some(user) = users.get(&username) {
                result.push(user.clone());
            }
        }
        result
    }

    pub fn get_all_users(&self) -> Vec<User> {
        let users = self.users.lock().unwrap();
        users.values().cloned().collect()
    }

    

    
    pub fn add_group(&self, username: &str, group: Group) -> bool {
        let mut users = self.users.lock().unwrap();
        if let Some(user) = users.get_mut(username) {
            user.groups.push(group);
            true
        } else {
            false
        }
    }

    
    pub fn update_group(&self, username: &str, updated: Group) -> bool {
        let mut users = self.users.lock().unwrap();
        if let Some(user) = users.get_mut(username) {
            if let Some(g) = user.groups.iter_mut().find(|g| g.uid == updated.uid) {
                *g = updated;
                return true;
            }
        }
        false
    }

    
    pub fn delete_group(&self, username: &str, group_uid: u128) -> bool {
        let mut users = self.users.lock().unwrap();
        if let Some(user) = users.get_mut(username) {
            let before = user.groups.len();
            user.groups.retain(|g| g.uid != group_uid);
            return user.groups.len() < before;
        }
        false
    }

    
    pub fn remove_email_from_groups(&self, username: &str, email_uid: u128) {
        let mut users = self.users.lock().unwrap();
        if let Some(user) = users.get_mut(username) {
            for group in &mut user.groups {
                group.email_uids.retain(|&id| id != email_uid);
            }
        }
    }

    
    pub fn add_email_to_matching_groups(&self, username: &str, email_uid: u128, sender_email: &str) {
        let sender_lower = sender_email.to_lowercase();
        let mut users = self.users.lock().unwrap();
        if let Some(user) = users.get_mut(username) {
            for group in &mut user.groups {
                if group.filter_addresses.iter().any(|addr| addr == &sender_lower) {
                    if !group.email_uids.contains(&email_uid) {
                        group.email_uids.push(email_uid);
                    }
                }
            }
        }
    }

    
    pub fn add_email_to_group(&self, username: &str, group_uid: u128, email_uid: u128) -> bool {
        let mut users = self.users.lock().unwrap();
        if let Some(user) = users.get_mut(username) {
            if let Some(group) = user.groups.iter_mut().find(|g| g.uid == group_uid) {
                if !group.email_uids.contains(&email_uid) {
                    group.email_uids.push(email_uid);
                }
                return true;
            }
        }
        false
    }

    
    pub fn remove_email_from_group(&self, username: &str, group_uid: u128, email_uid: u128) -> bool {
        let mut users = self.users.lock().unwrap();
        if let Some(user) = users.get_mut(username) {
            if let Some(group) = user.groups.iter_mut().find(|g| g.uid == group_uid) {
                group.email_uids.retain(|&id| id != email_uid);
                return true;
            }
        }
        false
    }


    
    pub fn save_to_file(&self) -> io::Result<()> {
        let users = self.users.lock().unwrap();
        
        let mut file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(&self.filename)?;
        let data = bincode::serialize(&*users)
            .map_err(|e| Error::new(ErrorKind::Other, e))?;

        file.write_all(&data)?;
        Ok(())
    }

    pub fn load_from_file(&self) -> io::Result<()> {
        let mut file = File::open(&self.filename)?;
        let mut data = Vec::new();
        file.read_to_end(&mut data)?;
        let users: HashMap<String, User> = bincode::deserialize_from(&data[..]).map_err(|e| Error::new(ErrorKind::Other, e))?;
        let mut users_lock = self.users.lock().unwrap();
        *users_lock = users;
        Ok(())
    }

}

pub fn get_or_init_storage(filename: String, domain: String) -> UserStorage {
    let storage = UserStorage::new(filename.clone(), domain);
    match storage.load_from_file() {
        Ok(_) => {
            log::info!("[Storage] Loaded {} users from '{}'", storage.get_user_count(), filename);
            storage
        },
        Err(e) => {
            log::warn!("[Storage] No existing user storage at '{}': {}. Creating new store.", filename, e);

            
            if let Some(parent) = std::path::Path::new(&filename).parent() {
                if let Err(dir_err) = std::fs::create_dir_all(parent) {
                    log::error!("[Storage] Failed to create directory: {}", dir_err);
                }
            }

            
            let admin_user = User::create_admin_user("admin".to_string());
            storage.add_user(admin_user);

            if let Err(save_err) = storage.save_to_file() {
                log::error!("[Storage] Failed to save initial user storage: {}", save_err);
            }

            storage
        }
    }
}