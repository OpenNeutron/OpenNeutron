
use crate::utils::cryptography::PublicKey;
use std::time::{SystemTime, UNIX_EPOCH};
use rand;
use rand::Rng;
use rand::RngCore;
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
    /// One-time provisioning secret for accounts created without a password.
    /// The user presents this as their password on first login, which grants a
    /// 'force_reset' session that may only be used to call '/api/user/setup'.
    /// Cleared as soon as a real password is set.
    #[serde(default)]
    pub setup_token: Option<String>,
    /// Unix seconds of the last credential change made by someone other than the
    /// session holder (admin password reset, admin demotion). Sessions issued
    /// before this instant are rejected - see 'utils::jwt' and the router.
    #[serde(default)]
    pub credentials_changed_at: u64,
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
            setup_token: None,
            credentials_changed_at: 0,
        }
    }

    pub fn create_user(username: String, password_hash: String, public_key: PublicKey, encrypted_private_key: String) -> Self {
        let uid = gen_uid();
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
            setup_token: None,
            credentials_changed_at: 0,
        }
    }

    /// Create an account that has no password yet. The returned user carries a
    /// freshly generated one-time 'setup_token' which the account owner must
    /// present as their password on first login; it is the only credential that
    /// authenticates the account until '/api/user/setup' runs.
    pub fn create_provisioned_user(username: String, is_admin: bool) -> Self {
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
            is_admin,
            groups: Vec::new(),
            salt: gen_salt(),
            encrypted_private_key: None,
            setup_token: Some(gen_setup_token()),
            credentials_changed_at: 0,
        }
    }

    /// Constant-time credential check.
    ///
    /// An account with no password hash is NOT open to everyone: it can only be
    /// unlocked with its one-time setup token. An account with neither a hash nor
    /// a token cannot be authenticated at all.
    pub fn verify_password(&self, presented: &str) -> bool {
        match (&self.passwordHash, &self.setup_token) {
            (Some(hash), _) => constant_time_eq(hash.as_bytes(), presented.as_bytes()),
            (None, Some(token)) => constant_time_eq(token.as_bytes(), presented.as_bytes()),
            (None, None) => false,
        }
    }

    pub fn needs_force_reset(&self) -> bool {
        self.passwordHash.is_none()
    }

    /// Record that the account's credentials were changed by an administrator,
    /// invalidating every session token issued before this moment.
    pub fn revoke_existing_sessions(&mut self) {
        self.credentials_changed_at = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
    }
}

/// Compare two byte strings without leaking their contents through timing.
/// Length is not secret here (both sides are fixed-width hex/base64 digests),
/// but the comparison itself always walks the full buffer.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff: u8 = 0;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

/// Usernames become the local part of an email address and are used as storage
/// keys, so they are restricted to an unambiguous, canonical character set.
pub fn validate_username(username: &str) -> Result<(), &'static str> {
    if username.is_empty() || username.len() > 64 {
        return Err("Username must be between 1 and 64 characters");
    }
    if !username.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, '.' | '_' | '-')) {
        return Err("Username may only contain lowercase letters, digits, '.', '_' and '-'");
    }
    let first = username.as_bytes()[0];
    let last = username.as_bytes()[username.len() - 1];
    if !first.is_ascii_alphanumeric() || !last.is_ascii_alphanumeric() {
        return Err("Username must start and end with a letter or digit");
    }
    if username.contains("..") {
        return Err("Username may not contain consecutive dots");
    }
    Ok(())
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

/// 256 bits of OS entropy, hex encoded - this value is a password equivalent.
pub fn gen_setup_token() -> String {
    let mut bytes = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}





pub struct UserStorage {
    users: Mutex<HashMap<String, User>>,
    filename: String,
    pub domain: String,
}

impl UserStorage {
    /// Acquire the user map, tolerating a poisoned lock.
    ///
    /// The guarded data is a plain map that is never left half-updated, so if
    /// some other thread panicked while holding this lock there is nothing to
    /// recover - and propagating the poison would turn one panic into a
    /// permanent, server-wide outage on every subsequent request.
    fn lock_users(&self) -> std::sync::MutexGuard<'_, HashMap<String, User>> {
        match self.users.lock() {
            Ok(guard) => guard,
            Err(poisoned) => {
                log::error!("[Storage] User map lock was poisoned by an earlier panic; continuing");
                poisoned.into_inner()
            }
        }
    }

    pub fn new(filename: String, domain: String) -> Self {
        UserStorage {
            users: Mutex::new(HashMap::new()),
            filename,
            domain,
        }
    }

    pub fn add_user(&self, user: User) {
        let mut users = self.lock_users();
        users.insert(user.username.clone(), user);
    }

    pub fn get_user(&self, username: &str) -> Option<User> {
        let users = self.lock_users();
        users.get(username).cloned()
    }

    pub fn update_user(&self, user: User) {
        let mut users = self.lock_users();
        users.insert(user.username.clone(), user);
    }

    pub fn check_user_exists(&self, username: &str) -> bool {
        let users = self.lock_users();
        users.contains_key(username)
    }

    pub fn delete_user(&self, username: &str) -> Vec<u128> {
        let mut users = self.lock_users();
        if let Some(user) = users.remove(username) {
            user.emailIds.clone()
        } else {
            Vec::new()
        }
    }

    pub fn get_user_count(&self) -> usize {
        let users = self.lock_users();
        users.len()
    }

    #[allow(dead_code)]
    pub fn get_users_bulk(&self, usernames: Vec<String>) -> Vec<User> {
        let users = self.lock_users();
        let mut result = Vec::new();
        for username in usernames {
            if let Some(user) = users.get(&username) {
                result.push(user.clone());
            }
        }
        result
    }

    pub fn get_all_users(&self) -> Vec<User> {
        let users = self.lock_users();
        users.values().cloned().collect()
    }

    

    
    pub fn add_group(&self, username: &str, group: Group) -> bool {
        let mut users = self.lock_users();
        if let Some(user) = users.get_mut(username) {
            user.groups.push(group);
            true
        } else {
            false
        }
    }

    
    pub fn update_group(&self, username: &str, updated: Group) -> bool {
        let mut users = self.lock_users();
        if let Some(user) = users.get_mut(username) {
            if let Some(g) = user.groups.iter_mut().find(|g| g.uid == updated.uid) {
                *g = updated;
                return true;
            }
        }
        false
    }

    
    pub fn delete_group(&self, username: &str, group_uid: u128) -> bool {
        let mut users = self.lock_users();
        if let Some(user) = users.get_mut(username) {
            let before = user.groups.len();
            user.groups.retain(|g| g.uid != group_uid);
            return user.groups.len() < before;
        }
        false
    }

    
    pub fn remove_email_from_groups(&self, username: &str, email_uid: u128) {
        let mut users = self.lock_users();
        if let Some(user) = users.get_mut(username) {
            for group in &mut user.groups {
                group.email_uids.retain(|&id| id != email_uid);
            }
        }
    }

    
    pub fn add_email_to_matching_groups(&self, username: &str, email_uid: u128, sender_email: &str) {
        let sender_lower = sender_email.to_lowercase();
        let mut users = self.lock_users();
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
        let mut users = self.lock_users();
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
        let mut users = self.lock_users();
        if let Some(user) = users.get_mut(username) {
            if let Some(group) = user.groups.iter_mut().find(|g| g.uid == group_uid) {
                group.email_uids.retain(|&id| id != email_uid);
                return true;
            }
        }
        false
    }


    
    pub fn save_to_file(&self) -> io::Result<()> {
        let users = self.lock_users();
        
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
        let mut users_lock = self.lock_users();
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

            
            let admin_user = User::create_provisioned_user("admin".to_string(), true);
            let setup_token = admin_user.setup_token.clone().unwrap_or_default();
            storage.add_user(admin_user);

            if let Err(save_err) = storage.save_to_file() {
                log::error!("[Storage] Failed to save initial user storage: {}", save_err);
            }

            // The bootstrap admin has no password. This token is the ONLY credential
            // that unlocks it, and it is shown exactly once per fresh data directory.
            log::warn!(
                "[Storage] Bootstrap admin created. Log in as 'admin' using this one-time \
                 setup token as the password, then set a real password immediately:\n\
                 \n    {}\n",
                setup_token
            );

            storage
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn passwordless_accounts_are_not_open_to_everyone() {
        let user = User::create_provisioned_user("alice".to_string(), false);
        let token = user.setup_token.clone().unwrap();

        assert!(!user.verify_password("anything"), "any password unlocked a provisioned account");
        assert!(!user.verify_password(""), "empty password unlocked a provisioned account");
        assert!(user.verify_password(&token), "the setup token should unlock the account");
    }

    #[test]
    fn an_account_with_no_credential_at_all_cannot_authenticate() {
        let mut user = User::create_provisioned_user("bob".to_string(), false);
        user.setup_token = None;
        assert!(!user.verify_password(""));
        assert!(!user.verify_password("anything"));
    }

    #[test]
    fn a_configured_password_ignores_any_leftover_setup_token() {
        let mut user = User::create_provisioned_user("carol".to_string(), false);
        let token = user.setup_token.clone().unwrap();
        user.passwordHash = Some("hashed".to_string());

        assert!(user.verify_password("hashed"));
        assert!(!user.verify_password(&token));
    }

    #[test]
    fn provisioned_accounts_are_not_admins_by_default() {
        assert!(!User::create_provisioned_user("dave".to_string(), false).is_admin);
        assert!(User::create_provisioned_user("root".to_string(), true).is_admin);
    }

    #[test]
    fn setup_tokens_are_unique_and_long() {
        let a = gen_setup_token();
        let b = gen_setup_token();
        assert_ne!(a, b);
        assert_eq!(a.len(), 64);
    }

    #[test]
    fn usernames_are_restricted_to_a_safe_character_set() {
        for ok in ["alice", "bob.smith", "a", "user-1", "x_y"] {
            assert!(validate_username(ok).is_ok(), "rejected valid username: {}", ok);
        }
        for bad in ["", "../etc", "a@b", "Alice", "with space", ".leading", "trailing.", "a..b", "a/b", &"x".repeat(65)] {
            assert!(validate_username(bad).is_err(), "accepted invalid username: {}", bad);
        }
    }

    #[test]
    fn email_uids_do_not_collide_within_the_same_second() {
        let user = User::create_provisioned_user("erin".to_string(), false);
        let uids: std::collections::HashSet<u128> = (0..1000)
            .map(|_| crate::utils::emailutils::generate_email_uid(&user))
            .collect();
        assert_eq!(uids.len(), 1000, "generated colliding email UIDs");
    }
}
