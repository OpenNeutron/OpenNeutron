use serde::{Serialize, Deserialize};
use std::collections::HashMap;
use tiny_http::Header;
use crate::core::User;
use crate::core::Group;

pub fn json_header() -> Header {
    Header::from_bytes(&b"Content-Type"[..], &b"application/json"[..]).unwrap()
}

pub fn cors_headers() -> Vec<Header> {
    vec![
        Header::from_bytes(&b"Access-Control-Allow-Origin"[..], &b"*"[..]).unwrap(),
        Header::from_bytes(&b"Access-Control-Allow-Methods"[..], &b"GET, POST, PUT, DELETE, OPTIONS"[..]).unwrap(),
        Header::from_bytes(&b"Access-Control-Allow-Headers"[..], &b"Authorization, Content-Type"[..]).unwrap(),
    ]
}

#[derive(Deserialize)]
pub struct LoginRequest {
    pub username: String,
    pub password: String,
}

#[derive(Serialize)]
pub struct LoginResponse {
    pub token: String,
    pub force_reset: bool,
    pub username: String,
    pub public_key: Option<String>,
    pub unread_emails: usize,
    /// Per-user salt (hex string) for client-side key derivation.
    pub salt: String,
    /// AES-256 encrypted private key blob (base64), or None if not set yet.
    pub encrypted_private_key: Option<String>,
}

#[derive(Serialize)]
pub struct UserDto {
    pub uid: String,
    pub username: String,
    pub email: String,
    pub user_created: u64,
    pub last_login: u64,
    pub email_count: usize,
    pub is_admin: bool,
}

impl UserDto {
    pub fn new(u: &User, domain: &str) -> Self {
        UserDto {
            uid: u.uid.to_string(),
            username: u.username.clone(),
            email: format!("{}@{}", u.username, domain),
            user_created: u.userCreated,
            last_login: u.lastLogin,
            email_count: u.emailIds.len(),
            is_admin: u.is_admin,
        }
    }
}

#[derive(Deserialize)]
pub struct CreateUserRequest {
    pub username: String,
    pub password: String,
    pub public_key: String,
    /// AES-256 encrypted private key (base64), encrypted client-side.
    pub encrypted_private_key: String,
}

#[derive(Serialize)]
pub struct AdminUsersResponse {
    pub users: Vec<UserDto>,
    pub total: usize,
}

#[derive(Deserialize)]
pub struct AdminCreateUserRequest {
    pub username: String,
}

#[derive(Deserialize)]
pub struct AdminDeleteUserRequest {
    pub username: String,
}

#[derive(Deserialize)]
pub struct AdminSetCredentialsRequest {
    pub username: String,
    pub password: Option<String>,            // password token; omit to leave unchanged
    pub public_key: Option<String>,          // base64 SPKI; omit to leave unchanged
    pub encrypted_private_key: Option<String>, // base64 AES-encrypted private key; omit to leave unchanged
}

#[derive(Deserialize)]
pub struct AdminSetAdminRequest {
    pub username: String,
    pub is_admin: bool,
}

#[derive(Deserialize)]
pub struct UserSetCredentialsRequest {
    pub password: Option<String>,              // new password token; omit to leave unchanged
    pub public_key: Option<String>,            // base64 SPKI; omit to leave unchanged
    pub encrypted_private_key: Option<String>, // base64 AES-encrypted private key; omit to leave unchanged
}

#[derive(Serialize)]
pub struct AdminCreateUserResponse {
    pub message: String,
    pub force_reset: bool,
}

#[derive(Serialize)]
pub struct UserDiskUsageDto {
    pub username: String,
    pub email_count: usize,
    pub disk_usage_bytes: u64,
}

#[derive(Serialize)]
pub struct AdminDiskUsageResponse {
    pub users: Vec<UserDiskUsageDto>,
}

#[derive(Serialize)]
pub struct ErrorResponse {
    pub error: String,
    pub code: String,
}

#[derive(Serialize)]
pub struct MessageResponse {
    pub message: String,
}



#[derive(Deserialize)]
pub struct GetEmailRequest {
    pub uid: u128,
}

#[derive(Serialize)]
pub struct EmailBytesResponse {
    pub uid: u128,
    /// AES ciphertext: 'nonce (12 bytes) || ciphertext || GCM tag (16 bytes)', base64-encoded.
    /// When 'secure == false' this is the raw plaintext bytes.
    pub data: String,
    /// RSA-OAEP encrypted AES-256 key, base64-encoded. 'null' when 'secure == false'.
    pub message_key: Option<String>,
    pub received_at: String,
    pub e2ee: bool,
}

#[derive(Deserialize)]
pub struct GetEmailsBulkRequest {
    pub uids: Vec<u128>,
}

#[derive(Serialize)]
pub struct EmailsBulkResponse {
    pub emails: Vec<EmailBytesResponse>,
}

#[derive(Serialize)]
pub struct EmailUidsResponse {
    pub uids: Vec<u128>,
}

#[derive(Deserialize)]
pub struct DeleteEmailRequest {
    pub uid: u128,
}

#[derive(Deserialize)]
pub struct SetEmailBytesRequest {
    pub uid: u128,
    /// AES ciphertext (base64). When updating an encrypted email, supply the new ciphertext here.
    pub data: String,
    /// RSA-OAEP encrypted AES-256 key (base64). Required when the email is encrypted; 'null'/omit otherwise.
    #[serde(default)]
    pub message_key: Option<String>,
}

#[derive(Deserialize)]
pub struct GetRecentEmailsRequest {
    pub offset: usize,
    pub limit: usize,
}

#[derive(Deserialize)]
pub struct SetupPasswordRequest {
    pub password: String,
    pub public_key: String,
    /// AES-256 encrypted private key (base64), encrypted client-side.
    pub encrypted_private_key: String,
}

#[derive(Deserialize)]
pub struct SendEmailRequest {
    pub from: String,
    pub to: Vec<String>,
    pub data: String,        
    pub smtp_host: String,
    pub smtp_port: Option<u16>,
}

#[derive(Deserialize)]
pub struct MarkEmailReadRequest {
    pub uid: u128,
}

#[derive(Deserialize)]
pub struct SetEmailStarredRequest {
    pub uid: u128,
    pub starred: bool,
}



#[derive(Serialize)]
pub struct GroupDto {
    pub uid: String,
    pub title: String,
    pub email_uids: Vec<u128>,
    pub filter_addresses: Vec<String>,
}

impl From<&Group> for GroupDto {
    fn from(g: &Group) -> Self {
        GroupDto {
            uid: g.uid.to_string(),
            title: g.title.clone(),
            email_uids: g.email_uids.clone(),
            filter_addresses: g.filter_addresses.clone(),
        }
    }
}

#[derive(Serialize)]
pub struct GroupsListResponse {
    pub groups: Vec<GroupDto>,
}

#[derive(Deserialize)]
pub struct CreateGroupRequest {
    pub title: String,
    pub filter_addresses: Option<Vec<String>>,
}

#[derive(Deserialize)]
pub struct GetGroupRequest {
    pub uid: u128,
}

#[derive(Deserialize)]
pub struct UpdateGroupRequest {
    pub uid: u128,
    pub title: Option<String>,
    pub filter_addresses: Option<Vec<String>>,
}

#[derive(Deserialize)]
pub struct DeleteGroupRequest {
    pub uid: u128,
}

#[derive(Deserialize)]
pub struct GroupEmailRequest {
    pub group_uid: u128,
    pub email_uid: u128,
}


// --- Encrypted Send Flow DTOs ---

/// Request to fetch public keys for a list of email addresses.
#[derive(Deserialize)]
pub struct GetPublicKeysRequest {
    pub addresses: Vec<String>,
}

/// A single recipient's public key info.
#[derive(Serialize)]
pub struct RecipientPublicKey {
    pub address: String,
    pub public_key: Option<String>,  // base64-encoded, None if user has no key or is external
    pub key_type: String,            // "none" for now (future: negotiated e2ee)
}

#[derive(Serialize)]
pub struct GetPublicKeysResponse {
    pub keys: Vec<RecipientPublicKey>,
}

/// The local copy metadata saved to the sender's sent_emails.
#[derive(Deserialize)]
pub struct SentEmailLocalCopy {
    // 'from' is NOT deserialized - server fills it in
    pub to: Vec<String>,
    pub timestamp: u64,
    pub public_key_hash: String,  // base64 sha256 hash
    /// AES ciphertext of the local copy, base64-encoded ('nonce || ct || tag').
    pub raw_data: String,
    /// RSA-OAEP encrypted AES-256 key for the local copy, base64-encoded.
    /// Required when 'e2ee == true'; omit or 'null' when 'e2ee == false'.
    #[serde(default)]
    pub message_key: Option<String>,
    #[serde(default)]
    pub e2ee: bool,               // true if the local copy is client-encrypted
}

/// Per-recipient payload in the encrypted send request.
#[derive(Deserialize)]
pub struct RecipientPayload {
    /// RSA-OAEP encrypted AES-256 key for this recipient, base64-encoded.
    /// Required when 'e2ee == true'; empty string or omit when 'e2ee == false'.
    #[serde(default)]
    pub aes_encrypted: String,
    /// AES-GCM ciphertext ('nonce || ct || tag') when 'e2ee == true',
    /// or raw RFC 5322 email bytes when 'e2ee == false', base64-encoded.
    pub data_encrypted: String,
    pub e2ee: bool,
}

/// Request body for /email/sendencrypted
#[derive(Deserialize)]
pub struct SendEncryptedRequest {
    pub localcopy: SentEmailLocalCopy,
    /// Map of "recipient@domain.com" -> { data, e2ee }
    pub recipients: HashMap<String, RecipientPayload>,
}

/// Response for /email/sendencrypted
#[derive(Serialize)]
pub struct SendEncryptedResponse {
    pub message: String,
    pub sent_email_uid: u128,  // UID of the local copy in sent_emails
    pub delivery_results: Vec<DeliveryResult>,
}

#[derive(Serialize)]
pub struct DeliveryResult {
    pub address: String,
    pub success: bool,
    pub error: Option<String>,
}
