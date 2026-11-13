use serde::{Serialize, Deserialize};
use std::collections::HashMap;
use tiny_http::Header;
use crate::core::User;
use crate::core::Group;

pub fn json_header() -> Header {
    Header::from_bytes(&b"Content-Type"[..], &b"application/json"[..]).unwrap()
}

/// CORS headers for an API response.
///
/// Only origins explicitly listed in 'server.cors_allowed_origins' are echoed
/// back. A wildcard is deliberately never emitted: it would let script on any
/// site call this API with a token it has obtained, and the bundled SPA is
/// same-origin so it needs no CORS headers at all.
pub fn cors_headers(request_origin: Option<&str>) -> Vec<Header> {
    let allowed = &crate::config::get().server.cors_allowed_origins;
    let origin = match request_origin {
        Some(o) if allowed.iter().any(|a| a == o) => o,
        _ => return Vec::new(),
    };

    let mut headers = vec![
        Header::from_bytes(&b"Access-Control-Allow-Methods"[..], &b"GET, POST, PUT, DELETE, OPTIONS"[..]).unwrap(),
        Header::from_bytes(&b"Access-Control-Allow-Headers"[..], &b"Authorization, Content-Type"[..]).unwrap(),
        // Responses differ per origin, so caches must not share them.
        Header::from_bytes(&b"Vary"[..], &b"Origin"[..]).unwrap(),
    ];
    if let Ok(h) = Header::from_bytes(&b"Access-Control-Allow-Origin"[..], origin.as_bytes()) {
        headers.push(h);
    }
    headers
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
    pub is_admin: bool,
    pub username: String,
    pub public_key: Option<String>,
    pub unread_emails: usize,
    /// Per-user salt (hex string) for client-side key derivation.
    pub salt: String,
    /// AES-256 encrypted private key blob (base64), or None if not set yet.
    pub encrypted_private_key: Option<String>,
    /// True when the password was right but a second factor is still required.
    /// In that case `token` is empty and `challenge` must be redeemed.
    #[serde(default)]
    pub two_factor_required: bool,
    #[serde(default)]
    pub challenge: Option<String>,
    /// Which second factors this account can satisfy: "totp", "webauthn".
    #[serde(default)]
    pub two_factor_methods: Vec<String>,
    /// Id of the session this token belongs to.
    #[serde(default)]
    pub session_id: Option<String>,
}

#[derive(Serialize)]
pub struct UserKeyResponse {
    pub salt: String,
    pub public_key: Option<String>,
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
    /// True while the account is queued for approval and cannot sign in.
    pub pending: bool,
    /// Address a recovery link can be sent to; None when the account has none.
    pub recovery_email: Option<String>,
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
            pending: false,
            recovery_email: crate::core::recovery::store().get(&u.username).email,
        }
    }

    /// Mark the account as queued for approval.
    ///
    /// The queue is a file, so it is read once per listing rather than once per
    /// account: '/api/admin/users' is polled every few seconds by the recipient
    /// sync on the host.
    pub fn with_pending(mut self, pending: bool) -> Self {
        self.pending = pending;
        self
    }
}

#[derive(Deserialize)]
pub struct CreateUserRequest {
    pub username: String,
    pub password: String,
    /// Optional: a client that already knows the server salt may wrap its key at
    /// registration time. A client that does not (the bundled one) omits this and
    /// wraps after its first login, once the server has handed out the salt.
    #[serde(default)]
    pub public_key: Option<String>,
    /// AES-256 encrypted private key (base64), encrypted client-side.
    #[serde(default)]
    pub encrypted_private_key: Option<String>,
    /// Proof-of-work solution for the challenge issued by /signup/challenge.
    #[serde(default)]
    pub pow_challenge: Option<String>,
    #[serde(default)]
    pub pow_nonce: Option<String>,
    /// Required when the server asks for manual approval before signup.
    #[serde(default)]
    pub invite_code: Option<String>,
}

#[derive(Serialize)]
pub struct AdminUsersResponse {
    pub users: Vec<UserDto>,
    pub total: usize,
}

#[derive(Deserialize)]
pub struct AdminCreateUserRequest {
    pub username: String,
    /// Whether the new account is an administrator. Defaults to 'false' - an
    /// omitted field must never silently create a privileged account.
    #[serde(default)]
    pub is_admin: bool,
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
    /// One-time secret the new user must present as their password on first
    /// login. Shown only in this response - it is not retrievable afterwards.
    pub setup_token: String,
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

#[derive(Serialize)]
pub struct AdminResetResponse {
    pub message: String,
    /// One-time secret for the reset account, present only when the reset put the
    /// account back into the setup state (no password supplied).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub setup_token: Option<String>,
}



#[derive(Deserialize)]
pub struct GetEmailRequest {
    #[serde(deserialize_with = "crate::api::u128_flex::uid")]
    pub uid: u128,
}

#[derive(Serialize)]
pub struct EmailBytesResponse {
    pub uid: u128,
    /// Server-side state, so a new device does not invent its own read/starred
    /// flags and show a different mailbox than the one you already read.
    pub read: bool,
    pub starred: bool,
    /// AES ciphertext: 'nonce (12 bytes) || ciphertext || GCM tag (16 bytes)', base64-encoded.
    /// When 'secure == false' this is the raw plaintext bytes.
    pub data: String,
    /// RSA-OAEP encrypted AES-256 key, base64-encoded. 'null' when 'secure == false'.
    pub message_key: Option<String>,
    pub received_at: String,
    pub e2ee: bool,
    /// Set when the message deletes itself: "read" (the moment it is opened) or
    /// "expire" (at 'expires_at'). Omitted for ordinary mail.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ephemeral: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<u64>,
    /// True only when serving *this* response deleted the message. A client must
    /// not show "deleted" for any other reason: a failed delete reports false.
    pub deleted: bool,
    /// Plaintext sender, so a preview whose body is withheld (a deleting message
    /// is never delivered through the preview path) can still be labelled.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub from: Option<String>,
    /// Set when the message was addressed to an alias: the local part it arrived
    /// at. A reply should go out from this address, not the account's real one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub alias: Option<String>,
}

#[derive(Serialize)]
pub struct EmailFlagResponse {
    pub uid: u128,
    pub read: bool,
    pub starred: bool,
}

#[derive(Serialize)]
pub struct EmailFlagsResponse {
    pub flags: Vec<EmailFlagResponse>,
}

#[derive(Deserialize)]
pub struct GetEmailsBulkRequest {
    #[serde(deserialize_with = "crate::api::u128_flex::uids")]
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
    #[serde(deserialize_with = "crate::api::u128_flex::uid")]
    pub uid: u128,
}

#[derive(Deserialize)]
pub struct SetEmailBytesRequest {
    #[serde(deserialize_with = "crate::api::u128_flex::uid")]
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
    /// Accepted for backwards compatibility but ignored: the envelope sender is
    /// always the authenticated account.
    #[serde(default)]
    pub from: String,
    pub to: Vec<String>,
    pub data: String,
    /// Accepted for backwards compatibility but ignored: delivery targets are
    /// resolved from each recipient's MX record, never from the request body.
    #[serde(default)]
    pub smtp_host: String,
    #[serde(default)]
    #[allow(dead_code)]
    pub smtp_port: Option<u16>,
    /// Unix seconds. When set, the message is held and released at that time
    /// instead of going out now. Omitted or 0 means send immediately.
    #[serde(default)]
    pub send_at: Option<u64>,
    /// For the sender's own list of queued messages. Never used for delivery —
    /// the subject that goes out is the one inside the MIME data.
    #[serde(default)]
    pub subject: String,
    /// Send as one of this account's own aliases (local part or full address).
    #[serde(default)]
    pub from_alias: Option<String>,
}

#[derive(Deserialize)]
pub struct MarkEmailReadRequest {
    #[serde(deserialize_with = "crate::api::u128_flex::uid")]
    pub uid: u128,
}

#[derive(Deserialize)]
pub struct SetEmailStarredRequest {
    #[serde(deserialize_with = "crate::api::u128_flex::uid")]
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
    #[serde(deserialize_with = "crate::api::u128_flex::uid")]
    pub uid: u128,
}

#[derive(Deserialize)]
pub struct UpdateGroupRequest {
    #[serde(deserialize_with = "crate::api::u128_flex::uid")]
    pub uid: u128,
    pub title: Option<String>,
    pub filter_addresses: Option<Vec<String>>,
}

#[derive(Deserialize)]
pub struct DeleteGroupRequest {
    #[serde(deserialize_with = "crate::api::u128_flex::uid")]
    pub uid: u128,
}

#[derive(Deserialize)]
pub struct GroupEmailRequest {
    // Quoted or bare, like every other id: a client that quotes ids (it must, past 2^53) was
    // refused here as invalid JSON.
    #[serde(deserialize_with = "crate::api::u128_flex::uid")]
    pub group_uid: u128,
    #[serde(deserialize_with = "crate::api::u128_flex::uid")]
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
#[derive(Deserialize, Serialize)]
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
#[derive(Deserialize, Serialize)]
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
///
/// Serialized back out when the message is scheduled: the held copy is the
/// request itself, so releasing it runs the same code path as sending now.
#[derive(Deserialize, Serialize)]
pub struct SendEncryptedRequest {
    pub localcopy: SentEmailLocalCopy,
    /// Map of "recipient@domain.com" -> { data, e2ee }
    pub recipients: HashMap<String, RecipientPayload>,
    /// Optional disappearing rule. Applied to recipients whose mailbox is on
    /// this server; other providers keep whatever copy they are given.
    #[serde(default)]
    pub ephemeral: Option<EphemeralPolicy>,
    /// Unix seconds. When set, the message is held and released then.
    #[serde(default)]
    pub send_at: Option<u64>,
    /// For the sender's list of queued messages; not used for delivery.
    #[serde(default)]
    pub subject: String,
    /// Send as one of this account's own aliases (local part or full address).
    #[serde(default)]
    pub from_alias: Option<String>,
    /// Replace a message already held, instead of queueing another. The id is kept,
    /// so the sender's list and their device-side copy still line up.
    #[serde(default)]
    pub replace_id: Option<String>,
}

/// How a message deletes itself.
#[derive(Deserialize, Serialize, Debug, Clone, Copy, Default)]
pub struct EphemeralPolicy {
    /// Delete the stored copy the moment its body is served.
    #[serde(default)]
    pub deletes_on_read: bool,
    /// Delete the stored copy after this many seconds, read or not.
    #[serde(default)]
    pub expires_in_seconds: Option<u64>,
}

impl EphemeralPolicy {
    /// Nothing to enforce, so no record and no behaviour change.
    pub fn is_noop(&self) -> bool {
        !self.deletes_on_read && self.expires_in_seconds.is_none()
    }

    /// Clamp a caller's timer into something enforceable.
    pub fn expires_at(&self, now: u64) -> Option<u64> {
        self.expires_in_seconds.map(|seconds| {
            now.saturating_add(seconds.clamp(
                crate::core::ephemeral::MIN_EXPIRY_SECONDS,
                crate::core::ephemeral::MAX_EXPIRY_SECONDS,
            ))
        })
    }
}

/// Status of a deleting message, from either side.
#[derive(Serialize)]
pub struct EphemeralStatusItem {
    pub uid: u128,
    /// "armed" (waiting to be read or to expire) or "read" (recipient's copy gone).
    pub state: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub read_at: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub recipient: Option<String>,
}

#[derive(Deserialize)]
pub struct EphemeralStatusRequest {
    /// u128 message ids arrive as JSON *strings* from the client: a 38-digit id
    /// does not survive a JavaScript number, so the app keeps them as strings and
    /// string-interpolates them elsewhere. Both forms are accepted here.
    pub uids: Vec<UidOrString>,
}

#[derive(Deserialize)]
#[serde(untagged)]
pub enum UidOrString {
    Number(u128),
    Text(String),
}

impl UidOrString {
    pub fn value(&self) -> Option<u128> {
        match self {
            UidOrString::Number(n) => Some(*n),
            UidOrString::Text(t) => t.trim().parse::<u128>().ok(),
        }
    }
}

#[derive(Serialize)]
pub struct EphemeralStatusResponse {
    pub items: Vec<EphemeralStatusItem>,
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

#[derive(Deserialize)]
pub struct AdminRecoveryAddressRequest {
    pub username: String,
    /// Empty or omitted clears the address.
    pub email: Option<String>,
}

#[derive(Deserialize)]
pub struct AdminSendRecoveryRequest {
    pub username: String,
}

#[derive(Serialize)]
pub struct AdminRecoveryAddressResponse {
    pub username: String,
    pub recovery_email: Option<String>,
}

#[derive(Serialize)]
pub struct AdminSendRecoveryResponse {
    pub sent_to: String,
    /// The token is returned so an administrator can relay it by hand when the
    /// recovery mailbox is unreachable. It is single-use and expires.
    pub token: String,
    pub expires_in_minutes: u64,
    pub emailed: bool,
    pub mail_error: Option<String>,
}

#[derive(Deserialize)]
pub struct ResetWithTokenRequest {
    pub token: String,
    /// Password token, hashed client-side exactly like login.
    pub credentials: String,
}

#[derive(Deserialize)]
pub struct SetRecoveryKeyRequest {
    /// Private key wrapped under a key derived from the user's recovery secret.
    pub wrapped_key: String,
    /// Salt for that derivation.
    pub kdf_salt: String,
    /// SHA-256(secret + domain separator), hex - proves possession without
    /// revealing the secret.
    pub auth_proof: String,
}

#[derive(Serialize)]
pub struct RecoveryKeyStatusResponse {
    pub set: bool,
    pub set_at: u64,
    pub used_at: u64,
}

#[derive(Deserialize)]
pub struct RecoveryFetchRequest {
    pub username: String,
}

#[derive(Serialize)]
pub struct RecoveryFetchResponse {
    pub wrapped_key: String,
    pub kdf_salt: String,
    /// The account's existing key-derivation salt. The client needs it to
    /// re-wrap the recovered key, and it is not secret.
    pub account_salt: String,
    pub set_at: u64,
}

#[derive(Deserialize)]
pub struct RecoveryRestoreRequest {
    pub username: String,
    pub auth_proof: String,
    /// New password token, hashed client-side.
    pub credentials: String,
    /// Private key re-wrapped under the new password.
    pub wrapped_key: String,
    pub kdf_salt: String,
}

#[derive(Debug, Serialize)]
pub struct TwoFactorStatusResponse {
    pub enabled: bool,
    pub pending: bool,
    pub enabled_at: u64,
    pub recovery_codes_remaining: usize,
}

#[derive(Debug, Serialize)]
pub struct TwoFactorStartResponse {
    pub secret: String,
    pub otpauth_url: String,
    pub recovery_codes: Vec<String>,
}

#[derive(Debug, Deserialize)]
pub struct TwoFactorCodeRequest {
    pub code: String,
}

#[derive(Debug, Deserialize)]
pub struct TwoFactorLoginRequest {
    pub challenge: String,
    pub code: String,
}

#[derive(Debug, Serialize)]
pub struct TwoFactorMessageResponse {
    pub message: String,
}
