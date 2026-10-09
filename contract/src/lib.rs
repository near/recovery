//! Recovery commitment registry.
//!
//! Every registered key `K` has exactly one instance: the `0u` account derived
//! from the v0 init `{code: v0.recover, data: {"k": hash(K)}, access_keys: {}}`.
//! The instance stores at most one entry: a commitment `hash(R)` to a recovery
//! key `R` and the block height of the original registration.
//!
//! `hash(key) = sha256("<scheme>:" ‖ raw key bytes)` for a scheme from [`SCHEMES`].
//! Keys and signatures travel as `"<scheme>:<base64>"`.
//!
//! Signatures are NEP-413 payloads with `recipient = "recover"`. Messages name
//! the instance account, which binds them to `K`.
//!
//! Versions are immutable global contracts at `v<N>.recover`. An instance moves
//! to a newer version via [`Registry::upgrade`], which switches code and calls
//! `migrate` of the new version in the same receipt. Every upgrade is
//! authorized and verified by the new version: an empty instance registers
//! there (signed by `K`), a registered one rotates its commitment (signed by `R`).

use near_sdk::base64::{Engine, engine::general_purpose::STANDARD as BASE64};
use near_sdk::serde_json::json;
use near_sdk::{
    AccountId, Gas, GasWeight, NearToken, Promise, borsh, env, json_types::Base64VecU8, near,
    require,
};

const REGISTRY: &str = "recover";
/// Version of this build, set with `RECOVER_VERSION` at compile time.
const VERSION: u32 = match option_env!("RECOVER_VERSION") {
    Some(v) => parse_u32(v),
    None => 0,
};

/// NEP-413 off-chain message prefix tag (NEP-461): `2^31 + 413`.
const NEP413_TAG: u32 = (1 << 31) + 413;

/// Entry: `commitment (32) ‖ registered_at (u64 LE)`.
const ENTRY: &[u8] = b"c";

/// Scheme name, accepted public key lengths, and signature length if this
/// version verifies the scheme on-chain. Other schemes can only be committed
/// to and revealed.
const SCHEMES: &[(&str, &[usize], Option<usize>)] = &[
    ("ed25519", &[32], Some(64)),
    ("secp256k1", &[64], Some(65)),
    ("ml-dsa-65", &[1952], Some(3309)),
    ("ml-dsa-44", &[1312], None),
    ("ml-dsa-87", &[2592], None),
    ("slh-dsa-sha2-128s", &[32], None),
    ("slh-dsa-shake-128s", &[32], None),
    ("slh-dsa-sha2-256s", &[64], None),
    ("slh-dsa-shake-256s", &[64], None),
    ("fn-dsa-512", &[897], None),
    ("fn-dsa-1024", &[1793], None),
    // HSS/LMS (RFC 8554, SP 800-208): u32 levels ‖ LMS public key, n = 24 | 32.
    ("lms", &[52, 60], None),
    // XMSS / XMSS^MT (RFC 8391, SP 800-208): u32 OID ‖ root ‖ seed, n = 24 | 32.
    ("xmss", &[52, 68], None),
    ("xmssmt", &[52, 68], None),
];

#[near(serializers = [json])]
pub struct Entry {
    /// Hex `hash(R)`.
    pub commitment: String,
    /// Block height of the original registration, kept across updates.
    pub registered_at: u64,
}

/// First commitment, signed by the key `K` this account is bound to.
#[near(serializers = [json])]
pub struct Registration {
    pub key: String,
    pub commitment: String,
    pub nonce: Base64VecU8,
    pub signature: String,
}

/// Rotation to a new commitment, signed by the currently committed key `R`.
#[near(serializers = [json])]
pub struct Rotation {
    pub revealed: String,
    pub commitment: String,
    pub nonce: Base64VecU8,
    pub signature: String,
}

/// What authorizes an upgrade: registering in the new version, or rotating there.
#[near(serializers = [json])]
#[serde(rename_all = "snake_case")]
pub enum Auth {
    Register(Registration),
    Rotate(Rotation),
}

#[near(contract_state)]
#[derive(Default)]
pub struct Registry {}

#[near]
impl Registry {
    /// Stores the first commitment. Signed by `key`, the key this account is bound to.
    pub fn register(key: String, commitment: String, nonce: Base64VecU8, signature: String) {
        register_key(Registration {
            key,
            commitment,
            nonce,
            signature,
        });
    }

    /// Replaces the commitment. Signed by the currently committed key.
    pub fn update(revealed: String, commitment: String, nonce: Base64VecU8, signature: String) {
        rotate(
            Rotation {
                revealed,
                commitment,
                nonce,
                signature,
            },
            "update",
        );
    }

    /// Reveals the committed key, logs it and deletes this account, sending its
    /// balance to the caller. Knowing the preimage is enough: the recovery key's
    /// authority is exercised by whoever consumes the record.
    pub fn recover(revealed: String) -> Promise {
        let (key, registered_at) = reveal(&revealed);
        env::log_str(&format!(
            r#"EVENT_JSON:{{"standard":"recover","version":"1.0.0","event":"recover","data":{{"revealed":"{}","registered_at":{registered_at}}}}}"#,
            key.canonical()
        ));
        Promise::new(env::current_account_id()).delete_account(env::predecessor_account_id())
    }

    /// Switches this instance to `v<version>.recover` and calls its `migrate`
    /// in the same receipt. If `migrate` fails, the code switch is rolled back.
    pub fn upgrade(version: u32, auth: Auth) -> Promise {
        require!(version > VERSION, "can only upgrade to a newer version");
        let code: AccountId = format!("v{version}.{REGISTRY}").parse().unwrap();
        Promise::new(env::current_account_id())
            .use_global_contract_by_account_id(code)
            .function_call_weight(
                "migrate".to_owned(),
                json!({ "auth": auth }).to_string().into_bytes(),
                NearToken::from_yoctonear(0),
                Gas::from_gas(0),
                GasWeight(1),
            )
    }

    /// Called by [`Self::upgrade`] right after switching to this version, which
    /// verifies the authorization: an empty instance registers here (signed by
    /// `K`), a registered one rotates its commitment (signed by `R`).
    pub fn migrate(auth: Auth) {
        require!(
            env::predecessor_account_id() == env::current_account_id(),
            "only via upgrade"
        );
        match auth {
            Auth::Register(registration) => register_key(registration),
            Auth::Rotate(rotation) => rotate(rotation, &format!("upgrade to v{VERSION}")),
        }
    }

    pub fn get() -> Option<Entry> {
        read_entry().map(|(commitment, registered_at)| Entry {
            commitment: to_hex(&commitment),
            registered_at,
        })
    }

    pub fn version() -> u32 {
        VERSION
    }
}

/// Verifies `registration` by the key this account is bound to and stores the
/// first entry. The message names this version, so a registration signed for
/// one version cannot be used to move the instance to another.
fn register_key(registration: Registration) {
    let key = Key::parse(&registration.key);
    require!(
        env::current_account_id() == canonical_account(&key.hash()),
        "not the canonical account for this key"
    );
    require!(env::storage_read(ENTRY).is_none(), "already registered");
    let new = parse_hex32(&registration.commitment);
    key.verify(
        &registration.signature,
        &message(&format!("register on v{VERSION}"), &registration.commitment),
        &registration.nonce,
    );
    write_entry(&new, env::block_height());
}

/// Verifies `rotation` by the currently committed key for `action` and stores
/// its new commitment, keeping the original registration height.
fn rotate(rotation: Rotation, action: &str) {
    let (key, registered_at) = reveal(&rotation.revealed);
    let new = parse_hex32(&rotation.commitment);
    key.verify(
        &rotation.signature,
        &message(action, &rotation.commitment),
        &rotation.nonce,
    );
    write_entry(&new, registered_at);
}

/// Parses `revealed`, checks it against the stored commitment and returns it
/// with the original registration height.
fn reveal(revealed: &str) -> (Key, u64) {
    let (commitment, registered_at) =
        read_entry().unwrap_or_else(|| env::panic_str("not registered"));
    let key = Key::parse(revealed);
    require!(
        key.hash() == commitment,
        "revealed key does not match commitment"
    );
    (key, registered_at)
}

/// `NEAR recovery: <action> <this account> commitment <hex>`
fn message(action: &str, commitment: &str) -> String {
    format!(
        "NEAR recovery: {action} {} commitment {commitment}",
        env::current_account_id()
    )
}

struct Key {
    scheme: usize,
    raw: Vec<u8>,
}

impl Key {
    /// Parses `"<scheme>:<base64>"` for a scheme from [`SCHEMES`].
    fn parse(s: &str) -> Self {
        let (scheme, raw) = split(s);
        require!(SCHEMES[scheme].1.contains(&raw.len()), "invalid key length");
        Self { scheme, raw }
    }

    fn name(&self) -> &'static str {
        SCHEMES[self.scheme].0
    }

    /// `sha256("<scheme>:" ‖ raw)`
    fn hash(&self) -> [u8; 32] {
        env::sha256_array([self.name().as_bytes(), b":", &self.raw].concat())
    }

    fn canonical(&self) -> String {
        format!("{}:{}", self.name(), BASE64.encode(&self.raw))
    }

    /// Verifies `signature` (`"<scheme>:<base64>"`) over the NEP-413 hash of `message`.
    fn verify(&self, signature: &str, message: &str, nonce: &Base64VecU8) {
        let sig_len = SCHEMES[self.scheme]
            .2
            .unwrap_or_else(|| env::panic_str("scheme cannot be verified on-chain"));
        let (scheme, sig) = split(signature);
        require!(scheme == self.scheme, "signature scheme does not match key");
        require!(sig.len() == sig_len, "invalid signature length");
        let nonce: [u8; 32] = nonce.0[..]
            .try_into()
            .unwrap_or_else(|_| env::panic_str("nonce must be 32 bytes"));
        let payload =
            borsh::to_vec(&(NEP413_TAG, message, nonce, REGISTRY, None::<String>)).unwrap();
        let hash = env::sha256_array(&payload);
        let pk = &self.raw[..];
        let ok = match self.name() {
            "ed25519" => {
                env::ed25519_verify(sig[..].try_into().unwrap(), hash, pk.try_into().unwrap())
            }
            "secp256k1" => {
                env::ecrecover(&hash, &sig[..64], sig[64], true).is_some_and(|r| r[..] == *pk)
            }
            _ => ml_dsa_verify(&sig, &hash, pk),
        };
        require!(ok, "invalid signature");
    }
}

/// Splits `"<scheme>:<base64>"` into the scheme index and decoded bytes.
fn split(s: &str) -> (usize, Vec<u8>) {
    let (name, data) = s
        .split_once(':')
        .unwrap_or_else(|| env::panic_str("expected <scheme>:<base64>"));
    let scheme = SCHEMES
        .iter()
        .position(|s| s.0 == name)
        .unwrap_or_else(|| env::panic_str("unknown scheme"));
    let raw = BASE64
        .decode(data)
        .unwrap_or_else(|_| env::panic_str("invalid base64"));
    (scheme, raw)
}

/// Account derived from the v0 init for a key with hash `k`: every key has
/// exactly one instance, whatever version it runs now.
fn canonical_account(k: &[u8; 32]) -> AccountId {
    // borsh(UniversalStateInit::V1 { code: Some(GlobalContractIdentifier::AccountId(v0.recover)),
    //                                data: {"k": k}, access_keys: {} })
    let init = borsh::to_vec(&(
        0u8,
        Some((1u8, format!("v0.{REGISTRY}"))),
        vec![(b"k".to_vec(), k.to_vec())],
        0u32,
    ))
    .unwrap();
    universal_account_id(&init)
}

fn parse_hex32(s: &str) -> [u8; 32] {
    // Lowercase only, so the hex string signed in the message is canonical.
    let nibble = |c: u8| match c {
        b'0'..=b'9' => c - b'0',
        b'a'..=b'f' => c - b'a' + 10,
        _ => env::panic_str("commitment must be 64 lowercase hex chars"),
    };
    require!(s.len() == 64, "commitment must be 64 lowercase hex chars");
    let b = s.as_bytes();
    std::array::from_fn(|i| nibble(b[2 * i]) << 4 | nibble(b[2 * i + 1]))
}

fn to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn read_entry() -> Option<([u8; 32], u64)> {
    let v = env::storage_read(ENTRY)?;
    Some((
        v[..32].try_into().unwrap(),
        u64::from_le_bytes(v[32..].try_into().unwrap()),
    ))
}

fn write_entry(commitment: &[u8; 32], registered_at: u64) {
    env::storage_write(
        ENTRY,
        &[&commitment[..], &registered_at.to_le_bytes()].concat(),
    );
}

const fn parse_u32(s: &str) -> u32 {
    let (b, mut i, mut n) = (s.as_bytes(), 0, 0u32);
    while i < b.len() {
        assert!(b[i].is_ascii_digit(), "RECOVER_VERSION must be a number");
        n = n * 10 + (b[i] - b'0') as u32;
        i += 1;
    }
    n
}

// Protocol v87 host functions that near-sdk does not wrap yet.
#[cfg(target_family = "wasm")]
mod host {
    unsafe extern "C" {
        pub fn ml_dsa_verify(
            sig_len: u64,
            sig_ptr: u64,
            msg_len: u64,
            msg_ptr: u64,
            pk_len: u64,
            pk_ptr: u64,
        ) -> u64;
        pub fn universal_state_init_to_account_id(len: u64, ptr: u64, register_id: u64);
    }
}

#[cfg(target_family = "wasm")]
fn ml_dsa_verify(sig: &[u8], msg: &[u8], pk: &[u8]) -> bool {
    unsafe {
        host::ml_dsa_verify(
            sig.len() as _,
            sig.as_ptr() as _,
            msg.len() as _,
            msg.as_ptr() as _,
            pk.len() as _,
            pk.as_ptr() as _,
        ) == 1
    }
}

#[cfg(target_family = "wasm")]
fn universal_account_id(init: &[u8]) -> AccountId {
    unsafe { host::universal_state_init_to_account_id(init.len() as _, init.as_ptr() as _, 0) };
    let id = env::read_register(0).unwrap();
    String::from_utf8(id).unwrap().parse().unwrap()
}

#[cfg(not(target_family = "wasm"))]
fn ml_dsa_verify(_: &[u8], _: &[u8], _: &[u8]) -> bool {
    unimplemented!("only available on-chain")
}

#[cfg(not(target_family = "wasm"))]
fn universal_account_id(_: &[u8]) -> AccountId {
    unimplemented!("only available on-chain")
}
