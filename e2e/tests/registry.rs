//! End-to-end tests for the recovery registry on a local sandbox `neard`.
//!
//! Requires a sandbox build of nearcore with protocol v87 (`0u` accounts,
//! `ml_dsa_verify`) and the contract wasm:
//!
//! ```sh
//! (cd ../nearcore && cargo build -p neard --features sandbox --profile dev-release)
//! (cd contract && cargo near build non-reproducible-wasm --no-abi --out-dir ../target/near/v0)
//! (cd contract && RECOVER_VERSION=1 cargo near build non-reproducible-wasm --no-abi --out-dir ../target/near/v1)
//! (cd e2e && cargo test -- --nocapture)
//! ```
//!
//! `NEARD` overrides the neard binary path.

use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use near_crypto::{InMemorySigner, KeyType, PublicKey, SecretKey, Signer};
use near_primitives::action::{
    Action, CreateAccountAction, DeployGlobalContractAction, FunctionCallAction, GlobalContractDeployMode,
    GlobalContractIdentifier, UniversalStateInitAction,
};
use near_primitives::hash::CryptoHash;
use near_primitives::transaction::{SignedTransaction, TransferAction};
use near_primitives::types::{AccountId, Balance, Gas};
use near_primitives::universal_state_init::{RawStateInit, UniversalStateInit, UniversalStateInitV1};
use near_primitives::utils::derive_universal_account_id;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::io::Write;
use std::net::TcpListener;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

const REGISTRY: &str = "recover";
const NEP413_TAG: u32 = (1 << 31) + 413;

// ---------------------------------------------------------------------------
// Sandbox node
// ---------------------------------------------------------------------------

struct Sandbox {
    node: Child,
    rpc: String,
    _home: tempfile::TempDir,
    relayer: Signer,
}

impl Drop for Sandbox {
    fn drop(&mut self) {
        let _ = self.node.kill();
        let _ = self.node.wait();
    }
}

#[derive(Debug)]
struct Outcome {
    logs: Vec<String>,
    gas_burnt: u64,
}

fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port()
}

fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("..")
}

impl Sandbox {
    fn start() -> Self {
        let neard = std::env::var("NEARD")
            .map(PathBuf::from)
            .unwrap_or_else(|_| root().join("../nearcore/target/dev-release/neard"));
        let home = tempfile::tempdir().unwrap();
        let ok = Command::new(&neard)
            .arg("--home")
            .arg(home.path())
            .args(["init", "--chain-id", "localnet"])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .unwrap_or_else(|e| panic!("cannot run {}: {e}", neard.display()));
        assert!(ok.success(), "neard init failed");

        let config_path = home.path().join("config.json");
        let mut config: Value = serde_json::from_slice(&std::fs::read(&config_path).unwrap()).unwrap();
        let rpc_port = free_port();
        config["rpc"]["addr"] = json!(format!("127.0.0.1:{rpc_port}"));
        config["network"]["addr"] = json!(format!("127.0.0.1:{}", free_port()));
        std::fs::write(&config_path, serde_json::to_vec_pretty(&config).unwrap()).unwrap();

        let log = std::fs::File::create(home.path().join("neard.log")).unwrap();
        let node = Command::new(&neard)
            .arg("--home")
            .arg(home.path())
            .arg("run")
            .stdout(log.try_clone().unwrap())
            .stderr(log)
            .spawn()
            .unwrap();

        let relayer = InMemorySigner::from_file(&home.path().join("validator_key.json")).unwrap();
        let sandbox = Sandbox { node, rpc: format!("http://127.0.0.1:{rpc_port}"), _home: home, relayer };
        sandbox.wait_for_blocks();
        sandbox
    }

    fn wait_for_blocks(&self) {
        let start = Instant::now();
        loop {
            if let Ok(block) = self.rpc("block", json!({"finality": "final"})) {
                if block["header"]["height"].as_u64().unwrap_or(0) > 2 {
                    return;
                }
            }
            assert!(start.elapsed() < Duration::from_secs(60), "sandbox did not start");
            std::thread::sleep(Duration::from_millis(200));
        }
    }

    fn rpc(&self, method: &str, params: Value) -> Result<Value, Value> {
        let body = json!({"jsonrpc": "2.0", "id": "0", "method": method, "params": params});
        let mut curl = Command::new("curl")
            .args(["-s", "-X", "POST", "-H", "Content-Type: application/json", "--data-binary", "@-"])
            .arg(&self.rpc)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .unwrap();
        curl.stdin.take().unwrap().write_all(body.to_string().as_bytes()).unwrap();
        let out = curl.wait_with_output().unwrap();
        let resp: Value = serde_json::from_slice(&out.stdout).map_err(|e| json!(e.to_string()))?;
        match resp.get("error") {
            Some(err) => Err(err.clone()),
            None => Ok(resp["result"].clone()),
        }
    }

    /// Creates the `recover` top-level account with the relayer's key. Only the
    /// registrar can create short TLAs, so the sandbox patches state directly.
    fn create_registry_account(&self) -> Signer {
        let genesis: Value =
            serde_json::from_slice(&std::fs::read(self._home.path().join("genesis.json")).unwrap()).unwrap();
        let relayer_id = self.relayer.get_account_id();
        let records: Vec<Value> = genesis["records"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|r| {
                let (kind, body) = r.as_object()?.iter().next()?;
                (matches!(kind.as_str(), "Account" | "AccessKey") && body["account_id"] == relayer_id.as_str())
                    .then(|| {
                        let mut r = r.clone();
                        r[kind]["account_id"] = json!(REGISTRY);
                        r
                    })
            })
            .collect();
        assert_eq!(records.len(), 2, "expected relayer account and key in genesis");
        self.rpc("sandbox_patch_state", json!({"records": records})).unwrap();
        let signer = InMemorySigner::from_secret_key(REGISTRY.parse().unwrap(), self.relayer_secret());
        // Patched state shows up a block later.
        let start = Instant::now();
        while self.view_account(REGISTRY).is_err() {
            assert!(start.elapsed() < Duration::from_secs(10), "registry account not created");
            std::thread::sleep(Duration::from_millis(200));
        }
        signer
    }

    fn relayer_secret(&self) -> SecretKey {
        match &self.relayer {
            Signer::InMemory(s) => s.secret_key.clone(),
            _ => unreachable!(),
        }
    }

    fn send(&self, signer: &Signer, receiver: &AccountId, actions: Vec<Action>) -> Result<Outcome, String> {
        let key = self
            .rpc(
                "query",
                json!({
                    "request_type": "view_access_key",
                    "finality": "optimistic",
                    "account_id": signer.get_account_id(),
                    "public_key": signer.public_key().to_string(),
                }),
            )
            .unwrap();
        let nonce = key["nonce"].as_u64().unwrap() + 1;
        let block = self.rpc("block", json!({"finality": "final"})).unwrap();
        let block_hash: CryptoHash = block["header"]["hash"].as_str().unwrap().parse().unwrap();
        let tx = SignedTransaction::from_actions(
            nonce,
            signer.get_account_id(),
            receiver.clone(),
            signer,
            actions,
            block_hash,
        );
        let res = self
            .rpc(
                "send_tx",
                json!({"signed_tx_base64": B64.encode(borsh::to_vec(&tx).unwrap()), "wait_until": "FINAL"}),
            )
            .map_err(|e| e.to_string())?;
        if res["status"].get("Failure").is_some() {
            return Err(res["status"]["Failure"].to_string());
        }
        // A tx can succeed while one of its receipts fails (e.g. the delete-account promise).
        for r in res["receipts_outcome"].as_array().unwrap() {
            if let Some(f) = r["outcome"]["status"].get("Failure") {
                return Err(f.to_string());
            }
        }
        let outcomes = std::iter::once(&res["transaction_outcome"]).chain(res["receipts_outcome"].as_array().unwrap());
        let mut logs = vec![];
        let mut gas_burnt = 0;
        for o in outcomes {
            gas_burnt += o["outcome"]["gas_burnt"].as_u64().unwrap();
            logs.extend(o["outcome"]["logs"].as_array().unwrap().iter().map(|l| l.as_str().unwrap().to_owned()));
        }
        Ok(Outcome { logs, gas_burnt })
    }

    fn view_account(&self, account: &str) -> Result<Value, Value> {
        self.rpc("query", json!({"request_type": "view_account", "finality": "final", "account_id": account}))
    }

    fn view(&self, account: &AccountId, method: &str) -> Value {
        let res = self
            .rpc(
                "query",
                json!({
                    "request_type": "call_function",
                    "finality": "final",
                    "account_id": account,
                    "method_name": method,
                    "args_base64": "",
                }),
            )
            .unwrap();
        let bytes: Vec<u8> =
            res["result"].as_array().unwrap().iter().map(|b| b.as_u64().unwrap() as u8).collect();
        serde_json::from_slice(&bytes).unwrap()
    }
}


// ---------------------------------------------------------------------------
// Registry client helpers
// ---------------------------------------------------------------------------

fn sha256(data: &[u8]) -> [u8; 32] {
    Sha256::digest(data).into()
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// A key of any registry scheme: `(scheme, raw bytes)`.
struct Raw(String, Vec<u8>);

impl From<&PublicKey> for Raw {
    fn from(pk: &PublicKey) -> Self {
        Raw(pk.key_type().to_string(), pk.key_data().to_vec())
    }
}

impl Raw {
    /// `"<scheme>:<base64>"`
    fn enc(&self) -> String {
        format!("{}:{}", self.0, B64.encode(&self.1))
    }

    /// `sha256("<scheme>:" ‖ raw)`
    fn hash(&self) -> [u8; 32] {
        sha256(&[self.0.as_bytes(), b":", &self.1].concat())
    }

    fn commitment(&self) -> String {
        hex(&self.hash())
    }
}

fn commitment(pk: &PublicKey) -> String {
    Raw::from(pk).commitment()
}

fn enc(pk: &PublicKey) -> String {
    Raw::from(pk).enc()
}

fn state_init_with(key: &PublicKey, extra: &[(&[u8], &[u8])]) -> RawStateInit {
    let mut data = BTreeMap::from([(b"k".to_vec(), Raw::from(key).hash().to_vec())]);
    data.extend(extra.iter().map(|(k, v)| (k.to_vec(), v.to_vec())));
    UniversalStateInit::V1(UniversalStateInitV1 {
        code: Some(GlobalContractIdentifier::AccountId(format!("v0.{REGISTRY}").parse().unwrap())),
        data,
        access_keys: BTreeSet::new(),
    })
    .to_raw()
}

fn account_of(key: &PublicKey) -> AccountId {
    derive_universal_account_id(&state_init_with(key, &[]))
}

/// NEP-413 signature: `(nonce base64, "<scheme>:<base64>")`.
fn sign413(sk: &SecretKey, message: &str, recipient: &str) -> (String, String) {
    let nonce = sha256(message.as_bytes());
    let payload = borsh::to_vec(&(NEP413_TAG, message, nonce, recipient, None::<String>)).unwrap();
    let sig = borsh::to_vec(&sk.sign(&sha256(&payload))).unwrap();
    (B64.encode(nonce), format!("{}:{}", sk.key_type(), B64.encode(&sig[1..])))
}

fn call(method: &str, args: Value) -> Action {
    Action::FunctionCall(Box::new(FunctionCallAction {
        method_name: method.to_owned(),
        args: args.to_string().into_bytes(),
        gas: Gas::from_teragas(300),
        deposit: Balance::ZERO,
    }))
}

fn init(key: &PublicKey) -> Action {
    init_raw(state_init_with(key, &[]))
}

fn init_raw(state_init: RawStateInit) -> Action {
    Action::UniversalStateInit(Box::new(UniversalStateInitAction { state_init, deposit: Balance::ZERO }))
}

fn register_args(account: &AccountId, k: &SecretKey, c: &str) -> Value {
    register_args_on(0, account, k, c)
}

/// Registration signed by `k` for version `v`.
fn register_args_on(v: u32, account: &AccountId, k: &SecretKey, c: &str) -> Value {
    let (nonce, signature) =
        sign413(k, &format!("NEAR recovery: register on v{v} {account} commitment {c}"), REGISTRY);
    json!({"key": enc(&k.public_key()), "commitment": c, "nonce": nonce, "signature": signature})
}

/// Rotation fields signed by `r` for `action` ("update", "upgrade to v1").
fn rotation(account: &AccountId, action: &str, r: &SecretKey, next: &str) -> Value {
    let (nonce, signature) = sign413(r, &format!("NEAR recovery: {action} {account} commitment {next}"), REGISTRY);
    json!({"revealed": enc(&r.public_key()), "commitment": next, "nonce": nonce, "signature": signature})
}

fn recover_args(r: &Raw) -> Value {
    json!({"revealed": r.enc()})
}

#[track_caller]
fn assert_err(res: Result<Outcome, String>, needle: &str) {
    match res {
        Ok(o) => panic!("expected failure containing {needle:?}, got success: {o:?}"),
        Err(e) => assert!(e.contains(needle), "expected {needle:?} in {e}"),
    }
}

fn random_raw(scheme: &str, len: usize) -> Raw {
    // Commit-only schemes are opaque bytes to the registry.
    let seed = SecretKey::from_random(KeyType::ED25519);
    let bytes: Vec<u8> = (0..len).map(|i| seed.public_key().key_data()[i % 32] ^ i as u8).collect();
    Raw(scheme.to_owned(), bytes)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[test]
fn registry_e2e() {
    let sb = Sandbox::start();
    let registry = sb.create_registry_account();
    // Immutable versions: sub-accounts without keys, each publishing its code by account id.
    for v in [0, 1] {
        let wasm = root().join(format!("target/near/v{v}/recover.wasm"));
        let code = std::fs::read(&wasm).unwrap_or_else(|e| panic!("{}: {e}", wasm.display()));
        sb.send(
            &registry,
            &format!("v{v}.{REGISTRY}").parse().unwrap(),
            vec![
                Action::CreateAccount(CreateAccountAction {}),
                Action::Transfer(TransferAction { deposit: Balance::from_near(50) }),
                Action::DeployGlobalContract(DeployGlobalContractAction {
                    code: code.into(),
                    deploy_mode: GlobalContractDeployMode::AccountId,
                }),
            ],
        )
        .unwrap();
    }

    for (k_type, r_type) in [
        (KeyType::ED25519, KeyType::MLDSA65),
        (KeyType::SECP256K1, KeyType::SECP256K1),
        (KeyType::MLDSA65, KeyType::ED25519),
    ] {
        lifecycle(&sb, k_type, r_type);
    }
    commit_only_schemes(&sb);
    upgrades(&sb);
    rejections(&sb);
}

/// register → update → recover → re-register, with `K` of `k_type` and recovery keys of `r_type`.
fn lifecycle(sb: &Sandbox, k_type: KeyType, r_type: KeyType) {
    println!("--- lifecycle K={k_type} R={r_type}");
    let k = SecretKey::from_random(k_type);
    let r1 = SecretKey::from_random(r_type);
    let r2 = SecretKey::from_random(r_type);
    let account = account_of(&k.public_key());
    assert!(account.as_str().starts_with("0u"));

    // Init + register in one tx from a relayer; no storage deposit.
    let c1 = commitment(&r1.public_key());
    let out = sb.send(&sb.relayer, &account, vec![init(&k.public_key()), call("register", register_args(&account, &k, &c1))]).unwrap();
    println!("register: {} Tgas", out.gas_burnt / 10u64.pow(12));
    let entry = sb.view(&account, "get");
    assert_eq!(entry["commitment"], c1);
    let registered_at = entry["registered_at"].as_u64().unwrap();
    assert_eq!(sb.view_account(account.as_str()).unwrap()["amount"], "0", "zero-balance account");

    // Rotate with R1; registered_at is preserved.
    let c2 = commitment(&r2.public_key());
    let out = sb.send(&sb.relayer, &account, vec![call("update", rotation(&account, "update", &r1, &c2))]).unwrap();
    println!("update:   {} Tgas", out.gas_burnt / 10u64.pow(12));
    let entry = sb.view(&account, "get");
    assert_eq!(entry["commitment"], c2);
    assert_eq!(entry["registered_at"].as_u64().unwrap(), registered_at);

    // R1 is no longer committed.
    assert_err(
        sb.send(&sb.relayer, &account, vec![call("update", rotation(&account, "update", &r1, &c1))]),
        "revealed key does not match commitment",
    );

    // Recover by revealing R2, no signature: event + account deleted.
    let out = sb.send(&sb.relayer, &account, vec![call("recover", recover_args(&Raw::from(&r2.public_key())))]).unwrap();
    println!("recover:  {} Tgas", out.gas_burnt / 10u64.pow(12));
    let event = out.logs.iter().find(|l| l.starts_with("EVENT_JSON:")).expect("recover event");
    let event: Value = serde_json::from_str(&event["EVENT_JSON:".len()..]).unwrap();
    assert_eq!(event["data"]["revealed"], enc(&r2.public_key()));
    assert_eq!(event["data"]["registered_at"].as_u64().unwrap(), registered_at);
    assert!(sb.view_account(account.as_str()).is_err(), "account must be deleted");

    // K can register again; the new entry carries a later registered_at.
    sb.send(&sb.relayer, &account, vec![init(&k.public_key()), call("register", register_args(&account, &k, &c1))]).unwrap();
    assert!(sb.view(&account, "get")["registered_at"].as_u64().unwrap() > registered_at);
}

/// Every commit-only scheme can be registered and revealed, but not used to sign.
fn commit_only_schemes(sb: &Sandbox) {
    println!("--- commit-only schemes");
    for (scheme, len) in [
        ("ml-dsa-44", 1312),
        ("ml-dsa-87", 2592),
        ("slh-dsa-sha2-128s", 32),
        ("slh-dsa-shake-128s", 32),
        ("slh-dsa-sha2-256s", 64),
        ("slh-dsa-shake-256s", 64),
        ("fn-dsa-512", 897),
        ("fn-dsa-1024", 1793),
        ("lms", 60),
        ("xmss", 68),
        ("xmssmt", 52),
        // Not a canonical name: the contract cannot see it at registration, so
        // it must still be revealable rather than stuck forever.
        ("ml-dsa87", 2592),
    ] {
        let k = SecretKey::from_random(KeyType::ED25519);
        let account = account_of(&k.public_key());
        let r = random_raw(scheme, len);
        sb.send(&sb.relayer, &account, vec![init(&k.public_key()), call("register", register_args(&account, &k, &r.commitment()))]).unwrap();

        let args = json!({"revealed": r.enc(), "commitment": r.commitment(), "nonce": B64.encode([0u8; 32]), "signature": format!("{scheme}:AA==")});
        assert_err(sb.send(&sb.relayer, &account, vec![call("update", args)]), "scheme cannot be verified on-chain");

        let out = sb.send(&sb.relayer, &account, vec![call("recover", recover_args(&r))]).unwrap();
        assert!(out.logs.iter().any(|l| l.contains(&r.enc())), "{scheme}: event must carry the revealed key");
        assert!(sb.view_account(account.as_str()).is_err());
    }
}

fn upgrade(version: u32, auth: &str, args: Value) -> Action {
    call("upgrade", json!({"version": version, "auth": {auth: args}}))
}

fn upgrades(sb: &Sandbox) {
    println!("--- upgrades");
    // A new user goes straight to v1 in one tx: init(v0) + upgrade with a
    // registration signed for v1, which v1.migrate verifies.
    let k = SecretKey::from_random(KeyType::ED25519);
    let r = SecretKey::from_random(KeyType::MLDSA65);
    let account = account_of(&k.public_key());
    let c = commitment(&r.public_key());

    // Empty instances cannot be moved by others: a registration by another key,
    // or the owner's v0 registration replayed as an upgrade, fails in v1.migrate
    // and the code switch rolls back.
    let other = SecretKey::from_random(KeyType::ED25519);
    assert_err(
        sb.send(&sb.relayer, &account, vec![init(&k.public_key()), upgrade(1, "register", register_args_on(1, &account, &other, &c))]),
        "not the canonical account for this key",
    );
    assert_err(
        sb.send(&sb.relayer, &account, vec![upgrade(1, "register", register_args_on(0, &account, &k, &c))]),
        "invalid signature",
    );
    assert_err(sb.send(&sb.relayer, &account, vec![upgrade(1, "rotate", rotation(&account, "upgrade to v1", &r, &c))]), "not registered");
    assert_eq!(sb.view(&account, "version"), 0, "failed upgrades must roll back the code switch");
    assert!(sb.view(&account, "get").is_null());

    let out = sb.send(&sb.relayer, &account, vec![upgrade(1, "register", register_args_on(1, &account, &k, &c))]).unwrap();
    println!("upgrade+register: {} Tgas", out.gas_burnt / 10u64.pow(12));
    assert_eq!(sb.view(&account, "version"), 1);
    assert_eq!(sb.view(&account, "get")["commitment"], c);

    // A registered v0 instance.
    let k = SecretKey::from_random(KeyType::SECP256K1);
    let r1 = SecretKey::from_random(KeyType::MLDSA65);
    let r2 = SecretKey::from_random(KeyType::ED25519);
    let account = account_of(&k.public_key());
    let (c1, c2) = (commitment(&r1.public_key()), commitment(&r2.public_key()));
    sb.send(&sb.relayer, &account, vec![init(&k.public_key()), call("register", register_args(&account, &k, &c1))]).unwrap();
    let registered_at = sb.view(&account, "get")["registered_at"].as_u64().unwrap();

    // K cannot move a registered instance; neither can a rotation signed for
    // another action or by a key that is not committed.
    assert_err(sb.send(&sb.relayer, &account, vec![upgrade(1, "register", register_args_on(1, &account, &k, &c2))]), "already registered");
    let wrong = rotation(&account, "update", &r1, &c2);
    assert_err(sb.send(&sb.relayer, &account, vec![upgrade(1, "rotate", wrong)]), "invalid signature");
    let not_committed = rotation(&account, "upgrade to v1", &r2, &c2);
    assert_err(sb.send(&sb.relayer, &account, vec![upgrade(1, "rotate", not_committed)]), "revealed key does not match commitment");
    assert_eq!(sb.view(&account, "version"), 0, "failed upgrades must roll back the code switch");
    assert_eq!(sb.view(&account, "get")["commitment"], c1);

    // Downgrades / same version, and calling migrate directly.
    let ok = rotation(&account, "upgrade to v1", &r1, &c2);
    assert_err(sb.send(&sb.relayer, &account, vec![upgrade(0, "rotate", ok.clone())]), "can only upgrade to a newer version");
    assert_err(sb.send(&sb.relayer, &account, vec![call("migrate", json!({"auth": {"rotate": ok.clone()}}))]), "only via upgrade");

    // Signed by R1 for "upgrade to v1": switches code and rotates to R2.
    let out = sb.send(&sb.relayer, &account, vec![upgrade(1, "rotate", ok)]).unwrap();
    println!("upgrade+rotate:   {} Tgas", out.gas_burnt / 10u64.pow(12));
    assert_eq!(sb.view(&account, "version"), 1);
    let entry = sb.view(&account, "get");
    assert_eq!(entry["commitment"], c2);
    assert_eq!(entry["registered_at"].as_u64().unwrap(), registered_at);
}

fn rejections(sb: &Sandbox) {
    println!("--- rejections");
    let k = SecretKey::from_random(KeyType::ED25519);
    let other = SecretKey::from_random(KeyType::ED25519);
    let r = SecretKey::from_random(KeyType::MLDSA65);
    let c = commitment(&r.public_key());
    let account = account_of(&k.public_key());
    let other_account = account_of(&other.public_key());
    sb.send(&sb.relayer, &account, vec![init(&k.public_key())]).unwrap();

    // Not registered yet.
    assert_err(sb.send(&sb.relayer, &account, vec![call("update", rotation(&account, "update", &r, &c))]), "not registered");
    assert_err(sb.send(&sb.relayer, &account, vec![call("recover", recover_args(&Raw::from(&r.public_key())))]), "not registered");

    // A key not bound to this account.
    assert_err(
        sb.send(&sb.relayer, &account, vec![call("register", register_args(&account, &other, &c))]),
        "not the canonical account for this key",
    );

    // A non-canonical instance for the same key (extra init data) cannot register.
    let odd_init = state_init_with(&k.public_key(), &[(b"x", b"1")]);
    let odd = derive_universal_account_id(&odd_init);
    assert_err(
        sb.send(&sb.relayer, &odd, vec![init_raw(odd_init), call("register", register_args(&odd, &k, &c))]),
        "not the canonical account for this key",
    );

    // Malformed keys.
    for (bad, needle) in [
        ("ML-DSA-65:AAAA", "invalid scheme name"),
        ("ed\"25519:AAAA", "invalid scheme name"),
        (":AAAA", "invalid scheme name"),
        ("ed25519", "expected <scheme>:<base64>"),
        ("ed25519:!!", "invalid base64"),
    ] {
        let mut args = register_args(&account, &k, &c);
        args["key"] = json!(bad);
        assert_err(sb.send(&sb.relayer, &account, vec![call("register", args)]), needle);
    }

    // Signature made for another account (cross-account replay).
    let mut args = register_args(&other_account, &k, &c);
    args["key"] = json!(enc(&k.public_key()));
    assert_err(sb.send(&sb.relayer, &account, vec![call("register", args)]), "invalid signature");

    // Wrong NEP-413 recipient.
    let (nonce, signature) = sign413(&k, &format!("NEAR recovery: register on v0 {account} commitment {c}"), "evil");
    let args = json!({"key": enc(&k.public_key()), "commitment": c, "nonce": nonce, "signature": signature});
    assert_err(sb.send(&sb.relayer, &account, vec![call("register", args)]), "invalid signature");

    // Signature by a different scheme than the key.
    let mut args = register_args(&account, &k, &c);
    args["signature"] = json!(sign413(&r, "x", REGISTRY).1);
    assert_err(sb.send(&sb.relayer, &account, vec![call("register", args)]), "signature scheme does not match key");

    // A commit-only scheme cannot register.
    let mut args = register_args(&account, &k, &c);
    args["key"] = json!(random_raw("slh-dsa-sha2-128s", 32).enc());
    assert_err(sb.send(&sb.relayer, &account, vec![call("register", args)]), "not the canonical account");

    // Uppercase hex is rejected so the signed message stays canonical.
    let mut args = register_args(&account, &k, &c);
    args["commitment"] = json!(c.to_uppercase());
    assert_err(sb.send(&sb.relayer, &account, vec![call("register", args)]), "lowercase hex");

    // Happy register, then a second register fails.
    sb.send(&sb.relayer, &account, vec![call("register", register_args(&account, &k, &c))]).unwrap();
    assert_err(
        sb.send(&sb.relayer, &account, vec![call("register", register_args(&account, &k, &commitment(&k.public_key())))]),
        "already registered",
    );

    // The original key cannot rotate the commitment.
    let next = commitment(&k.public_key());
    assert_err(
        sb.send(&sb.relayer, &account, vec![call("update", rotation(&account, "update", &k, &next))]),
        "revealed key does not match commitment",
    );

    // Correct revealed key, but signed for a different action.
    let args = rotation(&account, "upgrade to v1", &r, &next);
    assert_err(sb.send(&sb.relayer, &account, vec![call("update", args)]), "invalid signature");

    // A revealed key with the right bytes under another scheme name does not match.
    let mut wrong_scheme = Raw::from(&r.public_key());
    wrong_scheme.0 = "ml-dsa-44".into();
    wrong_scheme.1.truncate(1312);
    assert_err(
        sb.send(&sb.relayer, &account, vec![call("recover", recover_args(&wrong_scheme))]),
        "revealed key does not match commitment",
    );

    // Keys too long to reveal, and verifiable schemes with the wrong length.
    let k = SecretKey::from_random(KeyType::ED25519);
    let account = account_of(&k.public_key());
    let short = Raw("ed25519".into(), vec![7; 31]);
    sb.send(&sb.relayer, &account, vec![init(&k.public_key()), call("register", register_args(&account, &k, &short.commitment()))]).unwrap();
    let args = json!({"revealed": short.enc(), "commitment": c, "nonce": B64.encode([0u8; 32]), "signature": "ed25519:AA=="});
    assert_err(sb.send(&sb.relayer, &account, vec![call("update", args)]), "invalid key length");
    let huge = Raw("ml-dsa-87".into(), vec![1; 8193]);
    assert_err(sb.send(&sb.relayer, &account, vec![call("recover", recover_args(&huge))]), "key too long");
}
