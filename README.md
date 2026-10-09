# NEAR Recovery Registry

Commit today, from any key `K`, to a hidden recovery key `R`. If `K`'s
cryptography breaks later (quantum or classical), the commitment, signed while
only the owner held `K`, still identifies the true owner.

> Requires protocol 2.14 (v87: `0u` accounts, `ml_dsa_verify`). Testnet first.

## How it works

Each key `K` has exactly one registry account, a `0u` (NEP-655) account derived from the **v0** init:

```
id(K) = 0u...( UniversalStateInit::V1 { code: AccountId("v0.recover"), data: {"k": hash(K)}, access_keys: {} } )
hash(key) = sha256("<scheme>:" ‖ raw key bytes)
```

- **register:** `K` signs `hash(R)`, and anyone can submit it. It's stored with `registered_at = block height`.
- **update:** the committed `R` signs a new commitment. `K` can never change anything.
- **recover:** reveal `R`. No signature is needed, because R's authority is exercised by whoever consumes the record. It emits an event and deletes the account.

The design has no cross-contract calls, no storage deposit (zero-balance accounts), and spreads across shards automatically.

## Schemes

Keys and signatures are passed as `"<scheme>:<base64>"`. The contract never sees a commitment's scheme: it only receives the hash. It checks scheme names only on keys that are passed in clear.

- **Verified on-chain:** `ed25519`, `secp256k1`, `ml-dsa-65`. These are the schemes `K` can use and `R` can sign with in update and upgrade. The contract checks their key and signature lengths.
- **Revealed by `recover`:** any scheme named `[a-z0-9-]{1,32}` with a key up to 8 KiB. Revealing is just showing a preimage, so a nonstandard name must never make a commitment unrevealable.

Clients must use the canonical names below when creating commitments, because that's the only place a misspelling can be caught:

| Scheme | Public key (bytes) |
|---|---|
| `ed25519` / `secp256k1` / `ml-dsa-65` | 32 / 64 / 1952 |
| `ml-dsa-44` / `ml-dsa-87` | 1312 / 2592 |
| `slh-dsa-{sha2,shake}-128s` / `slh-dsa-{sha2,shake}-256s` | 32 / 64 |
| `fn-dsa-512` / `fn-dsa-1024` | 897 / 1793 |
| `lms` (HSS, RFC 8554) | 52 or 60 |
| `xmss` / `xmssmt` (RFC 8391) | 52 or 68 |

## Signed messages

NEP-413 payload with `recipient: "recover"`, where the message is `NEAR recovery: <action> <0u account> commitment <hex>`
and `<action>` is `register on v<N>`, `update` or `upgrade to v<N>`.

## Versions

- `recover` is a DAO-controlled top-level account. Each version is an immutable, keyless `v<N>.recover` that publishes its code as a global contract.
- `upgrade(N, auth)` makes the instance switch its own code to `v<N>.recover` and call the new version's `migrate` in the **same receipt**. If `migrate` fails, the switch is rolled back. Every upgrade is authorized and **verified by the new version**:
  - An empty instance registers there, signed by `K` for `register on v<N>`. New users join any version in one transaction, `[init(v0), upgrade(N, register)]`, and nobody else can choose the version for someone else's key.
  - A registered instance rotates there, signed by `R` for `upgrade to v<N>`. Schemes that only later versions can verify are therefore usable, and revealing `R` always comes with a fresh commitment.
- **Lock:** once the DAO stops publishing versions, the set of versions is final. DAO keys can be broken too.

## Rules for consumers

1. Derive `id(K)` yourself. Never trust another account just because its data contains `k = hash(K)`: anyone can create one with their own access keys.
2. Trust only entries whose `registered_at` predates the break.
3. The first `recover` event for `K` is final. Re-registration after `recover` is possible but always later.

`recover` retires `K`: anything still controlled only by `K` afterwards is unprotected.

## Future work

- A ZK proof of knowing `R` instead of revealing it, to stop mempool front-running of update and upgrade when `R` is an ECC key.
- On-chain verification of the commit-only schemes, in later versions.

## Build and test

```sh
cd contract
cargo near build non-reproducible-wasm --no-abi --out-dir ../target/near/v0                     # Rust 1.86
RECOVER_VERSION=1 cargo near build non-reproducible-wasm --no-abi --out-dir ../target/near/v1   # test v1
(cd ../../nearcore && cargo build -p neard --features sandbox --profile dev-release)
(cd ../e2e && cargo test -- --nocapture)
```
