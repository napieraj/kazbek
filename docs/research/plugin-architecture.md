> ## Status: informing, not normative
>
> This document is **research input, not a decision record.** Nothing in it is
> binding on any implementation. A recommendation here becomes a decision only
> when it appears in `docs/modules/plugins.md`, in the plugin contract under
> `contract/plugins/`, or in `DECISIONS.md` — and then that document, not this
> one, is the authority.
>
> **Its factual claims are unverified** (standing rule 1). It is a synthesis of
> external sources, not a security audit, and its own §10 says so. Two claims
> in particular must not be cited in any repo document without independent
> verification. Neither is load-bearing for anything adopted from it:
>
> - **The CVE identifier and its date attribution.** The document caveats this
>   itself, and the identifier's number range is inconsistent with the stated
>   disclosure date.
> - **The HACS download-path internals.** Implementation details of a
>   third-party project are a moving target, and the document says to re-check
>   before quoting.
>
> Where the HACS material is useful, cite the **pattern** — trust-by-listing
> with no artifact verification — and not a source line or a version-specific
> claim about someone else's code.
>
> Triage of this document into what was adopted, what was deferred, and what
> needs measurement first is recorded in `docs/modules/plugins.md`.

---

# Plugin Architecture for a Self-Hosted KVM Fleet: Research & Design Recommendations for kazbek

## TL;DR
- **The Verifier interface is the organizing principle.** Every signing model — hash-only today, single pinned key, threshold multi-sig, keyless/transparency-log, TUF — plugs into the same `Verify(manifest, payload) → ok | reason` hook. The transport, protocol, manifest schema, sidecar runtime, and fleet mechanics are all signing-model-agnostic. Choose the signing model that matches your trust requirements; nothing else has to change.
- **HACS is the anti-pattern to study.** It performs zero cryptographic verification of downloaded artifacts — trust = "the repo is in the curated list." kazbek inverts this: trust the Verify result over the artifact bytes, never the delivery channel.
- **The management-plugin sidecar tier needs out-of-process isolation with a well-defined IPC boundary.** The specific IPC mechanism — gRPC (go-plugin), Unix socket + any framing, WASM component, custom protocol — is a secondary decision. Several viable options are surveyed below; choose based on what the target environment already has, not a framework preference.

---

## 1. Code sharing across local and cloud execution contexts

The dominant portable-artifact pattern in 2026 is **WebAssembly components (WASI Preview 2 + the Component Model)**: the same `wasm32-wasi` artifact runs unchanged in browser, edge/OCI container, and cloud VM, with the host contract expressed as typed WIT imports rather than a vendor SDK. The wasmCloud docs state the runtime "can run as a standalone process on any Linux, macOS, or Windows host — bare metal servers, VMs, IoT gateways, or CI runners. Because components are WASI-standard bytecode, the same artifact deploys identically across all of these environments without recompilation."

The **contract-first principle** is what actually enables code sharing regardless of runtime: define the plugin's host interface once (a gRPC `.proto`, a WIT world, a Go interface, a JSON-RPC schema), and the same plugin binary/module satisfies it whether the host is a per-device daemon or a central server. HashiCorp go-plugin, OPA, and osquery all do this — the plugin implements an interface, and the host decides the execution environment.

**Practical implication for kazbek:** the shared element is the **manifest schema + the Verifier interface + the wire protocol + the invariants** — not any specific runtime. A device-plugin (per-console) and a management-plugin (fleet) can share all of this machinery while differing in the IPC mechanism used at runtime. Signing model plugs into the Verifier; runtime plugs into the sidecar boundary. Neither constrains the other.

---

## 2. HACS — the trust anti-pattern (study in detail)

**Manifest format:** HACS uses a repo-root `hacs.json` with keys `name` (required), `content_in_root`, `zip_release`, `filename`, `hide_default_branch`, `country`, `homeassistant`, `hacs`, and `persistent_directory`. HA's own `manifest.json` additionally requires `domain`, `documentation`, `issue_tracker`, `codeowners`, `name`, and `version`.

**Distribution/loading:** HACS downloads either individual files or a release ZIP from GitHub and unpacks into `custom_components/` or the frontend dir — **arbitrary code execution in the HA process** on install and restart.

**Trust model — the core finding:** HACS performs **no cryptographic signature verification and no checksum/hash verification** of downloaded artifacts. The download path (`custom_components/hacs/base.py`, `async_download_file`) validates only `if request.status == 200` and writes raw bytes to disk; there is no `hashlib`, no GPG, no sigstore in the path. **Trust = repository listing**: a repo is trusted because it appears in the curated `hacs/default` category lists — plain lists of `owner/repo` strings. No key is bound to a repo; inclusion checks validate metadata and ownership, never artifact integrity.

**Security properties it lacks:** no artifact integrity, no author identity/signature, no rollback protection, and no revocation beyond a reactive denylist. The `removed` file is a denylist with `removal_type` values (`archived`, `critical`, etc.); a `critical` entry triggers auto-removal and a persistent warning — allow-by-default, deny-reactively.

**Historical vulnerability:** CVE-2021-47942 (January 2021 HA disclosure) — a directory-traversal/account-takeover flaw via the unauthenticated `/hacsfiles/` webview, allowing an attacker to read `.storage/auth` and forge admin JWTs. An endpoint bug, not supply-chain, but it compounds the fact that a malicious-but-listed repo's code is simply trusted and executed.

**The inversion kazbek should implement:** verify the signature against a pinned key before activating anything. The delivery channel — GitHub, a static server, the pinned-mTLS tunnel, a USB stick — is untrusted plumbing.

---

## 3. Signing models — a spectrum, all plugging into one Verifier

The `Verifier` interface is the seam. All models below plug into it identically; only the implementation changes. The manifest's `signature.model` field tells the Verifier which implementation to invoke.

```
Verifier:
  Verify(manifest, payload) → ok | reason
```

**Fail closed on every model:** if Verify returns any error, do not activate; keep the previous version. This is OPA's exact behavior and is the invariant that makes all models safe regardless of which is chosen.

### 3a. Hash-only (buildable now, zero key management)
Verify that each file's SHA-256 matches the manifest. Integrity without authenticity — you know the bytes weren't corrupted in transit, but not who authored them. The floor for any deployment. Sufficient for a single-operator fleet where the manifest itself arrives over the pinned-mTLS tunnel (which already authenticates the server as kazbek). **Not sufficient** once community plugins or multi-operator deployments are in scope.

### 3b. Single pinned key (first real signing step)

**OPA bundle model — the closest ready-made artifact format:**
A tarball containing `manifest.json` + a detached `signatures.json` (a JWT whose payload is a `files` array — each entry `{name, hash, algorithm}` — plus `keyid`, `scope`, `iat`, `iss`). Verification: (1) verify the JWT signature with an out-of-band pinned public key, (2) verify the payload's file set matches the bundle's file set exactly, (3) verify each file's hash. OPA's `bundle.RegisterVerifier` makes the signing algorithm pluggable — kazbek's Verifier maps to this directly.

**Key algorithm choices, all viable:**
- **Ed25519** — fast, small signatures, excellent library support everywhere
- **ECDSA P-256** — hardware-friendly: plugs into the RV1126B's crypto engine via AF_ALG and into YubiKey PIV slots (PIV slot 9c is the standard signing slot)
- **RSA-PSS** — if interop with existing PKI matters

The Verifier interface hides the choice; swap at config time, not code time.

**Key storage options (all produce a signature the Verifier reads identically):**
- File on disk — low assurance, dev/small self-contained fleet
- YubiKey PIV slot — operator's key, physical presence per sign operation; touch-required on high-consequence artifacts
- YubiHSM / PKCS#11 HSM — unattended server signing, key never leaves hardware
- OpenBao/Vault transit — key never on disk, policy-controlled access, audit log

### 3c. Threshold / multi-sig (2-of-N, for fleet-wide management plugins)
The manifest carries N signatures from different keyids; the Verifier requires at least K to be valid before activating. Defends against a single compromised signing key approving a malicious plugin across the whole fleet. Implementable with the same JWT-per-signer schema (one `signatures.json` entry per signer) or with a separate signatures file. The Verifier counts valid sigs and compares to the threshold from the manifest or from a server-side policy.

**Strongly recommended for the management-plugin tier** given its fleet blast radius — the additional ceremony is proportionate to the blast radius.

### 3d. Keyless / transparency-log (Sigstore/Rekor, for community plugins)
Sigstore's `cosign` signs artifacts without long-lived keys: the signer authenticates via OIDC (GitHub Actions, Google, etc.), gets a short-lived certificate from Fulcio, signs, and the signature + cert is logged to Rekor (an append-only transparency log). The Verifier checks the Rekor inclusion proof and the OIDC identity (`--certificate-identity`, `--certificate-oidc-issuer`).

**Advantages:** no key management for plugin authors, non-repudiation via the log. **Trade-offs:** requires network access to Rekor at verify time (mitigated by a local mirror); the OIDC identity (a GitHub Actions workflow) is the trust anchor, not a hardware key. Suitable for community/device-tier plugins; less appropriate for the management tier where you want hardware-backed curator keys.

### 3e. TUF (mature fleet distribution — borrow the threat model first)
TUF separates signing roles (root, targets, snapshot, timestamp), uses threshold signatures per role, and protects against rollback (monotonic versioned metadata) and freeze (expiring metadata). TUF users include Foundries.io, IBM, VMware, Docker (Notary), and Cloudflare; Uptane (automotive TUF) targets over a third of US-road vehicles.

**Known subtlety:** even mature go-tuf shipped a rollback-protection bug (GHSA-66x3-6cw3-v5gj) — this is subtle to implement correctly.

**Recommendation:** adopt TUF's *threat model* and *disciplines* (digest-named subjects, expiring/versioned signed metadata, role/threshold separation) incrementally. Start with 3b or 3c; add a monotonic `revision` field and expiring manifests early; graduate to full TUF if the plugin ecosystem grows to require it.

### Anti-rollback (mandatory across all models)
Add a `revision` field (monotonic integer) to every manifest. The host rejects any bundle whose `revision` ≤ the installed revision. This closes the freeze/downgrade attack class independent of signing model — implement it in Stage 0 before any signing model is chosen.

---

## 4. Manifest schema

```yaml
name: <string>
version: <semver>                            # human-readable
revision: <integer>                          # monotonic, anti-rollback — mandatory from day 1
tier: device | management                    # blast-radius declaration
model_compat: ">=rm1pe" | "rm4pe" | ...
firmware_compat: ">=<version>"
min_kazbek_version: <semver>
entry: plugins/<type>/<file>
capabilities: [ ... ]                        # explicit allowlist; drives sidecar sandbox
payload:
  sha256: <hash>                             # ALWAYS present, ALWAYS checked
  size: <bytes>
signature:
  model: hash-only | single-key | threshold | keyless | tuf
  entries:                                   # one per signer/keyid; empty under hash-only
    - alg: <ed25519|ecdsa-p256|rsa-pss>
      keyid: <string>
      value: <base64>
  threshold: <integer>                       # for model: threshold; omit otherwise
  expires: <ISO-8601>                        # for expiring metadata; omit otherwise
```

The `signature` block is defined from day one so any model drops in without a schema change. `hash-only` is a valid `model` value that leaves `entries` empty — the block still exists and Verify is still called; it just uses the SHA-256-only path.

---

## 5. Sidecar / out-of-process isolation (management-plugins)

**The requirement is isolation, not a specific IPC mechanism.** A management-plugin crash or compromise must not take down the kazbek control plane or affect the rest of the fleet. The IPC boundary is where capability scope is enforced. The specific framing protocol is secondary — choose based on what the target environment already has.

### Option A: HashiCorp go-plugin (gRPC-over-subprocess)
The host launches the plugin as a subprocess; they communicate over gRPC (HTTP/2 multiplexing). `SecureConfig{Checksum, Hash}` verifies the plugin executable's integrity before exec. `AutoMTLS` generates an ephemeral client cert per launch for mutual TLS on the local connection. Protocol versioning (`VersionedPlugins`) enables hot upgrades without host restart.

**Isolation guarantees:** a plugin panic can't crash the host; the plugin sees only the gRPC interface and its args. Used by Vault, Terraform, Nomad.

**Caveats:** go-plugin does not sandbox the subprocess itself — OS-level confinement is your responsibility. `SecureConfig`'s bare checksum should be wrapped with kazbek's Verifier (signature, not just hash) for consistency. Adds a gRPC dependency on both sides.

**When to choose:** Go codebase on both sides; hot-upgrade semantics matter; team is comfortable with gRPC.

### Option B: Unix domain socket + any framing
Launch the plugin subprocess; it binds a socket path the host provides. Authority enforced by socket permissions (only the kazbek process can connect). Framing can be JSON-RPC, msgpack-RPC, the existing kazbek typed-message framing, or custom. **No additional dependencies**, language-agnostic, simpler than go-plugin.

**When to choose:** plugins may be in Python/Rust/C; you want to minimize the plugin author's dependency footprint; you want to reuse the existing kazbek framing protocol.

### Option C: WASM components (WASI Preview 2)
The plugin is a `.wasm` binary; the host runs a WASM runtime (wasmtime, WasmEdge). Capability isolation is **structural, not configured** — a component without a network WIT import literally cannot open a socket, regardless of any OS-level sandbox. Same artifact runs on both device and server without recompilation.

**Caveats:** adds a WASM runtime dependency; cold-start latency on device; ecosystem younger than gRPC. More compelling if you want one artifact for both tiers or if device architecture portability matters.

**When to choose:** structural capability isolation is a hard requirement; you want one artifact for both device and server plugin tiers.

### Option D: ArgoCD-style sidecar container (if running containerised)
Plugin runs as a sidecar container communicating over a Unix socket. ArgoCD moved plugins out-of-process precisely to fix "security risks from running arbitrary commands inside the repo-server." Appropriate if kazbek itself runs containerised; adds orchestration overhead if not.

### Common to all: OS-level capability enforcement

Regardless of IPC mechanism, generate a per-plugin OS sandbox from the manifest `capabilities`:

```
systemd unit (generated per plugin from manifest):
  User=kazbek-plugin-<name>          # dedicated unprivileged UID
  ProtectSystem=strict
  PrivateTmp=yes
  NoNewPrivileges=yes
  RestrictAddressFamilies=AF_UNIX [AF_INET if net.outbound declared]
  IPAddressAllow=<declared hosts>
  IPAddressDeny=any [if no net.outbound]
  MemoryMax=<from manifest or default>
  CPUQuota=<from manifest or default>
  SeccompFilter=<generated allowlist>
```

A plugin declaring no network capability gets `IPAddressDeny=any` on its systemd unit. The sandbox is derived from the manifest; the subprocess structurally cannot exceed what it declared. If the manifest changes (upgrade), the sandbox regenerates before the new subprocess launches.

### Lifecycle (common to all options)
- Host supervises each sidecar; watches for crash/hang; enforces resource limits
- On crash: **auto-deregister** the plugin's exposed functions immediately; restart with backoff; control plane degrades gracefully rather than blocking
- On upgrade: verify new bundle; start new subprocess; cut traffic over once healthy; stop old one — the kazbek host process never restarts (go-plugin protocol versioning makes this native; for other options, implement a version-negotiation handshake)
- Health-check via whatever the IPC protocol supports

---

## 6. Read-only rootfs plugin installation

**PiKVM/kvmd is the direct precedent.** PiKVM keeps the rootfs read-only by default; the `kvmd-pst` daemon manages a dedicated storage partition that "is mounted in read-only all the time, and remounts it to RW only when some user script requires it — if the daemon stops or any other error occurs, the script will be killed." This gives crash-safe, minimal-RW-window installs.

**Atomic install pattern:**
1. Unpack the bundle into a temp dir on the writable partition (never directly into the live plugin dir)
2. Run `Verify` — fail closed; on any error, clean up temp dir and stop
3. Anti-rollback check: `revision` > installed `revision`; refuse on failure
4. `rename()` temp dir into the live plugin location (atomic on same filesystem), or flip a symlink
5. Keep N previous versions for rollback; delete the oldest
6. Emit `readback`: hash every file in the installed bundle; report to server

**Alternatives for more sophisticated deployments:**
- **OverlayFS** (squashfs lower + persistent upper) for a writable view without remounting
- **OSTree** for content-addressed, A/B atomic deployment with built-in rollback ("a new version is staged completely and verified before anything switches over, then the system flips in a single atomic operation; the previous deployment is kept for rollback")

For v1, the kvmd-pst remount + atomic rename is simpler and directly applicable to the target hardware.

---

## 7. Fleet plugin management prior art

- **OPA + static/OCI store:** pulls signed bundles from any server; verifies locally; the delivery channel is untrusted. Caches by ETag; persists last-good bundle to survive server outages — important for intermittently-connected KVM devices. Digest-pinning is the read-back attestation primitive.
- **Kubernetes OLM:** versioned bundles as OCI images with `replaces`/`skips` expressing the upgrade graph — useful vocabulary for kazbek's version/upgrade metadata.
- **in-toto/SLSA provenance:** the subject names the artifact by content hash (not a mutable tag); the predicate records how/where/when it was built. `gh attestation verify` / `slsa-verifier` implement this. This is the read-back attestation discipline: verify installed digest == pushed/attested digest.
- **Defense-in-depth principle:** kazbek should both refuse to push an unverifiable plugin (server-side) and have each device independently re-verify on receipt. The server verifying is not sufficient.

---

## 8. Assessment — directly usable vs needs adaptation

| Prior art | Directly usable | Needs adaptation |
|---|---|---|
| **OPA bundle format** (`.manifest` + `.signatures.json` JWT; fail-closed activation; pluggable Verifier) | Format + Verifier interface map 1:1 | Add `tier`, `capabilities`, `revision`, `signature.model` field |
| **go-plugin** (gRPC subprocess, `SecureConfig`, `AutoMTLS`, protocol versioning) | **One concrete sidecar option** — not the prescribed one | Wrap `SecureConfig` with Verifier; add OS sandbox; consider alternatives for non-Go plugins |
| **Unix socket + framing** (osquery model) | Simpler sidecar option; language-agnostic | Add Verifier integration; add watchdog/auto-deregister |
| **WASM components** (WASI Preview 2) | Structural capability isolation; one artifact both tiers | Runtime dependency; ecosystem younger than gRPC |
| **PiKVM `kvmd-pst`** | Direct precedent on the actual target platform | Extend for atomic rename + Verify before activation |
| **Sigstore/cosign + in-toto/SLSA** | Read-back attestation discipline; future keyless signing option | Full Sigstore infra heavy for self-hosted v1; digest discipline adoptable now |
| **TUF** | Threat model; rollback/freeze protection disciplines | Full 4-role TUF over-engineered for v1; adopt incrementally |
| **HACS** | Nothing — it is the negative example | — |

---

## 9. Recommendations for the kazbek plugin system

**Stage 0 — lock the contract and the Verifier seam (now, signing-model agnostic):**
1. Define the plugin bundle format (tarball + `manifest.json` + `signatures.json`). Manifest must include: `name`, `version`, `revision` (monotonic, anti-rollback — mandatory from day one), `tier`, `capabilities`, `min_kazbek_version`, per-file SHA-256.
2. Implement the **single `Verifier` interface** and route BOTH the server-push path and the local drop-in path through it without exception. Ship `NoopVerifier` (dev only, never a default) and `HashVerifier` (SHA-256 integrity) now. Stub `SingleKeyVerifier`, `ThresholdVerifier`, `KeylessVerifier`, `TUFVerifier` as interfaces; implement when needed — each plugs in without touching anything else.
3. Make activation **atomic**: unpack → Verify → anti-rollback check → rename/symlink. Keep N previous versions.

**Stage 1 — device-plugins (per-console blast radius):**
4. In-process or per-device child; manifest `capabilities` + OS sandboxing. kvmd-pst-style writable partition; atomic install.

**Stage 2 — management-plugins (fleet blast radius, out-of-process):**
5. Choose a sidecar IPC mechanism based on your stack (go-plugin, Unix socket, WASM component — see §5). **The invariant is out-of-process with a well-defined interface boundary; the protocol is secondary.** Generate the OS sandbox from the manifest `capabilities`.

**Stage 3 — distribution, attestation, fleet ops:**
6. Choose a signing model from §3 appropriate to current trust requirements. Progress: hash-only → single pinned key (Ed25519 or ECDSA-P256) → threshold for management tier. Nothing else changes.
7. Distribute via any store (static, OCI, the pinned-mTLS tunnel). Each device independently re-verifies on receipt — defense in depth.
8. Read-back attestation: device reports installed manifest digest; server asserts installed == pushed; flags drift.
9. Denylist for reactive revocation — defense in depth on top of signature verification, never the primary control.

**Thresholds that would change the plan:**
- Community/third-party plugin authors → threshold or keyless signing + consider TUF
- One artifact for both device and server → WASM components priority over go-plugin
- Devices frequently offline → persist-last-good + expiring metadata before revocation
- Non-Go plugins expected → Unix-socket sidecar over go-plugin

---

## 10. Caveats

- **HACS internals** confirmed against `custom_components/hacs/base.py` source — no crypto in the download path — but HACS evolves; re-check before quoting as current.
- **CVE-2021-47942** is genuine but is an endpoint bug, not a supply-chain bug; post-dated database timestamps are database artifacts, not the incident date.
- **go-plugin's `AutoMTLS`/`SecureConfig`** protect integrity and the local channel, not authorization; OS-level capability confinement is explicitly your responsibility.
- **WASM "same artifact everywhere"** includes vendor marketing; treat as directional.
- **TUF/Sigstore full stacks** are powerful but heavy; borrow their disciplines before adopting the full frameworks.
- This is a design-informing research synthesis, not a security audit; concrete crypto choices (algorithm, key storage, rotation policy) require a dedicated threat model before implementation.
