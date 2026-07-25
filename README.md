# codex-egress-relay

Single-process identity + TLS/H2 fingerprint layer that makes an arbitrary
client's request to a Codex Responses upstream **byte-for-byte indistinguishable
from a genuine Codex CLI turn**.

```
client (anything) → codex-egress-relay :18092 → upstream (Codex Responses API)
```

It replaces the former two-process chain (FastAPI identity proxy → Rust rustls
relay) with one binary: identity synthesis and rustls egress in the same
process, removing a loopback HTTP hop.

## Why it exists

A public Codex relay guards its endpoint with a **client-identity gate** that
rejects anything not recognizable as a real Codex CLI. Bypassing it requires
matching the real client on two independent wire dimensions:

1. **TLS/H2 fingerprint** — the ClientHello and HTTP/2 settings must match.
2. **Request identity** — headers *and* a body field the gate validates.

This relay reproduces both, verified against a captured interactive Codex CLI
v0.145.0 session and a live upstream gate.

## Design principle: replicate, do not over-cover

The goal is to be **indistinguishable** from a real Codex CLI, not to send "as
much as possible." That means:

- **What the real client sends → send it,** canonically, exactly once.
- **What the real client does NOT send → never send it.** Any extra header or
  field is itself a spoofing tell a deep-inspection gate can key on.

Concretely: `version` and `conversation_id` are deliberately never emitted, and
the injected body `client_metadata` mirrors the real 6-field shape rather than
only the single field the current gate checks. Over-covering is a liability,
not free insurance.

## The two camouflage layers

### 1. TLS fingerprint (`tls.rs`)

rustls 0.23 + **aws-lc-rs** (NOT ring) + the h2 crate.

```
JA4    : t13d1011h2_61a7ad8aa9b6_f9531d972513
Akamai : 2:0;4:2097152;5:16384;6:16384|5177345|0|m,s,a,p
```

The reqwest `rustls-tls` feature pulls the **ring** provider, whose default
signature_algorithms set is missing `ecdsa_secp521r1_sha512` (0x0603). That one
missing sigalg was the ONLY byte that differed in the JA4's third segment.
aws-lc-rs advertises 0x0603, so the full sigalg set — and the JA4 — matches the
real client exactly. We build the rustls `ClientConfig` ourselves with the
aws-lc-rs provider and inject it via `use_preconfigured_tls`, using the
reqwest `*-no-provider` feature so ring is never linked.

ALPN offers `h2` then `http/1.1`, keeping the JA4 ALPN marker `h2` and
negotiating HTTP/2. `http2_prior_knowledge` is intentionally NOT enabled (it
would send h2c and drop the TLS ALPN handshake the fingerprint depends on).

### 2. Request identity (`identity.rs`)

A turn's identity spans two wire layers, both **projections of one
`ResolvedIdentity`** resolved once per request — so the header layer and the
body layer can never drift apart:

- **Headers** — `user-agent`, `originator`, `session-id`, `thread-id`,
  `x-client-request-id`, `x-codex-window-id`, `x-codex-installation-id`,
  `x-codex-beta-features`, `x-codex-turn-metadata`, `accept-encoding`. Client
  casing variants are dropped first (dedup), then each canonical header is set
  exactly once.
- **Body `client_metadata`** — empirically the **sole field the upstream gate
  validates**: it checks that `client_metadata.x-codex-installation-id` is
  present. The relay injects a full, real-shaped `client_metadata` into a bare
  JSON body that lacks one.

**Preserve vs. synthesize:**

- A *genuine* Codex CLI (UA/originator start with `codex-`/`codex_`, or it
  already carries the field) is preserved untouched — its headers pass through,
  and a body that already has `client_metadata` is left byte-for-byte intact.
- Any other client gets a full, session-coherent identity synthesized:
  `session-id`, `thread-id`, `x-client-request-id`, `x-codex-window-id` and the
  turn-metadata all derive from ONE session UUID, `window-id = "<session>:0"`,
  and a matching `client_metadata` is injected into the JSON body.

**Body safety:** only a parseable `application/json` object missing
`client_metadata` is modified. Non-JSON, unparseable, or non-object bodies pass
through untouched, so non-Responses traffic is never corrupted.

## Configuration (environment)

Only `CODEX_PROXY_UPSTREAM_URL` is required; everything else defaults to values
captured from a real Codex CLI v0.145.0 session.

| Env var                        | Default                              | Purpose |
|--------------------------------|--------------------------------------|---------|
| `CODEX_PROXY_UPSTREAM_URL`     | (required)                           | Upstream base, e.g. `https://new.sharedchat.cc/codex` |
| `CODEX_PROXY_PORT`             | `18092`                              | Listen port |
| `CODEX_PROXY_UA_VERSION`       | `0.145.0`                            | Codex version in the synthesized UA |
| `CODEX_PROXY_ORIGINATOR`       | `codex-tui`                          | `originator` header + UA token |
| `CODEX_PROXY_UA_OS`            | `Debian 12.0.0; x86_64`              | OS string in the UA |
| `CODEX_PROXY_UA_TERMINAL`      | `unknown`                            | Terminal token in the UA |
| `CODEX_PROXY_USER_AGENT`       | derived from the above               | Full UA override |
| `CODEX_PROXY_BETA_FEATURES`    | `remote_compaction_v2`               | `x-codex-beta-features` |
| `CODEX_PROXY_INSTALLATION_ID`  | random uuid (stable per process)     | `x-codex-installation-id` |
| `CODEX_PROXY_ACCEPT_ENCODING`  | `gzip, deflate`                      | Forced accept-encoding (never leak br/zstd) |
| `CODEX_PROXY_TIMEOUT`          | `120`                                | Upstream timeout (seconds) |
| `CODEX_PROXY_MAX_BODY_BYTES`   | `10485760` (10 MiB)                  | Buffered request-body ceiling |

Runtime config lives in `relay.env`; the systemd unit is
`systemd/codex-egress-relay.service`.

## Build, test, run

```sh
cargo build --release        # aws-lc-rs compiles C/asm; needs cmake + a C toolchain
cargo test                   # identity unit tests (header + body projection)
cargo clippy --release       # must be clean

systemctl restart codex-egress-relay   # SIGTERM-clean; restarts in ~0s
curl -s localhost:18092/health
```

`GET /health` reports the effective synthesized identity without needing to
inspect an upstream request. All other paths are reverse-proxied to the fixed
upstream; the response body streams back byte-for-byte (no decompression, so SSE
and any content-encoding pass through untouched).

## Regression methodology (when the gate deepens)

The gate can tighten at any time (any new-api upgrade or channel rewrite is a
trigger). To re-locate what it checks and extend the replica:

1. **Capture two requests** with a full-request logging sink (method + all
   headers in order + body):
   - **A** = a real Codex CLI turn through the relay → the ground-truth request
     that passes the gate.
   - **B** = a bare client (no codex identity) through the relay → what the
     relay currently emits.
2. **Diff A vs. B** to enumerate every field the replica is missing.
3. **Subtractive probe:** starting from a fully-completed request that passes,
   remove one candidate field at a time and hit the live gate. A field whose
   removal flips 200 → 403 is a real gate criterion; everything else is decoy.
4. **Additive confirm:** add back only the minimal necessary set and verify it
   passes.
5. **Extend the replica** in `identity.rs` following the replicate-don't-
   over-cover principle, add a unit test, and re-run the multi-turn e2e check
   (bare client through the relay, N consecutive turns, all 200).

Judge pass/fail by **HTTP status** (200 vs. 403), not by grepping the body —
403 bodies are gzip-compressed and won't match plaintext keywords.

## Scope

This is a thin egress camouflage layer. It does **not** do OAuth, connect to any
official backend, route across tenants/providers, or record a corpus. It relays
to exactly one configured upstream. The upstream URL is fixed by env (no control
header), so the listener only ever reaches that one upstream.

**Security note:** the listener binds `0.0.0.0` with no authentication — it
forwards a valid client `authorization` header straight through. Do not expose
the port beyond the trusted host/network.
