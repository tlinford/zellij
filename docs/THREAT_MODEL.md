# Zellij Relay Threat Model

This document describes what the Zellij relay-based session sharing protects,
what it does not, and how to independently verify the code an app origin serves.
It is intended to be precise rather than reassuring: read the residual-trust
section carefully before sharing a sensitive session.

## Summary

When you share a session, terminal output and control traffic are encrypted
end-to-end between the host (the machine running `zellij`) and each viewer. The
relay is a pure ciphertext transport: it forwards opaque bytes and never holds
the keys needed to read or forge them.

There are three trust tiers, strongest to weakest:

1. Native client (`zellij attach <url>`) — strongest.
2. Browser viewer over a self-hosted/federated relay you control.
3. Browser viewer over a relay operated by someone else.

All tiers protect against third parties and against the relay operator. Only
the native client protects against a malicious *app origin* (the server that
delivers the browser viewer code). See "Residual trust" below.

## What is protected

- **Confidentiality and integrity of session content.** Terminal output and
  control messages are encrypted with per-viewer **AES-256-GCM**. Each viewer
  negotiates its own keys; one viewer's keys cannot read another viewer's frames.
- **Authentication of the shared secret.** Key agreement uses **SPAKE2**, a
  password-authenticated key exchange (PAKE). The link secret (`#k=`) or the
  spoken PIN is the SPAKE2 password. The relay only ever sees opaque SPAKE2
  blobs; it never sees the secret, and it cannot run an offline dictionary
  attack against a high-entropy link secret.
- **Replay and reordering resistance.** AEAD frames are **sequence-bound**: the
  sequence number is mixed into the per-frame nonce, so the relay (or any
  in-path attacker) cannot reorder, drop-and-replay, or splice frames without
  the receiver detecting it.
- **Code/data origin separation.** The relay serves *no* HTML, JS, or wasm. The
  browser viewer code is delivered from a separate **app origin**
  (`https://zellij.online`). The relay (`relay.zellij.online` or a self-hosted
  host) does transport only. A compromised relay therefore cannot inject viewer
  code, because it never serves any.

### The join URL and the fragment

A join link looks like:

```
https://zellij.online/r/<slug>#k=<secret>      # link share: secret in the fragment
https://zellij.online/r/<slug>                 # PIN share: PIN spoken out of band
```

The part after `#` (`#k=<secret>`) is a **URL fragment**. Browsers never
transmit the fragment to any server. The app origin receives only `/r/<slug>`;
the secret stays in the client. The native client parses the same URL form
locally. The relay host is always derived from the app host (`relay.` +
app host; an IP-literal app host is used verbatim) — the link cannot redirect
the connection to a different relay.

## Residual trust, per tier

### Native (`zellij attach`)

Strongest. The crypto runs entirely inside the binary you installed. The native
client **never loads app-origin code** — it does not fetch or execute the
browser viewer. End-to-end encryption therefore holds even against a *fully
malicious relay*: the relay can drop your connection, but it cannot read or
forge session content. Beyond the integrity of the binary you installed, no
additional party is trusted. **Recommended for sensitive sessions.**

### Browser viewer

The browser viewer is ordinary web code: the browser fetches HTML/JS/wasm from
the app origin over TLS and runs it. This is **trust-on-delivery** — the same
trust model as any web application. You are trusting:

- the **app origin** (`zellij.online`) to serve honest code, and
- **TLS** (and therefore any CA and any TLS-terminating CDN in front of the app
  origin) to deliver that code unmodified.

Given honest code, end-to-end encryption holds against third parties and
against the relay in isolation: a malicious relay still cannot read or forge
content, because the keys live in the browser, not the relay.

What it does **not** do: it does **not** cryptographically protect against the
project compelling or compromising its **own app origin**. An app origin that
serves modified viewer code could exfiltrate the secret or plaintext from within
the browser. No web delivery model can prevent this by cryptography alone;
the defenses are operational, not cryptographic:

- **Self-hostable / federated relays** plus **reproducible builds** plus the
  **verification recipe** (below) let you confirm that the bytes the app origin
  served match a published, reproducible release — so a silent code swap is
  detectable.
- Hosting the app origin and the relay under separate operators reduces the
  chance that one party can both serve code and observe traffic.

**CDN note (be honest):** if a CDN terminates TLS for the app origin (e.g.
Cloudflare), that CDN can see and rewrite the bytes it serves and therefore
**joins the app-origin trust set**. Subresource Integrity (SRI) on every
script/style/wasm asset, plus the verification recipe, are what let you *detect*
a tampered or coerced CDN. They do not prevent it; they make it auditable.

#### Two-stage browser delivery (core vs. application bundle)

The browser viewer is split into two tiers with different trust:

- The **handshake core** (`index.html` + `/assets/…`) is unversioned and frozen.
  It runs the PAKE and derives the E2E keys, so something must execute before
  E2E exists: it is irreducibly **trust-on-delivery**, mitigated by being small,
  frozen, URL-pinned, SRI-pinned, reproducible, and verifiable (the recipe
  below). This is the only tier that is purely trust-on-delivery.
- The **application bundle** (`/v/<version>/…`) is verified against a digest the
  **sharer attests over the E2E control channel**. After the PAKE, the core
  sends a `VersionRequest` and the sharer answers — as the first authenticated
  sharer→viewer control frame — with a `VersionAnnounce` carrying its Zellij
  version and a rolled-up `app_bundle_sha384` over the application assets. The
  core fetches `/v/<version>/app-manifest.json`, recomputes the rolled-up digest,
  and refuses unless it equals the attested value; each bundle asset is then
  pinned by its now-authenticated per-asset SRI. A compromised app origin that
  swaps a bundle file is therefore **detected** — the digest or SRI fails and the
  viewer refuses, even though the app origin served the code.

**The relay cannot cause version-confusion.** The version + bundle digest arrive
*inside* the AEAD control channel (`VersionAnnounce`), keyed off the PAKE, not
from any relay-controlled plaintext. The former unauthenticated
`/r/<slug>/info/version` relay endpoint has been **removed entirely**; reconnect
liveness now probes the relay's content-free global `/health` route, whose body
is ignored.

**Failure modes all fail closed:** sharer version not hosted by the app origin
(`/v/<version>/` 404) → "update Zellij", nothing connects; manifest digest ≠
attested digest → refuse; a served asset's bytes ≠ its manifest SRI → the browser
blocks the load → refuse; first control frame is not `VersionAnnounce` → abort.

### Metadata the relay still sees

Even though the relay cannot read content, it observes traffic metadata:

- client **IP addresses**;
- **viewer counts** and connection lifetimes;
- **frame timing and sizes**, including the timing of input frames.

Input-frame timing can leak **keystroke-timing patterns**, which are known to
carry information about what is being typed. **Input padding and timing jitter
are NOT yet implemented** — they are on the roadmap but are not currently a
mitigation. Treat all timing/size metadata as visible to the relay operator.

## Burner / single-use URLs

Single-use or short-lived join URLs are a **leak-containment** convenience: they
limit how long a leaked link is usable. They are **not** an end-to-end security
mechanism and provide no cryptographic protection on their own. Do not treat a
burner URL as a substitute for the protections above.

## Verification recipe

This confirms that the bytes `https://zellij.online` is currently serving match
a specific published release. Each GitHub release publishes a
`RELEASE_HASHES.txt` asset: one `sha256` line per served file (`index.html`,
everything under `assets/`, and the versioned application bundle under
`v/<version>/…`), produced by `cargo x build --app-origin`. A clean rebuild with
the pinned toolchain reproduces these hashes **byte-for-byte**.

### One step

```sh
scripts/verify-app-origin.sh <release-tag>
# e.g.
scripts/verify-app-origin.sh v0.43.0
# against a self-hosted app origin:
scripts/verify-app-origin.sh v0.43.0 https://zellij.example.com
```

It fetches the release's `RELEASE_HASHES.txt`, downloads each listed file from
the live origin, and compares hashes, printing OK/MISMATCH per file and exiting
non-zero on any mismatch or unreachable file.

### Manual equivalent

Fetch the published manifest and check the live origin against it. `index.html`
lives at the origin root (`/`); `assets/...` map directly:

```sh
TAG=v0.43.0
ORIGIN=https://zellij.online

curl -fsSL "https://github.com/zellij-org/zellij/releases/download/$TAG/RELEASE_HASHES.txt" -o RELEASE_HASHES.txt

while read -r want path; do
  [ -n "$path" ] || continue
  url="$ORIGIN/$path"
  [ "$path" = "index.html" ] && url="$ORIGIN/"
  got=$(curl -fsSL "$url" | sha256sum | cut -d' ' -f1)
  if [ "$got" = "$want" ]; then echo "OK    $path"; else echo "MISMATCH $path"; fi
done < RELEASE_HASHES.txt
```

To confirm the published manifest itself corresponds to the source you can read,
check out the tag, install the pinned toolchain (`rust-toolchain.toml`) and the
pinned `wasm-opt`/binaryen version used in CI, run `cargo x build --app-origin
out/`, and diff `out/RELEASE_HASHES.txt` against the published asset. They must
be identical.

A successful run proves the live origin is serving exactly the audited bytes —
**as long as the host does not rewrite content in transit.** Any CDN feature
that mutates bytes (e.g. Cloudflare Rocket Loader, Auto Minify, Email
Obfuscation, Mirage) will break both SRI and this recipe and must be disabled on
the app origin.

## What this model does not claim

- It does **not** claim the browser viewer is cryptographically protected
  against a malicious or coerced app-origin operator. It is not.
- It does **not** claim metadata (IPs, counts, timing, sizes) is hidden from the
  relay. It is not.
- It does **not** claim burner URLs add cryptographic protection. They do not.

For sessions where these residual trusts are unacceptable, use the native client
(`zellij attach`), which removes the app-origin trust entirely.
