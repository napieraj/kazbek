# TLS material — you supply this

`docker-compose.yml` bind-mounts two files from this directory:

| this directory | in the container | read by |
|---|---|---|
| `glkvm.cer` | `/home/certificate/glkvm_cer` | `xconfig.SslCert` (`xconfig/config.go`) |
| `glkvm.key` | `/home/certificate/glkvm_key` | `xconfig.SslKey` |

**Neither is in the repository, and neither ever should be.** Both are
gitignored. Put your own here, or point the mounts at material you manage
elsewhere.

## Why this is empty

This directory previously shipped a working `glkvm.key` / `glkvm.cer` pair,
inherited from upstream. It was a real 256-bit EC private key with a real
Let's Encrypt certificate for `CN = clanxie.life` (issued 2025-07-28, expired
2025-10-26) — committed to a public repository.

That means every deployment using the shipped default served TLS with a private
key that anyone could read out of the repo. For a product whose premise is that
the trust root is yours, shipping a published private key as the default is the
exact inversion of the claim.

> **The key is permanently compromised.** Deleting it here removes it from the
> working tree, not from git history and not from the public upstream it came
> from. It must be treated as burned, not rotated-and-forgotten. If you deployed
> any glkvm-cloud build using the bundled certificate, replace it and revoke.

## Getting a certificate

For anything real, use a certificate your clients trust — your internal CA, or
Let's Encrypt via a reverse proxy (see `../nginx-reverse-proxy-example.conf`,
and set `REVERSE_PROXY_ENABLED=true` so the app does not also terminate TLS).

For a local test deployment, a self-signed pair:

```sh
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
    -keyout glkvm.key -out glkvm.cer -days 90 -nodes \
    -subj "/CN=$(hostname -f)"
chmod 600 glkvm.key
```

A self-signed certificate is for bring-up only. Device trust in kazbek is
pinned mutual TLS (D-002/D-003), and the pinning ceremony is the provisioning
module's job — not this file.
