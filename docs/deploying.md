# Deploying fastapi-spnego

Getting SPNEGO/Kerberos working end-to-end has three moving parts: a **service
keytab** on the server, the **app configuration**, and **browser** (or client)
setup. This guide walks each one, plus reverse-proxy and delegation notes and a
troubleshooting table.

## 1. Create a service keytab

Your app authenticates as a *service principal* of the form `HTTP/<fqdn>@REALM`
(e.g. `HTTP/app.example.com@EXAMPLE.COM`). The FQDN is the name **clients use in
the URL**, not necessarily the machine's own hostname.

### Active Directory

On a domain controller (or with RSAT), map the SPN to a service account and
export a keytab:

```powershell
setspn -S HTTP/app.example.com svc-app
ktpass -princ HTTP/app.example.com@EXAMPLE.COM -mapuser svc-app@EXAMPLE.COM ^
       -pass * -crypto AES256-SHA1 -ptype KRB5_NT_PRINCIPAL -out app.keytab
```

### MIT Kerberos

```bash
kadmin -q "addprinc -randkey HTTP/app.example.com@EXAMPLE.COM"
kadmin -q "ktadd -k /etc/app.keytab HTTP/app.example.com@EXAMPLE.COM"
```

Protect the keytab — it is a credential:

```bash
chown app:app /etc/app.keytab && chmod 600 /etc/app.keytab
```

Verify what's inside:

```bash
klist -kte /etc/app.keytab
```

## 2. Configure the app

All settings are read from `SPNEGO_`-prefixed environment variables (see
`fastapi_spnego/config.py`):

```bash
export SPNEGO_HOSTNAME=app.example.com     # FQDN in the SPN (as clients see it)
export SPNEGO_KEYTAB=/etc/app.keytab       # exported as KRB5_KTNAME for GSSAPI
export SPNEGO_ALLOW_DELEGATION=false       # true to capture forwarded TGTs
export SPNEGO_ACCEPT_ANY_PRINCIPAL=false   # true = accept any SPN in the keytab
```

`SPNEGO_HOSTNAME` defaults to the machine's FQDN, which is often **wrong behind a
proxy or in a container** — set it explicitly to the public name.

## 3. Configure the browser (client)

Browsers only send Kerberos tokens to hosts on an allowlist:

- **Chrome / Edge (Linux/macOS):** launch with
  `--auth-server-allowlist="*.example.com"` (older flag: `--auth-server-whitelist`).
  On Windows/domain-joined machines this is usually set via the
  `AuthServerAllowlist` group policy and Internet Options → Local Intranet.
- **Firefox:** open `about:config` and add your host to
  `network.negotiate-auth.trusted-uris` (e.g. `https://app.example.com`). For
  delegation also set `network.negotiate-auth.delegation-uris`.

The client must have a valid TGT (`kinit user@EXAMPLE.COM`, or an AD login).

### curl (handy for testing)

```bash
kinit alice@EXAMPLE.COM
curl --negotiate -u : https://app.example.com/whoami
```

## Behind a reverse proxy

Kerberos binds to the hostname in the SPN, so the name the **client** uses must
match the keytab. Two working setups:

1. **Pin the public name (recommended):** set `SPNEGO_HOSTNAME` to the public FQDN
   and put exactly `HTTP/<public-fqdn>` in the keytab. Make sure the proxy passes
   the original `Host`/`Authorization` headers through unmodified.
2. **Accept any keytab principal:** set `SPNEGO_ACCEPT_ANY_PRINCIPAL=true`. The
   server then accepts whichever SPN the client's ticket targets, as long as it is
   in the keytab. Convenient for multi-SPN or mismatched-name setups — enable it
   only if you trust every principal in the keytab.

Also ensure the proxy does **not** strip the `Authorization` header and does not
buffer/alter the `WWW-Authenticate` response header.

## Credential delegation lifecycle

With `SPNEGO_ALLOW_DELEGATION=true` and a client that forwards its TGT, the
server stores the delegated credentials in a per-user ccache and exposes the
handle:

```python
from fastapi_spnego import ticket_lifetime, cleanup

identity.delegated_ccache          # "FILE:/tmp/fastapi_spnego_ccache/cache_alice_EXAMPLE.COM"
ticket_lifetime(identity.delegated_ccache)   # remaining seconds, or None if gone/expired
```

- **Use it:** set `KRB5CCNAME=<handle>` for an onward Kerberos connection so the
  app acts as the user.
- **Refresh:** every authenticated request re-captures and overwrites the same
  per-user ccache, so the credentials refresh automatically — no extra endpoint.
- **Clean up on logout:** call `cleanup(identity.delegated_ccache)` to remove the
  ccache file when the user's session ends.

Requires the SPN to be flagged *trusted for delegation* (AD: "Trust this computer
for delegation"; MIT: `+ok_as_delegate`) and the client to opt in.

## Troubleshooting

| Symptom | Likely cause |
|---|---|
| `Server HTTP/... not found in Kerberos database` | Client's SPN doesn't match the keytab — check `SPNEGO_HOSTNAME` / the URL FQDN, or use `accept_any_principal`. |
| `No key table entry found for HTTP/...` | Keytab missing that SPN, or `SPNEGO_KEYTAB`/`KRB5_KTNAME` not pointing at it. `klist -kte` to inspect. |
| Browser sends no token (you always get `401`) | Host not on the browser's Negotiate allowlist, or no TGT (`kinit`). |
| `Clock skew too great` | Server and KDC clocks differ by >5 min — sync NTP. |
| Works with `curl` but not the browser | Missing allowlist entry, or the site isn't recognized as Intranet (Windows). |
| `delegated_ccache` is `None` with delegation on | SPN not trusted for delegation, client didn't forward, or the client's TGT isn't forwardable. |
| Single-label host SPN fails | Kerberos appends a trailing dot to single-label names — always use an FQDN. |
