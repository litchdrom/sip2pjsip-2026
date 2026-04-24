# sip2pjsip

A Python utility that converts Asterisk `sip.conf` configuration files to the modern PJSIP format (`pjsip.conf`). Asterisk 13+ deprecates the legacy `chan_sip` channel driver in favour of `res_pjsip`; this tool automates the tedious migration work.

---

## Features

- **Global settings** — parses the `[general]` section for:
  - `externip`, `localnet`
  - `useragent`, `dtmfmode`
  - `bindaddr`, `bindport`
  - `tcpenable`, `tlsenable`
  - TLS options: `tlscertfile`, `tlsprivatekey`, `tlscafile`
- **Transport blocks** — generates:
  - `[transport-udp]` (always)
  - `[transport-tcp]` (when `tcpenable=yes`)
  - `[transport-tls]` (when `tlsenable=yes`, with cert/key/CA paths)
- **Peer / trunk conversion** — each `[peername]` section becomes a set of PJSIP objects:
  - `endpoint` — inherits from a shared `[endpoint-defaults](!)` template
  - `aor` — contact URI for static hosts, `max_contacts` for dynamic peers
  - `outbound_auth` — generated when `secret` + username are present
  - `identify` — IP-based matching for static peers and trunks
  - `acl` — created when `permit`/`deny` rules are present
- **Mapped peer options**:
  - `nat=` → `rtp_symmetric`, `force_rport`, `rewrite_contact`
  - `insecure=` → `rtp_symmetric` / skips outbound auth reference
  - `encryption=` → `media_encryption`
  - `qualify=` → `qualify_frequency` (milliseconds converted to seconds)
  - `callerid=` → `callerid`
  - `outboundproxy=` → `outbound_proxy`
  - `setvar=` (repeated) → `set_var`
  - `mailbox=` → `mailboxes`
  - `busylevel=` → `devicestate_busy_at`
  - `directmedia=` / `canreinvite=` → `direct_media`
  - per-peer `transport=` → named transport reference
- **Registration conversion** — `register =>` lines become PJSIP `registration` + `outbound_auth` blocks, linked to matching peer sections where possible
- **Disabled sections** — commented-out section headers (`; [peername]`) and their associated `register =>` lines are preserved as comments in the output
- **Reusable template** — a `[endpoint-defaults](!)` template is generated from global defaults so individual endpoints stay concise

---

## Requirements

- Python **3.8** or later
- No third-party packages — only the Python standard library (`re`, `dataclasses`, `typing`, `sys`)

---

## Installation

```bash
git clone https://github.com/litchdrom/sip2pjsip-2026.git
cd sip2pjsip-2026
pip install -r requirements.txt   # no-op: stdlib only, listed for completeness
```

---

## Usage

```bash
# Explicit input file, redirect output to new config:
python sip2pjsip.py sip.conf > pjsip.conf

# Defaults to sip.conf in the current working directory:
python sip2pjsip.py
```

---

## Output structure

The generated `pjsip.conf` is organised into clearly labelled sections:

| Section | Description |
|---------|-------------|
| `[transport-udp]` | UDP transport (always present) |
| `[transport-tcp]` | TCP transport (when `tcpenable=yes`) |
| `[transport-tls]` | TLS transport (when `tlsenable=yes`) |
| `[endpoint-defaults](!)` | Shared template inherited by all endpoints |
| `[peername](endpoint-defaults)` | One `endpoint` per peer/trunk |
| `[peername]` (aor) | Address-of-record for the peer |
| `[peername]` (outbound_auth) | Credentials, if a secret is configured |
| `[peername]` (identify) | IP-matching block for static peers |
| `[peername_acl]` | ACL rules, if permit/deny are configured |
| `[peername_reg]` | Registration block (from `register =>` lines) |

---

## Limitations / Notes

- **Manual review is strongly recommended** before deploying the generated config in production.
- Not every `sip.conf` option has a direct PJSIP equivalent; unsupported options are silently ignored.
- Complex `insecure=` combinations or custom codec negotiation may require additional hand-tuning.
- The script assumes well-formed `sip.conf` input; heavily non-standard files may produce incomplete output.
- PJSIP configuration is split across multiple object types (`endpoint`, `aor`, `auth`, etc.) — the generated file reflects this; importing it as-is requires Asterisk 13+.

---

## License

MIT
