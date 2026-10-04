# ANONCHAIN v1.0

**Multi-hop chain proxy interface + tool launcher.**
TUI + real HTTP/SOCKS5/UDP relay + Tor control + DoH DNS bridge + LD_PRELOAD shim + iptables kill-switch + transparent netns mode + proxy scraper + health monitor + profiles + SQLite session log.

```
┌─ ◤ ANONCHAIN ◢ ───────────────────────────────────────┐
│  CONTROLLER   │  SYSTEM          │  CHAIN ▸ RELAY       │
│  probe        │  host, cpu, ram  │  hops, bind, stats   │
│  scrape       │  local/public IP │  doh, tor, health    │
│  build chain  │  uptime, home    │  kill-sw, transparent│
├───────────────┴──────────────────┴──────────────────────┤
│  DEBUGGER · live event stream · kill-switch badge        │
└──────────────────────────────────────────────────────────┘
```

---

## Table of Contents

1. [Overview](#overview)
2. [Features](#features)
3. [Requirements](#requirements)
4. [Installation](#installation)
5. [Quick Start](#quick-start)
6. [TUI Usage](#tui-usage)
7. [Tool Mode](#tool-mode)
8. [Configuration](#configuration)
9. [Emergency Rescue — sos.py](#emergency-rescue--sospy)
10. [Security Model](#security-model)
11. [Troubleshooting](#troubleshooting)
12. [File Locations](#file-locations)
13. [FAQ](#faq)
14. [Uninstall](#uninstall)
15. [License](#license)

---

## Overview

ANONCHAIN turns a list of proxy endpoints into a working multi-hop chain, then lets you run any tool through that chain without modifying the tool.

- **HTTP-aware tools** (`curl`, `dirsearch`, `sqlmap`) → use `HTTP_PROXY` env
- **Non-HTTP tools** (`nmap`, `ssh`, `nc`) → use LD_PRELOAD SOCKS5 shim
- **DNS** → routed through DoH via local bridge (no leaks)
- **Tor** → optional hop or standalone
- **Kill-switch** → iptables whitelist to force egress through proxies
- **Emergency rescue** → `sos.py` resets everything if something breaks

---

## Features

| Category | Feature |
|---|---|
| **Chain** | HTTP CONNECT, SOCKS5, SOCKS5h, mixed multi-hop |
| **Chain** | Automatic failover + latency-based hop selection |
| **Chain** | UDP ASSOCIATE (when first hop is SOCKS5) |
| **DNS** | DoH resolver (Cloudflare, Google, Quad9) with cache |
| **DNS** | Local DNS bridge (127.0.0.1:5353) for system-wide DoH |
| **Tor** | Auto-spawn, control-port NEWNYM, use as chain hop |
| **Preload** | LD_PRELOAD shim: hooks `connect()` + `getaddrinfo()` |
| **Kill-switch** | iptables whitelist, backup + restore, atexit-safe |
| **Transparent** | netns + REDIRECT for tools that ignore env |
| **Scraper** | 6 public proxy sources, parallel validator |
| **Health** | Background monitor, auto-drop dead, hop failover |
| **Profiles** | TOML config, multi-profile save/load |
| **Sessions** | SQLite log, replay, JSON export |
| **UI** | 30fps TUI, animations, no banner |
| **Ops** | systemd unit, Dockerfile, pyproject.toml |
| **Rescue** | sos.py — stdlib-only emergency reset |

---

## Requirements

**OS:** Linux / Unix (POSIX only)

**Mandatory:**
- Python 3.10+
- `python3-pip` (auto-installs `rich`, `requests`, `urllib3`, `psutil`)

**Optional but recommended:**
- `gcc` → LD_PRELOAD shim (non-HTTP tools)
- `iptables` / `ip6tables` → kill-switch
- `tor` → Tor hop
- `iproute2` → transparent mode
- Root access → kill-switch, transparent, ip_forward

---

## Installation

```bash
git clone <repo> anonchain
cd anonchain
chmod +x install.sh anonchain.py sos.py
./install.sh
```

Installs to:
- `/usr/local/lib/anonchain/` — modules + compiled shim
- `/usr/local/bin/anonchain` — launcher
- `~/.anonchain/` — user config, proxies, DB

---

## Quick Start

**Terminal 1 — start the chain:**
```bash
anonchain
```
Inside the TUI:
1. `1` → Probe Proxy Swarm (validates `~/.anonchain/proxy.txt`)
2. `4` → Assemble Chain (starts local relay on `127.0.0.1:9050`)
3. `8` → Start DNS Bridge (starts DoH on `127.0.0.1:5353`)

**Terminal 2 — run anything through the chain:**
```bash
anonchain curl https://ifconfig.me
anonchain dirsearch -u https://example.com
anonchain nmap -sT -Pn scanme.nmap.org
```

That's it. Chain port and env vars are auto-configured.

---

## TUI Usage

### Menu (keyboard: `↑ ↓ Enter`, or number keys)

| # | Action | Notes |
|---|---|---|
| 1 | Probe Proxy Swarm | Parallel validate all proxies in `proxy.txt` |
| 2 | Scrape Fresh Proxies | Fetch + validate from 6 public sources |
| 3 | Persist Working Set | Save passing proxies to `working_proxies.txt` |
| 4 | Assemble Chain | Start local HTTP/SOCKS5 proxy on chosen port |
| 5 | Teardown Chain | Stop the local relay |
| 6 | Toggle Kill-Switch | iptables whitelist (needs root) |
| 7 | Toggle Transparent | netns + REDIRECT (needs root) |
| 8 | Start DNS Bridge | Local DoH server on `127.0.0.1:5353` |
| 9 | Stop DNS Bridge | Stop the local DoH server |
| 10 | Start Tor | Spawn tor, wait for bootstrap |
| 11 | New Tor Circuit | Signal NEWNYM |
| 12 | Stop Tor | Kill tor process |
| 13 | Start Health Monitor | Background health checks |
| 14 | Stop Health Monitor | Stop health thread |
| 15 | New Session | Start a new SQLite session |
| 16 | Export Session | Write current session JSON |
| 17 | Save Profile | Save current chain as a named profile |
| 18 | Load Profile | Load most recent saved profile |
| 19 | Reload proxy.txt | Re-read proxy file from disk |
| 20 | Flush Logs | Clear debugger pane |
| 21 | Open Config Dir | Open `~/.anonchain/` in file manager |
| 22 | Terminate | Exit cleanly (restores all state) |

### Hotkeys (work anywhere in the TUI)

| Key | Action |
|---|---|
| `↑` `↓` | Navigate menu |
| `Enter` | Execute selected item |
| `1-9` | Jump to item 1-9 and run |
| `0` | Jump to item 10 and run |
| `k` | Toggle kill-switch |
| `r` | Reload `proxy.txt` |
| `c` | Clear log |
| `t` | Start Tor |
| `n` | New Tor circuit |
| `q` `Q` `Ctrl+C` | Quit (runs cleanup) |

---

## Tool Mode

`anonchain <command> [args...]` runs `<command>` through the active chain.

### How it works

- Sets `HTTP_PROXY`, `HTTPS_PROXY`, `ALL_PROXY` → HTTP-aware tools
- Sets `LD_PRELOAD` to shim → non-HTTP tools
- Sets `ANONCHAIN_RESOLVE=1` → forces `getaddrinfo()` through local DoH
- Reads port from `/tmp/anonchain.$(id -u).port`

### Examples

```bash
# HTTP-aware
anonchain curl https://ifconfig.me
anonchain wget https://example.com/file.zip
anonchain dirsearch -u https://target.com
anonchain sqlmap -u "http://target/?id=1" --batch

# Non-HTTP-aware (via LD_PRELOAD)
anonchain nmap -sT -Pn scanme.nmap.org
anonchain ssh user@host
anonchain nc -v host 443
anonchain openssl s_client -connect host:443

# Disable LD_PRELOAD for one call
ANONCHAIN_PRELOAD=off anonchain curl https://ifconfig.me

# Override port
ANONCHAIN_PORT=9051 anonchain curl https://ifconfig.me
```

### Environment variables

| Var | Values | Meaning |
|---|---|---|
| `ANONCHAIN_HOME` | path | Override `~/.anonchain` |
| `ANONCHAIN_PORT` | 1-65535 | Chain proxy port |
| `ANONCHAIN_PRELOAD` | `auto` / `on` / `off` | LD_PRELOAD shim control |
| `ANONCHAIN_RESOLVE` | `1` / `0` | Force `getaddrinfo` through DoH |

---

## Configuration

**Location:** `~/.anonchain/config.toml`

```toml
[general]
proxy_file = "/home/user/.anonchain/proxy.txt"
working_file = "/home/user/.anonchain/working_proxies.txt"
workers = 40
local_port = 9050
chain_hops = 3
use_doh = true
use_udp = false
health_interval = 60
auto_scrape = false
auto_failover = true

[tor]
socks_port = 9051
control_port = 9052
auto_start = false

[dns]
bridge_port = 5353
auto_start = true

[killswitch]
auto_arm = false

[netns]
name = "anonchain"
table = "100"

[profiles]
# user profiles saved here
```

### `~/.anonchain/proxy.txt` format

```
# one endpoint per line, # for comments
1.2.3.4:8080
5.6.7.8:1080
socks5://1.2.3.4:1080
socks5://user:pass@1.2.3.4:1080
http://user:pass@5.6.7.8:8080
```

---

## Emergency Rescue — sos.py

**If something breaks** (internet dead, iptables stuck, LD_PRELOAD leaking, process orphaned), run:

```bash
sudo python3 sos.py
```

Interactive menu shows diagnosis, then offers targeted or full rescue.

### Usage

```bash
# Full interactive rescue
sudo python3 sos.py

# Non-interactive full rescue
sudo python3 sos.py --yes

# Diagnose only (no changes)
python3 sos.py --check

# Rescue + remove all user config
sudo python3 sos.py --yes --nuke

# Only one subsystem
sudo python3 sos.py --only iptables
sudo python3 sos.py --only netns
sudo python3 sos.py --only procs
sudo python3 sos.py --only perms
sudo python3 sos.py --only ports
sudo python3 sos.py --only ldpreload

# Restore latest iptables backup
sudo python3 sos.py --restore-backup

# Just test network
python3 sos.py --verify

# Dry run (show what would happen)
sudo python3 sos.py --dry-run
```

### What sos.py resets

| Subsystem | Action |
|---|---|
| **iptables** | Removes `ANONCHAIN` chain from filter + nat, unhooks `OUTPUT` |
| **iptables** | Sets `OUTPUT` policy to `ACCEPT` |
| **ip6tables** | Same, best-effort |
| **ip_forward** | Resets to `0` |
| **Processes** | `SIGTERM` then `SIGKILL` any anonchain/tor processes |
| **Port files** | Removes stale `/tmp/anonchain.*.port` |
| **Permissions** | Fixes `~/.anonchain/` tree to `0700` / `0600` |
| **LD_PRELOAD** | Detects leakage in self + parent + rc files, prints fix |
| **Backups** | Can restore latest `iptables-save` backup |
| **Nuke** | Removes `~/.anonchain/` (backs up `proxy.txt` first) |

### Exit codes

| Code | Meaning |
|---|---|
| 0 | Nothing to do / clean |
| 1 | Rescue done, network verified |
| 2 | Rescue done, network still broken |
| 3 | Usage error |
| 4 | Root required but missing |

### If sos.py itself fails

Nuclear option (last resort):

```bash
sudo iptables -P INPUT ACCEPT
sudo iptables -P FORWARD ACCEPT
sudo iptables -P OUTPUT ACCEPT
sudo iptables -t nat -F
sudo iptables -t nat -X
sudo iptables -F
sudo iptables -X
sudo sysctl -w net.ipv4.ip_forward=0
unset LD_PRELOAD
```

Then reboot.

---

## Security Model

### What's safe

- `paths.py`, `doh.py`, `scraper.py`, `session_db.py`, `profiles.py` → no system modification
- `tor_manager.py`, `health.py` → isolated subprocesses / threads

### What modifies system state

| Module | Modifies | Risk | Mitigation |
|---|---|---|---|
| `killswitch.py` | iptables filter rules | High | Backup + atexit restore + sos.py |
| `netns.py` | iptables nat + `ip_forward` | High | Default off + sos.py |
| `anonchain_preload.c` | Intercepts `connect()`, `getaddrinfo()` | Medium | Loopback short-circuit + `busy` flag |

### Threat model

- **Trusted:** local machine, chain proxy on loopback, user's own proxies
- **Untrusted:** public proxies (`proxy.txt` from scraper)
- **Out of scope:** malware on the host, compromised kernel, physical access

### What anonchain does NOT do

- Does NOT encrypt proxy traffic (TLS is end-to-end if target supports it)
- Does NOT hide metadata from exit proxy (destination, timing, volume)
- Does NOT protect against malicious exit proxies
- Does NOT defeat TLS fingerprinting

### Safe defaults

- Kill-switch: **off**
- Transparent mode: **off**
- Auto-scrape: **off**
- Health monitor: **off**
- LD_PRELOAD: **off** unless launcher is used
- UDP tunnel: **off**

### Recommended

- Run inside a VM for first-time use
- Use Tor as the last hop for anything sensitive
- Do not run banking / email / SSH-key-over-network on public proxies
- Keep `~/.anonchain/` at `0700` perms
- Do not commit `config.toml` / `proxy.txt` to git

---

## Troubleshooting

### Internet dead after using anonchain

```bash
sudo python3 sos.py --yes
```

### `anonchain: command not found`

```bash
cd <anonchain-src>
sudo bash install.sh
```

### `chain not listening on 127.0.0.1:9050`

Start the TUI and pick **Assemble Chain** first.

### Proxies all fail

```bash
anonchain
# menu → Scrape Fresh Proxies
```

### `LD_PRELOAD` messing with `sudo` / new shells

In the affected shell:
```bash
unset LD_PRELOAD
```

If it persists across new shells, check `~/.bashrc` / `~/.zshrc` / `~/.profile` for a line exporting `LD_PRELOAD` and remove it.

### `iptables: Permission denied`

Kill-switch and transparent mode need root. Run TUI with:
```bash
sudo -E anonchain
```

### Tor won't start

```bash
sudo apt install tor
```

### Port 9050 already in use

TUI auto-picks next free port (9051, 9052, …). Or set in `config.toml`.

### Session DB locked

```bash
rm ~/.anonchain/sessions.db-wal ~/.anonchain/sessions.db-shm
```

---

## File Locations

| Path | Purpose |
|---|---|
| `~/.anonchain/` | User home (perms `0700`) |
| `~/.anonchain/config.toml` | Config + profiles |
| `~/.anonchain/proxy.txt` | Proxy source list |
| `~/.anonchain/working_proxies.txt` | Validated proxy list |
| `~/.anonchain/sessions.db` | SQLite session log |
| `~/.anonchain/logs/` | Optional log dumps |
| `/tmp/anonchain.$(id -u).port` | Active chain port |
| `/tmp/anonchain-ipt-*.rules` | iptables backup (removed on disarm) |
| `/usr/local/lib/anonchain/` | Installed modules |
| `/usr/local/bin/anonchain` | Launcher |

---

## FAQ

**Q: Can I use this on Windows / macOS?**
A: No. Linux/Unix only (POSIX, `termios`, `iptables`, `LD_PRELOAD`).

**Q: Do I need root?**
A: Only for kill-switch, transparent mode, and `ip_forward`. Chain and tool mode work as normal user.

**Q: Does it hide my IP from the target?**
A: Yes — the target sees the exit proxy's IP, not yours. But the proxy operator sees your real IP + destination.

**Q: Is my DNS leaked?**
A: Not if you keep the DNS bridge running (starts by default) and set `ANONCHAIN_RESOLVE=1` (default in tool mode).

**Q: Can I use Tor?**
A: Yes. Either as the only hop (safest but slow) or as the last hop of a chain (recommended).

**Q: Can I mix HTTP + SOCKS5 hops?**
A: Yes. `proxy.txt` supports both formats and they chain transparently.

**Q: What if I'm blocked by a captive portal?**
A: Kill-switch will block you. Disable it (`k` in TUI) or run `sos.py`.

**Q: Will this survive reboot?**
A: iptables rules do not survive reboot by default. `~/.anonchain/` persists. systemd unit is optional.

**Q: Where are the logs?**
A: In-memory (`deque`, 800 lines) + SQLite (`sessions.db`).

**Q: Can I run two anonchain instances?**
A: Yes, if they use different ports. Set `local_port` in `config.toml`.

**Q: How do I contribute?**
A: Send patches via PR. Keep stdlib-only for `sos.py`.

---

## Uninstall

```bash
sudo bash uninstall.sh       # removes /usr/local/{lib,bin}/anonchain
rm -rf ~/.anonchain          # removes user config (manual)
```

---

## License

MIT.
