#!/usr/bin/env python3
"""
ANONCHAIN SOS — emergency rescue tool.

Resets everything ANONCHAIN touches: iptables chains, netns REDIRECT,
ip_forward, running processes, stale port files, config permissions,
LD_PRELOAD leakage. Works without pip / venv — stdlib only.

Usage:
  python3 sos.py                     # interactive rescue (default)
  sudo python3 sos.py --yes          # auto-confirm full rescue
  python3 sos.py --check             # diagnose only, no changes
  python3 sos.py --yes --nuke        # rescue + remove ~/.anonchain
  python3 sos.py --only iptables     # only one subsystem
  python3 sos.py --only netns
  python3 sos.py --only procs
  python3 sos.py --only perms
  python3 sos.py --only ports
  python3 sos.py --only ldpreload
  python3 sos.py --restore-backup    # restore latest iptables backup
  python3 sos.py --verify            # test network after rescue
  python3 sos.py --dry-run           # show what would happen

Exit codes:
  0  success / no problems found
  1  rescue performed, verify OK
  2  rescue performed, verify FAILED
  3  usage error
  4  root required but missing
"""

import os, sys, re, time, signal, shutil, socket, subprocess, argparse
from pathlib import Path
from datetime import datetime

# ─────────────────────────────────────────────────────────────
#  COLORS
# ─────────────────────────────────────────────────────────────
if sys.stdout.isatty() and os.name == "posix":
    R="\033[31m"; G="\033[32m"; Y="\033[33m"; B="\033[34m"
    M="\033[35m"; C="\033[36m"; W="\033[37m"
    DIM="\033[2m"; BOLD="\033[1m"; RST="\033[0m"
else:
    R=G=Y=B=M=C=W=DIM=BOLD=RST=""

def _c(color, text): return f"{color}{text}{RST}"

# ─────────────────────────────────────────────────────────────
#  LOGGING
# ─────────────────────────────────────────────────────────────
class Log:
    def __init__(self):
        self.records = []
        self.start = time.time()

    def add(self, level, msg):
        ts = datetime.now().strftime("%H:%M:%S")
        icon = {"OK":"✔","WARN":"⚠","ERR":"✘","INFO":"•","DBG":"·"}.get(level, "?")
        col  = {"OK":G,"WARN":Y,"ERR":R,"INFO":C,"DBG":DIM}.get(level, W)
        line = f"{DIM}{ts}{RST} {col}{icon}{RST}  {msg}"
        print(line)
        self.records.append((level, msg))

    def ok(self, m):    self.add("OK", m)
    def warn(self, m):  self.add("WARN", m)
    def err(self, m):   self.add("ERR", m)
    def info(self, m):  self.add("INFO", m)
    def dbg(self, m):   self.add("DBG", m)

    def count(self, level):
        return sum(1 for l, _ in self.records if l == level)

log = Log()

# ─────────────────────────────────────────────────────────────
#  UTILITIES
# ─────────────────────────────────────────────────────────────
def run(cmd, timeout=10, input_text=None, dry=False):
    if dry:
        log.dbg(f"[dry] would run: {' '.join(cmd)}")
        return 0, "", ""
    try:
        r = subprocess.run(cmd, capture_output=True, text=True,
                           timeout=timeout, input=input_text)
        return r.returncode, r.stdout, r.stderr
    except FileNotFoundError:
        return 127, "", f"command not found: {cmd[0]}"
    except subprocess.TimeoutExpired:
        return 124, "", "timeout"
    except Exception as e:
        return 1, "", str(e)

def has(name):
    return shutil.which(name) is not None

def is_root():
    return os.geteuid() == 0

def sudo_hint():
    if not is_root():
        log.warn(f"run with {BOLD}sudo{RST}{Y} for full rescue (some parts skipped)")

def header(title):
    print()
    print(_c(BOLD, f"━━ {title} ") + _c(DIM, "━" * max(0, 60 - len(title))))

def banner():
    print(_c(C, "╔" + "═" * 62 + "╗"))
    print(_c(C, "║") + _c(BOLD, "  ◤ ANONCHAIN SOS ◢  ").ljust(62 + len(BOLD) + len(RST)) + _c(C, "║"))
    print(_c(C, "║") + _c(DIM, "  emergency rescue · system + network + configs").ljust(62 + len(DIM) + len(RST)) + _c(C, "║"))
    print(_c(C, "╚" + "═" * 62 + "╝"))
    print()

# ─────────────────────────────────────────────────────────────
#  DIAGNOSE
# ─────────────────────────────────────────────────────────────
def find_iptables_backups():
    out = []
    for d in (Path("/tmp"), Path.home() / ".anonchain"):
        if not d.exists(): continue
        try:
            for f in d.glob("anonchain-ipt-*.rules"):
                out.append(f)
        except Exception:
            pass
    return sorted(out, key=lambda p: p.stat().st_mtime, reverse=True)

def iptables_chain_state(table, chain):
    """Return ('active','hooked') tuple."""
    if not has("iptables"): return False, False
    rc, out, _ = run(["iptables", "-t", table, "-S", chain])
    active = rc == 0 and out.strip() != ""
    rc2, _, _ = run(["iptables", "-t", table, "-C", "OUTPUT", "-j", chain])
    hooked = rc2 == 0
    return active, hooked

def find_anonchain_procs():
    out = []
    if has("pgrep"):
        for pat in ("anonchain.py", "anonchain-tor", "anonchain_preload"):
            rc, o, _ = run(["pgrep", "-af", pat])
            if rc == 0:
                for line in o.strip().splitlines():
                    parts = line.split(None, 1)
                    if parts and parts[0].isdigit():
                        out.append((int(parts[0]), parts[1] if len(parts) > 1 else ""))
    if not out:
        try:
            for p in Path("/proc").iterdir():
                if not p.name.isdigit(): continue
                try:
                    cmd = (p / "cmdline").read_bytes().replace(b"\0", b" ").decode(errors="ignore")
                    if "anonchain" in cmd and "sos.py" not in cmd:
                        out.append((int(p.name), cmd))
                except Exception: pass
        except Exception: pass
    # dedupe
    seen, uniq = set(), []
    for pid, cmd in out:
        if pid in seen: continue
        seen.add(pid); uniq.append((pid, cmd))
    return uniq

def diagnose():
    d = {}
    # iptables
    d["ipt_filter"] = iptables_chain_state("filter", "ANONCHAIN")
    d["ipt_nat"]    = iptables_chain_state("nat", "ANONCHAIN")
    # ip_forward
    d["ip_forward"] = None
    if has("sysctl"):
        rc, out, _ = run(["sysctl", "-n", "net.ipv4.ip_forward"])
        if rc == 0: d["ip_forward"] = out.strip()
    # processes
    d["procs"] = find_anonchain_procs()
    # port files
    d["port_files"] = list(Path("/tmp").glob("anonchain.*.port")) if Path("/tmp").exists() else []
    # backups
    d["backups"] = find_iptables_backups()
    # perms
    home = Path.home() / ".anonchain"
    d["home"] = home
    d["home_exists"] = home.exists()
    d["home_perm"] = oct(home.stat().st_mode & 0o777) if home.exists() else None
    # LD_PRELOAD
    d["ldpreload_self"] = os.environ.get("LD_PRELOAD", "")
    d["ldpreload_parent"] = ""
    try:
        ppid = os.getppid()
        env = Path(f"/proc/{ppid}/environ").read_bytes()
        for kv in env.split(b"\0"):
            if kv.startswith(b"LD_PRELOAD="):
                d["ldpreload_parent"] = kv.split(b"=", 1)[1].decode(errors="ignore")
                break
    except Exception:
        pass
    # network
    d["dns_ok"] = False
    try:
        socket.gethostbyname("one.one.one.one"); d["dns_ok"] = True
    except Exception: pass
    d["tcp_ok"] = False
    try:
        s = socket.create_connection(("1.1.1.1", 443), timeout=4); s.close()
        d["tcp_ok"] = True
    except Exception: pass
    return d

def print_diag(d):
    header("DIAGNOSIS")
    def row(label, val, color=W):
        print(f"  {DIM}{label:<22}{RST}  {color}{val}{RST}")

    active, hooked = d["ipt_filter"]
    row("filter/ANONCHAIN",
        "active" if active else "clean",
        Y if active else G)
    row("filter/OUTPUT hook", "hooked" if hooked else "clean", Y if hooked else G)
    active, hooked = d["ipt_nat"]
    row("nat/ANONCHAIN",
        "active" if active else "clean",
        Y if active else G)
    row("nat/OUTPUT hook", "hooked" if hooked else "clean", Y if hooked else G)

    if d["ip_forward"] is not None:
        row("ip_forward", d["ip_forward"],
            Y if d["ip_forward"] == "1" else G)

    row("anonchain procs",
        f"{len(d['procs'])} running" if d["procs"] else "none",
        Y if d["procs"] else G)

    row("stale port files",
        f"{len(d['port_files'])}" if d["port_files"] else "none",
        Y if d["port_files"] else G)

    row("iptables backups",
        f"{len(d['backups'])} found" if d["backups"] else "none",
        C if d["backups"] else G)

    row("~/.anonchain", "exists" if d["home_exists"] else "missing",
        G if d["home_exists"] else DIM)
    if d["home_perm"]:
        row("  permissions", d["home_perm"],
            G if d["home_perm"] == "0o700" else Y)

    lp = d["ldpreload_self"] or d["ldpreload_parent"]
    row("LD_PRELOAD",
        (lp[:48] + "…") if len(lp) > 48 else (lp or "clean"),
        Y if "anonchain" in lp else G)

    row("DNS resolution", "works" if d["dns_ok"] else "FAILED",
        G if d["dns_ok"] else R)
    row("TCP egress",     "works" if d["tcp_ok"] else "FAILED",
        G if d["tcp_ok"] else R)
    return d

def diagnose_issues(d):
    """Return list of (level, msg) for problems."""
    issues = []
    if d["ipt_filter"][0] or d["ipt_filter"][1]:
        issues.append(("WARN", "iptables filter chain ANONCHAIN is present"))
    if d["ipt_nat"][0] or d["ipt_nat"][1]:
        issues.append(("WARN", "iptables nat chain ANONCHAIN is present"))
    if d["ip_forward"] == "1":
        issues.append(("WARN", "ip_forward is 1 (leftover from netns mode)"))
    if d["procs"]:
        issues.append(("WARN", f"{len(d['procs'])} anonchain process(es) running"))
    if d["port_files"]:
        issues.append(("INFO", f"{len(d['port_files'])} stale /tmp port files"))
    if d["home_exists"] and d["home_perm"] and d["home_perm"] != "0o700":
        issues.append(("WARN", f"~/.anonchain perms are {d['home_perm']} (should be 0o700)"))
    if "anonchain" in (d["ldpreload_self"] + d["ldpreload_parent"]).lower():
        issues.append(("WARN", "LD_PRELOAD is leaking anonchain shim"))
    if not d["dns_ok"] or not d["tcp_ok"]:
        issues.append(("ERR", "network is currently broken"))
    return issues

# ─────────────────────────────────────────────────────────────
#  RESCUE FUNCTIONS
# ─────────────────────────────────────────────────────────────
def rescue_iptables(dry=False):
    header("RESCUE · iptables")
    if not has("iptables"):
        log.warn("iptables not installed — skip")
        return

    changed = False
    for table in ("filter", "nat"):
        # unhook
        rc, _, _ = run(["iptables", "-t", table, "-C", "OUTPUT", "-j", "ANONCHAIN"], dry=dry)
        if rc == 0:
            run(["iptables", "-t", table, "-D", "OUTPUT", "-j", "ANONCHAIN"], dry=dry)
            log.ok(f"removed OUTPUT hook [{table}/ANONCHAIN]")
            changed = True
        # flush + delete chain
        rc, _, _ = run(["iptables", "-t", table, "-L", "ANONCHAIN"], dry=dry)
        if rc == 0:
            run(["iptables", "-t", table, "-F", "ANONCHAIN"], dry=dry)
            run(["iptables", "-t", table, "-X", "ANONCHAIN"], dry=dry)
            log.ok(f"deleted chain [{table}/ANONCHAIN]")
            changed = True
        # ensure ACCEPT default for OUTPUT (only filter table)
        if table == "filter":
            rc, out, _ = run(["iptables", "-t", "filter", "-S", "OUTPUT"], dry=dry)
            if rc == 0 and "-P OUTPUT ACCEPT" not in out:
                run(["iptables", "-t", "filter", "-P", "OUTPUT", "ACCEPT"], dry=dry)
                log.ok("set filter/OUTPUT policy to ACCEPT")
                changed = True

    # IPv6 (best effort, silently ignore failures)
    if has("ip6tables"):
        for table in ("filter", "nat"):
            try:
                run(["ip6tables", "-t", table, "-D", "OUTPUT", "-j", "ANONCHAIN"],
                    dry=dry, timeout=5)
                run(["ip6tables", "-t", table, "-F", "ANONCHAIN"],
                    dry=dry, timeout=5)
                run(["ip6tables", "-t", table, "-X", "ANONCHAIN"],
                    dry=dry, timeout=5)
            except Exception:
                pass
        log.ok("ip6tables cleanup attempted (best-effort)")

    if not changed:
        log.ok("no ANONCHAIN rules found in iptables")

def rescue_netns(dry=False):
    header("RESCUE · netns / ip_forward")
    if not is_root() and not dry:
        log.warn("root required for ip_forward reset — skipping")
        return

    # ip_forward → 0
    if has("sysctl"):
        rc, out, _ = run(["sysctl", "-n", "net.ipv4.ip_forward"], dry=dry)
        if rc == 0 and out.strip() == "1":
            run(["sysctl", "-w", "net.ipv4.ip_forward=0"], dry=dry)
            log.ok("ip_forward disabled")
        else:
            log.ok("ip_forward already 0")

    # NAT REDIRECT cleanup (already done in iptables rescue, keep idempotent)
    if has("iptables"):
        run(["iptables", "-t", "nat", "-D", "OUTPUT", "-j", "ANONCHAIN"], dry=dry)
        run(["iptables", "-t", "nat", "-F", "ANONCHAIN"], dry=dry)
        run(["iptables", "-t", "nat", "-X", "ANONCHAIN"], dry=dry)
        log.ok("nat table cleaned")

def rescue_procs(dry=False, wait=3):
    header("RESCUE · processes")
    procs = find_anonchain_procs()
    if not procs:
        log.ok("no anonchain processes running")
        return
    for pid, cmd in procs:
        try:
            if dry:
                log.dbg(f"[dry] would SIGTERM {pid} ({cmd[:60]})")
                continue
            os.kill(pid, signal.SIGTERM)
            log.ok(f"SIGTERM → PID {pid}  ({cmd[:60]})")
        except ProcessLookupError:
            pass
        except PermissionError:
            log.warn(f"cannot signal PID {pid} (permission — rerun with sudo)")
        except Exception as e:
            log.err(f"kill {pid}: {e}")
    if dry:
        return
    # wait and force-kill leftovers
    time.sleep(wait)
    leftover = find_anonchain_procs()
    for pid, cmd in leftover:
        try:
            os.kill(pid, signal.SIGKILL)
            log.ok(f"SIGKILL → PID {pid}")
        except Exception as e:
            log.warn(f"still alive {pid}: {e}")

def rescue_ports(dry=False):
    header("RESCUE · stale port files")
    tmp = Path("/tmp")
    if not tmp.exists():
        log.ok("no /tmp"); return
    n = 0
    for f in tmp.glob("anonchain.*.port"):
        try:
            if dry:
                log.dbg(f"[dry] would remove {f}")
                n += 1; continue
            f.unlink(); n += 1
            log.ok(f"removed {f}")
        except Exception as e:
            log.warn(f"{f}: {e}")
    if n == 0:
        log.ok("no stale port files")

def rescue_perms(dry=False):
    header("RESCUE · permissions")
    home = Path.home() / ".anonchain"
    if not home.exists():
        log.ok("~/.anonchain missing — nothing to fix")
        return
    targets = [(home, 0o700), (home / "logs", 0o700)]
    for name in ("config.toml", "sessions.db", "proxy.txt",
                 "working_proxies.txt"):
        targets.append((home / name, 0o600))
    for path, mode in targets:
        if not path.exists(): continue
        try:
            cur = path.stat().st_mode & 0o777
            if cur == mode:
                log.ok(f"{path.name:<22} {oct(cur)}  (already)")
                continue
            if dry:
                log.dbg(f"[dry] would chmod {oct(mode)} {path}")
                continue
            os.chmod(path, mode)
            log.ok(f"{path.name:<22} {oct(cur)} → {oct(mode)}")
        except Exception as e:
            log.warn(f"{path}: {e}")

def rescue_ldpreload(dry=False):
    header("RESCUE · LD_PRELOAD")
    lp_self = os.environ.get("LD_PRELOAD", "")
    if "anonchain" in lp_self.lower():
        log.warn(f"this process has LD_PRELOAD={lp_self}")
        log.info("in your shell run:  " + _c(BOLD, "unset LD_PRELOAD"))
    else:
        log.ok("this process LD_PRELOAD is clean")

    # check parent
    try:
        ppid = os.getppid()
        env = Path(f"/proc/{ppid}/environ").read_bytes()
        parent_lp = ""
        for kv in env.split(b"\0"):
            if kv.startswith(b"LD_PRELOAD="):
                parent_lp = kv.split(b"=", 1)[1].decode(errors="ignore")
                break
        if "anonchain" in parent_lp.lower():
            log.warn(f"parent shell has LD_PRELOAD={parent_lp}")
            log.info("in parent shell run:  " + _c(BOLD, "unset LD_PRELOAD"))
        else:
            log.ok("parent shell LD_PRELOAD clean")
    except Exception as e:
        log.dbg(f"cannot read parent env: {e}")

    # scan common rc files
    suspicious = []
    for rc in (".bashrc", ".zshrc", ".profile", ".bash_profile", ".zprofile"):
        p = Path.home() / rc
        if not p.exists(): continue
        try:
            txt = p.read_text(errors="ignore")
            if "anonchain" in txt and "LD_PRELOAD" in txt:
                suspicious.append(p)
        except Exception:
            pass
    if suspicious:
        for p in suspicious:
            log.warn(f"{p} mentions LD_PRELOAD + anonchain — review manually")

def restore_latest_backup(dry=False):
    header("RESTORE · iptables backup")
    backups = find_iptables_backups()
    if not backups:
        log.warn("no backup files found")
        return False
    if not has("iptables-restore"):
        log.err("iptables-restore missing")
        return False
    latest = backups[0]
    log.info(f"using backup: {latest}")
    if dry:
        log.dbg(f"[dry] would run: iptables-restore < {latest}")
        return True
    try:
        with open(latest) as f:
            r = subprocess.run(["iptables-restore"], stdin=f,
                               capture_output=True, text=True, timeout=15)
        if r.returncode == 0:
            log.ok(f"restored from {latest.name}")
            try: latest.unlink()
            except Exception: pass
            return True
        log.err(f"iptables-restore failed: {r.stderr.strip()}")
        return False
    except Exception as e:
        log.err(f"restore: {e}")
        return False

def verify_network(dry=False):
    header("VERIFY · network")
    if dry:
        log.dbg("[dry] skip network verify"); return True
    ok = True

    # DNS
    try:
        socket.gethostbyname("one.one.one.one")
        log.ok("DNS resolution works")
    except Exception as e:
        log.err(f"DNS failed: {e}"); ok = False

    # TCP
    try:
        s = socket.create_connection(("1.1.1.1", 443), timeout=5); s.close()
        log.ok("TCP egress works")
    except Exception as e:
        log.err(f"TCP egress failed: {e}"); ok = False

    # HTTP
    try:
        import urllib.request
        with urllib.request.urlopen("http://api.ipify.org", timeout=6) as r:
            ip = r.read().decode().strip()
        log.ok(f"HTTP egress works · public IP {ip}")
    except Exception as e:
        log.warn(f"HTTP egress: {e}")

    return ok

def nuke_home(dry=False):
    header("NUKE · ~/.anonchain")
    home = Path.home() / ".anonchain"
    if not home.exists():
        log.ok("nothing to remove")
        return
    # safety: back up proxy.txt
    proxy = home / "proxy.txt"
    if proxy.exists() and proxy.stat().st_size > 0:
        backup = Path.home() / "anonchain-proxy-backup.txt"
        try:
            if not dry:
                shutil.copy2(proxy, backup)
            log.ok(f"proxy.txt backed up → {backup}")
        except Exception as e:
            log.warn(f"proxy backup failed: {e}")
    if dry:
        log.dbg(f"[dry] would remove {home}")
        return
    try:
        shutil.rmtree(home)
        log.ok(f"removed {home}")
    except Exception as e:
        log.err(f"rmtree: {e}")

# ─────────────────────────────────────────────────────────────
#  ORCHESTRATION
# ─────────────────────────────────────────────────────────────
def full_rescue(dry=False, nuke=False):
    header("FULL RESCUE")
    if not is_root():
        log.warn("running as non-root — some steps will be skipped")
    rescue_procs(dry=dry)
    rescue_iptables(dry=dry)
    rescue_netns(dry=dry)
    rescue_ports(dry=dry)
    rescue_perms(dry=dry)
    rescue_ldpreload(dry=dry)
    if nuke:
        nuke_home(dry=dry)
    return verify_network(dry=dry)

ONLY_MAP = {
    "iptables":  rescue_iptables,
    "netns":     rescue_netns,
    "procs":     rescue_procs,
    "perms":     rescue_perms,
    "ports":     rescue_ports,
    "ldpreload": rescue_ldpreload,
    "backup":    restore_latest_backup,
    "verify":    verify_network,
}

def interactive(dry=False):
    banner()
    d = diagnose()
    print_diag(d)
    issues = diagnose_issues(d)

    header("FINDINGS")
    if not issues:
        log.ok("no problems found — system is clean")
        print()
        ans = input(f"{C}run verification anyway? [y/N]{RST} ").strip().lower()
        if ans == "y":
            ok = verify_network()
            return 0 if ok else 2
        return 0

    for lvl, msg in issues:
        log.add(lvl, msg)

    print()
    print(_c(BOLD, "  [1]") + "  Full rescue (recommended)")
    print(_c(BOLD, "  [2]") + "  iptables only")
    print(_c(BOLD, "  [3]") + "  netns / ip_forward only")
    print(_c(BOLD, "  [4]") + "  processes only")
    print(_c(BOLD, "  [5]") + "  permissions only")
    print(_c(BOLD, "  [6]") + "  ports + LD_PRELOAD only")
    print(_c(BOLD, "  [7]") + "  Restore iptables backup")
    print(_c(BOLD, "  [8]") + "  Verify network only")
    print(_c(R,    "  [9]") + "  NUKE ~/.anonchain (removes configs)")
    print(_c(DIM,  "  [0]") + "  Exit without changes")
    print()

    try:
        choice = input(f"{C}choose [1]:{RST} ").strip() or "1"
    except KeyboardInterrupt:
        print(); return 0

    if choice == "0":
        print(_c(DIM, "aborted")); return 0
    if choice == "1":
        ok = full_rescue(dry=dry)
        return 1 if ok else 2
    if choice == "2": rescue_iptables(dry);  verify_network(dry); return 1
    if choice == "3": rescue_netns(dry);     verify_network(dry); return 1
    if choice == "4": rescue_procs(dry);     verify_network(dry); return 1
    if choice == "5": rescue_perms(dry);     return 1
    if choice == "6": rescue_ports(dry); rescue_ldpreload(dry); return 1
    if choice == "7": restore_latest_backup(dry); verify_network(dry); return 1
    if choice == "8":
        ok = verify_network(dry); return 1 if ok else 2
    if choice == "9":
        c = input(f"{R}confirm NUKE? type 'YES': {RST}").strip()
        if c != "YES":
            print(_c(DIM, "aborted")); return 0
        full_rescue(dry=dry, nuke=True)
        return 1
    print(_c(R, "invalid choice")); return 3

def summary(rc):
    header("SUMMARY")
    log.ok(f"{log.count('OK')} succeeded")
    if log.count("WARN"): log.warn(f"{log.count('WARN')} warnings")
    if log.count("ERR"):  log.err(f"{log.count('ERR')} errors")
    print()
    if rc == 0:
        print(_c(G, "  ✓ no action needed"))
    elif rc == 1:
        print(_c(G, "  ✓ rescue complete · network verified"))
    elif rc == 2:
        print(_c(Y, "  ⚠ rescue done but network still failing"))
        print(_c(DIM, "    → try: sudo python3 sos.py --nuke"))
        print(_c(DIM, "    → or reboot and reinstall"))
    print()

# ─────────────────────────────────────────────────────────────
#  CLI
# ─────────────────────────────────────────────────────────────
def parse_args():
    p = argparse.ArgumentParser(
        prog="sos.py",
        description="ANONCHAIN emergency rescue tool (stdlib only).",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="Examples:\n"
               "  sudo python3 sos.py                 # interactive\n"
               "  sudo python3 sos.py --yes           # auto-confirm\n"
               "  python3 sos.py --check              # diagnose only\n"
               "  sudo python3 sos.py --yes --nuke    # remove ~/.anonchain\n"
               "  python3 sos.py --only iptables      # one subsystem\n"
               "  sudo python3 sos.py --restore-backup\n")
    p.add_argument("--yes", "-y", action="store_true",
                   help="skip confirmation")
    p.add_argument("--check", action="store_true",
                   help="diagnose only, no changes")
    p.add_argument("--dry-run", action="store_true",
                   help="show what would be done")
    p.add_argument("--nuke", action="store_true",
                   help="rescue + remove ~/.anonchain")
    p.add_argument("--only", choices=list(ONLY_MAP.keys()),
                   help="run only one subsystem")
    p.add_argument("--restore-backup", action="store_true",
                   help="restore latest iptables backup")
    p.add_argument("--verify", action="store_true",
                   help="test network only")
    return p.parse_args()

def main():
    args = parse_args()
    dry = args.dry_run

    # verify only
    if args.verify:
        banner()
        ok = verify_network(dry=False)
        summary(1 if ok else 2)
        return 1 if ok else 2

    # check only
    if args.check:
        banner()
        d = diagnose()
        print_diag(d)
        issues = diagnose_issues(d)
        header("FINDINGS")
        if not issues:
            log.ok("no problems found"); summary(0); return 0
        for lvl, msg in issues:
            log.add(lvl, msg)
        summary(0)
        return 0

    # restore backup
    if args.restore_backup:
        banner()
        restore_latest_backup(dry=dry)
        ok = verify_network(dry=dry)
        summary(1 if ok else 2)
        return 1 if ok else 2

    # only one subsystem
    if args.only:
        banner()
        fn = ONLY_MAP[args.only]
        try:
            fn(dry=dry)
        except TypeError:
            fn()
        if args.only not in ("perms", "ldpreload"):
            ok = verify_network(dry=dry)
            summary(1 if ok else 2)
            return 1 if ok else 2
        summary(1)
        return 1

    # full rescue via flags
    if args.yes:
        banner()
        ok = full_rescue(dry=dry, nuke=args.nuke)
        summary(1 if ok else 2)
        return 1 if ok else 2

    # interactive
    try:
        return interactive(dry=dry)
    except KeyboardInterrupt:
        print()
        print(_c(DIM, "aborted by user"))
        return 0
    except Exception as e:
        print()
        print(_c(R, f"fatal: {e}"))
        import traceback; traceback.print_exc()
        return 3

if __name__ == "__main__":
    sys.exit(main())
