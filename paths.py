"""ANONCHAIN path resolver — works from any CWD, any user, any install."""
import os, sys, shutil
from pathlib import Path

APP = "anonchain"

def _env_home():
    """Respect ANONCHAIN_HOME, else XDG, else ~/.anonchain."""
    v = os.environ.get("ANONCHAIN_HOME")
    if v:
        return Path(v).expanduser().resolve()
    xdg = os.environ.get("XDG_CONFIG_HOME")
    if xdg:
        return Path(xdg).expanduser().resolve() / APP
    return Path.home() / f".{APP}"

HOME_DIR    = _env_home()
CONFIG_FILE = HOME_DIR / "config.toml"
DB_FILE     = HOME_DIR / "sessions.db"
LOG_DIR     = HOME_DIR / "logs"
PROXY_FILE  = HOME_DIR / "proxy.txt"
WORKING_FILE= HOME_DIR / "working_proxies.txt"
PORT_FILE   = Path("/tmp") / f"{APP}.{os.getuid()}.port"
LOCK_FILE   = HOME_DIR / ".lock"


def ensure_home():
    """Create ~/.anonchain tree with safe perms. Idempotent."""
    HOME_DIR.mkdir(mode=0o700, parents=True, exist_ok=True)
    LOG_DIR.mkdir(mode=0o700, parents=True, exist_ok=True)
    try: os.chmod(HOME_DIR, 0o700)
    except Exception: pass
    try: os.chmod(LOG_DIR, 0o700)
    except Exception: pass


def migrate_legacy():
    """
    If user ran v0.x from a folder with proxy.txt, migrate it.
    Only if home copy doesn't exist yet. Idempotent, non-destructive.
    """
    ensure_home()
    if PROXY_FILE.exists() and PROXY_FILE.stat().st_size > 0:
        return False
    legacy = Path.cwd() / "proxy.txt"
    if legacy.exists() and legacy.resolve() != PROXY_FILE.resolve():
        try:
            shutil.copy2(legacy, PROXY_FILE)
            return True
        except Exception:
            return False
    # create empty file so first run doesn't warn
    if not PROXY_FILE.exists():
        try:
            PROXY_FILE.write_text(
                "# ANONCHAIN proxy list — one ip:port per line\n"
                "# e.g. socks5://user:pass@1.2.3.4:1080\n"
                "# http://5.6.7.8:8080\n")
        except Exception:
            pass
    return False


def resolve_user_path(value, default):
    """
    Accepts absolute, ~-relative, or relative paths.
    Relative → resolved against HOME_DIR, never CWD.
    """
    if value is None:
        return default
    p = Path(str(value)).expanduser()
    if not p.is_absolute():
        p = HOME_DIR / p
    return p.resolve()
