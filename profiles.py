"""ANONCHAIN profiles — TOML config, portable paths, profiles."""
import threading
from pathlib import Path
import paths as _p
from paths import (
    HOME_DIR, CONFIG_FILE, LOG_DIR, PROXY_FILE,
    WORKING_FILE, ensure_home, migrate_legacy, resolve_user_path,
)

try:
    import tomli_w as _w
except ImportError:
    _w = None

# ensure tree exists at import time
ensure_home()

DEFAULTS = {
    "general": {
        "proxy_file":   str(PROXY_FILE),
        "working_file": str(WORKING_FILE),
        "log_dir":      str(LOG_DIR),
        "workers":      40,
        "local_port":   9050,
        "chain_hops":   3,
        "use_doh":      True,
        "use_udp":      False,
        "health_interval": 60,
        "auto_scrape":  False,
        "auto_failover": True,
    },
    "tor":   {"socks_port": 9051, "control_port": 9052, "auto_start": False},
    "dns":   {"bridge_port": 5353, "auto_start": True},
    "killswitch": {"auto_arm": False},
    "netns": {"name": "anonchain", "table": "100"},
    "profiles": {},
}


class Profiles:
    def __init__(self, on_event=None):
        self.on_event = on_event or (lambda *a, **k: None)
        self._lock = threading.Lock()
        ensure_home()
        self.data = self._load()
        # migrate legacy proxy.txt once
        if migrate_legacy():
            self.on_event("OK", f"migrated proxy.txt → {PROXY_FILE}")

    def _load(self):
        import tomllib
        d = {k: (dict(v) if isinstance(v, dict) else v) for k, v in DEFAULTS.items()}
        if CONFIG_FILE.exists():
            try:
                with open(CONFIG_FILE, "rb") as f:
                    loaded = tomllib.load(f)
                for k, v in loaded.items():
                    if isinstance(v, dict) and isinstance(d.get(k), dict):
                        d[k].update(v)
                    else:
                        d[k] = v
            except Exception as e:
                self.on_event("ERR", f"config load: {e}")
        return d

    def save(self):
        with self._lock:
            try:
                if _w:
                    with open(CONFIG_FILE, "wb") as f:
                        _w.dump(self.data, f)
                else:
                    with open(CONFIG_FILE, "w") as f:
                        self._write_toml(f, self.data)
                return True
            except Exception as e:
                self.on_event("ERR", f"config save: {e}")
                return False

    @staticmethod
    def _write_toml(f, d, prefix=""):
        for k, v in d.items():
            if isinstance(v, dict):
                f.write(f"\n[{prefix}{k}]\n")
                Profiles._write_toml(f, v, f"{prefix}{k}.")
            else:
                f.write(f"{k} = {v!r}\n")

    def get(self, section, key, default=None):
        return self.data.get(section, {}).get(key, default)

    def get_path(self, section, key, fallback):
        """Always return absolute Path inside HOME_DIR."""
        raw = self.get(section, key, None)
        return resolve_user_path(raw, fallback)

    def set(self, section, key, value):
        self.data.setdefault(section, {})[key] = value

    def list_profiles(self):
        return list(self.data.get("profiles", {}).keys())

    def save_profile(self, name, chain_strings, hops, notes=""):
        self.data.setdefault("profiles", {})[name] = {
            "chain": list(chain_strings), "hops": hops, "notes": notes,
        }
        return self.save()

    def load_profile(self, name):
        return self.data.get("profiles", {}).get(name)

    def delete_profile(self, name):
        if name in self.data.get("profiles", {}):
            del self.data["profiles"][name]
            return self.save()
        return False
