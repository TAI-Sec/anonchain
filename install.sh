#!/usr/bin/env bash
set -e
SRC="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LIB="/usr/local/lib/anonchain"
BIN="/usr/local/bin/anonchain"
MAN="/usr/local/share/man/man1"

PY_FILES=(anonchain.py paths.py chain_engine.py killswitch.py doh.py
          dns_bridge.py tor_manager.py scraper.py health.py profiles.py
          session_db.py netns.py)

for f in "${PY_FILES[@]}" anonchain_preload.c anonchain; do
    [[ -f "$SRC/$f" ]] || { echo "missing $f"; exit 1; }
done

echo "[*] copying python modules → $LIB"
sudo mkdir -p "$LIB" "$MAN"
sudo cp "${PY_FILES[@]/#/$SRC/}" "$LIB/"
sudo cp "$SRC/anonchain" "$BIN"
sudo chmod +x "$BIN" "$LIB/anonchain.py"

if command -v gcc >/dev/null 2>&1; then
    echo "[*] compiling LD_PRELOAD shim"
    sudo gcc -shared -fPIC -O2 -o "$LIB/anonchain_preload.so" \
             "$SRC/anonchain_preload.c" -ldl
    sudo chmod 644 "$LIB/anonchain_preload.so"
else
    echo "[!] gcc missing — LD_PRELOAD disabled (apt install gcc)"
fi

if [[ -f "$SRC/man/anonchain.1" ]]; then
    sudo cp "$SRC/man/anonchain.1" "$MAN/"
    sudo gzip -f "$MAN/anonchain.1"
fi

if [[ -f "$SRC/anonchain.service" ]]; then
    sudo cp "$SRC/anonchain.service" /etc/systemd/system/
    sudo systemctl daemon-reload || true
fi

# --- create per-user home dir for the installing user ---
USER_HOME="${HOME:-/root}/.anonchain"
mkdir -p "$USER_HOME" 2>/dev/null || true
if [[ ! -f "$USER_HOME/proxy.txt" ]]; then
    cat > "$USER_HOME/proxy.txt" <<'EOF'
# ANONCHAIN proxy list — one endpoint per line
# formats accepted:
#   1.2.3.4:8080
#   1.2.3.4:1080
#   socks5://1.2.3.4:1080
#   socks5://user:pass@1.2.3.4:1080
#   http://user:pass@1.2.3.4:8080
EOF
fi

command -v tor >/dev/null 2>&1 || echo "[i] tor not installed (apt install tor)"
command -v iptables >/dev/null 2>&1 || echo "[i] iptables not installed"

echo
echo "[+] ANONCHAIN v1.0 installed"
echo "    home   : $USER_HOME"
echo "    config : $USER_HOME/config.toml"
echo "    proxies: $USER_HOME/proxy.txt"
echo "    TUI    : anonchain"
echo "    Tool   : anonchain curl https://ifconfig.me"
echo "    man    : man anonchain"
