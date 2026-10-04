#!/usr/bin/env bash
set -e
sudo rm -rf /usr/local/lib/anonchain
sudo rm -f /usr/local/bin/anonchain
sudo rm -f /usr/local/share/man/man1/anonchain.1.gz
sudo rm -f /etc/systemd/system/anonchain.service
sudo systemctl daemon-reload || true
echo "[+] uninstalled. User config kept at ~/.anonchain/"
