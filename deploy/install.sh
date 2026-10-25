#!/usr/bin/env bash
# Install or upgrade emerchat as a systemd service.
#
# Fresh install, downloading the latest release:
#   curl -fsSL https://raw.githubusercontent.com/alireza-hariri/emerchat/main/deploy/install.sh \
#     | sudo bash -s -- --domain chat.example.com --nginx
#
# From an extracted release tarball (uses the emerchat binary next to this script):
#   sudo ./install.sh --domain chat.example.com
#
# Upgrade (keeps the existing unit file and its flags, backs up the database first):
#   sudo ./install.sh
set -euo pipefail

REPO=alireza-hariri/emerchat
PREFIX=/usr/local/bin
DATA_DIR=/var/lib/emerchat
UNIT=/etc/systemd/system/emerchat.service
SVC_USER=emerchat

domain=""
base_url=""
listen=127.0.0.1:8080
version=latest
binary=""
with_nginx=0
force_unit=0

usage() {
	cat <<EOF
Usage: install.sh [options]

  --domain NAME     public host name, e.g. chat.example.com (sets base URL and nginx server_name)
  --base-url URL    public URL, if it isn't https://<domain>
  --listen ADDR     address the service listens on (default $listen)
  --version TAG     release to download, e.g. v1.2.0 (default: latest)
  --binary PATH     install this binary instead of downloading one
  --nginx           also install the nginx site config (TLS certs must exist already)
  --force-unit      rewrite the systemd unit even if one exists
  -h, --help        show this help
EOF
}

die() { echo "error: $*" >&2; exit 1; }
log() { echo "==> $*"; }

while [ $# -gt 0 ]; do
	case $1 in
	--domain) domain=${2:?}; shift 2 ;;
	--base-url) base_url=${2:?}; shift 2 ;;
	--listen) listen=${2:?}; shift 2 ;;
	--version) version=${2:?}; shift 2 ;;
	--binary) binary=${2:?}; shift 2 ;;
	--nginx) with_nginx=1; shift ;;
	--force-unit) force_unit=1; shift ;;
	-h | --help) usage; exit 0 ;;
	*) usage >&2; die "unknown option: $1" ;;
	esac
done

[ "$(id -u)" -eq 0 ] || die "run as root (sudo)"
command -v systemctl >/dev/null || die "systemd is required"
[ -n "$base_url" ] || { [ -n "$domain" ] && base_url="https://$domain"; }

fresh=1
[ -f "$UNIT" ] && fresh=0
if [ "$fresh" -eq 1 ] || [ "$force_unit" -eq 1 ]; then
	[ -n "$base_url" ] || die "--domain or --base-url is required for a fresh install"
fi
if [ "$with_nginx" -eq 1 ]; then
	[ -n "$domain" ] || die "--nginx needs --domain"
	command -v nginx >/dev/null || die "nginx is not installed"
fi

# Find the release files: next to this script (extracted tarball / repo checkout),
# or downloaded from GitHub.
script_dir=""
if [ -n "${BASH_SOURCE[0]:-}" ] && [ -f "${BASH_SOURCE[0]}" ]; then
	script_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
fi
src=""
if [ -n "$script_dir" ] && [ -f "$script_dir/emerchat.service" ]; then
	src=$script_dir
fi
[ -z "$binary" ] && [ -n "$src" ] && [ -x "$src/emerchat" ] && binary=$src/emerchat

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

if [ -z "$binary" ] || [ -z "$src" ]; then
	case $(uname -m) in
	x86_64 | amd64) arch=amd64 ;;
	aarch64 | arm64) arch=arm64 ;;
	*) die "unsupported architecture: $(uname -m)" ;;
	esac
	asset=emerchat-linux-$arch.tar.gz
	if [ "$version" = latest ]; then
		url=https://github.com/$REPO/releases/latest/download
	else
		url=https://github.com/$REPO/releases/download/$version
	fi
	log "downloading $asset ($version)"
	curl -fsSL -o "$tmp/$asset" "$url/$asset" || die "download failed: $url/$asset"
	curl -fsSL -o "$tmp/SHA256SUMS" "$url/SHA256SUMS" || die "download failed: $url/SHA256SUMS"
	(cd "$tmp" && grep " $asset\$" SHA256SUMS | sha256sum -c --quiet -) || die "checksum mismatch"
	mkdir "$tmp/dist"
	tar -xzf "$tmp/$asset" -C "$tmp/dist"
	[ -z "$src" ] && src=$tmp/dist
	[ -z "$binary" ] && binary=$tmp/dist/emerchat
fi
[ -x "$binary" ] || die "binary not found or not executable: $binary"

# Service user and data directory.
if ! id "$SVC_USER" >/dev/null 2>&1; then
	log "creating system user $SVC_USER"
	useradd --system --home-dir "$DATA_DIR" --no-create-home --shell /usr/sbin/nologin "$SVC_USER"
fi
install -d -m 0750 -o "$SVC_USER" -g "$SVC_USER" "$DATA_DIR"

# On upgrade, take a consistent DB snapshot with the old binary before replacing it.
if [ "$fresh" -eq 0 ] && [ -x "$PREFIX/emerchat" ] && [ -f "$DATA_DIR/emerchat.db" ]; then
	snap=$DATA_DIR/emerchat.db.pre-upgrade-$(date +%Y%m%d%H%M%S)
	log "backing up database to $snap"
	runuser -u "$SVC_USER" -- "$PREFIX/emerchat" -db "$DATA_DIR/emerchat.db" -backup "$snap" >/dev/null
fi

log "installing $PREFIX/emerchat"
install -m 0755 "$binary" "$PREFIX/emerchat.new"
mv -f "$PREFIX/emerchat.new" "$PREFIX/emerchat"

if [ "$fresh" -eq 1 ] || [ "$force_unit" -eq 1 ]; then
	log "writing $UNIT"
	sed -e "s|https://chat.example.com|$base_url|" \
		-e "s|-addr 127.0.0.1:8080|-addr $listen|" \
		"$src/emerchat.service" >"$UNIT"
	chmod 0644 "$UNIT"
fi

if [ "$with_nginx" -eq 1 ]; then
	if [ -d /etc/nginx/sites-available ]; then
		site=/etc/nginx/sites-available/emerchat.conf
	else
		site=/etc/nginx/conf.d/emerchat.conf
	fi
	if [ -f "$site" ]; then
		log "keeping existing $site"
	else
		log "writing $site"
		sed -e "s|chat.example.com|$domain|g" \
			-e "s|127.0.0.1:8080|$listen|g" \
			"$src/nginx.conf" >"$site"
		if [ -d /etc/nginx/sites-enabled ]; then
			ln -sf "$site" /etc/nginx/sites-enabled/emerchat.conf
		fi
	fi
	if nginx -t 2>/dev/null; then
		systemctl reload nginx
	else
		echo "warning: nginx -t failed (missing TLS certs for $domain?); fix it and reload nginx" >&2
	fi
fi

systemctl daemon-reload
log "starting emerchat"
since=$(date '+%Y-%m-%d %H:%M:%S')
systemctl enable --quiet emerchat
systemctl restart emerchat

# Show the start-up invite (an admin invite while there are no users yet).
invite=""
for _ in $(seq 1 20); do
	invite=$(journalctl -u emerchat --since "$since" -o cat 2>/dev/null | grep -A1 -i 'invite (' | grep -o 'http[^ ]*' | tail -n1 || true)
	[ -n "$invite" ] && break
	systemctl is-active --quiet emerchat || break
	sleep 0.5
done
systemctl is-active --quiet emerchat || die "service failed to start; see: journalctl -u emerchat"

log "done: emerchat is running"
if [ -n "$invite" ]; then
	echo
	if [ "$fresh" -eq 1 ]; then
		echo "  Admin invite (valid 7 days, single use; open it to create the first account):"
	else
		echo "  Invite link (valid 7 days, single use):"
	fi
	echo "  $invite"
	echo
fi
echo "New admin invite:  sudo -u $SVC_USER $PREFIX/emerchat -db $DATA_DIR/emerchat.db -base-url <url> -new-admin-invite"
echo "Logs:              journalctl -u emerchat -f"
