#!/bin/bash
# Remote Mac network setup. Recheck state on every run.
set +x
set -euo pipefail
umask 077
src=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)
# shellcheck source=network-common.sh
source "$src/network-common.sh"
usage() { echo 'REMOTE MAC ONLY: bash setup-mac-server.sh --on-server --config FILE [--preflight] [--wait-seconds 120]'; }
config=''; preflight=false; on_server=false; wait_seconds=120
while (($#)); do
  case $1 in
    --on-server) on_server=true; shift;;
    --config) [[ $# -ge 2 ]] || exit 2; config=$2; shift 2;;
    --preflight) preflight=true; shift;;
    --wait-seconds) [[ $# -ge 2 ]] || exit 2; wait_seconds=$2; shift 2;;
    --help|-h) usage; exit 0;;
    *) usage; die INVALID_OPTION "$1" 2;;
  esac
done
[[ $on_server == true && -n $config ]] || { usage; exit 2; }
[[ $(uname -s) == Darwin && $EUID != 0 ]] || die WRONG_MACHINE 'Use the intended remote Mac account, without sudo.'
if [[ -f $HOME/Library/Application\ Support/RemoteSSHClient/.managed-client && ! -f $HOME/Library/Application\ Support/RemoteSSHServer/.managed-server ]]; then
  die CLIENT_MACHINE 'This account is marked as a client. Run server setup on the remote Mac.'
fi
[[ $wait_seconds =~ ^[0-9]{1,3}$ ]] && ((10#$wait_seconds >= 1 && 10#$wait_seconds <= 600)) || die INVALID_WAIT 'Use 1 to 600 seconds.'
major=$(sw_vers -productVersion | cut -d . -f 1)
[[ $major =~ ^[0-9]+$ ]] && ((major >= 13)) || die UNSUPPORTED_MAC 'macOS 13 or later is required.'
load_setup "$config"
work=$(mktemp -d "${TMPDIR:-/tmp}/remote-ssh-preflight.XXXXXXXX")
locked=false; stage=preflight; root="$HOME/Library/Application Support/RemoteSSHServer"
cleanup() {
  local code=$?
  if [[ $locked == true ]]; then
    if ((code != 0)); then
      printf '{"state":"blocked","stage":"%s","exitCode":%s}\n' "$stage" "$code" > "$root/install-status.json"
      printf 'SETUP_BLOCKED: stage=%s. Resolve the message above, then rerun the SAME command.\n' "$stage" >&2
    fi
    rm -f "$root/.install.lock/pid"; rmdir "$root/.install.lock" || true
  fi
  rm -rf -- "$work"
}
trap cleanup EXIT
printf '%s\n' "$jump_key" > "$work/jump.pub"
ssh-keygen -lf "$work/jump.pub" >/dev/null || die INVALID_JUMP_KEY 'Supply the trusted Ed25519 public host key from the VPS console.'
private_path "$root"
[[ ! -e $root || -f $root/.managed-server ]] || die UNMANAGED_DIRECTORY 'Existing network directory is not managed by this installer.'
for item in downloads backups input.sha256 .managed-server .install.lock .install.lock/pid install-status.json server-receipt.json; do private_path "$root/$item"; done
private_path "$HOME/.ssh"; private_path "$HOME/.ssh/authorized_keys"
policy="from=\"$jump_ip\",no-agent-forwarding,no-port-forwarding,no-X11-forwarding $client_key"
if [[ -f $HOME/.ssh/authorized_keys ]]; then
  awk -v key="$client_key" -v policy="$policy" 'index($0,key) && $0!=policy && index($0,policy " ")!=1 {bad=1} END {exit bad}' "$HOME/.ssh/authorized_keys" || die KEY_POLICY_CONFLICT 'This key already has different SSH options. Review it before installation; existing permissions are preserved.'
fi
digest=$(printf '%s\n' "$jump_host" "$jump_port" "$jump_ip" "$jump_key" "$client_key" | shasum -a 256 | awk '{print $1}')
[[ ! -f $root/input.sha256 || $(cat "$root/input.sha256") == "$digest" ]] || die INPUT_CHANGED 'Existing network deployment has different inputs. Review a migration instead of silently changing its SSH policy.'
echo 'PRECHECK_INPUT_OK'
printf 'Server user: %s\nJump: %s:%s | Tailnet source: %s\nClient key: %s\n' "$(id -un)" "$jump_host" "$jump_port" "$jump_ip" "$client_fingerprint"
find_tailscale >/dev/null || echo 'ACTION: a signed Tailscale package will be installed with sudo.'
if [[ $preflight == true ]]; then echo 'PREFLIGHT_OK: no software, permissions, login or persistent files changed.'; exit 0; fi
mkdir -p "$root/downloads" "$root/backups"
chmod 700 "$root" "$root/downloads" "$root/backups"
touch "$root/.managed-server"
if ! mkdir "$root/.install.lock" 2>/dev/null; then
  pid=$(cat "$root/.install.lock/pid" 2>/dev/null || true)
  if [[ $pid =~ ^[0-9]+$ ]] && ! kill -0 "$pid" 2>/dev/null; then
    rm -f "$root/.install.lock/pid"; rmdir "$root/.install.lock"; mkdir "$root/.install.lock"
  else die INSTALL_RUNNING 'Another installation holds the lock. Finish it before retrying.'; fi
fi
locked=true; echo $$ > "$root/.install.lock/pid"
[[ ! -f $root/input.sha256 || $(cat "$root/input.sha256") == "$digest" ]] || die INPUT_CHANGED 'Another installation committed different inputs.'
[[ ! -f $root/server-receipt.json ]] || mv "$root/server-receipt.json" "$root/backups/receipt.$(date +%Y%m%d-%H%M%S).$$.json"
printf '%s\n' "$digest" > "$root/input.sha256"
step() { stage=$1; printf '{"state":"running","stage":"%s"}\n' "$stage" > "$root/install-status.json"; printf '\n[%s] %s\n' "$1" "$2"; }
download() { curl -q -fLsS --proto '=https' --proto-redir '=https' --connect-timeout 20 --max-time 300 --retry 2 "$1" -o "$2"; }
step software 'Install only missing software; keep existing versions.'
if ! ts=$(find_tailscale); then
  url=https://dl.tailscale.com/stable/Tailscale-1.104.2-macos.pkg
  download "$url" "$root/downloads/tailscale.pkg"
  download "$url.sha256" "$work/tailscale.sha256"
  sha=$(awk 'NR==1 {print $1}' "$work/tailscale.sha256")
  [[ $sha =~ ^[0-9a-fA-F]{64}$ ]] || die DOWNLOAD_INVALID 'Invalid Tailscale checksum response.'
  printf '%s  %s\n' "$sha" "$root/downloads/tailscale.pkg" | shasum -a 256 -c -
  pkgutil --check-signature "$root/downloads/tailscale.pkg"
  spctl --assess --type install "$root/downloads/tailscale.pkg"
  sudo installer -pkg "$root/downloads/tailscale.pkg" -target /
  ts=$(find_tailscale) || die TAILSCALE_MISSING 'Complete the Tailscale installation and rerun.'
fi
step tailnet 'Authorize Tailscale on this Mac in the same tailnet as the jump server.'
"$ts" status --json > "$work/tailnet.json" 2>/dev/null || true
if [[ $(joptional "$work/tailnet.json" BackendState) != Running ]]; then open -a Tailscale || true; fi
deadline=$((SECONDS + wait_seconds)); ip=''
while true; do
  "$ts" status --json > "$work/tailnet.json" 2>/dev/null || true
  ip=$("$ts" ip -4 2>/dev/null || true)
  if [[ $(joptional "$work/tailnet.json" BackendState) == Running ]] && tail_ip "$ip" && [[ $ip != "$jump_ip" ]]; then break; fi
  ((SECONDS < deadline)) || die TAILNET_AUTH_REQUIRED 'Open Tailscale, approve its system extension, log in to the jump server tailnet, then rerun.' 20
  sleep 2
done
"$ts" whois --json "$jump_ip" > "$work/peer.json" 2>/dev/null || die TAILNET_PEER_MISSING 'This tailnet does not expose the supplied jump IP. Verify the account/tailnet, node authorization and access policy, then rerun.' 20
if ! "$ts" ping --c=1 --timeout=5s --until-direct=false "$jump_ip" > "$work/ping.log" 2>&1; then
  echo 'TAILNET_PEER_UNCONFIRMED: check jump availability/ACL. Reverse ping is not proof of inbound TCP 22; the client test is mandatory.'
fi
step ssh 'Enable native Remote Login and register the exact client public key.'
if nc -z -G 3 "$ip" 22; then
  echo 'SSH_ALREADY_LISTENING: preserving Remote Login settings; no sudo query or toggle needed.'
elif ! login_state=$(sudo systemsetup -getremotelogin); then
  die REMOTE_LOGIN_REQUIRED 'Could not query Remote Login. Check administrator access; no enable command was attempted.' 21
elif grep -Eq 'Remote Login: Off[[:space:]]*$' <<< "$login_state"; then
  sudo systemsetup -setremotelogin on || die REMOTE_LOGIN_REQUIRED 'System Settings > General > Sharing > Remote Login: enable this user. Full Disk Access may be required. Then rerun.' 21
elif ! grep -Eq 'Remote Login: On[[:space:]]*$' <<< "$login_state"; then
  die REMOTE_LOGIN_REQUIRED 'Unrecognized Remote Login state; inspect it in System Settings before rerunning.' 21
fi
mkdir -p "$HOME/.ssh"; chmod 700 "$HOME/.ssh"
auth="$HOME/.ssh/authorized_keys"
policy="from=\"$jump_ip\",no-agent-forwarding,no-port-forwarding,no-X11-forwarding $client_key"
if [[ -f $auth ]] && grep -Fq "$client_key" "$auth"; then
  # A key appearing with other options could bypass the intended restrictions.
  awk -v key="$client_key" -v policy="$policy" 'index($0,key) && $0!=policy && index($0,policy " ")!=1 {bad=1} END {exit bad}' "$auth" || die KEY_POLICY_CONFLICT 'This key already has different SSH options. Review that entry; no permissions were widened or replaced.'
else
  [[ ! -f $auth ]] || cp -p "$auth" "$root/backups/authorized_keys.$(date +%Y%m%d-%H%M%S).$$"
  next=$(mktemp "$HOME/.ssh/.authorized_keys.XXXXXXXX")
  [[ ! -f $auth ]] || cat "$auth" > "$next"
  printf '\n%s remote-ssh-client\n' "$policy" >> "$next"
  chmod 600 "$next"; mv "$next" "$auth"
fi
chmod 600 "$auth"
[[ -f /etc/ssh/ssh_host_ed25519_key.pub ]] || sudo ssh-keygen -A
nc -z -G 3 "$ip" 22 || die SSH_NOT_LISTENING 'Native SSH is not reachable on this Mac tailnet IP. Check Remote Login user access and firewall.' 22
step receipt 'Export public connection information; client acceptance is still pending.'
server_key=$(awk '{print $1" "$2}' /etc/ssh/ssh_host_ed25519_key.pub)
printf '%s\n' "$server_key" > "$work/server.pub"
public_key "$server_key" && ssh-keygen -lf "$work/server.pub" >/dev/null || die INVALID_SERVER_KEY 'Cannot read a valid server Ed25519 host key.'
receipt="$work/receipt.json"
printf '{"schemaVersion":1,"kind":"remote-ssh"}\n' > "$receipt"
plutil -insert serverOs -string macos "$receipt"
plutil -insert host -string "$ip" "$receipt"
plutil -insert user -string "$(id -un)" "$receipt"
plutil -insert port -integer 22 "$receipt"
plutil -insert hostKey -string "$server_key" "$receipt"
plutil -insert jumpHost -string "$jump_host" "$receipt"
plutil -insert jumpPort -integer "$jump_port" "$receipt"
plutil -insert jumpTailnetIp -string "$jump_ip" "$receipt"
plutil -insert jumpHostKey -string "$jump_key" "$receipt"
plutil -insert clientKeyFingerprint -string "$client_fingerprint" "$receipt"
plutil -insert serverReady -bool YES "$receipt"
plutil -convert json "$receipt"
mv "$receipt" "$root/server-receipt.json"
printf '{"state":"server-ready","stage":"complete","clientAcceptance":"pending"}\n' > "$root/install-status.json"
echo "SERVER_LOCAL_READY: $root/server-receipt.json"
echo 'Return this public receipt to the originating client. VPS authorization and client-to-server SSH still require verification.'
