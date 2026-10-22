#!/bin/bash
# CLIENT ONLY. Import a trusted public network receipt.
set -euo pipefail
umask 077
src=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)
# shellcheck source=network-common.sh
source "$src/network-common.sh"
root="$HOME/Library/Application Support/RemoteSSHClient"
receipt=''; provision=true; prepare=false; identity=''; export_file=''
while (($#)); do
  case $1 in
    --prepare-only) prepare=true; shift;;
    --receipt) [[ $# -ge 2 ]] || exit 2; receipt=$2; shift 2;;
    --no-provision) provision=false; shift;;
    --identity-file) [[ $# -ge 2 && -n $2 ]] || exit 2; identity=$2; shift 2;;
    --export-vps-command) [[ $# -ge 2 && -n $2 ]] || exit 2; export_file=$2; provision=false; shift 2;;
    --help|-h) echo 'bash install-mac-client.sh --prepare-only | --receipt FILE [--no-provision | --export-vps-command FILE] [--identity-file PRIVATE_KEY]'; exit 0;;
    *) die INVALID_OPTION "$1" 2;;
  esac
done
[[ $(uname -s) == Darwin && $EUID != 0 ]] || die WRONG_MACHINE 'Run as your normal Mac client user.'
[[ $prepare == true || -n $receipt ]] || die INPUT_REQUIRED 'Provide --receipt, or --prepare-only before setting up the server.' 2
[[ $prepare != true || ( -z $receipt && -z $export_file ) ]] || die INVALID_OPTION 'Preparation cannot also import a receipt or export a VPS command.' 2
[[ ! -L $root && ( ! -e $root || -f $root/.managed-client ) ]] || die UNMANAGED_DIRECTORY 'Unmanaged client directory.'
[[ $root != *'"'* && $root != *$'\n'* && $root != *'%'* ]] || die UNSUPPORTED_HOME 'Unsupported HOME characters for OpenSSH config.'
key="$root/ssh/id_ed25519"
private_path "$root"
for item in .managed-client bin ssh backups receipt.json ssh/config ssh/known_hosts ssh/id_ed25519 client-key.pub client-acceptance.json bin/start-mac-client.sh bin/network-common.sh bin/init-vps.sh; do private_path "$root/$item"; done
if [[ -n $export_file ]]; then
  [[ -d $(dirname "$export_file") && ! -e $export_file && ! -L $export_file ]] || die EXPORT_EXISTS 'Choose a new output filename in an existing directory.'
fi
actual=''
if [[ -n $identity ]]; then
  read_client_identity "$identity"
  actual=$client_fingerprint
fi
if [[ -f $key ]]; then
  read_client_identity "$key"
  [[ -z $actual || $actual == "$client_fingerprint" ]] || die CLIENT_KEY_CONFLICT 'The installed key differs. No key was replaced; use its public key or arrange a deliberate migration.'
  actual=$client_fingerprint
fi
if [[ $prepare == false ]]; then
  [[ -n $actual ]] || die CLIENT_KEY_MISSING 'Run --prepare-only, or explicitly reuse your existing key with --identity-file PRIVATE_KEY.'
  load_receipt "$receipt"
  [[ $actual == "$(jget "$receipt" clientKeyFingerprint)" ]] || die CLIENT_KEY_MISMATCH 'This receipt authorizes a DIFFERENT client key. Supply its matching local private key or rerun server setup; nothing was provisioned.'
fi
mkdir -p "$root/bin" "$root/ssh" "$root/backups" "$HOME/.local/bin"
chmod 700 "$root" "$root/bin" "$root/ssh" "$root/backups"
touch "$root/.managed-client"
if [[ ! -f $key && -n $identity ]]; then
  candidate=$(mktemp "$root/ssh/.identity.XXXXXXXX")
  trap 'rm -f "$candidate"' EXIT
  cp -- "$identity" "$candidate"; chmod 600 "$candidate"
  read_client_identity "$candidate"
  [[ $actual == "$client_fingerprint" ]] || die IDENTITY_CHANGED 'Source identity changed during import; no key was installed.'
  ln "$candidate" "$key" || die CLIENT_KEY_CONFLICT 'A client key appeared during import; nothing was overwritten.'
  rm "$candidate"; trap - EXIT
  echo "CLIENT_IDENTITY_IMPORTED: $client_fingerprint; source file preserved."
elif [[ ! -f $key ]]; then
  ssh-keygen -q -t ed25519 -N '' -C remote-ssh-client -f "$key"
fi
chmod 600 "$key"
read_client_identity "$key"
printf '%s\n' "$client_key" > "$root/client-key.pub"
backup=$(mktemp -d "$root/backups/client.XXXXXXXX")
for item in receipt.json ssh/config ssh/known_hosts; do [[ ! -f $root/$item ]] || cp -p "$root/$item" "$backup/$(basename "$item")"; done
[[ ! -e $HOME/.local/bin/remote-ssh && ! -L $HOME/.local/bin/remote-ssh ]] || cp -P "$HOME/.local/bin/remote-ssh" "$backup/remote-ssh"
for file in start-mac-client.sh network-common.sh init-vps.sh; do cp "$src/$file" "$root/bin/$file"; done
launcher=$(mktemp "$HOME/.local/bin/.remote-ssh.XXXXXXXX")
cp "$src/remote-ssh" "$launcher"; chmod 700 "$launcher"; mv "$launcher" "$HOME/.local/bin/remote-ssh"
printf 'Public key: %s\n' "$root/client-key.pub"
ssh-keygen -lf "$root/client-key.pub" -E sha256
if [[ $prepare == true ]]; then
  printf 'clientPublicKey: %s\n' "$(cat "$root/client-key.pub")"
  echo 'CLIENT_PREPARED: paste the public key into setup.json clientPublicKey. Only setup.json is needed on the server. No remote connection made.'
  exit 0
fi
printf 'remote-ssh-jump %s\nremote-ssh-server %s\n' "$jump_key" "$pub" > "$root/ssh/known_hosts"
ssh-keygen -lf "$root/ssh/known_hosts" >/dev/null
[[ $receipt -ef $root/receipt.json ]] || cp "$receipt" "$root/receipt.json"
cat > "$root/ssh/config" <<CONF
Host remote-ssh-jump
    HostName $jump_host
    HostKeyAlias remote-ssh-jump
    User remote-jump
    Port $jump_port
Host remote-ssh-server
    HostName $host
    HostKeyAlias remote-ssh-server
    User $user
    Port 22
    ProxyCommand /usr/bin/ssh -F "\$HOME/Library/Application Support/RemoteSSHClient/ssh/config" -W %h:%p remote-ssh-jump
Host *
    BatchMode yes
    PreferredAuthentications publickey
    IdentityFile "$key"
    IdentitiesOnly yes
    IdentityAgent none
    UserKnownHostsFile "$root/ssh/known_hosts"
    GlobalKnownHostsFile /dev/null
    StrictHostKeyChecking yes
    HostKeyAlgorithms ssh-ed25519
    ForwardAgent no
    ForwardX11 no
    PermitLocalCommand no
    ServerAliveInterval 15
    ServerAliveCountMax 3
    ConnectTimeout 15
    IPQoS none
CONF
write_client_status "$root" pending client-configured 0
if [[ -n $export_file ]]; then
  read -r kind data _ < "$root/client-key.pub"
  write_vps_command "$export_file" "$src/init-vps.sh" "$host" "$data" "$jump_ip"
  echo "VPS_COMMAND_EXPORTED: $export_file"
  echo 'Run this self-contained script as root using your trusted VPS console, then run remote-ssh --check on this client. No repository login is needed on the VPS.'
fi
if [[ $provision == true ]]; then
  read -r kind data _ < "$root/client-key.pub"
  [[ $kind == ssh-ed25519 ]] || die INVALID_CLIENT_KEY 'Expected Ed25519 public key.'
  echo 'Jump setup: enter the jump server root password only at the SSH prompt.'
  write_client_status "$root" pending jump-setup 0
  if ssh -F /dev/null -T -a -x -p "$jump_port" -o "UserKnownHostsFile=\"$root/ssh/known_hosts\"" -o HostKeyAlias=remote-ssh-jump -o GlobalKnownHostsFile=/dev/null \
    -o StrictHostKeyChecking=yes -o HostKeyAlgorithms=ssh-ed25519 -o ConnectTimeout=15 -o IPQoS=none \
    -o ForwardAgent=no -o PermitLocalCommand=no "root@$jump_host" "bash -s -- $host 22 $data $jump_ip" < "$src/init-vps.sh"; then :
  else
    code=$?; write_client_status "$root" failed jump-setup "$code"
    die VPS_SETUP_FAILED 'Check the root SSH login, or rerun with --export-vps-command FILE for a trusted VPS console.' "$code"
  fi
  "$HOME/.local/bin/remote-ssh" --check
  echo 'CLIENT_CHAIN_READY: SSH public-key authentication and server identity passed from this client.'
else echo 'CLIENT_CONFIGURED_OFFLINE: jump provisioning and end-to-end acceptance have NOT run.'; fi
