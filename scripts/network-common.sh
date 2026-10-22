#!/bin/bash
# Shared validators. No installation or network effects when sourced.
die() { printf '%s: %s\n' "$1" "$2" >&2; exit "${3:-1}"; }
jget() { plutil -extract "$2" raw -o - "$1" 2>/dev/null; }
joptional() { jget "$1" "$2" || true; }
tail_ip() {
  [[ $1 =~ ^100\.([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})$ ]] || return 1
  ((10#${BASH_REMATCH[1]} >= 64 && 10#${BASH_REMATCH[1]} <= 127 && 10#${BASH_REMATCH[2]} <= 255 && 10#${BASH_REMATCH[3]} <= 255))
}
host_name() { [[ ${#1} -le 253 && $1 =~ ^[a-zA-Z0-9]([a-zA-Z0-9.-]*[a-zA-Z0-9])?$ && $1 != *..* ]]; }
ssh_port() { [[ $1 =~ ^[0-9]{1,5}$ ]] && ((10#$1 >= 1 && 10#$1 <= 65535)); }
one_line() { [[ -n $1 && $1 != *$'\n'* && $1 != *$'\r'* && $1 != *$'\t'* ]]; }
public_key() { [[ $1 =~ ^ssh-ed25519\ [A-Za-z0-9+/=]+$ && ${#1} -lt 200 ]]; }
private_path() {
  [[ ! -L $1 ]] || die UNSAFE_PATH "Symlinked path: $1"
  [[ ! -e $1 || $(stat -f %u "$1") == "$(id -u)" ]] || die UNSAFE_OWNER "Not owned by this user: $1"
}
read_client_identity() {
  local file=$1 mode value
  private_path "$file"
  [[ -f $file && $(stat -f %z "$file") -lt 65536 ]] || die INVALID_IDENTITY 'Provide an existing local Ed25519 private key file.'
  mode=$(stat -f %Lp "$file")
  (( (8#$mode & 077) == 0 )) || die UNSAFE_KEY_MODE 'Private key is accessible by other users. Review permissions and use chmod 600 on the source file.'
  value=$(ssh-keygen -y -P '' -f "$file" 2>/dev/null) || die IDENTITY_LOCKED_OR_INVALID 'Use a dedicated unencrypted Ed25519 key for unattended SSH. The source key was not changed.'
  read_public_key_text "$value"
}
write_client_status() {
  local directory=$1 state=$2 stage=$3 code=$4 tmp
  private_path "$directory/client-acceptance.json"
  tmp=$(mktemp "$directory/.acceptance.XXXXXXXX")
  printf '{"schemaVersion":1,"state":"%s","stage":"%s","exitCode":%s,"updatedAt":"%s"}\n' \
    "$state" "$stage" "$code" "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" > "$tmp"
  chmod 600 "$tmp"
  mv "$tmp" "$directory/client-acceptance.json"
}
write_vps_command() {
  local destination=$1 script=$2 target=$3 data=$4 source_ip=$5 digest payload
  digest=$(shasum -a 256 "$script" | awk '{print $1}')
  payload=$(base64 < "$script" | tr -d '\r\n')
  # Public inputs were validated by load_receipt/read_client_identity.
  # Noclobber prevents accidental replacement of another local file.
  (
    set -o noclobber
    cat > "$destination" <<COMMAND
#!/bin/bash
# Self-contained VPS setup. Contains public network inputs only.
set -euo pipefail
umask 077
bundle=\$(mktemp -d)
trap 'rm -rf "\$bundle"' EXIT
base64 -d > "\$bundle/init-vps.sh" <<'REMOTE_SSH_PAYLOAD'
$payload
REMOTE_SSH_PAYLOAD
printf '$digest  %s\\n' "\$bundle/init-vps.sh" | sha256sum -c -
bash "\$bundle/init-vps.sh" $target 22 $data $source_ip
COMMAND
  ) || die EXPORT_FAILED 'Choose a new output filename; existing files are never overwritten.'
}
read_public_key_text() {
  local value=$1 kind data rest fingerprint
  [[ ${#value} -lt 4096 ]] && one_line "$value" || die INVALID_CLIENT_KEY 'Supply exactly one client Ed25519 PUBLIC key line.'
  read -r kind data rest <<< "$value"
  public_key "$kind $data" || die INVALID_CLIENT_KEY 'Not an Ed25519 public key. Never supply a private key.'
  fingerprint=$(ssh-keygen -lf /dev/stdin -E sha256 <<< "$kind $data" 2>/dev/null) || die INVALID_CLIENT_KEY 'Malformed public key.'
  # Outputs consumed by installers sourcing this library.
  # shellcheck disable=SC2034
  client_key="$kind $data"
  # shellcheck disable=SC2034
  client_fingerprint=$(awk '{print $2}' <<< "$fingerprint")
}
read_public_key() {
  local file=$1
  [[ -f $file && $(wc -c < "$file") -lt 4096 ]] || die INVALID_CLIENT_KEY 'Supply one client Ed25519 PUBLIC key file.'
  read_public_key_text "$(cat "$file")"
}
load_setup() {
  local config=$1 key basedir inline_type file_type
  [[ -f $config ]] && plutil -convert json -o /dev/null "$config" || die INVALID_INPUT 'Provide a valid JSON setup file.'
  for key in $(plutil -p "$config" | sed -n 's/^  "\([^"]*\)" =>.*/\1/p'); do
    case $key in schemaVersion|jumpHost|jumpPort|jumpTailnetIp|jumpHostKey|clientPublicKey|clientPublicKeyFile) ;;
      *) die UNKNOWN_INPUT "Unsupported input field: $key (credentials must not be put in this file).";; esac
  done
  [[ $(jget "$config" schemaVersion) == 1 ]] || die INVALID_INPUT 'schemaVersion must be 1.'
  jump_host=$(jget "$config" jumpHost) || die MISSING_INPUT jumpHost
  jump_port=$(joptional "$config" jumpPort); jump_port=${jump_port:-22}
  jump_ip=$(jget "$config" jumpTailnetIp) || die MISSING_INPUT jumpTailnetIp
  jump_key=$(jget "$config" jumpHostKey) || die MISSING_INPUT jumpHostKey
  host_name "$jump_host" && ssh_port "$jump_port" && tail_ip "$jump_ip" && public_key "$jump_key" || die INVALID_JUMP 'Check jumpHost, jumpPort, jumpTailnetIp and trusted jumpHostKey.'
  inline_type=$(plutil -type clientPublicKey "$config" 2>/dev/null) || inline_type=''
  file_type=$(plutil -type clientPublicKeyFile "$config" 2>/dev/null) || file_type=''
  [[ -z $inline_type || -z $file_type ]] || die INVALID_CLIENT_KEY 'Use clientPublicKey OR clientPublicKeyFile, not both.'
  if [[ -n $inline_type ]]; then
    [[ $inline_type == string ]] || die INVALID_CLIENT_KEY 'clientPublicKey must be a public key string.'
    read_public_key_text "$(jget "$config" clientPublicKey)"
  elif [[ -n $file_type ]]; then
    [[ $file_type == string ]] || die INVALID_CLIENT_KEY 'clientPublicKeyFile must be a file path string.'
    key=$(jget "$config" clientPublicKeyFile)
    [[ -n $key ]] || die INVALID_CLIENT_KEY 'clientPublicKeyFile must not be empty.'
    basedir=$(cd "$(dirname "$config")" && pwd -P)
    [[ $key == /* ]] || key="$basedir/$key"
    read_public_key "$key"
  else
    die MISSING_INPUT 'clientPublicKey (or legacy clientPublicKeyFile)'
  fi
}
find_tailscale() {
  local candidate
  if command -v tailscale >/dev/null; then command -v tailscale; return; fi
  for candidate in /Applications/Tailscale.app/Contents/MacOS/Tailscale /Applications/Tailscale.app/Contents/MacOS/tailscale; do
    [[ ! -x $candidate ]] || { printf '%s\n' "$candidate"; return; }
  done
  return 1
}
load_receipt() {
  local receipt=$1 field
  [[ -f $receipt ]] && plutil -convert json -o /dev/null "$receipt" || die INVALID_RECEIPT 'Provide a valid public server receipt.'
  for field in $(plutil -p "$receipt" | sed -n 's/^  "\([^"]*\)" =>.*/\1/p'); do
    case $field in schemaVersion|kind|serverOs|serverReady|host|port|user|hostKey|jumpHost|jumpPort|jumpTailnetIp|jumpHostKey|clientKeyFingerprint) ;;
      *) die INVALID_RECEIPT 'Unsupported receipt field.';; esac
  done
  [[ $(jget "$receipt" schemaVersion) == 1 && $(jget "$receipt" kind) == remote-ssh && $(jget "$receipt" serverOs) == macos && $(plutil -type serverReady "$receipt") == bool && $(jget "$receipt" serverReady) == true ]] || die INVALID_RECEIPT 'A ready Remote SSH Mac server receipt is required.'
  host=$(jget "$receipt" host); user=$(jget "$receipt" user); port=$(jget "$receipt" port); pub=$(jget "$receipt" hostKey)
  jump_host=$(jget "$receipt" jumpHost); jump_port=$(jget "$receipt" jumpPort); jump_ip=$(jget "$receipt" jumpTailnetIp); jump_key=$(jget "$receipt" jumpHostKey)
  tail_ip "$host" && tail_ip "$jump_ip" && [[ $host != "$jump_ip" && $port == 22 && $user =~ ^[a-zA-Z0-9_][a-zA-Z0-9_.-]*$ ]] || die INVALID_RECEIPT 'Invalid server identity.'
  host_name "$jump_host" && ssh_port "$jump_port" && public_key "$pub" && public_key "$jump_key" || die INVALID_RECEIPT 'Invalid jump identity or host public key.'
  ssh-keygen -lf /dev/stdin <<< "$pub" >/dev/null 2>&1 && ssh-keygen -lf /dev/stdin <<< "$jump_key" >/dev/null 2>&1 || die INVALID_RECEIPT 'Malformed host public key.'
  [[ $(jget "$receipt" clientKeyFingerprint) =~ ^SHA256:[A-Za-z0-9+/]+$ ]] || die INVALID_RECEIPT 'Missing client key fingerprint.'
}
