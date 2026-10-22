#!/bin/bash
# Opens a remote terminal, or runs a fixed SSH identity check.
set -euo pipefail
root="$HOME/Library/Application Support/RemoteSSHClient"
src=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)
# shellcheck source=network-common.sh
source "$src/network-common.sh"
mode=shell
while (($#)); do
  case $1 in
    --help|-h) echo 'remote-ssh [--check]'; echo 'Open the remote login shell, or verify SSH authentication and server identity.'; exit 0;;
    --check) mode=check; shift;;
    *) die INVALID_OPTION 'Use remote-ssh or remote-ssh --check.' 2;;
  esac
done
status_stage=client-preflight
if [[ $mode == check && -d $root ]]; then
  write_client_status "$root" checking "$status_stage" 0
  trap 'code=$?; if ((code != 0)); then write_client_status "$root" failed "$status_stage" "$code"; fi' EXIT
fi
[[ -f $root/receipt.json && -f $root/ssh/config ]] || die CLIENT_NOT_READY 'Import the server receipt with install-mac-client.sh first.'
load_receipt "$root/receipt.json"
if [[ $mode == check ]]; then
  status_stage=ssh-check
  write_client_status "$root" checking ssh-check 0
  command="test \"\$(/usr/bin/id -un)\" = '$user' && test \"\$(/usr/bin/uname -s)\" = Darwin && printf 'REMOTE_SSH_OK\\n'"
  output=$(ssh -F "$root/ssh/config" -T -o BatchMode=yes remote-ssh-server "$command") || exit $?
  grep -Fxq REMOTE_SSH_OK <<< "$output" || die SSH_CHECK_FAILED 'SSH returned without the expected server identity confirmation.'
  write_client_status "$root" ready ssh-check 0
  echo 'SSH_CHAIN_READY: authenticated to the expected Mac account through the jump server.'
else
  printf 'REMOTE TERMINAL: %s@%s\n' "$user" "$host"
  exec ssh -F "$root/ssh/config" -tt remote-ssh-server
fi
