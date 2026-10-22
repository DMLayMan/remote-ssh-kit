#!/bin/bash
# VPS ONLY. Dedicated restricted OpenSSH jump account.
set -euo pipefail
umask 077
[[ $EUID == 0 ]] || { echo 'Run as root on the VPS.' >&2; exit 1; }
host=${1:?Server Tailscale IPv4 required}; port=${2:?Server SSH port required}; key=${3:?Ed25519 public-key data required}
jump_ip=${4:?Jump server Tailscale IPv4 required}
[[ $host =~ ^100\.([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})$ ]] || exit 2
((10#${BASH_REMATCH[1]} >= 64 && 10#${BASH_REMATCH[1]} <= 127 && 10#${BASH_REMATCH[2]} <= 255 && 10#${BASH_REMATCH[3]} <= 255)) || exit 2
[[ $jump_ip =~ ^100\.([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})$ ]] || exit 2
((10#${BASH_REMATCH[1]} >= 64 && 10#${BASH_REMATCH[1]} <= 127 && 10#${BASH_REMATCH[2]} <= 255 && 10#${BASH_REMATCH[3]} <= 255)) || exit 2
[[ $host != "$jump_ip" && $port == 22 && $key =~ ^[A-Za-z0-9+/=]+$ && ${#key} -lt 200 ]] || exit 2
command -v tailscale >/dev/null || { echo 'VPS Tailscale is missing; restore its existing private network first.' >&2; exit 1; }
[[ $(tailscale ip -4) == "$jump_ip" ]] || { echo 'Unexpected jump server tailnet identity; check the setup input.' >&2; exit 1; }
root=/opt/remote-ssh-kit
[[ ! -L $root && ( ! -e $root || -f $root/.managed-jump ) ]] || exit 1
if [[ ! -e $root ]]; then
  ! getent passwd remote-jump >/dev/null || { echo 'Unmanaged remote-jump user exists.' >&2; exit 1; }
  install -d -m 700 "$root"; touch "$root/.managed-jump"
fi
[[ ! -L $root/target && ! -L $root/.setup.lock ]] || exit 1
[[ ! -f $root/target || $(cat "$root/target") == "$host:$port" ]] || { echo 'TARGET_CONFLICT: this jump account already serves another host; arrange an explicit migration.' >&2; exit 1; }
mkdir "$root/.setup.lock" || { echo 'Another jump setup is running. Inspect the lock before retrying.' >&2; exit 1; }
trap 'rmdir "$root/.setup.lock"' EXIT
printf 'ssh-ed25519 %s\n' "$key" > "$root/key-check.pub"
ssh-keygen -lf "$root/key-check.pub" >/dev/null
grep -Eq '^[[:space:]]*Include[[:space:]]+/etc/ssh/sshd_config.d/\*' /etc/ssh/sshd_config || { echo 'sshd drop-in Include is missing.' >&2; exit 1; }
conf=/etc/ssh/sshd_config.d/60-remote-ssh-jump.conf
if [[ -e $conf ]] && ! grep -q REMOTE_SSH_MANAGED "$conf"; then echo 'Unmanaged SSH drop-in.' >&2; exit 1; fi
[[ ! -L /var/lib/remote-jump && ! -L /var/lib/remote-jump/.ssh && ! -L "$conf" ]] || exit 1
getent passwd remote-jump >/dev/null || useradd --system --create-home --home-dir /var/lib/remote-jump --shell /usr/sbin/nologin remote-jump
# Disable passwords without treating the account as locked for public-key SSH.
usermod -p '*' remote-jump
chown root:root /var/lib/remote-jump; chmod 755 /var/lib/remote-jump
install -d -m 755 -o root -g root /var/lib/remote-jump/.ssh
auth=/var/lib/remote-jump/.ssh/authorized_keys
[[ ! -L $auth ]] || exit 1
run=$(mktemp -d "$root/setup.XXXXXXXX")
[[ ! -f $auth ]] || cp "$auth" "$run/authorized_keys.previous"
[[ ! -f $conf ]] || cp "$conf" "$run/sshd.previous.conf"
committed=false
reload_attempted=false
service=sshd
systemctl is-active --quiet sshd || service=ssh
rollback() {
  status=$?
  if [[ $committed == false ]]; then
    if [[ -f $run/sshd.previous.conf ]]; then cp "$run/sshd.previous.conf" "$conf"; chmod 644 "$conf";
    elif [[ -f $conf ]]; then mv "$conf" "$run/rejected.conf"; fi
    if [[ -f $run/authorized_keys.previous ]]; then cp "$run/authorized_keys.previous" "$auth"; chmod 644 "$auth";
    elif [[ -f $auth ]]; then mv "$auth" "$run/rejected.authorized_keys"; fi
    if [[ $reload_attempted == true ]]; then systemctl reload "$service" || true; fi
  fi
  rmdir "$root/.setup.lock"
  exit "$status"
}
trap rollback EXIT
touch "$auth"
line="restrict,port-forwarding,permitopen=\"$host:$port\",command=\"/bin/false\" ssh-ed25519 $key remote-ssh-client"
if grep -Fq "ssh-ed25519 $key" "$auth" && ! grep -Fqx "$line" "$auth"; then echo 'KEY_POLICY_CONFLICT: inspect existing authorization; no permissions were widened.' >&2; exit 1; fi
grep -Fqx "$line" "$auth" || printf '%s\n' "$line" >> "$auth"
chown root:root "$auth"; chmod 644 "$auth"
cat > "$conf" <<CONF
# REMOTE_SSH_MANAGED
Match User remote-jump
    AuthorizedKeysFile /var/lib/remote-jump/.ssh/authorized_keys
    AuthenticationMethods publickey
    PasswordAuthentication no
    KbdInteractiveAuthentication no
    AllowTcpForwarding local
    PermitOpen $host:$port
    AllowStreamLocalForwarding no
    AllowAgentForwarding no
    X11Forwarding no
    PermitTTY no
    PermitTunnel no
    GatewayPorts no
    ForceCommand /bin/false
Match all
CONF
chmod 644 "$conf"
/usr/sbin/sshd -t
effective=$(/usr/sbin/sshd -T -C user=remote-jump,host=localhost,addr=127.0.0.1)
grep -Fxq "permitopen $host:$port" <<< "$effective"
grep -Fxq 'passwordauthentication no' <<< "$effective"
grep -Fxq 'allowtcpforwarding local' <<< "$effective"
grep -Fxq 'forcecommand /bin/false' <<< "$effective"
grep -Fxq 'permittty no' <<< "$effective"
grep -Fxq 'allowagentforwarding no' <<< "$effective"
grep -Fxq 'authenticationmethods publickey' <<< "$effective"
grep -Fxq 'authorizedkeysfile /var/lib/remote-jump/.ssh/authorized_keys' <<< "$effective"
reload_attempted=true
systemctl reload "$service"
printf '%s:%s\n' "$host" "$port" > "$root/target"
committed=true
echo "VPS_JUMP_READY: permits only $host:$port; client-to-server authentication still needs client checks."
