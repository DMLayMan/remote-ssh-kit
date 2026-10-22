# Network deployment boundaries

- Scope is network infrastructure only: Tailscale, native OpenSSH, key authorization, a restricted VPS jump account, terminal access and identity verification.
- Do not add application installation, application configuration, account management, credentials, service-specific commands or branding to source, docs, tests, packages or outputs.
- Home machines are SSH CLIENTS. Never install or start Tailscale/tailscaled on the client. Server installation requires an explicit --on-server flag and a remote Mac account.
- Never run the server installer on the real client HOME for testing. Use disposable fixture HOME directories and fake privileged/network commands. No testing bypass flags may be shipped in production scripts.
- Preserve unrelated SSH keys, shell files, application data, services and installed versions. Changing a bound jump target or server input requires a deliberate migration.
- One setup.json contains deployment inputs and the inline clientPublicKey. No private keys, passwords or account secrets belong in Git, setup inputs, receipts or release packages.
- Dedicated roots: RemoteSSHClient, RemoteSSHServer and /opt/remote-ssh-kit; jump user remote-jump. Do not auto-import older installations or overwrite their launchers.
- Server readiness, successful client SSH, actual system installation, GUI authorization, reboot recovery and Windows hardware acceptance are separate claims. Report only checks actually performed.
- Keep current tree and fixed-allowlist release package generic. Old history and releases are kept only in private backups outside this repository. Never reintroduce old refs or real environment identifiers, including in tests. Run privacy checks on the index, all history and final package; real private denylist terms must remain outside the repository. No deployment to live hosts is implied by a source change or release.
- Supported targets: macOS 13+ server and Mac/Windows clients. Linux/systemd VPS must already have OpenSSH and an online Tailscale identity.
