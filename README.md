# Remote SSH Kit

通用远程网络环境部署工具，当前源码候选版 **v0.4.0-rc.3**。只负责 Tailscale、OpenSSH、公钥授权、远端终端和连接验收。

```text
Mac / Windows 客户端 ──公网 SSH──> VPS 的 remote-jump
                                      │ Tailscale 私网 → TCP 22
                                      ▼
                               Mac mini 原生 SSH → 用户终端
```

客户端只需 OpenSSH，不安装本地 VPN。VPS 与 Mac mini 加入同一 tailnet；该通路不改变 Mac mini 的上网出口，也不提供匿名保证。输入准备完成后，每端执行一条安装命令；首次系统授权、管理员密码和回执传递仍需要用户完成。

[仓库与源码](https://github.com/DMLayMan/remote-ssh-kit) · [服务端准备与恢复](MAC-SERVER-SETUP.md) · [架构与边界](ARCHITECTURE-AND-RISKS.md) · [验证记录](verification.md)

## 0. 取得安装文件

本仓库为 **Public**，可直接下载源码，无需 GitHub 登录。VPS 初始化仍使用包内脚本直传或完整控制台脚本，不依赖在线下载源码。

在 GitHub 网页选择 **Code → Download ZIP** 并解压；也可通过 HTTPS 克隆：

```bash
git clone https://github.com/DMLayMan/remote-ssh-kit.git
cd remote-ssh-kit
```

旧版源码副本请保留未提交工作后重新克隆；不要合并或推送旧分支、旧标签。此次版本使用新的干净历史，不能沿用旧历史进行普通 pull。后续同一新历史内可使用 `git pull --ff-only`。后续命令均在包含 `scripts/` 的目录运行，Windows 命令在普通 PowerShell 运行。

若使用私有 fork 或日后改为私有仓库，须先在有权限的电脑完成认证，例如 `gh auth login` 后使用 GitHub CLI 克隆。匿名 raw URL 的 404 可能表示缺少访问权限，不应直接判定 VPS 网络故障；仍可使用下述通用安装包和控制台部署路径。

目标 Mac 也可接收操作者通过可信渠道提供的通用安装包，无需在服务器登录 GitHub。维护者在 Mac 执行 `node scripts/build-release.mjs`，将 `dist/` 中对应 ZIP 与 `SHA256SUMS` 一并提供；接收方核验校验和后解压。源码 ZIP 不自带此校验和。当前源码版本与已发布的 Release 可能不同，勿把旧安装包当作本次更新。

Mac 核验构建包：`shasum -a 256 -c SHA256SUMS`。Windows 用 `Get-FileHash .\remote-ssh-kit-v0.4.0-rc.3.zip -Algorithm SHA256` 与可信渠道收到的 `SHA256SUMS` 比对。校验和检测传输损坏，文件与校验和的来源仍须可信。不要把 GitHub token 放入脚本、命令 URL 或 JSON。

## 1. 在最终客户端准备身份

已有本工具的专用密钥会直接复用，私钥只保存在客户端。**已有授权要继续使用原公钥时，必须显式提供对应的原私钥；只复制公钥或回执不够。**

新客户端、新身份：

```bash
# Mac
bash scripts/install-mac-client.sh --prepare-only
```

```powershell
# Windows
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\Install-WindowsClient.ps1 -PrepareOnly
```

复用原客户端已有的专用身份，两端各选对应的一条，替换私钥路径（不是 `.pub` 文件）：

```bash
bash scripts/install-mac-client.sh --prepare-only --identity-file "/path/to/existing/id_ed25519"
```

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\Install-WindowsClient.ps1 -PrepareOnly -IdentityFile "C:\Existing Client\id_ed25519"
```

安装器先检查本机私钥的所有者、权限、类型与指纹，再复制到独立客户端目录，保留源文件；已有工具密钥不同时拒绝覆盖。无交互连接采用**无口令的专用 Ed25519 私钥**，不读取 SSH agent。加密私钥会立即拒绝，不弹入口令提示，也不解除原文件的加密；可选择生成新专用身份并重新准备服务器授权。Mac 源私钥须仅当前用户可访问（通常 `chmod 600`）；Windows 须检查文件的“安全”权限，不能向其他普通用户开放。

看到 `CLIENT_PREPARED` 后，将打印的 `clientPublicKey` 整行文本填入下一步 JSON。不要把私钥复制进仓库、JSON 或发到服务器。全新物理机器通常应生成新身份；只有明确要保留旧身份且已安全迁移对应私钥时才使用导入参数。

## 2. 准备一份私有 setup.json

复制 `setup.example.json`，填写五项连接信息：

```json
{
  "schemaVersion": 1,
  "jumpHost": "vps.example.com",
  "jumpPort": 22,
  "jumpTailnetIp": "100.80.0.1",
  "jumpHostKey": "ssh-ed25519 REPLACE_WITH_TRUSTED_PUBLIC_KEY",
  "clientPublicKey": "ssh-ed25519 REPLACE_WITH_CLIENT_PUBLIC_KEY"
}
```

这些是占位值，不能原样执行。VPS 主机公钥应从可信控制台读取；获取方法、系统版本、tailnet 策略与权限见 [提前准备](MAC-SERVER-SETUP.md#提前准备)。JSON 不含密码或私钥，但真实地址、公钥、设备身份仍属于私有部署资料。请放在仓库外，不要上传 GitHub、公开 Issue 或 Release；回执、控制台导出文件和验收记录同样处理。旧 JSON 请以本模板重新整理，额外字段会拒绝，不会被静默丢弃；保留旧文件。`clientPublicKeyFile` 兼容文件输入，但与内嵌公钥只能二选一。

## 3. 远端 Mac mini 一条命令初始化

将安装文件与 `setup.json` 放到目标 Mac。使用将来登录的普通系统账号执行，整条命令不要加 sudo：

```bash
bash scripts/deploy-mac-server.command --on-server --config ./setup.json
```

可追加 `--preflight` 先检查输入和既有授权冲突。安装器复用在线 Tailscale 和已开启的原生 SSH；缺少时引导安装或开启，必要时请用户完成系统权限与 tailnet 授权。

`SERVER_LOCAL_READY` 只代表服务器自身检查成功。将输出路径的 **`server-receipt.json`** 经可信渠道带回最终客户端，不能仅凭服务端就绪判定全链路成功。

## 4. 客户端一条命令配置跳板并验收

默认需要 VPS 已有 Linux/systemd/OpenSSH、在线 Tailscale 和可用 root SSH 管理入口；密码仅在 SSH 提示中输入。脚本会把包内 `init-vps.sh` 直接送到 VPS 执行，VPS 不下载仓库文件，也不需要 GitHub 账号。

```bash
# Mac
bash scripts/install-mac-client.sh --receipt "/path/to/server-receipt.json"
```

```powershell
# Windows
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\Install-WindowsClient.ps1 -ReceiptFile "C:\Setup\server-receipt.json"
```

若已有服务器回执、尚未在本工具准备客户端，可在上述命令同时加入 `--identity-file "/path/to/existing/id_ed25519"` 或 `-IdentityFile "C:\Existing Client\id_ed25519"`，一次完成身份导入和验收；**指纹不匹配会在修改配置、连接 VPS 前停止**。

安装器固定两端主机公钥，初始化受限 `remote-jump`，随后验证 SSH 认证及远端系统账号。看到 `CLIENT_CHAIN_READY` 才算这一轮全链路验收通过。重复运行会复用相同身份和目标。

### root SSH 不可用时：导出 VPS 控制台脚本

如果只能使用云厂商命令助手或救援控制台，执行以下命令准备本机配置并导出一个新文件：

```bash
bash scripts/install-mac-client.sh --receipt "/path/to/server-receipt.json" --export-vps-command ./vps-init.sh
```

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\Install-WindowsClient.ps1 -ReceiptFile "C:\Setup\server-receipt.json" -ExportVpsCommand .\vps-init.sh
```

同样可加身份导入参数。导出文件包含包内 VPS 脚本、公钥和目标信息，不含私钥或凭证；只创建新文件，重复导出请换名。它以 Base64 携带原始脚本，校验 SHA256 后执行，不依赖 VPS 访问 GitHub。

在**可信 VPS 控制台**以 root 执行导出文件的完整内容，或把文件传至 VPS 后运行 `bash /path/to/vps-init.sh`。不要只复制其中的 Base64 行。若控制台有限制，须完整传文件；截断或修改内容会校验失败。完成后回客户端运行下一节的检查命令。这个备用路径需要一次控制台操作，导出成功本身不代表 VPS 已部署。

若管理员已经配置好同一跳板，使用 `--no-provision` / `-NoProvision` 只写客户端配置，然后执行检查。不要通过关闭主机公钥验证或放宽转发范围解决连接失败。

## 5. 日常连接与验收状态

```bash
# Mac；PATH 未包含 ~/.local/bin 时使用 "$HOME/.local/bin/remote-ssh"
remote-ssh --check
remote-ssh
```

```powershell
# Windows；安装后打开新终端
remote-ssh -Check
remote-ssh
# 当前终端尚未刷新 PATH 时，可直接调用：
& "$env:LOCALAPPDATA\RemoteSSHClient\bin\remote-ssh.cmd" -Check
```

普通连接打开远端用户终端；检查模式只执行固定的系统身份命令。两段日常 SSH 都仅使用指定公钥，认证失败会退出，不等待隐藏的密码提示；首次 root 管理连接单独处理。

| 输出 / 状态 | 含义 |
| --- | --- |
| `CLIENT_PREPARED` | 本机身份已准备，尚未连接 |
| `SERVER_LOCAL_READY` | 服务器自身检查通过，客户端链路待验收 |
| `CLIENT_CONFIGURED_OFFLINE` / `pending` | 本机配置完成，尚未完成本轮全链路检查 |
| `SSH_CHAIN_READY` / `CLIENT_CHAIN_READY` / `ready` | 从当前客户端到指定服务器账号的 SSH 检查通过 |
| `checking` | 检查进行中或被中断，不代表成功 |
| `failed` | 本轮操作失败；查看 `stage`、`exitCode` 和终端错误 |

客户端最近一次状态保存在 Mac 的 `~/Library/Application Support/RemoteSSHClient/client-acceptance.json` 或 Windows 的 `%LOCALAPPDATA%\RemoteSSHClient\client-acceptance.json`，含 UTC 时间。配置重新导入会重置为 `pending`；后续检查失败会替换旧成功状态。它是最近一次检查记录，不是持续在线监控。服务端 `install-status.json` 中的客户端待验收提示不会远程同步，以实际客户端检查为准。

## 升级与故障恢复

取得新安装文件后，重跑步骤 4 即可更新客户端；跳板已配置时可用 `--no-provision` / `-NoProvision`，然后执行检查。服务端用原私有部署 JSON 重跑步骤 3。保留原身份、原 JSON 和回执；不要为了重试删除密钥或整个工具目录。

- `CLIENT_KEY_MISSING` / `CLIENT_KEY_MISMATCH`：提供回执对应的本机原私钥；没有原私钥时，先生成新身份，再明确安排服务器授权变更，不能直接修改回执指纹。
- `CLIENT_KEY_CONFLICT`：本工具已存在另一把密钥，停止覆盖；核对真正需要使用的客户端身份。
- `IDENTITY_LOCKED_OR_INVALID` / 权限错误：提供无口令专用 Ed25519 私钥并检查所有者/访问权限，源文件不会被自动修改。
- VPS root `Permission denied`：核对管理账号、密码和管理入口；只能控制台操作时使用导出路径。
- `remote-jump` 或服务器账号 `Permission denied`：核对公钥授权、来源限制与回执；不要输入 root 密码尝试日常跳板连接。
- 超时：按客户端 → VPS 公网 SSH、VPS → 目标私网 TCP 22 两段定位；目标在线不等于 TCP 22 放行。
- 主机公钥变化：通过可信控制台重新核对，不自动接受新公钥。
- `TARGET_CONFLICT` / 服务端 `INPUT_CHANGED`：当前部署绑定另一目标或输入；先安排迁移，不自动覆盖。

工具使用独立名称与目录，保留其他用户文件、原有服务和入口，不自动接管旧安装。一个 `remote-jump` 账号只绑定一个目标服务器。旧开发历史和发布只保存在仓库外的私有备份；公开历史从本版重新开始。当前源码与通用安装包仅包含网络工具。Windows 真机、首次系统授权与重启恢复等验证边界见 [验证记录](verification.md)。

## 发布与隐私检查

维护者须执行 [隐私与发布流程](PRIVACY.md)。构建会检查工作区和最终安装包；Git 历史检查、凭证扫描和下载后复核也必须通过。日常部署无需运行维护者检查。
