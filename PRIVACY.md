# 隐私与发布检查

真实 IP、主机公钥及指纹、系统用户名、设备名、个人目录和验收记录，都属于部署资料。它们不一定是登录凭证，但仍不能进入公开 Git、测试断言、Issue、日志或 Release。个人 setup.json、回执和控制台导出文件放在仓库外，只经可信渠道传递。

## 本地维护

以下维护者命令针对源码克隆，通用安装包不包含开发检查工具。需要 Node.js、Git、zip/unzip，完整测试还需要 macOS 自带的系统工具。新克隆启用本地提交及推送检查：

```bash
git config core.hooksPath .githooks
node scripts/privacy-check.mjs --worktree
node scripts/privacy-check.mjs --index
node scripts/privacy-check.mjs --history
node --test tests/*.test.mjs
node scripts/build-release.mjs
node scripts/privacy-check.mjs --archive dist/remote-ssh-kit-v0.4.0-rc.3.zip
bash scripts/check-secrets.sh dist
```

工作区检查包含未忽略的新文件和所有已跟踪文件；index 检查读取真正暂存的字节；history 检查所有本地引用可达的提交、文件、提交身份与标签信息。pre-push 还运行固定版本 Gitleaks 全历史检查（需联网下载并校验官方工具摘要，不会全局安装）。CI 同样检查历史和构建产物。安装包先在临时目录生成，内容检查通过才写入 dist。自动检查只输出规则、记录序号和行号，不打印命中值、原文或可能包含个人信息的文件名。退出码 1 是发现问题，2 是检查无法完成，都必须阻止提交/发布。

项目样例只允许文档地址段、loopback 和少量明确的合成 tailnet 地址；新样例不得使用真实机器值。公钥与指纹样例用占位文本；测试需要密钥时运行时生成。规则只能发现所覆盖的模式，不能替代人工复核或专业凭证扫描。

## 私有标识清单

维护者可在仓库外创建一个 JSON 字符串数组，存放需要额外禁止出现的真实地址、用户名、设备名等。文件只对当前用户可读，不要放进 Git，也不要将值复制进测试。通过环境变量 REMOTE_SSH_PRIVATE_DENYLIST 指向该文件，所有上述命令会自动使用它。路径在仓库内、JSON 无效、清单为空或 Unix 权限过宽时检查失败。

这个清单也不能存放可用密码/令牌；凭证检查交给 Gitleaks 等专用工具。CI 只执行通用规则；维护者发布前必须额外使用自己的私有清单。不要为了 CI 把个人标识传到公开日志或仓库变量。

## 发布顺序

1. 从全新克隆获取全部分支和标签，检查历史引用，确认没有旧开发历史重新进入。
2. 执行通用检查与仓库外私有标识检查，再运行 Gitleaks 全历史扫描。Gitleaks 使用官方发行版，校验下载摘要；关闭源码内忽略标记。日志与 JSON 报告必须脱敏，保存在仓库外。
3. 运行测试并构建，检查最终 ZIP、SHA256SUMS、发布描述和自动生成的源码快照。固定白名单不允许加入个性化配置。
4. 将验证过的通用 ZIP 和校验文件发布。重新下载并对照校验和、逐文件比对源码，复查包内内容。
5. 公开仓库启用 GitHub secret scanning 与 push protection，并确认 CI 通过。它们不负责识别所有个人信息，仍要执行以上检查。

旧副本请保留未提交工作后重新克隆。不要 merge、push --all 或 push --tags 导入旧历史。旧历史备份仅保存在仓库外私有位置，不应作为公开仓库的新分支或标签。发现问题时先保持仓库私有，完成清理与复查后再公开；已被他人下载的副本不能保证回收。
