# Argus-Agent

**用 Linux 内核审计记录 AI Agent 和普通用户在主机上的真实行为，并归因到具体的人、会话与 Agent。**

AI 编码 Agent（Claude Code、Codex、Gemini CLI 等）带着 shell 权限跑在开发机上。你通常不知道它实际执行了哪些命令、改了哪些预期之外的文件。Agent 的自述不可信——它可能漏报、误报，或根本没意识到自己做了什么。

Argus 不问 Agent 做了什么，只看内核记录了什么。Agent 以普通用户身份运行时，**绕不过内核审计**。

---

## 安装

从 [Releases](https://github.com/xaigroking/argus-agent/releases) 下载对应架构的包：

```sh
tar xzf argus_v0.1.0_linux_amd64.tar.gz
cd argus_v0.1.0_linux_amd64
sha256sum -c ../SHA256SUMS      # 建议核对
sudo ./install.sh
```

安装后无需任何配置。前置条件：Linux + systemd + auditd（`apt install auditd` / `dnf install audit`）。

## 使用

```sh
argus query labels                     # 哪个 Agent 最活跃
argus query exec --label claude-code   # 该 Agent 执行了什么
argus query files                      # 受监控文件的访问
argus query sessions                   # 登录会话
argus verify                           # 自检
```

看板：<http://127.0.0.1:8873>（仅本机可访问，远程请用 SSH 隧道）。

进阶配置可选，升级不会覆盖：`/etc/argus/config.json`（保留期、监听地址）、`/etc/argus/agents.json`（要识别的 Agent 列表）。

---

## ⚠️ 当前状态：v0.1.0，未在真实 auditd 环境验证

代码已完成并通过测试，但**尚未在装有 auditd 的真实主机上跑过**：

| 已验证 | 未验证 |
|---|---|
| 解析器（410 万次 fuzz 无崩溃） | 真实 auditd 日志格式的全部变体 |
| 进程血缘归因（含 pid 复用、父进程退出断链） | 真实负载下的日志量与性能影响 |
| 端到端：日志 → 入库 → 查询 → 看板 | `pam_loginuid.so` 在各发行版各入口的实际覆盖 |
| 看板转义（反向验证：换成不转义的模板后测试会失败） | 日志轮转、安装脚本在真实系统上的行为 |
| 两个架构的静态二进制构建 | auditd 的 `log_group` 权限方案 |

装上后请先跑 `argus verify`，它会检查这些项并给出处置建议。
遇到问题欢迎提 issue，附上 `argus verify` 的输出。

---

## 文档

| 文档 | 内容 |
|---|---|
| [01 · 方案与架构](docs/01-方案与架构.md) | 定位、能力边界、架构、数据模型、安全设计 |
| [02 · 审计规则与验收](docs/02-审计规则与验收.md) | auditd 规则集、auid 核对清单、量化验收项 |
| [03 · 里程碑任务表](docs/03-里程碑任务表.md) | M0–M4 任务拆解与出口条件 |
| [04 · 部署与运维手册](docs/04-部署与运维手册.md) | 部署形态、安装、升级、排障 |

---

## 设计要点

| 要点 | 说明 |
|---|---|
| **不重造采集层** | auditd 由发行版维护、有 CVE 流程。我们的代码全部是它输出的只读消费者 |
| **做归因，不做检测** | 不与 Suricata / Zeek / Falco 竞争。空白的是"这次行为是谁/哪个 Agent 发起的" |
| **解析器是安全边界** | 被监控用户能控制进入日志的内容。强制参数化 SQL、输出转义、fuzz 测试 |
| **权限分离** | 单二进制多子命令，解析与展示均不以 root 运行；看板默认仅绑 `127.0.0.1` |
| **数据库是派生缓存** | 真相源是 `audit.log`。schema 变更时删库重建，不写迁移脚本 |

---

## 不做什么

| 不是 | 说明 |
|---|---|
| 不是录屏/录键 | 看不到终端原始字符，也看不到 Agent 与模型之间的对话内容 |
| 不是沙箱 | 只记录和展示，不拦截 |
| 不防 root | 被监控者拥有 root 时，任何主机内监控都不成立 |
| 不支持容器内部署 | 容器通常无法加载审计规则 |
| 不记录 tty 输入 | `pam_tty_audit` 可能捕获口令，本项目不提供该功能 |

能看到：执行了哪个程序及完整参数、访问了哪些受监控文件、登录会话、提权尝试、进程血缘。

看不到：shell 内置命令（`cd` / `export` 不走 execve）、脚本内部逻辑、访问的域名（属 S1）。

---

## 开发

```sh
go test ./...                                              # 全部测试
go test ./internal/auditlog/ -fuzz=FuzzParseLine -fuzztime=60s   # fuzz 解析器
./scripts/build-release.sh v0.1.0                          # 构建安装包
argus import --db /tmp/t.db /path/to/audit.log             # 离线导入日志用于调试
```

解析器处理被监控用户可控的内容，改动它必须附带测试语料并通过 fuzz。
测试语料在 `testdata/`，欢迎补充真实环境中遇到的日志格式（请脱敏）。

---

## 合规

对自然人的行为监控在多数法域受法律约束。部署前需明确：事先告知与依据、目的限定（仅用于安全审计，不得用于绩效考核）、最小化采集、保留期限、谁有权查看审计数据。

---

## 许可证

[Apache-2.0](LICENSE)
