#!/bin/sh
# Argus-Agent 安装脚本。需要 root。
#
# 安装后无需任何配置即可运行：默认配置写入 /etc/argus/，
# 进阶用户可在那里修改，升级不会覆盖已有配置。
#
# 用法：
#   sudo ./install.sh                 安装并启动
#   sudo ./install.sh --no-start      只安装不启动
#   sudo ./install.sh --no-rules      不下发审计规则（自行管理规则时使用）
set -eu

BIN_DIR=/usr/local/sbin
CFG_DIR=/etc/argus
DATA_DIR=/var/lib/argus
UNIT_DIR=/etc/systemd/system
AUDITD_CONF=/etc/audit/auditd.conf
ARGUS_USER=argus

DO_START=1
DO_RULES=1
for arg in "$@"; do
    case "$arg" in
        --no-start) DO_START=0 ;;
        --no-rules) DO_RULES=0 ;;
        -h|--help) sed -n '2,12p' "$0"; exit 0 ;;
        *) echo "未知参数: $arg" >&2; exit 2 ;;
    esac
done

say()  { printf '  %s\n' "$*"; }
step() { printf '\n==> %s\n' "$*"; }
die()  { printf '错误: %s\n' "$*" >&2; exit 1; }

[ "$(id -u)" = 0 ] || die "需要 root 权限运行"

SRC=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
[ -f "$SRC/argus" ] || die "未找到 $SRC/argus"

# ---- 前置检查 ----
step "检查运行环境"
[ "$(uname -s)" = Linux ] || die "本工具仅支持 Linux（依赖内核审计子系统）"
command -v systemctl >/dev/null 2>&1 || die "未找到 systemd"
if ! command -v auditctl >/dev/null 2>&1; then
    die "未找到 auditd。请先安装：
      Debian/Ubuntu:  apt install auditd
      RHEL/Fedora:    dnf install audit
    然后重新运行本脚本。"
fi
say "Linux + systemd + auditd 均就绪"

if [ -f /.dockerenv ] || grep -qa 'container=' /proc/1/environ 2>/dev/null; then
    say "警告: 似乎在容器中运行。容器通常无法加载审计规则，归因将不可用。"
fi

# ---- 用户 ----
step "创建系统用户 $ARGUS_USER"
if id "$ARGUS_USER" >/dev/null 2>&1; then
    say "已存在"
else
    if command -v useradd >/dev/null 2>&1; then
        useradd --system --no-create-home --shell /usr/sbin/nologin "$ARGUS_USER"
    else
        adduser --system --no-create-home --disabled-login --shell /usr/sbin/nologin "$ARGUS_USER"
    fi
    say "已创建（无登录权限、无家目录）"
fi

# ---- 二进制 ----
step "安装程序"
install -d -m 0755 "$BIN_DIR"
install -m 0755 "$SRC/argus" "$BIN_DIR/argus"
say "$BIN_DIR/argus  ($("$BIN_DIR/argus" version))"

# ---- 目录与默认配置 ----
step "写入默认配置"
install -d -m 0755 "$CFG_DIR"
install -d -o "$ARGUS_USER" -g "$ARGUS_USER" -m 0750 "$DATA_DIR"
# 已有配置不覆盖：升级时保留用户的修改
if [ -f "$CFG_DIR/config.json" ]; then
    say "$CFG_DIR/config.json 已存在，保留不动"
else
    cat > "$CFG_DIR/config.json" <<'JSON'
{
  "audit_log": "/var/log/audit/audit.log",
  "db_path": "/var/lib/argus/argus.db",
  "state_path": "/var/lib/argus/state.json",
  "listen": "127.0.0.1:8873",
  "retention_days": 30,
  "max_tracked_procs": 200000,
  "flush_interval_sec": 2
}
JSON
    chmod 0644 "$CFG_DIR/config.json"
    say "$CFG_DIR/config.json"
fi
if [ -f "$CFG_DIR/agents.json" ]; then
    say "$CFG_DIR/agents.json 已存在，保留不动"
else
    cat > "$CFG_DIR/agents.json" <<'JSON'
[
  { "name": "claude-code",  "exe": ["claude"] },
  { "name": "codex",        "exe": ["codex"] },
  { "name": "gemini-cli",   "exe": ["gemini"] },
  { "name": "cursor-agent", "exe": ["cursor-agent"] },
  { "name": "aider",        "exe": ["aider"] },
  { "name": "opencode",     "exe": ["opencode"] },
  { "name": "copilot-cli",  "exe": ["copilot"] }
]
JSON
    chmod 0644 "$CFG_DIR/agents.json"
    say "$CFG_DIR/agents.json（可在此增删要识别的 Agent）"
fi

# ---- 审计日志读取权限 ----
# audit.log 默认为 0600 root。用 auditd 的 log_group 让解析服务可读：
# 这是唯一能在日志轮转后依然生效的办法（ACL 会在轮转时丢失）。
step "配置审计日志读取权限"
if [ -f "$AUDITD_CONF" ]; then
    CURRENT=$(sed -n 's/^[[:space:]]*log_group[[:space:]]*=[[:space:]]*//p' "$AUDITD_CONF" | tail -1)
    if [ "$CURRENT" = "$ARGUS_USER" ]; then
        say "auditd 的 log_group 已是 $ARGUS_USER"
    else
        cp -p "$AUDITD_CONF" "$AUDITD_CONF.argus-bak.$(date +%Y%m%d-%H%M%S)"
        say "已备份 $AUDITD_CONF"
        if [ -n "$CURRENT" ]; then
            sed -i "s/^[[:space:]]*log_group[[:space:]]*=.*/log_group = $ARGUS_USER/" "$AUDITD_CONF"
        else
            printf 'log_group = %s\n' "$ARGUS_USER" >> "$AUDITD_CONF"
        fi
        say "已设置 log_group = $ARGUS_USER"
        NEED_AUDITD_RESTART=1
    fi
else
    say "警告: 未找到 $AUDITD_CONF，需手动确保 $ARGUS_USER 可读审计日志"
fi

# ---- 审计规则 ----
if [ "$DO_RULES" = 1 ]; then
    step "下发审计规则"
    say "规则文件以 -D 开头，会清空主机上其他用途的审计规则。"
    "$BIN_DIR/argus" rules install || die "规则下发失败"
else
    step "跳过规则下发（--no-rules）"
fi

# ---- 重启 auditd 使 log_group 生效 ----
if [ "${NEED_AUDITD_RESTART:-0}" = 1 ]; then
    step "重启 auditd 使权限变更生效"
    # auditd 不响应常规 systemctl restart，用 service 命令
    if command -v service >/dev/null 2>&1 && service auditd restart >/dev/null 2>&1; then
        say "已重启"
    elif systemctl restart auditd >/dev/null 2>&1; then
        say "已重启"
    else
        say "警告: 自动重启失败，请手动执行: service auditd restart"
    fi
fi

# ---- systemd 单元 ----
step "安装 systemd 服务"
install -m 0644 "$SRC/systemd/argus-parse.service" "$UNIT_DIR/argus-parse.service"
install -m 0644 "$SRC/systemd/argus-serve.service" "$UNIT_DIR/argus-serve.service"
systemctl daemon-reload
say "argus-parse.service  argus-serve.service"

if [ "$DO_START" = 1 ]; then
    step "启动服务"
    systemctl enable --now argus-parse.service
    systemctl enable --now argus-serve.service
    say "已启动并设为开机自启"
    sleep 2
else
    step "跳过启动（--no-start）"
fi

# ---- 自检 ----
step "自检"
set +e
"$BIN_DIR/argus" verify
VERIFY=$?
set -e

LISTEN=$(sed -n 's/.*"listen"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' "$CFG_DIR/config.json" | head -1)
[ -n "$LISTEN" ] || LISTEN=127.0.0.1:8873

cat <<EOF

安装完成。

  看板    http://$LISTEN   （仅本机可访问；远程请用 SSH 隧道）
  命令行  argus query exec --hours 1
          argus query labels         # 哪个 Agent 最活跃
          argus query exec --label claude-code
  自检    argus verify
  日志    journalctl -u argus-parse -f

  配置    $CFG_DIR/config.json   $CFG_DIR/agents.json
  卸载    sudo $BIN_DIR/argus rules uninstall && sudo ./uninstall.sh

EOF

if [ "$VERIFY" != 0 ]; then
    echo "自检存在失败项，请按上面的提示处理后再用 argus verify 复查。"
    exit 1
fi
