#!/usr/bin/env bash
# 构建各平台的一键安装包。
#   ./scripts/build-release.sh v0.1.0
#
# 每个包内含：静态二进制、install.sh、uninstall.sh、systemd 单元、
# 默认配置与审计规则。安装后无需任何额外配置。
set -euo pipefail

VERSION="${1:-dev}"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DIST="$ROOT/dist"

# auditd 是 Linux 内核子系统，因此只构建 Linux 目标。
PLATFORMS=(
    "linux/amd64"
    "linux/arm64"
)

rm -rf "$DIST"
mkdir -p "$DIST"
cd "$ROOT"

echo "构建 Argus $VERSION"

for p in "${PLATFORMS[@]}"; do
    GOOS="${p%/*}"
    GOARCH="${p#*/}"
    NAME="argus_${VERSION}_${GOOS}_${GOARCH}"
    STAGE="$DIST/$NAME"

    echo "  → $GOOS/$GOARCH"
    mkdir -p "$STAGE/systemd"

    # CGO_ENABLED=0 产出完全静态的二进制：
    # 目标机不需要任何运行时依赖，这也是选用纯 Go SQLite 实现的原因。
    CGO_ENABLED=0 GOOS="$GOOS" GOARCH="$GOARCH" \
        go build -trimpath \
        -ldflags "-s -w -X github.com/xaigroking/argus-agent/internal/cli.Version=$VERSION" \
        -o "$STAGE/argus" ./cmd/argus

    cp packaging/install.sh packaging/uninstall.sh "$STAGE/"
    cp packaging/systemd/*.service "$STAGE/systemd/"
    chmod +x "$STAGE/install.sh" "$STAGE/uninstall.sh"

    cat > "$STAGE/README.txt" <<EOF
Argus-Agent $VERSION — $GOOS/$GOARCH

安装（需要 root）：

    sudo ./install.sh

安装完成后即可使用，无需任何配置：

    argus query labels                    哪个 Agent 最活跃
    argus query exec --label claude-code  该 Agent 执行了什么
    argus verify                          自检
    http://127.0.0.1:8873                 本地看板

前置条件：Linux + systemd + auditd。
auditd 未安装时请先执行：
    Debian/Ubuntu   apt install auditd
    RHEL/Fedora     dnf install audit

卸载：
    sudo ./uninstall.sh            保留数据
    sudo ./uninstall.sh --purge    一并删除数据与配置

进阶配置（可选）：
    /etc/argus/config.json   保留期、监听地址等
    /etc/argus/agents.json   要识别的 AI Agent 列表

文档：https://github.com/xaigroking/argus-agent
EOF

    tar -czf "$DIST/$NAME.tar.gz" -C "$DIST" "$NAME"
    rm -rf "$STAGE"
done

cd "$DIST"
sha256sum ./*.tar.gz > SHA256SUMS

cat > RELEASE_NOTES.md <<EOF
## Argus-Agent $VERSION

用 Linux 内核审计记录 AI Agent 与普通用户在主机上的真实行为，并归因到具体的人、会话与 Agent。
Agent 以普通用户身份运行时绕不过内核审计，因此不依赖它的自述。

### 安装

下载对应架构的包，核对校验和后安装：

\`\`\`sh
tar xzf argus_${VERSION}_linux_amd64.tar.gz
cd argus_${VERSION}_linux_amd64
sudo ./install.sh
\`\`\`

安装后无需任何配置。看板在 http://127.0.0.1:8873（仅本机可访问）。

### 校验

\`\`\`sh
sha256sum -c SHA256SUMS
\`\`\`

### 常用命令

\`\`\`sh
argus query labels                     # 哪个 Agent 最活跃
argus query exec --label claude-code   # 该 Agent 执行了什么
argus query files                      # 受监控文件的访问
argus verify                           # 自检
\`\`\`

### 前置条件

Linux + systemd + auditd。不支持容器内部署（容器通常无法加载审计规则）。

### 已知边界

看不到 shell 内置命令（\`cd\`、\`export\` 不走 execve）、脚本内部逻辑、终端原始输入、访问的域名。
被监控者拥有 root 时，任何主机内监控都不成立。
EOF

echo
echo "产物："
ls -lh "$DIST"
