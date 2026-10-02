#!/bin/sh
# 卸载 Argus-Agent。需要 root。
#   sudo ./uninstall.sh            保留数据与配置
#   sudo ./uninstall.sh --purge    一并删除数据与配置
set -eu

PURGE=0
[ "${1:-}" = "--purge" ] && PURGE=1

[ "$(id -u)" = 0 ] || { echo "需要 root 权限" >&2; exit 1; }
say() { printf '  %s\n' "$*"; }

printf '\n==> 停止服务\n'
for u in argus-serve argus-parse; do
    systemctl disable --now "$u.service" >/dev/null 2>&1 || true
    say "$u"
done
rm -f /etc/systemd/system/argus-parse.service /etc/systemd/system/argus-serve.service
systemctl daemon-reload

printf '\n==> 移除审计规则\n'
if [ -x /usr/local/sbin/argus ]; then
    /usr/local/sbin/argus rules uninstall || say "移除失败，请手动删除 /etc/audit/rules.d/50-argus.rules"
else
    rm -f /etc/audit/rules.d/50-argus.rules
    if command -v augenrules >/dev/null 2>&1; then
        augenrules --load || say "重新加载规则失败，请手动执行: augenrules --load"
    fi
fi
say "若此前启用过 -e 2（规则锁定），需重启主机才能真正移除规则"

printf '\n==> 移除程序\n'
rm -f /usr/local/sbin/argus
say "/usr/local/sbin/argus"

if [ "$PURGE" = 1 ]; then
    printf '\n==> 删除数据与配置\n'
    rm -rf /var/lib/argus /etc/argus
    say "/var/lib/argus  /etc/argus"
    userdel argus >/dev/null 2>&1 || true
    say "已删除 argus 用户"
    printf '\n提示: /etc/audit/auditd.conf 中的 log_group 未改回，\n'
    printf '      如需恢复请使用安装时生成的 auditd.conf.argus-bak.* 备份。\n'
else
    printf '\n数据与配置已保留：/var/lib/argus  /etc/argus\n'
    printf '完全清除请执行: sudo ./uninstall.sh --purge\n'
fi
echo
