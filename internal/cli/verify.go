package cli

import (
	"flag"
	"fmt"
	"os"
	"os/exec"

	"github.com/xaigroking/argus-agent/internal/rules"
	"github.com/xaigroking/argus-agent/internal/store"
)

// cmdVerify 实现 M0 验收检查，返回进程退出码：0 全通过，1 有失败项。
func cmdVerify(args []string) int {
	fs := flag.NewFlagSet("verify", flag.ContinueOnError)
	cfgPath := fs.String("config", "", "配置文件路径")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	cfg, err := loadConfig(*cfgPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "错误:", err)
		return 1
	}

	v := &checker{}
	fmt.Println("Argus 自检")
	fmt.Println()

	// 1. auditd 是否安装
	if _, err := exec.LookPath("auditctl"); err != nil {
		v.fail("auditctl 不可用", "未安装 auditd。请先用发行版包管理器安装并启用 auditd")
	} else {
		v.ok("auditctl 可用")

		// 2. 内核审计状态
		st, err := rules.QueryStatus()
		if err != nil {
			v.fail("读取审计状态失败", err.Error())
		} else {
			if st.Enabled >= 1 {
				v.ok(fmt.Sprintf("内核审计已启用 (enabled=%d)", st.Enabled))
			} else {
				v.fail("内核审计未启用", "auditctl -s 显示 enabled=0")
			}
			if st.Lost == 0 {
				v.ok("无事件丢失 (lost=0)")
			} else {
				v.fail(fmt.Sprintf("已丢失 %d 条事件", st.Lost),
					"backlog 不足或消费过慢：增大 -b，或补充 never 排除规则")
			}
			if st.BacklogMax > 0 && st.Backlog*2 > st.BacklogMax {
				v.warn(fmt.Sprintf("backlog 使用率偏高 (%d/%d)", st.Backlog, st.BacklogMax))
			}
		}

		// 3. 规则是否加载
		if keys, err := rules.LoadedKeys(); err != nil {
			v.warn("无法读取已加载规则: " + err.Error())
		} else {
			missing := []string{}
			for _, k := range []string{rules.KeyExec, rules.KeySensitive, rules.KeyPriv} {
				if !keys[k] {
					missing = append(missing, k)
				}
			}
			if len(missing) == 0 {
				v.ok("Argus 规则已加载")
			} else {
				v.fail(fmt.Sprintf("规则未加载: %v", missing),
					"运行 sudo argus rules install && sudo augenrules --load")
			}
		}
	}

	// 4. 审计日志可读（parse 服务以 argus 用户运行，必须能读）
	if f, err := os.Open(cfg.AuditLog); err != nil {
		v.fail("无法读取 "+cfg.AuditLog, err.Error()+"（检查 ACL 或 auditd 的 log_group 配置）")
	} else {
		f.Close()
		v.ok("可读取 " + cfg.AuditLog)
	}

	// 5. 数据库与归因覆盖率
	db, err := store.OpenReadOnly(cfg.DBPath)
	if err != nil {
		v.warn("数据库尚不可用: " + err.Error())
	} else {
		defer db.Close()
		s, err := db.Stats()
		if err != nil {
			v.fail("查询数据库失败", err.Error())
		} else {
			v.ok(fmt.Sprintf("数据库可用：%d 条事件，%d 条执行记录", s.Events, s.Execs))
			if s.Events == 0 {
				v.warn("尚无数据。parse 服务是否在运行？规则是否已加载？")
			} else {
				pct := s.UnsetAUID * 100 / s.Events
				switch {
				case pct == 0:
					v.ok("auid 覆盖率 100%，全部行为可归因到人")
				case pct <= 5:
					v.warn(fmt.Sprintf("%d%% 的事件 auid 为 unset", pct))
				default:
					v.fail(fmt.Sprintf("%d%% 的事件无法归因（auid=unset）", pct),
						"检查各登录入口（sshd、login、systemd-user、cron）是否加载了 pam_loginuid.so")
				}
			}
		}
	}

	// 6. 不应以 root 运行解析与展示
	if os.Geteuid() == 0 {
		v.warn("当前以 root 运行。parse 与 serve 应以非特权的 argus 用户运行")
	}

	fmt.Println()
	fmt.Printf("通过 %d · 警告 %d · 失败 %d\n", v.nOK, v.nWarn, v.nFail)
	if v.nFail > 0 {
		return 1
	}
	return 0
}

type checker struct{ nOK, nWarn, nFail int }

func (c *checker) ok(msg string) {
	c.nOK++
	fmt.Printf("  [通过] %s\n", msg)
}

func (c *checker) warn(msg string) {
	c.nWarn++
	fmt.Printf("  [警告] %s\n", msg)
}

func (c *checker) fail(msg, hint string) {
	c.nFail++
	fmt.Printf("  [失败] %s\n         → %s\n", msg, hint)
}
