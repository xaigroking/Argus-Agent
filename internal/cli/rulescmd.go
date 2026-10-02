package cli

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/xaigroking/argus-agent/internal/config"
	"github.com/xaigroking/argus-agent/internal/rules"
)

func cmdRules(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("用法: argus rules <install|uninstall|show|status>")
	}
	sub, rest := args[0], args[1:]

	fs := flag.NewFlagSet("rules", flag.ContinueOnError)
	path := fs.String("path", rules.InstallPath, "规则文件路径")
	dryRun := fs.Bool("dry-run", false, "只显示将要做的改动，不实际写入")
	noReload := fs.Bool("no-reload", false, "安装后不自动重新加载规则")
	if err := fs.Parse(rest); err != nil {
		return err
	}

	switch sub {
	case "show":
		os.Stdout.Write(rules.Embedded())
		return nil

	case "status":
		st, err := rules.QueryStatus()
		if err != nil {
			return err
		}
		fmt.Printf("enabled=%d  lost=%d  backlog=%d/%d  failure=%d\n",
			st.Enabled, st.Lost, st.Backlog, st.BacklogMax, st.Failure)
		keys, err := rules.LoadedKeys()
		if err != nil {
			return err
		}
		fmt.Println("已加载的 Argus 规则标记:")
		for _, k := range []string{rules.KeyExec, rules.KeySensitive, rules.KeyPriv, rules.KeySelfProtect} {
			mark := "缺失"
			if keys[k] {
				mark = "已加载"
			}
			fmt.Printf("  %-20s %s\n", k, mark)
		}
		return nil

	case "install":
		if os.Geteuid() != 0 && !*dryRun {
			return fmt.Errorf("需要 root 权限写入 %s", *path)
		}
		// 规则文件以 -D 开头会清空主机上其他用途的审计规则，先留底。
		if bk, err := rules.BackupExisting(filepath.Dir(config.DefaultPath)); err != nil {
			fmt.Fprintf(os.Stderr, "提示: 无法备份现有规则（%v），继续\n", err)
		} else {
			fmt.Println("已备份当前加载的规则到", bk)
		}
		changed, backup, err := rules.Install(*path, *dryRun)
		if err != nil {
			return err
		}
		if backup != "" {
			fmt.Println("已备份原规则文件到", backup)
		}
		switch {
		case *dryRun && changed:
			fmt.Println("将会写入", *path, "（--dry-run，未实际修改）")
			return nil
		case *dryRun:
			fmt.Println(*path, "已是最新，无需改动")
			return nil
		case !changed:
			fmt.Println(*path, "已是最新")
		default:
			fmt.Println("已写入", *path)
		}
		if *noReload {
			fmt.Println("跳过重新加载。请手动执行: augenrules --load")
			return nil
		}
		if err := rules.Reload(); err != nil {
			return fmt.Errorf("%w\n请手动执行: augenrules --load", err)
		}
		fmt.Println("规则已重新加载。用 argus rules status 确认。")
		return nil

	case "uninstall":
		if os.Geteuid() != 0 {
			return fmt.Errorf("需要 root 权限")
		}
		if err := rules.Uninstall(*path); err != nil {
			return err
		}
		fmt.Println("已移除", *path)
		if err := rules.Reload(); err != nil {
			fmt.Fprintln(os.Stderr, "提示:", err)
		}
		fmt.Println("注意: 若此前启用过 -e 2（规则锁定），需重启主机才能真正移除规则。")
		return nil

	default:
		return fmt.Errorf("未知子命令 %q", sub)
	}
}
