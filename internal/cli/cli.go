// Package cli 实现各子命令。
package cli

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"text/tabwriter"
	"time"

	"github.com/xaigroking/argus-agent/internal/config"
	"github.com/xaigroking/argus-agent/internal/pipeline"
	"github.com/xaigroking/argus-agent/internal/server"
	"github.com/xaigroking/argus-agent/internal/store"
)

// Version 由构建时注入。
var Version = "dev"

const usage = `Argus — 基于内核审计的主机行为归因

用法：
  argus parse     [--config PATH]           跟随 audit.log 并入库（常驻，由 systemd 启动）
  argus serve     [--config PATH] [--listen ADDR]   启动本地只读看板
  argus query     <exec|files|sessions|top|labels|stats> [选项]
  argus verify    [--config PATH]           自检：审计状态、规则、auid 覆盖率、权限
  argus rules     <install|uninstall|show|status>   管理 auditd 规则（需 root）
  argus import    [--config PATH] FILE      离线导入一份 audit.log（用于测试与重建）
  argus version

说明：
  安装后无需任何配置即可运行。配置文件为可选覆盖：
    /etc/argus/config.json   主配置
    /etc/argus/agents.json   AI Agent 识别规则
`

// Main 是进程入口，返回退出码。
func Main(args []string) int {
	if len(args) < 2 {
		fmt.Fprint(os.Stderr, usage)
		return 2
	}
	cmd, rest := args[1], args[2:]
	var err error
	switch cmd {
	case "parse":
		err = cmdParse(rest)
	case "serve":
		err = cmdServe(rest)
	case "query":
		err = cmdQuery(rest)
	case "verify":
		return cmdVerify(rest)
	case "rules":
		err = cmdRules(rest)
	case "import":
		err = cmdImport(rest)
	case "version", "--version", "-v":
		fmt.Println("argus", Version)
		return 0
	case "help", "--help", "-h":
		fmt.Print(usage)
		return 0
	default:
		fmt.Fprintf(os.Stderr, "未知子命令 %q\n\n%s", cmd, usage)
		return 2
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "错误:", err)
		return 1
	}
	return 0
}

func newLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))
}

func loadConfig(path string) (config.Config, error) {
	cfg, err := config.Load(path)
	if err != nil {
		return cfg, err
	}
	if err := cfg.LoadAgents(""); err != nil {
		return cfg, err
	}
	return cfg, nil
}

// ---------- parse ----------

func cmdParse(args []string) error {
	fs := flag.NewFlagSet("parse", flag.ContinueOnError)
	cfgPath := fs.String("config", "", "配置文件路径")
	if err := fs.Parse(args); err != nil {
		return err
	}
	cfg, err := loadConfig(*cfgPath)
	if err != nil {
		return err
	}
	db, err := store.Open(cfg.DBPath)
	if err != nil {
		return err
	}
	defer db.Close()

	log := newLogger()
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	p := pipeline.New(cfg, db, log)
	if err := p.Run(ctx); err != nil {
		return err
	}
	m := p.Metrics()
	log.Info("已停止", "读取行数", m.LinesRead, "事件", m.Events, "写入", m.Written)
	return nil
}

// ---------- import ----------

func cmdImport(args []string) error {
	fs := flag.NewFlagSet("import", flag.ContinueOnError)
	cfgPath := fs.String("config", "", "配置文件路径")
	dbPath := fs.String("db", "", "覆盖数据库路径")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return fmt.Errorf("需要一个文件参数（用 - 表示标准输入）")
	}
	cfg, err := loadConfig(*cfgPath)
	if err != nil {
		return err
	}
	if *dbPath != "" {
		cfg.DBPath = *dbPath
	}

	var r io.Reader = os.Stdin
	if fs.Arg(0) != "-" {
		f, err := os.Open(fs.Arg(0))
		if err != nil {
			return err
		}
		defer f.Close()
		r = f
	}

	db, err := store.Open(cfg.DBPath)
	if err != nil {
		return err
	}
	defer db.Close()

	p := pipeline.New(cfg, db, newLogger())
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64<<10), 256<<10)
	for sc.Scan() {
		p.ProcessLine(sc.Text())
	}
	if err := sc.Err(); err != nil {
		return err
	}
	p.FinishInput()
	if err := p.Flush(); err != nil {
		return err
	}
	m := p.Metrics()
	fmt.Printf("读取 %d 行，跳过 %d 行，聚合 %d 个事件（其中 execve %d），写入 %d 条\n",
		m.LinesRead, m.LinesSkipped, m.Events, m.Execs, m.Written)
	return nil
}

// ---------- serve ----------

func cmdServe(args []string) error {
	fs := flag.NewFlagSet("serve", flag.ContinueOnError)
	cfgPath := fs.String("config", "", "配置文件路径")
	listen := fs.String("listen", "", "监听地址，默认 127.0.0.1:8873")
	if err := fs.Parse(args); err != nil {
		return err
	}
	cfg, err := loadConfig(*cfgPath)
	if err != nil {
		return err
	}
	if *listen != "" {
		cfg.Listen = *listen
	}
	// 只读打开：看板被攻破也无法篡改审计数据
	db, err := store.OpenReadOnly(cfg.DBPath)
	if err != nil {
		return err
	}
	defer db.Close()

	log := newLogger()
	s, err := server.New(db, cfg.Listen, log)
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	go func() {
		<-ctx.Done()
		sctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		s.Shutdown(sctx)
	}()
	return s.ListenAndServe()
}

// ---------- query ----------

func cmdQuery(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("用法: argus query <exec|files|sessions|top|labels|stats> [选项]")
	}
	sub, rest := args[0], args[1:]

	fs := flag.NewFlagSet("query", flag.ContinueOnError)
	cfgPath := fs.String("config", "", "配置文件路径")
	hours := fs.Int("hours", 24, "回溯小时数")
	label := fs.String("label", "", "按归因来源过滤，如 claude-code")
	auidF := fs.Int64("auid", -1, "按登录用户过滤")
	limit := fs.Int("limit", 50, "最大行数")
	if err := fs.Parse(rest); err != nil {
		return err
	}
	cfg, err := loadConfig(*cfgPath)
	if err != nil {
		return err
	}
	db, err := store.OpenReadOnly(cfg.DBPath)
	if err != nil {
		return err
	}
	defer db.Close()

	win := store.Window{
		Since: time.Now().Add(-time.Duration(*hours) * time.Hour),
		Label: *label, Limit: *limit,
	}
	if *auidF >= 0 {
		win = win.WithAUID(*auidF)
	}
	w := tabwriter.NewWriter(os.Stdout, 0, 2, 2, ' ', 0)
	defer w.Flush()

	switch sub {
	case "exec":
		rows, err := db.Execs(win)
		if err != nil {
			return err
		}
		fmt.Fprintln(w, "时间\tauid\t来源\t命令")
		for _, r := range rows {
			fmt.Fprintf(w, "%s\t%s\t%s\t%s\n",
				r.TS.Local().Format("01-02 15:04:05"), fmtAUID(r.AUID), r.Label, oneLine(r.Argv, 100))
		}
	case "files":
		rows, err := db.Files(win)
		if err != nil {
			return err
		}
		fmt.Fprintln(w, "时间\tauid\t来源\t规则\t路径")
		for _, r := range rows {
			fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\n",
				r.TS.Local().Format("01-02 15:04:05"), fmtAUID(r.AUID), r.Label, r.Key, oneLine(r.Paths, 80))
		}
	case "sessions":
		rows, err := db.Sessions(win)
		if err != nil {
			return err
		}
		fmt.Fprintln(w, "开始\t结束\tauid\t会话\t来源\t终端\t结果")
		for _, r := range rows {
			end := "-"
			if !r.End.IsZero() {
				end = r.End.Local().Format("01-02 15:04:05")
			}
			fmt.Fprintf(w, "%s\t%s\t%s\t%d\t%s\t%s\t%s\n",
				r.Start.Local().Format("01-02 15:04:05"), end, fmtAUID(r.AUID), r.SES, r.Addr, r.Terminal, r.Result)
		}
	case "top":
		rows, err := db.TopCommands(win, *limit)
		if err != nil {
			return err
		}
		fmt.Fprintln(w, "次数\t程序")
		for _, r := range rows {
			fmt.Fprintf(w, "%d\t%s\n", r.Count, r.Name)
		}
	case "labels":
		rows, err := db.LabelBreakdown(win)
		if err != nil {
			return err
		}
		fmt.Fprintln(w, "次数\t来源")
		for _, r := range rows {
			fmt.Fprintf(w, "%d\t%s\n", r.Count, r.Name)
		}
	case "stats":
		s, err := db.Stats()
		if err != nil {
			return err
		}
		fmt.Fprintf(w, "事件总数\t%d\n执行记录\t%d\n进程条目\t%d\n登录会话\t%d\n无法归因(auid unset)\t%d\n",
			s.Events, s.Execs, s.Procs, s.Sessions, s.UnsetAUID)
		if !s.Oldest.IsZero() {
			fmt.Fprintf(w, "最早事件\t%s\n最新事件\t%s\n",
				s.Oldest.Local().Format(time.DateTime), s.Newest.Local().Format(time.DateTime))
		}
	default:
		return fmt.Errorf("未知查询 %q", sub)
	}
	return nil
}

func fmtAUID(v int64) string {
	if v < 0 {
		return "unset"
	}
	return strconv.FormatInt(v, 10)
}

func oneLine(s string, max int) string {
	out := make([]rune, 0, max)
	for _, r := range s {
		if r == '\n' || r == '\r' || r == '\t' {
			r = ' '
		}
		// 控制字符可能来自被监控用户构造的文件名，终端输出前必须剔除
		if r < 0x20 || r == 0x7f {
			r = '.'
		}
		out = append(out, r)
		if len(out) >= max {
			return string(out) + "…"
		}
	}
	return string(out)
}
