package pipeline

import (
	"bufio"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/xaigroking/argus-agent/internal/config"
	"github.com/xaigroking/argus-agent/internal/store"
)

func runImport(t *testing.T, logPath string) *store.DB {
	t.Helper()
	dir := t.TempDir()
	cfg := config.Default()
	cfg.DBPath = filepath.Join(dir, "argus.db")
	cfg.StatePath = filepath.Join(dir, "state.json")

	db, err := store.Open(cfg.DBPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })

	f, err := os.Open(logPath)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	p := New(cfg, db, slog.New(slog.NewTextHandler(io.Discard, nil)))
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64<<10), 256<<10)
	for sc.Scan() {
		p.ProcessLine(sc.Text())
	}
	p.FinishInput()
	if err := p.Flush(); err != nil {
		t.Fatal(err)
	}
	return db
}

func labelCounts(t *testing.T, db *store.DB) map[string]int64 {
	t.Helper()
	rows, err := db.LabelBreakdown(store.Window{Since: longAgo(), Limit: 100})
	if err != nil {
		t.Fatal(err)
	}
	m := map[string]int64{}
	for _, r := range rows {
		m[r.Name] = r.Count
	}
	return m
}

// 端到端：一份模拟的 Agent 会话日志，归因结果必须正确。
func TestAgentSessionAttribution(t *testing.T) {
	db := runImport(t, "../../testdata/agent-session.log")

	got := labelCounts(t, db)
	if got["claude-code"] != 5 {
		t.Errorf("claude-code 执行次数 = %d，期望 5（claude 自身 + bash + go + git + curl）", got["claude-code"])
	}
	if got["codex"] != 2 {
		t.Errorf("codex 执行次数 = %d，期望 2", got["codex"])
	}
	// 用户手动执行的 -bash 与 ls 不应被归到任何 Agent
	if got["unknown"] != 2 {
		t.Errorf("unknown 执行次数 = %d，期望 2", got["unknown"])
	}
}

// 核心场景：Agent 的孙进程做了敏感操作，必须追溯到 Agent。
func TestAgentDescendantGitPush(t *testing.T) {
	db := runImport(t, "../../testdata/agent-session.log")
	rows, err := db.Execs(store.Window{Since: longAgo(), Label: "claude-code", Limit: 100})
	if err != nil {
		t.Fatal(err)
	}
	var sawPush, sawCurl bool
	for _, r := range rows {
		if r.Argv == "git push origin main" {
			sawPush = true
		}
		if r.Argv == "curl https://example.com" {
			sawCurl = true
		}
	}
	if !sawPush {
		t.Error("git push 未归因到 claude-code")
	}
	// curl 的父进程 bash 的父进程 claude 已退出，断链后仍应保持归因
	if !sawCurl {
		t.Error("父进程退出后，curl 未保持 claude-code 归因")
	}
}

// 非 execve 事件（文件访问）应继承发起进程的归因；
// 自身 execve 记录缺失时按父进程回退。
func TestFileEventInheritsLabel(t *testing.T) {
	db := runImport(t, "../../testdata/agent-session.log")
	rows, err := db.Files(store.Window{Since: longAgo(), Limit: 100})
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) == 0 {
		t.Fatal("没有文件访问记录")
	}
	for _, r := range rows {
		if r.Paths == "/etc/sudoers" && r.Label != "claude-code" {
			t.Errorf("/etc/sudoers 的归因 = %q，期望 claude-code", r.Label)
		}
	}
}

func TestSessionRecorded(t *testing.T) {
	db := runImport(t, "../../testdata/agent-session.log")
	rows, err := db.Sessions(store.Window{Since: longAgo(), Limit: 10})
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 {
		t.Fatalf("会话数 = %d，期望 1", len(rows))
	}
	s := rows[0]
	if s.AUID != 1000 || s.SES != 7 || s.Addr != "198.51.100.2" || s.Result != "success" {
		t.Errorf("会话信息错误: %+v", s)
	}
}

// 重复导入同一份日志不应产生重复事件（UNIQUE 约束 + INSERT OR IGNORE）。
func TestImportIsIdempotent(t *testing.T) {
	dir := t.TempDir()
	cfg := config.Default()
	cfg.DBPath = filepath.Join(dir, "argus.db")
	cfg.StatePath = filepath.Join(dir, "state.json")
	db, err := store.Open(cfg.DBPath)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	load := func() {
		f, err := os.Open("../../testdata/agent-session.log")
		if err != nil {
			t.Fatal(err)
		}
		defer f.Close()
		p := New(cfg, db, slog.New(slog.NewTextHandler(io.Discard, nil)))
		sc := bufio.NewScanner(f)
		for sc.Scan() {
			p.ProcessLine(sc.Text())
		}
		p.FinishInput()
		if err := p.Flush(); err != nil {
			t.Fatal(err)
		}
	}
	load()
	first, err := db.Stats()
	if err != nil {
		t.Fatal(err)
	}
	load()
	second, err := db.Stats()
	if err != nil {
		t.Fatal(err)
	}
	if first.Events != second.Events {
		t.Errorf("重复导入后事件数 %d → %d，应保持不变", first.Events, second.Events)
	}
}

// 含敌意内容的样本日志不得导致任何失败。
func TestHostileSampleImports(t *testing.T) {
	db := runImport(t, "../../testdata/sample.log")
	s, err := db.Stats()
	if err != nil {
		t.Fatal(err)
	}
	if s.Events == 0 {
		t.Fatal("没有导入任何事件")
	}
	rows, err := db.Execs(store.Window{Since: longAgo(), Limit: 100})
	if err != nil {
		t.Fatal(err)
	}
	var sawXSS bool
	for _, r := range rows {
		if r.Argv == `echo <script>alert(1)</script>` {
			sawXSS = true
		}
	}
	if !sawXSS {
		t.Error("十六进制编码的参数未被还原入库")
	}
}

func longAgo() time.Time { return time.Unix(0, 0) }
