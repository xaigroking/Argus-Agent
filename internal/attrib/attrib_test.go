package attrib

import (
	"testing"
	"time"

	"github.com/xaigroking/argus-agent/internal/auditlog"
	"github.com/xaigroking/argus-agent/internal/config"
)

func ev(ms int64, pid, ppid int64, exe string, argv ...string) *auditlog.Event {
	return &auditlog.Event{
		Time: time.UnixMilli(ms),
		PID:  pid, PPID: ppid, Exe: exe, Argv: argv,
		AUID: 1000, SES: 3,
	}
}

func newTracker() *Tracker { return New(config.DefaultAgentRules(), 1000) }

func TestAgentSelfMatch(t *testing.T) {
	tr := newTracker()
	p := tr.OnExec(ev(1000, 100, 1, "/usr/local/bin/claude", "claude"))
	if p.Label != "claude-code" || p.LabelDepth != 0 {
		t.Errorf("label=%q depth=%d", p.Label, p.LabelDepth)
	}
}

// Agent 派生的子孙进程都应归到该 Agent 名下。
func TestInheritThroughDescendants(t *testing.T) {
	tr := newTracker()
	tr.OnExec(ev(1000, 100, 1, "/usr/local/bin/claude", "claude"))
	sh := tr.OnExec(ev(1100, 101, 100, "/bin/bash", "bash", "-c", "make"))
	if sh.Label != "claude-code" || sh.LabelDepth != 1 {
		t.Errorf("子进程 label=%q depth=%d", sh.Label, sh.LabelDepth)
	}
	gc := tr.OnExec(ev(1200, 102, 101, "/usr/bin/make", "make"))
	if gc.Label != "claude-code" || gc.LabelDepth != 2 {
		t.Errorf("孙进程 label=%q depth=%d", gc.Label, gc.LabelDepth)
	}
}

// 核心场景：父进程退出后 ppid 链断裂，但增量映射仍能保留归因。
func TestAncestrySurvivesParentExit(t *testing.T) {
	tr := newTracker()
	tr.OnExec(ev(1000, 100, 1, "/usr/local/bin/claude", "claude"))
	tr.OnExec(ev(1100, 101, 100, "/bin/bash", "bash"))
	// claude 退出，但我们早已记录了 101 的归因
	p, ok := tr.Lookup(101)
	if !ok || p.Label != "claude-code" {
		t.Fatalf("父进程退出后归因丢失: %+v", p)
	}
	// 101 再派生新进程，归因仍然成立
	child := tr.OnExec(ev(1300, 103, 101, "/usr/bin/git", "git", "push"))
	if child.Label != "claude-code" {
		t.Errorf("断链后 label=%q", child.Label)
	}
}

// pid 复用：新进程的父 pid 恰好等于一个已结束进程的 pid，
// 且父条目启动时间晚于子进程时，不得继承。
func TestPIDReuseDoesNotMisattribute(t *testing.T) {
	tr := newTracker()
	tr.OnExec(ev(1000, 100, 1, "/usr/local/bin/claude", "claude"))
	// pid 100 被复用为一个无关进程
	reused := tr.OnExec(ev(5000, 100, 1, "/usr/bin/cron", "cron"))
	if reused.Label != LabelUnknown {
		t.Errorf("复用后的 pid 100 label=%q，期望 unknown", reused.Label)
	}
	// 之后以 100 为父的进程应继承 cron（unknown），而不是 claude-code
	child := tr.OnExec(ev(5100, 200, 100, "/bin/sh", "sh"))
	if child.Label == "claude-code" {
		t.Error("pid 复用导致了错误归因")
	}
}

// 父进程记录晚于子进程（乱序或复用），不得继承。
func TestParentNewerThanChildNotInherited(t *testing.T) {
	tr := newTracker()
	tr.OnExec(ev(9000, 300, 1, "/usr/local/bin/claude", "claude"))
	child := tr.OnExec(ev(8000, 301, 300, "/bin/sh", "sh"))
	if child.Label != LabelUnknown {
		t.Errorf("label=%q，父进程更晚启动时不应继承", child.Label)
	}
}

func TestUnknownStaysUnknown(t *testing.T) {
	tr := newTracker()
	p := tr.OnExec(ev(1000, 400, 1, "/usr/bin/ls", "ls"))
	if p.Label != LabelUnknown {
		t.Errorf("label=%q", p.Label)
	}
	c := tr.OnExec(ev(1100, 401, 400, "/usr/bin/grep", "grep"))
	if c.Label != LabelUnknown || c.LabelDepth != 0 {
		t.Errorf("label=%q depth=%d", c.Label, c.LabelDepth)
	}
}

// 解释器启动的 Agent：exe 是 node，脚本名在 argv[0]。
func TestMatchViaArgv(t *testing.T) {
	tr := newTracker()
	p := tr.OnExec(ev(1000, 500, 1, "/usr/bin/node", "claude", "--print"))
	if p.Label != "claude-code" {
		t.Errorf("label=%q", p.Label)
	}
}

// 内存必须有界：大量进程下跟踪表不得无限增长。
func TestEvictionBoundsMemory(t *testing.T) {
	tr := New(config.DefaultAgentRules(), 1000)
	for i := int64(0); i < 20000; i++ {
		tr.OnExec(ev(1000+i, i, 1, "/usr/bin/true", "true"))
	}
	if tr.Len() > 1000 {
		t.Errorf("跟踪表大小 = %d，超过上限 1000", tr.Len())
	}
	if len(tr.order) > 2000 {
		t.Errorf("order 切片未回收，长度 = %d", len(tr.order))
	}
}

func TestUnsetPIDIgnored(t *testing.T) {
	tr := newTracker()
	e := ev(1000, 0, 1, "/usr/bin/ls", "ls")
	e.PID = auditlog.Unset
	if p := tr.OnExec(e); p != nil {
		t.Error("PID 为 Unset 时应返回 nil")
	}
}
