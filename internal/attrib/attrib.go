// Package attrib 做进程血缘归因：判断一条 execve 出自哪个 AI Agent 或哪条会话。
//
// 两个必须处理的现实问题：
//   - 父进程退出后子进程被 init 收养，ppid 链断裂。因此必须按事件顺序
//     增量维护祖先映射，不能事后回查。
//   - pid 会被复用。因此进程以 (pid, start_ts) 标识，新的 exec 关闭旧条目。
package attrib

import (
	"path/filepath"
	"strings"

	"github.com/xaigroking/argus-agent/internal/auditlog"
	"github.com/xaigroking/argus-agent/internal/config"
)

// LabelUnknown 表示无法确定来源。宁可标记未知，也不猜测。
const LabelUnknown = "unknown"

// Proc 是一次 execve 产生的进程快照。
type Proc struct {
	PID     int64
	PPID    int64
	StartTS int64 // UnixMilli
	EndTS   int64 // 0 表示未观察到结束
	Exe     string
	Argv    string
	AUID    int64
	SES     int64
	// Label 为归因结果：某个 Agent 名，或 LabelUnknown。
	Label string
	// LabelDepth 是到被识别 Agent 的层级，0 表示自身即 Agent。
	LabelDepth int
}

// Tracker 维护 pid → 祖先 的增量映射。非并发安全，由单个解析循环使用。
type Tracker struct {
	live    map[int64]*Proc
	rules   []config.AgentRule
	maxLive int
	// order 记录插入顺序，用于容量超限时淘汰最旧条目。
	order []int64
}

func New(rules []config.AgentRule, maxLive int) *Tracker {
	if maxLive < 1000 {
		maxLive = 1000
	}
	return &Tracker{
		live:    make(map[int64]*Proc, 1024),
		rules:   rules,
		maxLive: maxLive,
	}
}

// OnExec 处理一条 execve 事件，返回该进程的归因结果。
// 必须按事件时间顺序调用。
func (t *Tracker) OnExec(e *auditlog.Event) *Proc {
	if e.PID == auditlog.Unset {
		return nil
	}
	ts := e.Time.UnixMilli()

	p := &Proc{
		PID:     e.PID,
		PPID:    e.PPID,
		StartTS: ts,
		Exe:     e.Exe,
		Argv:    strings.Join(e.Argv, " "),
		AUID:    e.AUID,
		SES:     e.SES,
	}

	// 1. 自身是否就是某个 Agent
	if name := t.matchAgent(e.Exe, e.Comm, e.Argv); name != "" {
		p.Label, p.LabelDepth = name, 0
	} else if parent, ok := t.live[e.PPID]; ok && e.PPID != auditlog.Unset {
		// 2. 否则继承父进程的归因。
		//    父进程必须早于本进程启动，否则是 pid 复用导致的错误关联。
		if parent.StartTS <= ts && parent.Label != "" {
			p.Label = parent.Label
			if parent.Label == LabelUnknown {
				p.LabelDepth = 0
			} else {
				p.LabelDepth = parent.LabelDepth + 1
			}
		}
	}
	if p.Label == "" {
		p.Label = LabelUnknown
	}

	// pid 复用：同一 pid 的旧条目在此关闭
	if old, ok := t.live[e.PID]; ok {
		old.EndTS = ts
	} else {
		t.order = append(t.order, e.PID)
	}
	t.live[e.PID] = p
	t.evictIfNeeded()
	return p
}

// matchAgent 按可执行文件名匹配 Agent 规则。
// 同时比对 exe 的 basename 与 comm，前者更可靠，后者在 exe 缺失时兜底。
func (t *Tracker) matchAgent(exe, comm string, argv []string) string {
	base := ""
	if exe != "" {
		base = filepath.Base(exe)
	}
	for _, r := range t.rules {
		for _, want := range r.Exe {
			if want == "" {
				continue
			}
			if base == want || comm == want {
				return r.Name
			}
			// node/python 启动的 Agent：可执行文件是解释器，脚本名在 argv[0]
			if len(argv) > 0 && filepath.Base(argv[0]) == want {
				return r.Name
			}
		}
	}
	return ""
}

// evictIfNeeded 在超出容量时淘汰最旧的条目，保证内存有界。
func (t *Tracker) evictIfNeeded() {
	if len(t.live) <= t.maxLive {
		return
	}
	drop := len(t.live) - t.maxLive*3/4
	cut := 0
	for i := 0; i < len(t.order) && cut < drop; i++ {
		pid := t.order[i]
		if _, ok := t.live[pid]; ok {
			delete(t.live, pid)
			cut++
		}
		t.order[i] = -1
	}
	kept := t.order[:0]
	for _, pid := range t.order {
		if pid >= 0 {
			kept = append(kept, pid)
		}
	}
	t.order = kept
}

// Len 返回当前跟踪的进程数，用于观测。
func (t *Tracker) Len() int { return len(t.live) }

// Lookup 返回某 pid 当前的进程条目。
func (t *Tracker) Lookup(pid int64) (*Proc, bool) {
	p, ok := t.live[pid]
	return p, ok
}
