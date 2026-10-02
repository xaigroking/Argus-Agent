package auditlog

import (
	"sort"
	"strconv"
	"strings"
)

// Unset 表示 auid/ses 未被 PAM 注入。出现它意味着该行为无法归因到具体的人，
// 通常是对应登录入口缺少 pam_loginuid.so。
const Unset int64 = -1

// Grouper 把按时间顺序到达的记录聚合成事件。
// 同一事件的记录在日志中连续出现，因此只需缓存当前一组。
type Grouper struct {
	cur  []*Record
	curT int64 // 当前组的时间（UnixMilli）
	curS int64 // 当前组的序列号
	have bool
}

// Add 加入一条记录。若它开启了新的一组，返回上一组聚合成的事件。
func (g *Grouper) Add(r *Record) *Event {
	t := r.Time.UnixMilli()
	var out *Event
	if g.have && (t != g.curT || r.Serial != g.curS) {
		out = g.flush()
	}
	if !g.have {
		g.curT, g.curS, g.have = t, r.Serial, true
	}
	if len(g.cur) < 64 { // 单个事件的记录数上限，防畸形输入撑爆内存
		g.cur = append(g.cur, r)
	}
	return out
}

// Flush 结束当前组并返回事件，没有则返回 nil。
func (g *Grouper) Flush() *Event { return g.flush() }

func (g *Grouper) flush() *Event {
	if !g.have || len(g.cur) == 0 {
		g.have, g.cur = false, nil
		return nil
	}
	e := buildEvent(g.cur)
	g.cur, g.have = nil, false
	return e
}

func buildEvent(recs []*Record) *Event {
	e := &Event{
		Time:    recs[0].Time,
		Serial:  recs[0].Serial,
		Records: recs,
		AUID:    Unset,
		SES:     Unset,
		UID:     Unset,
		PID:     Unset,
		PPID:    Unset,
	}
	type pathItem struct {
		item int
		name string
	}
	var paths []pathItem

	for _, r := range recs {
		if r.Truncated {
			e.Truncated = true
		}
		switch r.Type {
		case "SYSCALL":
			e.Type = "SYSCALL"
			e.AUID = intField(r.Fields, "auid")
			e.UID = intField(r.Fields, "uid")
			e.SES = intField(r.Fields, "ses")
			e.PID = intField(r.Fields, "pid")
			e.PPID = intField(r.Fields, "ppid")
			e.Exe = r.Fields["exe"]
			e.Comm = r.Fields["comm"]
			e.TTY = r.Fields["tty"]
			e.Key = normalizeKey(r.Fields["key"])
			e.Success = r.Fields["success"] == "yes"
		case "EXECVE":
			if len(r.Args) > 0 {
				e.Argv = r.Args
			}
		case "CWD":
			e.CWD = r.Fields["cwd"]
		case "PATH":
			if name := r.Fields["name"]; name != "" && len(paths) < MaxPathsPerEvent {
				paths = append(paths, pathItem{item: int(intField(r.Fields, "item")), name: name})
			}
		case "PROCTITLE":
			if len(e.Argv) == 0 {
				if p := r.Fields["proctitle"]; p != "" {
					e.Argv = strings.Fields(p)
				}
			}
		}
		// 登录类与用户命令类记录：字段在主记录或嵌套 msg 中。
		switch r.Type {
		case "USER_LOGIN", "USER_LOGOUT", "USER_AUTH", "USER_START", "USER_END", "USER_CMD", "LOGIN":
			if e.Type == "" {
				e.Type = r.Type
			}
			if v := intField(r.Fields, "auid"); v != Unset {
				e.AUID = v
			}
			if v := intField(r.Fields, "ses"); v != Unset {
				e.SES = v
			}
			if v := intField(r.Fields, "uid"); v != Unset && e.UID == Unset {
				e.UID = v
			}
			if v := intField(r.Fields, "pid"); v != Unset && e.PID == Unset {
				e.PID = v
			}
			if a := r.Fields["addr"]; a != "" && a != "?" {
				e.Addr = a
			} else if h := r.Fields["hostname"]; h != "" && h != "?" {
				e.Addr = h
			}
			if t := r.Fields["terminal"]; t != "" {
				e.Terminal = t
			}
			if res := r.Fields["res"]; res != "" {
				e.Result = res
			}
			if e.Exe == "" {
				e.Exe = r.Fields["exe"]
			}
			// LOGIN 记录用 new-auid/new-ses 表示本次登录的归属
			if v := intField(r.Fields, "new-auid"); v != Unset {
				e.AUID = v
			}
			if v := intField(r.Fields, "new-ses"); v != Unset {
				e.SES = v
			}
		}
	}

	if e.Type == "" {
		e.Type = recs[0].Type
	}
	sort.Slice(paths, func(i, j int) bool { return paths[i].item < paths[j].item })
	for _, p := range paths {
		e.Paths = append(e.Paths, p.name)
	}
	return e
}

// normalizeKey 处理一条事件命中多个规则时的 key（以 0x01 分隔）。
func normalizeKey(k string) string {
	if k == "" {
		return ""
	}
	return strings.ReplaceAll(k, "\x01", ",")
}

// intField 读取整数字段，unset / 4294967295 / 缺失一律返回 Unset。
func intField(f map[string]string, key string) int64 {
	v, ok := f[key]
	if !ok || v == "" || v == "unset" || v == "?" || v == "(none)" {
		return Unset
	}
	n, err := strconv.ParseInt(v, 10, 64)
	if err != nil {
		return Unset
	}
	// 32 位下的 (uid_t)-1，历史上用于表示 unset
	if n == 4294967295 {
		return Unset
	}
	return n
}
