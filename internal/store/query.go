package store

import (
	"fmt"
	"time"
)

// Window 是查询的时间与过滤条件。
type Window struct {
	Since time.Time
	Until time.Time
	// AUID 为 nil 表示不按用户过滤。用指针而非哨兵值：
	// 零值必须等于“不过滤”，否则会静默筛成 auid=0（root）而查不到任何数据。
	AUID  *int64
	Label string
	Limit int
}

// WithAUID 返回带用户过滤的窗口。
func (w Window) WithAUID(v int64) Window { w.AUID = &v; return w }

// auidFilter 返回传给 SQL 的两个参数：是否过滤、过滤值。
func (w Window) auidFilter() (int, int64) {
	if w.AUID == nil {
		return 0, 0
	}
	return 1, *w.AUID
}

func (w Window) norm() (int64, int64, int) {
	since := w.Since
	if since.IsZero() {
		since = time.Now().AddDate(0, 0, -1)
	}
	until := w.Until
	if until.IsZero() {
		until = time.Now().Add(time.Minute)
	}
	limit := w.Limit
	if limit <= 0 || limit > 5000 {
		limit = 200
	}
	return since.UnixMilli(), until.UnixMilli(), limit
}

// ExecRow 是一条执行记录。
type ExecRow struct {
	TS    time.Time
	AUID  int64
	SES   int64
	PID   int64
	Exe   string
	Argv  string
	CWD   string
	Label string
}

// Execs 返回时间倒序的执行记录。
func (d *DB) Execs(w Window) ([]ExecRow, error) {
	since, until, limit := w.norm()
	afOn, afVal := w.auidFilter()
	// 过滤条件通过参数传入，SQL 文本保持固定，不做字符串拼接。
	rows, err := d.sql.Query(`
		SELECT ts, auid, ses, pid, exe, argv, cwd, label
		FROM events
		WHERE ts >= ? AND ts <= ?
		  AND akey LIKE 'argus_exec%'
		  AND (? = 0 OR auid = ?)
		  AND (? = ''  OR label = ?)
		ORDER BY ts DESC, id DESC
		LIMIT ?`,
		since, until, afOn, afVal, w.Label, w.Label, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []ExecRow
	for rows.Next() {
		var r ExecRow
		var ms int64
		var exe, argv, cwd, label nullString
		if err := rows.Scan(&ms, &r.AUID, &r.SES, &r.PID, &exe, &argv, &cwd, &label); err != nil {
			return nil, err
		}
		r.TS = time.UnixMilli(ms)
		r.Exe, r.Argv, r.CWD, r.Label = exe.v, argv.v, cwd.v, label.v
		out = append(out, r)
	}
	return out, rows.Err()
}

// FileRow 是一条文件访问记录。
type FileRow struct {
	TS    time.Time
	AUID  int64
	Exe   string
	Paths string
	Key   string
	Label string
}

// Files 返回命中文件监控规则的记录。
func (d *DB) Files(w Window) ([]FileRow, error) {
	since, until, limit := w.norm()
	afOn, afVal := w.auidFilter()
	rows, err := d.sql.Query(`
		SELECT ts, auid, exe, paths, akey, label
		FROM events
		WHERE ts >= ? AND ts <= ?
		  AND akey NOT LIKE 'argus_exec%' AND akey != ''
		  AND paths != ''
		  AND (? = 0 OR auid = ?)
		  AND (? = ''  OR label = ?)
		ORDER BY ts DESC, id DESC
		LIMIT ?`,
		since, until, afOn, afVal, w.Label, w.Label, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []FileRow
	for rows.Next() {
		var r FileRow
		var ms int64
		var exe, paths, key, label nullString
		if err := rows.Scan(&ms, &r.AUID, &exe, &paths, &key, &label); err != nil {
			return nil, err
		}
		r.TS = time.UnixMilli(ms)
		r.Exe, r.Paths, r.Key, r.Label = exe.v, paths.v, key.v, label.v
		out = append(out, r)
	}
	return out, rows.Err()
}

// TopRow 是一行频次统计。
type TopRow struct {
	Name  string
	Count int64
}

// TopCommands 返回执行次数最多的程序。
func (d *DB) TopCommands(w Window, n int) ([]TopRow, error) {
	since, until, _ := w.norm()
	afOn, afVal := w.auidFilter()
	if n <= 0 || n > 200 {
		n = 20
	}
	rows, err := d.sql.Query(`
		SELECT exe, COUNT(*) AS c
		FROM events
		WHERE ts >= ? AND ts <= ? AND akey LIKE 'argus_exec%' AND exe != ''
		  AND (? = 0 OR auid = ?)
		  AND (? = ''  OR label = ?)
		GROUP BY exe ORDER BY c DESC LIMIT ?`,
		since, until, afOn, afVal, w.Label, w.Label, n)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanTop(rows)
}

// LabelBreakdown 按归因标签统计执行次数，是"哪个 Agent 最活跃"的直接答案。
func (d *DB) LabelBreakdown(w Window) ([]TopRow, error) {
	since, until, _ := w.norm()
	rows, err := d.sql.Query(`
		SELECT COALESCE(NULLIF(label,''),'unknown') AS l, COUNT(*) AS c
		FROM events
		WHERE ts >= ? AND ts <= ? AND akey LIKE 'argus_exec%'
		GROUP BY l ORDER BY c DESC LIMIT 50`, since, until)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanTop(rows)
}

// UserBreakdown 按 auid 统计执行次数。
func (d *DB) UserBreakdown(w Window) ([]TopRow, error) {
	since, until, _ := w.norm()
	rows, err := d.sql.Query(`
		SELECT CAST(auid AS TEXT), COUNT(*) AS c
		FROM events
		WHERE ts >= ? AND ts <= ? AND akey LIKE 'argus_exec%'
		GROUP BY auid ORDER BY c DESC LIMIT 50`, since, until)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanTop(rows)
}

func scanTop(rows interface {
	Next() bool
	Scan(...any) error
	Err() error
}) ([]TopRow, error) {
	var out []TopRow
	for rows.Next() {
		var r TopRow
		var name nullString
		if err := rows.Scan(&name, &r.Count); err != nil {
			return nil, err
		}
		r.Name = name.v
		out = append(out, r)
	}
	return out, rows.Err()
}

// SessionInfo 是一次登录会话。
type SessionInfo struct {
	SES      int64
	AUID     int64
	Start    time.Time
	End      time.Time
	Addr     string
	Terminal string
	Result   string
}

func (d *DB) Sessions(w Window) ([]SessionInfo, error) {
	since, until, limit := w.norm()
	afOn, afVal := w.auidFilter()
	rows, err := d.sql.Query(`
		SELECT ses, auid, start_ts, end_ts, addr, terminal, result
		FROM sessions
		WHERE start_ts >= ? AND start_ts <= ?
		  AND (? = 0 OR auid = ?)
		ORDER BY start_ts DESC LIMIT ?`,
		since, until, afOn, afVal, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []SessionInfo
	for rows.Next() {
		var s SessionInfo
		var start int64
		var end nullInt
		var addr, term, res nullString
		if err := rows.Scan(&s.SES, &s.AUID, &start, &end, &addr, &term, &res); err != nil {
			return nil, err
		}
		s.Start = time.UnixMilli(start)
		if end.valid {
			s.End = time.UnixMilli(end.v)
		}
		s.Addr, s.Terminal, s.Result = addr.v, term.v, res.v
		out = append(out, s)
	}
	return out, rows.Err()
}

// Stats 是概览数据。
type Stats struct {
	Events    int64
	Execs     int64
	Procs     int64
	Sessions  int64
	UnsetAUID int64 // auid 缺失的事件数——归因盲区的直接度量
	Oldest    time.Time
	Newest    time.Time
}

func (d *DB) Stats() (Stats, error) {
	var s Stats
	q := func(dst *int64, sql string) error { return d.sql.QueryRow(sql).Scan(dst) }
	if err := q(&s.Events, `SELECT COUNT(*) FROM events`); err != nil {
		return s, err
	}
	if err := q(&s.Execs, `SELECT COUNT(*) FROM events WHERE akey LIKE 'argus_exec%'`); err != nil {
		return s, err
	}
	if err := q(&s.Procs, `SELECT COUNT(*) FROM processes`); err != nil {
		return s, err
	}
	if err := q(&s.Sessions, `SELECT COUNT(*) FROM sessions`); err != nil {
		return s, err
	}
	if err := q(&s.UnsetAUID, `SELECT COUNT(*) FROM events WHERE auid < 0`); err != nil {
		return s, err
	}
	var lo, hi nullInt
	if err := d.sql.QueryRow(`SELECT MIN(ts), MAX(ts) FROM events`).Scan(&lo, &hi); err != nil {
		return s, err
	}
	if lo.valid {
		s.Oldest = time.UnixMilli(lo.v)
	}
	if hi.valid {
		s.Newest = time.UnixMilli(hi.v)
	}
	return s, nil
}

// UnsetAUIDRatio 返回归因盲区比例，用于 verify 的 auid 覆盖率检查。
func (d *DB) UnsetAUIDRatio() (float64, int64, error) {
	s, err := d.Stats()
	if err != nil || s.Events == 0 {
		return 0, 0, err
	}
	return float64(s.UnsetAUID) / float64(s.Events), s.UnsetAUID, nil
}

// nullString / nullInt 用于安全扫描可空列。
type nullString struct{ v string }

func (n *nullString) Scan(src any) error {
	switch t := src.(type) {
	case nil:
		n.v = ""
	case string:
		n.v = t
	case []byte:
		n.v = string(t)
	default:
		n.v = fmt.Sprint(t)
	}
	return nil
}

type nullInt struct {
	v     int64
	valid bool
}

func (n *nullInt) Scan(src any) error {
	switch t := src.(type) {
	case nil:
		n.v, n.valid = 0, false
	case int64:
		n.v, n.valid = t, true
	case float64:
		n.v, n.valid = int64(t), true
	default:
		n.v, n.valid = 0, false
	}
	return nil
}
