// Package store 封装 SQLite 存储。
//
// 重要：数据库是派生缓存，真相源是 audit.log。schema 变更时直接删库重建，
// 不写迁移脚本（见 docs/01-方案与架构.md §2.3）。
//
// 安全约束：所有 SQL 必须参数化，禁止任何形式的字符串拼接。
package store

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"time"

	_ "modernc.org/sqlite" // 纯 Go 实现，无需 cgo，便于交叉编译静态二进制
)

// SchemaVersion 变更时数据库会被重建。
const SchemaVersion = 1

type DB struct {
	sql *sql.DB
	ro  bool
}

const schema = `
CREATE TABLE IF NOT EXISTS meta (
  k TEXT PRIMARY KEY,
  v TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS events (
  id        INTEGER PRIMARY KEY AUTOINCREMENT,
  ts        INTEGER NOT NULL,
  serial    INTEGER NOT NULL,
  type      TEXT NOT NULL,
  auid      INTEGER,
  uid       INTEGER,
  ses       INTEGER,
  pid       INTEGER,
  ppid      INTEGER,
  exe       TEXT,
  comm      TEXT,
  argv      TEXT,
  cwd       TEXT,
  tty       TEXT,
  akey      TEXT,
  success   INTEGER,
  paths     TEXT,
  addr      TEXT,
  result    TEXT,
  label     TEXT,
  truncated INTEGER NOT NULL DEFAULT 0,
  UNIQUE(ts, serial, type, pid)
);
CREATE INDEX IF NOT EXISTS idx_events_ts    ON events(ts);
CREATE INDEX IF NOT EXISTS idx_events_auid  ON events(auid, ts);
CREATE INDEX IF NOT EXISTS idx_events_label ON events(label, ts);
CREATE INDEX IF NOT EXISTS idx_events_key   ON events(akey, ts);

CREATE TABLE IF NOT EXISTS processes (
  pid         INTEGER NOT NULL,
  start_ts    INTEGER NOT NULL,
  end_ts      INTEGER,
  ppid        INTEGER,
  exe         TEXT,
  argv        TEXT,
  auid        INTEGER,
  ses         INTEGER,
  label       TEXT,
  label_depth INTEGER,
  PRIMARY KEY (pid, start_ts)
);
CREATE INDEX IF NOT EXISTS idx_proc_label ON processes(label, start_ts);

CREATE TABLE IF NOT EXISTS sessions (
  ses       INTEGER PRIMARY KEY,
  auid      INTEGER,
  start_ts  INTEGER,
  end_ts    INTEGER,
  addr      TEXT,
  terminal  TEXT,
  result    TEXT
);
`

// Open 打开（必要时创建）数据库。schema 版本不符时整库重建。
func Open(path string) (*DB, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return nil, fmt.Errorf("创建数据目录: %w", err)
	}
	db, err := openAt(path, false)
	if err != nil {
		return nil, err
	}
	ver, _ := db.GetMetaInt("schema_version")
	if ver != 0 && ver != SchemaVersion {
		db.sql.Close()
		// 数据库是派生缓存，版本不符直接重建
		if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
			return nil, fmt.Errorf("删除旧数据库: %w", err)
		}
		for _, suffix := range []string{"-wal", "-shm"} {
			os.Remove(path + suffix)
		}
		if db, err = openAt(path, false); err != nil {
			return nil, err
		}
	}
	if _, err := db.sql.Exec(schema); err != nil {
		db.sql.Close()
		return nil, fmt.Errorf("建表: %w", err)
	}
	if err := db.SetMeta("schema_version", fmt.Sprint(SchemaVersion)); err != nil {
		db.sql.Close()
		return nil, err
	}
	return db, nil
}

// OpenReadOnly 以只读方式打开，供展示层使用——
// 即使展示层被攻破也无法修改审计数据。
func OpenReadOnly(path string) (*DB, error) {
	if _, err := os.Stat(path); err != nil {
		return nil, fmt.Errorf("数据库不存在 %s（parse 服务是否已运行？）", path)
	}
	return openAt(path, true)
}

func openAt(path string, readonly bool) (*DB, error) {
	dsn := "file:" + path + "?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)&_pragma=foreign_keys(1)"
	if readonly {
		dsn += "&mode=ro"
	}
	sdb, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("打开数据库: %w", err)
	}
	sdb.SetMaxOpenConns(1) // SQLite 单写者；串行化避免 busy
	if err := sdb.Ping(); err != nil {
		sdb.Close()
		return nil, fmt.Errorf("连接数据库: %w", err)
	}
	return &DB{sql: sdb, ro: readonly}, nil
}

func (d *DB) Close() error { return d.sql.Close() }
func (d *DB) SQL() *sql.DB { return d.sql }

func (d *DB) SetMeta(k, v string) error {
	_, err := d.sql.Exec(`INSERT INTO meta(k,v) VALUES(?,?)
		ON CONFLICT(k) DO UPDATE SET v=excluded.v`, k, v)
	return err
}

func (d *DB) GetMeta(k string) (string, error) {
	var v string
	err := d.sql.QueryRow(`SELECT v FROM meta WHERE k=?`, k).Scan(&v)
	if err == sql.ErrNoRows {
		return "", nil
	}
	return v, err
}

func (d *DB) GetMetaInt(k string) (int, error) {
	v, err := d.GetMeta(k)
	if err != nil || v == "" {
		return 0, err
	}
	var n int
	_, err = fmt.Sscanf(v, "%d", &n)
	return n, err
}

// EventRow 是待写入的一条事件。
type EventRow struct {
	TS, Serial                     int64
	Type                           string
	AUID, UID, SES, PID, PPID      int64
	Exe, Comm, Argv, CWD, TTY, Key string
	Success                        bool
	Paths, Addr, Result, Label     string
	Truncated                      bool
}

// ProcRow 是待写入的一个进程条目。
type ProcRow struct {
	PID, StartTS, EndTS, PPID int64
	Exe, Argv                 string
	AUID, SES                 int64
	Label                     string
	LabelDepth                int
}

// SessionRow 是一次登录会话。
type SessionRow struct {
	SES, AUID, StartTS, EndTS int64
	Addr, Terminal, Result    string
}

// Batch 在单个事务中写入一批数据。批量写入是 SQLite 吞吐的关键。
type Batch struct {
	Events   []EventRow
	Procs    []ProcRow
	Sessions []SessionRow
}

func (b *Batch) Len() int { return len(b.Events) + len(b.Procs) + len(b.Sessions) }
func (b *Batch) Reset()   { b.Events, b.Procs, b.Sessions = b.Events[:0], b.Procs[:0], b.Sessions[:0] }

func (d *DB) WriteBatch(b *Batch) error {
	if d.ro {
		return fmt.Errorf("数据库以只读方式打开")
	}
	if b.Len() == 0 {
		return nil
	}
	tx, err := d.sql.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	if len(b.Events) > 0 {
		st, err := tx.Prepare(`INSERT OR IGNORE INTO events
			(ts,serial,type,auid,uid,ses,pid,ppid,exe,comm,argv,cwd,tty,akey,success,paths,addr,result,label,truncated)
			VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`)
		if err != nil {
			return err
		}
		for i := range b.Events {
			e := &b.Events[i]
			if _, err := st.Exec(e.TS, e.Serial, e.Type, e.AUID, e.UID, e.SES, e.PID, e.PPID,
				e.Exe, e.Comm, e.Argv, e.CWD, e.TTY, e.Key, boolInt(e.Success),
				e.Paths, e.Addr, e.Result, e.Label, boolInt(e.Truncated)); err != nil {
				st.Close()
				return err
			}
		}
		st.Close()
	}

	if len(b.Procs) > 0 {
		st, err := tx.Prepare(`INSERT INTO processes
			(pid,start_ts,end_ts,ppid,exe,argv,auid,ses,label,label_depth)
			VALUES (?,?,?,?,?,?,?,?,?,?)
			ON CONFLICT(pid,start_ts) DO UPDATE SET end_ts=excluded.end_ts`)
		if err != nil {
			return err
		}
		for i := range b.Procs {
			p := &b.Procs[i]
			var end any
			if p.EndTS > 0 {
				end = p.EndTS
			}
			if _, err := st.Exec(p.PID, p.StartTS, end, p.PPID, p.Exe, p.Argv,
				p.AUID, p.SES, p.Label, p.LabelDepth); err != nil {
				st.Close()
				return err
			}
		}
		st.Close()
	}

	if len(b.Sessions) > 0 {
		st, err := tx.Prepare(`INSERT INTO sessions (ses,auid,start_ts,end_ts,addr,terminal,result)
			VALUES (?,?,?,?,?,?,?)
			ON CONFLICT(ses) DO UPDATE SET
			  end_ts=COALESCE(excluded.end_ts, sessions.end_ts),
			  addr=COALESCE(NULLIF(excluded.addr,''), sessions.addr),
			  result=COALESCE(NULLIF(excluded.result,''), sessions.result)`)
		if err != nil {
			return err
		}
		for i := range b.Sessions {
			s := &b.Sessions[i]
			var end any
			if s.EndTS > 0 {
				end = s.EndTS
			}
			if _, err := st.Exec(s.SES, s.AUID, s.StartTS, end, s.Addr, s.Terminal, s.Result); err != nil {
				st.Close()
				return err
			}
		}
		st.Close()
	}
	return tx.Commit()
}

// Purge 删除超过保留期的数据。
func (d *DB) Purge(retentionDays int) (int64, error) {
	if d.ro {
		return 0, fmt.Errorf("数据库以只读方式打开")
	}
	cutoff := time.Now().AddDate(0, 0, -retentionDays).UnixMilli()
	res, err := d.sql.Exec(`DELETE FROM events WHERE ts < ?`, cutoff)
	if err != nil {
		return 0, err
	}
	n, _ := res.RowsAffected()
	if _, err := d.sql.Exec(`DELETE FROM processes WHERE start_ts < ?`, cutoff); err != nil {
		return n, err
	}
	if _, err := d.sql.Exec(`DELETE FROM sessions WHERE start_ts < ?`, cutoff); err != nil {
		return n, err
	}
	return n, nil
}

func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}
