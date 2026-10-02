package pipeline

import (
	"context"
	"log/slog"
	"strings"
	"time"

	"github.com/xaigroking/argus-agent/internal/attrib"
	"github.com/xaigroking/argus-agent/internal/auditlog"
	"github.com/xaigroking/argus-agent/internal/config"
	"github.com/xaigroking/argus-agent/internal/store"
)

// Metrics 是流水线的运行计数，用于观测与 verify。
type Metrics struct {
	LinesRead    int64
	LinesSkipped int64
	Events       int64
	Execs        int64
	Written      int64
}

// Pipeline 把 audit.log 转为结构化记录并入库。
type Pipeline struct {
	cfg     config.Config
	db      *store.DB
	tracker *attrib.Tracker
	log     *slog.Logger

	grouper auditlog.Grouper
	batch   store.Batch
	m       Metrics
}

const maxBatch = 500

func New(cfg config.Config, db *store.DB, log *slog.Logger) *Pipeline {
	return &Pipeline{
		cfg:     cfg,
		db:      db,
		tracker: attrib.New(cfg.Agents, cfg.MaxTrackedProcs),
		log:     log,
	}
}

func (p *Pipeline) Metrics() Metrics { return p.m }

// Run 持续读取并入库，直到 ctx 取消。
func (p *Pipeline) Run(ctx context.Context) error {
	t, err := NewTailer(p.cfg.AuditLog, LoadState(p.cfg.StatePath))
	if err != nil {
		return err
	}
	defer t.Close()

	flushTick := time.NewTicker(p.cfg.FlushInterval())
	defer flushTick.Stop()
	purgeTick := time.NewTicker(6 * time.Hour)
	defer purgeTick.Stop()

	p.log.Info("开始跟随审计日志", "path", p.cfg.AuditLog, "db", p.cfg.DBPath)

	for {
		select {
		case <-ctx.Done():
			p.flush(t)
			return nil
		case <-purgeTick.C:
			if n, err := p.db.Purge(p.cfg.RetentionDays); err != nil {
				p.log.Error("清理过期数据失败", "err", err)
			} else if n > 0 {
				p.log.Info("清理过期数据", "events", n)
			}
		case <-flushTick.C:
			p.flush(t)
		default:
		}

		line, ok, err := t.Next()
		if err != nil {
			p.log.Error("读取日志失败", "err", err)
			select {
			case <-ctx.Done():
				return nil
			case <-time.After(2 * time.Second):
			}
			continue
		}
		if !ok {
			p.flush(t)
			select {
			case <-ctx.Done():
				return nil
			case <-time.After(t.PollInterval):
			}
			continue
		}
		p.consume(line)
		if p.batch.Len() >= maxBatch {
			p.flush(t)
		}
	}
}

func (p *Pipeline) consume(line string) {
	if strings.TrimSpace(line) == "" {
		return
	}
	p.m.LinesRead++
	rec, err := auditlog.ParseLine(line)
	if err != nil {
		p.m.LinesSkipped++
		return
	}
	if ev := p.grouper.Add(rec); ev != nil {
		p.handleEvent(ev)
	}
}

// ProcessLine 供测试与离线导入使用。
func (p *Pipeline) ProcessLine(line string) { p.consume(line) }

// FinishInput 结束输入，刷出聚合中的最后一个事件。
func (p *Pipeline) FinishInput() {
	if ev := p.grouper.Flush(); ev != nil {
		p.handleEvent(ev)
	}
}

func (p *Pipeline) handleEvent(e *auditlog.Event) {
	p.m.Events++

	label := ""
	if e.IsExec() {
		p.m.Execs++
		if proc := p.tracker.OnExec(e); proc != nil {
			label = proc.Label
			p.batch.Procs = append(p.batch.Procs, store.ProcRow{
				PID: proc.PID, StartTS: proc.StartTS, PPID: proc.PPID,
				Exe: proc.Exe, Argv: proc.Argv,
				AUID: proc.AUID, SES: proc.SES,
				Label: proc.Label, LabelDepth: proc.LabelDepth,
			})
		}
	} else if e.PID != auditlog.Unset {
		// 非 execve 事件（如文件访问）继承发起进程的归因。
		// 先按自身 pid 查；查不到再按父进程回退——解析从日志中途开始、
		// 或该进程的 execve 发生在规则加载之前时，自身记录会缺失。
		if proc, ok := p.tracker.Lookup(e.PID); ok {
			label = proc.Label
		} else if e.PPID != auditlog.Unset {
			if parent, ok := p.tracker.Lookup(e.PPID); ok {
				label = parent.Label
			}
		}
	}
	if label == "" {
		label = attrib.LabelUnknown
	}

	p.batch.Events = append(p.batch.Events, store.EventRow{
		TS: e.Time.UnixMilli(), Serial: e.Serial, Type: e.Type,
		AUID: e.AUID, UID: e.UID, SES: e.SES, PID: e.PID, PPID: e.PPID,
		Exe: e.Exe, Comm: e.Comm, Argv: strings.Join(e.Argv, " "),
		CWD: e.CWD, TTY: e.TTY, Key: e.Key, Success: e.Success,
		Paths: strings.Join(e.Paths, "\n"), Addr: e.Addr, Result: e.Result,
		Label: label, Truncated: e.Truncated,
	})

	// 登录类事件维护会话表
	switch e.Type {
	case "USER_LOGIN", "LOGIN", "USER_START":
		if e.SES != auditlog.Unset {
			p.batch.Sessions = append(p.batch.Sessions, store.SessionRow{
				SES: e.SES, AUID: e.AUID, StartTS: e.Time.UnixMilli(),
				Addr: e.Addr, Terminal: e.Terminal, Result: e.Result,
			})
		}
	case "USER_LOGOUT", "USER_END":
		if e.SES != auditlog.Unset {
			p.batch.Sessions = append(p.batch.Sessions, store.SessionRow{
				SES: e.SES, AUID: e.AUID, StartTS: e.Time.UnixMilli(),
				EndTS: e.Time.UnixMilli(), Addr: e.Addr, Terminal: e.Terminal,
			})
		}
	}
}

// Flush 写出当前批次并保存读取位置。
func (p *Pipeline) Flush() error {
	if p.batch.Len() == 0 {
		return nil
	}
	n := int64(len(p.batch.Events))
	if err := p.db.WriteBatch(&p.batch); err != nil {
		return err
	}
	p.m.Written += n
	p.batch.Reset()
	return nil
}

func (p *Pipeline) flush(t *Tailer) {
	if err := p.Flush(); err != nil {
		p.log.Error("写入数据库失败", "err", err)
		return
	}
	if t != nil {
		if err := SaveState(p.cfg.StatePath, t.State()); err != nil {
			p.log.Error("保存读取位置失败", "err", err)
		}
	}
}
