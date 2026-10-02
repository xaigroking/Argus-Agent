// Package server 提供本地只读看板。
//
// 安全约束：
//   - 默认仅监听 127.0.0.1，不对外暴露。
//   - 数据库以只读方式打开，看板被攻破也无法篡改审计数据。
//   - 全部使用 html/template 渲染，所有审计字段自动转义。
//     被监控用户可以把任意内容放进命令名和文件名，这是最现实的攻击面。
package server

import (
	"context"
	_ "embed"
	"errors"
	"fmt"
	"html/template"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/xaigroking/argus-agent/internal/store"
)

//go:embed page.html
var pageHTML string

type Server struct {
	db   *store.DB
	log  *slog.Logger
	tmpl *template.Template
	srv  *http.Server
}

func New(db *store.DB, addr string, log *slog.Logger) (*Server, error) {
	// html/template 对所有插值自动按上下文转义，不要换成 text/template。
	t, err := template.New("page").Funcs(template.FuncMap{
		"fmtTime": func(ts time.Time) string {
			if ts.IsZero() {
				return "-"
			}
			return ts.Local().Format("01-02 15:04:05")
		},
		"auid": func(v int64) string {
			if v < 0 {
				return "unset"
			}
			return strconv.FormatInt(v, 10)
		},
		"lines": func(s string) []string {
			if s == "" {
				return nil
			}
			return strings.Split(s, "\n")
		},
	}).Parse(pageHTML)
	if err != nil {
		return nil, err
	}
	s := &Server{db: db, log: log, tmpl: t}

	mux := http.NewServeMux()
	mux.HandleFunc("/", s.handleIndex)
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		fmt.Fprintln(w, "ok")
	})

	s.srv = &http.Server{
		Addr:              addr,
		Handler:           securityHeaders(mux),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       120 * time.Second,
	}
	return s, nil
}

// securityHeaders 加上最小必要的响应头。CSP 禁止任何脚本执行——
// 页面本身不需要 JS，这样即使转义出现疏漏也无法执行注入的脚本。
func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Security-Policy",
			"default-src 'none'; style-src 'unsafe-inline'; img-src data:; form-action 'self'")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "no-referrer")
		next.ServeHTTP(w, r)
	})
}

func (s *Server) ListenAndServe() error {
	s.log.Info("看板已启动", "addr", s.srv.Addr)
	if err := s.srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

func (s *Server) Shutdown(ctx context.Context) error { return s.srv.Shutdown(ctx) }

// pageData 是模板的数据模型。
type pageData struct {
	Now      time.Time
	Hours    int
	Label    string
	AUID     int64
	Stats    store.Stats
	Labels   []store.TopRow
	Users    []store.TopRow
	TopCmds  []store.TopRow
	Execs    []store.ExecRow
	Files    []store.FileRow
	Sessions []store.SessionInfo
	Warn     string
}

func (s *Server) handleIndex(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	hours := clampInt(r.URL.Query().Get("hours"), 24, 1, 24*90)
	label := r.URL.Query().Get("label")
	if len(label) > 64 {
		label = label[:64]
	}
	win := store.Window{
		Since: time.Now().Add(-time.Duration(hours) * time.Hour),
		Label: label,
		Limit: 200,
	}
	au := int64(-1)
	if v := r.URL.Query().Get("auid"); v != "" {
		if n, err := strconv.ParseInt(v, 10, 64); err == nil && n >= 0 {
			au = n
			win = win.WithAUID(n)
		}
	}

	d := pageData{Now: time.Now(), Hours: hours, Label: label, AUID: au}
	var err error
	if d.Stats, err = s.db.Stats(); err != nil {
		s.fail(w, err)
		return
	}
	if d.Labels, err = s.db.LabelBreakdown(win); err != nil {
		s.fail(w, err)
		return
	}
	if d.Users, err = s.db.UserBreakdown(win); err != nil {
		s.fail(w, err)
		return
	}
	if d.TopCmds, err = s.db.TopCommands(win, 15); err != nil {
		s.fail(w, err)
		return
	}
	if d.Execs, err = s.db.Execs(win); err != nil {
		s.fail(w, err)
		return
	}
	if d.Files, err = s.db.Files(win); err != nil {
		s.fail(w, err)
		return
	}
	if d.Sessions, err = s.db.Sessions(win); err != nil {
		s.fail(w, err)
		return
	}
	if d.Stats.Events > 0 && d.Stats.UnsetAUID*100/d.Stats.Events > 5 {
		d.Warn = fmt.Sprintf("%d 条事件的 auid 为 unset（占 %d%%），这部分行为无法归因到具体用户。"+
			"请检查各登录入口是否加载了 pam_loginuid.so。",
			d.Stats.UnsetAUID, d.Stats.UnsetAUID*100/d.Stats.Events)
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := s.tmpl.Execute(w, d); err != nil {
		s.log.Error("渲染页面失败", "err", err)
	}
}

func (s *Server) fail(w http.ResponseWriter, err error) {
	s.log.Error("查询失败", "err", err)
	// 不把内部错误原文返回给客户端
	http.Error(w, "查询失败，详见服务日志", http.StatusInternalServerError)
}

func clampInt(s string, def, lo, hi int) int {
	if s == "" {
		return def
	}
	n, err := strconv.Atoi(s)
	if err != nil || n < lo || n > hi {
		return def
	}
	return n
}
