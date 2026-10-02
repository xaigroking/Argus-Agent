package server

import (
	"encoding/hex"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/xaigroking/argus-agent/internal/config"
	"github.com/xaigroking/argus-agent/internal/pipeline"
	"github.com/xaigroking/argus-agent/internal/store"
)

// newTestServer 导入含敌意载荷的样本日志并返回看板。
func newTestServer(t *testing.T) *Server {
	t.Helper()
	dir := t.TempDir()
	cfg := config.Default()
	cfg.DBPath = filepath.Join(dir, "argus.db")
	cfg.StatePath = filepath.Join(dir, "state.json")

	db, err := store.Open(cfg.DBPath)
	if err != nil {
		t.Fatal(err)
	}
	p := pipeline.New(cfg, db, slog.New(slog.NewTextHandler(io.Discard, nil)))
	for _, line := range hostileLines() {
		p.ProcessLine(line)
	}
	p.FinishInput()
	if err := p.Flush(); err != nil {
		t.Fatal(err)
	}
	db.Close()

	ro, err := store.OpenReadOnly(cfg.DBPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ro.Close() })

	s, err := New(ro, "127.0.0.1:0", slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// hostileLines 构造一条当前时间的 execve 事件，参数为 XSS 载荷。
// auditd 在参数含特殊字符时会用十六进制编码，这里照此生成。
func hostileLines() []string {
	ts := float64(time.Now().UnixMilli()) / 1000
	payload := hex.EncodeToString([]byte(xssPayload))
	path := hex.EncodeToString([]byte(`/tmp/<img src=x onerror=alert(2)>`))
	return []string{
		fmt.Sprintf(`type=SYSCALL msg=audit(%.3f:9001): arch=c000003e syscall=59 success=yes exit=0 `+
			`items=1 ppid=100 pid=101 auid=1000 uid=1000 tty=pts0 ses=3 comm="echo" exe="/usr/bin/echo" key="argus_exec"`, ts),
		fmt.Sprintf(`type=EXECVE msg=audit(%.3f:9001): argc=2 a0="echo" a1=%s`, ts, payload),
		fmt.Sprintf(`type=SYSCALL msg=audit(%.3f:9002): arch=c000003e syscall=257 success=yes exit=3 `+
			`items=1 ppid=100 pid=102 auid=1000 uid=1000 tty=pts0 ses=3 comm="cat" exe="/usr/bin/cat" key="argus_sensitive"`, ts),
		fmt.Sprintf(`type=PATH msg=audit(%.3f:9002): item=0 name=%s nametype=NORMAL`, ts, path),
		fmt.Sprintf(`type=USER_LOGIN msg=audit(%.3f:9003): pid=90 uid=0 auid=1000 ses=3 `+
			`msg='op=login id=1000 addr=203.0.113.5 terminal=/dev/pts/0 res=success'`, ts),
	}
}

const xssPayload = `<script>alert(1)</script>`

func get(t *testing.T, s *Server, url string) *httptest.ResponseRecorder {
	t.Helper()
	rr := httptest.NewRecorder()
	s.srv.Handler.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, url, nil))
	return rr
}

// 这是本项目最现实的漏洞：被监控用户执行
//
//	echo '<script>alert(1)</script>'
//
// 该字符串会进入审计日志、数据库，最后渲染到看板。
// 若未转义即为存储型 XSS，攻击者正是被监控对象。
func TestHostileCommandIsEscaped(t *testing.T) {
	s := newTestServer(t)
	rr := get(t, s, "/?hours=24")
	if rr.Code != http.StatusOK {
		t.Fatalf("状态码 = %d", rr.Code)
	}
	body := rr.Body.String()

	// 载荷必须出现（证明数据确实渲染了），但只能以转义形式出现
	if !strings.Contains(body, "&lt;script&gt;") {
		t.Error("未找到转义后的载荷，测试可能没有覆盖到渲染路径")
	}
	if strings.Contains(body, xssPayload) {
		t.Fatal("存储型 XSS：命令参数未经转义直接输出到页面")
	}
	// 文件路径同样由用户控制
	if strings.Contains(body, "<img src=x onerror=") {
		t.Fatal("存储型 XSS：文件路径未经转义直接输出到页面")
	}
	// 页面本身不使用 JS，正常情况下不应出现任何 script 标签
	if strings.Contains(strings.ToLower(body), "<script") {
		t.Error("页面中出现了 <script 标签")
	}
}

// 查询参数同样来自外部，必须转义。
func TestQueryParamEscaped(t *testing.T) {
	s := newTestServer(t)
	rr := get(t, s, "/?hours=24&label=%3Cimg+src%3Dx+onerror%3Dalert(1)%3E")
	body := rr.Body.String()
	if strings.Contains(body, "<img src=x onerror=") {
		t.Fatal("反射型 XSS：label 参数未经转义")
	}
}

// CSP 禁止脚本执行，是转义之外的第二道防线。
func TestSecurityHeaders(t *testing.T) {
	s := newTestServer(t)
	rr := get(t, s, "/")
	csp := rr.Header().Get("Content-Security-Policy")
	if !strings.Contains(csp, "default-src 'none'") {
		t.Errorf("CSP 未限制默认来源: %q", csp)
	}
	if strings.Contains(csp, "script-src") && !strings.Contains(csp, "script-src 'none'") {
		t.Errorf("CSP 允许了脚本: %q", csp)
	}
	if rr.Header().Get("X-Content-Type-Options") != "nosniff" {
		t.Error("缺少 X-Content-Type-Options")
	}
	if rr.Header().Get("X-Frame-Options") != "DENY" {
		t.Error("缺少 X-Frame-Options")
	}
}

// 展示层以只读连接打开数据库，被攻破也不能篡改审计数据。
func TestDatabaseIsReadOnly(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "argus.db")
	db, err := store.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	db.Close()

	ro, err := store.OpenReadOnly(path)
	if err != nil {
		t.Fatal(err)
	}
	defer ro.Close()
	if _, err := ro.SQL().Exec(`INSERT INTO meta(k,v) VALUES('x','y')`); err == nil {
		t.Fatal("只读连接竟然允许写入")
	}
	if err := ro.WriteBatch(&store.Batch{Events: []store.EventRow{{TS: 1, Serial: 1, Type: "X"}}}); err == nil {
		t.Fatal("只读连接竟然允许 WriteBatch")
	}
}

// 畸形查询参数不得导致 panic 或 5xx。
func TestMalformedQueryParams(t *testing.T) {
	s := newTestServer(t)
	for _, u := range []string{
		"/?hours=abc", "/?hours=-1", "/?hours=99999999999999999999",
		"/?auid=notanumber", "/?auid=-5",
		"/?label=" + strings.Repeat("A", 5000),
		"/?hours=24&label=%00%01%02",
	} {
		rr := get(t, s, u)
		if rr.Code >= 500 {
			t.Errorf("%s → 状态码 %d", u, rr.Code)
		}
	}
}

func TestNotFound(t *testing.T) {
	s := newTestServer(t)
	if rr := get(t, s, "/admin"); rr.Code != http.StatusNotFound {
		t.Errorf("状态码 = %d，期望 404", rr.Code)
	}
}

func TestHealthz(t *testing.T) {
	s := newTestServer(t)
	if rr := get(t, s, "/healthz"); rr.Code != http.StatusOK {
		t.Errorf("状态码 = %d", rr.Code)
	}
}
