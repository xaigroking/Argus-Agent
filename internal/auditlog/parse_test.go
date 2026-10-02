package auditlog

import (
	"bufio"
	"os"
	"strings"
	"testing"
)

// loadSample 读取测试语料并聚合成事件。
func loadSample(t *testing.T) ([]*Event, int, int) {
	t.Helper()
	f, err := os.Open("../../testdata/sample.log")
	if err != nil {
		t.Fatalf("打开语料失败: %v", err)
	}
	defer f.Close()

	var g Grouper
	var events []*Event
	parsed, skipped := 0, 0
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64<<10), MaxLineLen)
	for sc.Scan() {
		line := sc.Text()
		if strings.TrimSpace(line) == "" {
			continue
		}
		rec, err := ParseLine(line)
		if err != nil {
			skipped++
			continue
		}
		parsed++
		if ev := g.Add(rec); ev != nil {
			events = append(events, ev)
		}
	}
	if ev := g.Flush(); ev != nil {
		events = append(events, ev)
	}
	return events, parsed, skipped
}

func findBySerial(events []*Event, serial int64) *Event {
	for _, e := range events {
		if e.Serial == serial {
			return e
		}
	}
	return nil
}

func TestParseCoverage(t *testing.T) {
	_, parsed, skipped := loadSample(t)
	// 语料中有 2 行是故意构造的非 audit 内容
	if skipped != 2 {
		t.Errorf("跳过行数 = %d，期望 2", skipped)
	}
	if parsed < 18 {
		t.Errorf("成功解析 %d 行，过少", parsed)
	}
}

func TestExecQuotedArgs(t *testing.T) {
	events, _, _ := loadSample(t)
	e := findBySerial(events, 1001)
	if e == nil {
		t.Fatal("未找到事件 1001")
	}
	if !e.IsExec() {
		t.Error("应识别为 execve")
	}
	if e.Exe != "/usr/bin/ls" {
		t.Errorf("Exe = %q", e.Exe)
	}
	if got := strings.Join(e.Argv, " "); got != "ls -la" {
		t.Errorf("Argv = %q", got)
	}
	if e.CWD != "/home/alice" {
		t.Errorf("CWD = %q", e.CWD)
	}
	if e.AUID != 1000 || e.SES != 3 || e.PID != 2001 || e.PPID != 2000 {
		t.Errorf("归因字段错误: auid=%d ses=%d pid=%d ppid=%d", e.AUID, e.SES, e.PID, e.PPID)
	}
	if len(e.Paths) != 1 || e.Paths[0] != "/usr/bin/ls" {
		t.Errorf("Paths = %v", e.Paths)
	}
	if e.Key != "argus_exec" {
		t.Errorf("Key = %q", e.Key)
	}
}

// 被监控用户可以把任意内容放进命令参数，这里确认十六进制参数被正确还原。
// 该载荷同时用于验证展示层转义（见 server 包测试）。
func TestExecHexArgs(t *testing.T) {
	events, _, _ := loadSample(t)
	e := findBySerial(events, 1002)
	if e == nil {
		t.Fatal("未找到事件 1002")
	}
	if len(e.Argv) != 2 {
		t.Fatalf("Argv 长度 = %d: %v", len(e.Argv), e.Argv)
	}
	want := `<script>alert(1)</script>`
	if e.Argv[1] != want {
		t.Errorf("Argv[1] = %q，期望 %q", e.Argv[1], want)
	}
}

func TestExecSplitArgs(t *testing.T) {
	events, _, _ := loadSample(t)
	e := findBySerial(events, 1003)
	if e == nil {
		t.Fatal("未找到事件 1003")
	}
	if len(e.Argv) != 2 {
		t.Fatalf("Argv 长度 = %d", len(e.Argv))
	}
	if len(e.Argv[1]) != 120 || strings.Trim(e.Argv[1], "A") != "" {
		t.Errorf("拆分参数未正确拼接，长度 = %d", len(e.Argv[1]))
	}
}

// 数值字段恰好是合法十六进制（如 uid=1000），绝不能被解码。
func TestNumericFieldsNotHexDecoded(t *testing.T) {
	rec, err := ParseLine(`type=SYSCALL msg=audit(1700000000.000:1): arch=c000003e syscall=59 uid=1000 ses=1234 pid=4321 auid=1000 exe="/bin/sh"`)
	if err != nil {
		t.Fatal(err)
	}
	for k, want := range map[string]string{"uid": "1000", "ses": "1234", "pid": "4321"} {
		if rec.Fields[k] != want {
			t.Errorf("%s = %q，期望 %q（不应被十六进制解码）", k, rec.Fields[k], want)
		}
	}
}

// SYSCALL 的 a0..a3 是寄存器值，不是字符串，不能解码。
func TestSyscallRegisterArgsNotDecoded(t *testing.T) {
	rec, err := ParseLine(`type=SYSCALL msg=audit(1700000000.000:1): arch=c000003e syscall=59 a0=55f8c0a0b0c0 a1=6c73 exe="/bin/ls"`)
	if err != nil {
		t.Fatal(err)
	}
	if rec.Fields["a1"] != "6c73" {
		t.Errorf("SYSCALL a1 = %q，不应被解码为 \"ls\"", rec.Fields["a1"])
	}
}

func TestUserLoginNestedMsg(t *testing.T) {
	events, _, _ := loadSample(t)
	e := findBySerial(events, 1005)
	if e == nil {
		t.Fatal("未找到事件 1005")
	}
	if e.Type != "USER_LOGIN" {
		t.Errorf("Type = %q", e.Type)
	}
	if e.AUID != 1000 || e.SES != 3 {
		t.Errorf("auid=%d ses=%d", e.AUID, e.SES)
	}
	if e.Addr != "203.0.113.5" {
		t.Errorf("Addr = %q", e.Addr)
	}
	if e.Result != "success" {
		t.Errorf("Result = %q", e.Result)
	}
	if e.Terminal != "/dev/pts/0" {
		t.Errorf("Terminal = %q", e.Terminal)
	}
}

// auid/ses 为 unset 或 4294967295 时必须归一化为 Unset，
// 否则会被当成真实用户 ID，造成错误归因。
func TestUnsetAttribution(t *testing.T) {
	events, _, _ := loadSample(t)
	for _, serial := range []int64{1006, 1007} {
		e := findBySerial(events, serial)
		if e == nil {
			t.Fatalf("未找到事件 %d", serial)
		}
		if e.AUID != Unset {
			t.Errorf("事件 %d 的 AUID = %d，期望 Unset", serial, e.AUID)
		}
		if e.SES != Unset {
			t.Errorf("事件 %d 的 SES = %d，期望 Unset", serial, e.SES)
		}
	}
}

func TestMultipleKeys(t *testing.T) {
	events, _, _ := loadSample(t)
	e := findBySerial(events, 1008)
	if e == nil {
		t.Fatal("未找到事件 1008")
	}
	if e.Key != "argus_exec,argus_priv" {
		t.Errorf("Key = %q", e.Key)
	}
}

func TestAarch64Execve(t *testing.T) {
	events, _, _ := loadSample(t)
	e := findBySerial(events, 1009)
	if e == nil {
		t.Fatal("未找到事件 1009")
	}
	if !e.IsExec() {
		t.Error("aarch64 的 syscall=221 应识别为 execve")
	}
}

func TestSensitiveFileEvent(t *testing.T) {
	events, _, _ := loadSample(t)
	e := findBySerial(events, 1004)
	if e == nil {
		t.Fatal("未找到事件 1004")
	}
	if e.IsExec() {
		t.Error("open 不应被识别为 execve")
	}
	if len(e.Paths) != 1 || e.Paths[0] != "/etc/passwd" {
		t.Errorf("Paths = %v", e.Paths)
	}
	if e.Key != "argus_sensitive" {
		t.Errorf("Key = %q", e.Key)
	}
}

// 畸形输入不得 panic，也不得产生异常时间。
func TestMalformedInput(t *testing.T) {
	cases := []string{
		"", " ", "type=", "msg=audit(", "msg=audit():",
		"type=X msg=audit(abc:def): k=v",
		"type=X msg=audit(99999999999999.000:1): k=v",
		"type=X msg=audit(1700000000.000:1): " + strings.Repeat("k=v ", 10000),
		"type=X msg=audit(1700000000.000:1): a=\"unterminated",
		"type=X msg=audit(1700000000.000:1): msg='nested unterminated",
		"type=EXECVE msg=audit(1700000000.000:1): argc=999999999 a0=\"x\"",
		"type=EXECVE msg=audit(1700000000.000:1): argc=-5",
		"type=X msg=audit(1700000000.000:1): =noKey",
		"type=X msg=audit(1700000000.000:1): key=" + strings.Repeat("41", 100000),
	}
	for _, c := range cases {
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Errorf("输入 %.60q 导致 panic: %v", c, r)
				}
			}()
			ParseLine(c)
		}()
	}
}

// 超长字段必须被截断并标记，不能无限分配。
func TestFieldTruncation(t *testing.T) {
	long := strings.Repeat("x", MaxFieldLen*2)
	rec, err := ParseLine(`type=SYSCALL msg=audit(1700000000.000:1): exe="` + long + `"`)
	if err != nil {
		t.Fatal(err)
	}
	if len(rec.Fields["exe"]) > MaxFieldLen {
		t.Errorf("字段未截断，长度 = %d", len(rec.Fields["exe"]))
	}
	if !rec.Truncated {
		t.Error("应标记 Truncated")
	}
}

func TestGrouperSeparatesEvents(t *testing.T) {
	events, _, _ := loadSample(t)
	seen := map[int64]int{}
	for _, e := range events {
		seen[e.Serial]++
	}
	for s, n := range seen {
		if n != 1 {
			t.Errorf("序列号 %d 产生了 %d 个事件，应为 1", s, n)
		}
	}
	for _, want := range []int64{1001, 1002, 1003, 1004, 1005, 1006, 1007, 1008, 1009} {
		if seen[want] == 0 {
			t.Errorf("缺少事件 %d", want)
		}
	}
}
