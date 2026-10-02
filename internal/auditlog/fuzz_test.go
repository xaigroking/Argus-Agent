package auditlog

import (
	"strings"
	"testing"
)

// FuzzParseLine 针对敌意输入。被监控用户可控制命令名、参数与文件名，
// 这些内容会原样进入 audit.log，因此解析器必须对任意字节序列安全。
func FuzzParseLine(f *testing.F) {
	seeds := []string{
		`type=SYSCALL msg=audit(1700000000.123:1001): arch=c000003e syscall=59 success=yes ppid=2000 pid=2001 auid=1000 uid=1000 tty=pts0 ses=3 comm="ls" exe="/usr/bin/ls" key="argus_exec"`,
		`type=EXECVE msg=audit(1700000000.123:1001): argc=2 a0="ls" a1=2d6c61`,
		`type=EXECVE msg=audit(1700000000.123:1): argc=1 a0_len=8 a0[0]="ab" a0[1]="cd"`,
		`type=CWD msg=audit(1700000000.123:1001): cwd="/home/alice"`,
		`type=PATH msg=audit(1700000000.123:1): item=0 name="/etc/passwd" nametype=NORMAL`,
		`type=USER_LOGIN msg=audit(1700000004.000:1005): pid=3000 uid=0 auid=1000 ses=3 msg='op=login id=1000 addr=203.0.113.5 terminal=/dev/pts/0 res=success'`,
		`node=web01 type=SYSCALL msg=audit(1700000006.000:1007): auid=unset ses=unset exe="/x"` + "\x1d" + `AUID="unset"`,
		"",
		"not an audit line",
		`type=X msg=audit(0.0:0): a="`,
	}
	for _, s := range seeds {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, line string) {
		rec, err := ParseLine(line)
		if err != nil {
			return
		}
		if rec == nil {
			t.Fatal("返回 nil record 但无错误")
		}
		// 不变量 1：所有字段长度有界
		for k, v := range rec.Fields {
			if len(v) > MaxFieldLen {
				t.Fatalf("字段 %q 长度 %d 超过上限", k, len(v))
			}
		}
		// 不变量 2：参数数量与单项长度有界
		if len(rec.Args) > MaxArgs {
			t.Fatalf("参数数量 %d 超过上限", len(rec.Args))
		}
		for _, a := range rec.Args {
			if len(a) > MaxFieldLen {
				t.Fatalf("参数长度 %d 超过上限", len(a))
			}
		}
		// 不变量 3：时间戳在合理范围（畸形输入不得产生极端时间）
		if y := rec.Time.Year(); y < 1970 || y > 2100 {
			t.Fatalf("时间戳越界: %v", rec.Time)
		}
		// 不变量 4：聚合不得 panic
		var g Grouper
		if ev := g.Add(rec); ev != nil {
			_ = ev.IsExec()
		}
		if ev := g.Flush(); ev != nil {
			_ = ev.IsExec()
		}
	})
}

// FuzzParseFields 单独针对字段切分，这是最容易出边界错误的地方。
func FuzzParseFields(f *testing.F) {
	f.Add(`a="b" c=64 d='e=f g=h'`)
	f.Add(`exe=` + strings.Repeat("41", 64))
	f.Add(`a0="x" a1[0]="y" a1[1]="z"`)

	f.Fuzz(func(t *testing.T, body string) {
		for _, rt := range []string{"SYSCALL", "EXECVE", "PATH"} {
			dst := make(map[string]string)
			parseFields(body, rt, dst)
			for k, v := range dst {
				if len(v) > MaxFieldLen {
					t.Fatalf("类型 %s 字段 %q 超长: %d", rt, k, len(v))
				}
			}
			if rt == "EXECVE" {
				if args := assembleArgs(dst); len(args) > MaxArgs {
					t.Fatalf("参数数量超限: %d", len(args))
				}
			}
		}
	})
}
