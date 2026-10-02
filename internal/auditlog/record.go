// Package auditlog 解析 auditd 的 audit.log。
//
// 安全约束：本包处理的内容由被监控用户控制（命令名、文件名、参数），
// 必须视为敌意输入。所有函数禁止 panic，所有长度必须有界。
package auditlog

import "time"

// 单字段与整条记录的长度上限。超限截断并置 Truncated。
const (
	MaxFieldLen      = 16 << 10  // 16 KiB
	MaxLineLen       = 256 << 10 // 256 KiB
	MaxArgs          = 512
	MaxPathsPerEvent = 64
)

// Record 是 audit.log 中的一行。
type Record struct {
	Type   string
	Time   time.Time
	Serial int64
	Fields map[string]string
	// Args 仅 EXECVE 记录有值，已按 a0..aN 顺序还原。
	Args []string
	// Truncated 表示本行有字段因超长被截断。
	Truncated bool
}

// Event 是同一 (时间, 序列号) 下所有记录的聚合。
type Event struct {
	Time    time.Time
	Serial  int64
	Records []*Record

	// 以下为从记录中提取的常用字段，缺失时为零值。
	Type    string // 主记录类型：SYSCALL 优先，否则第一条
	AUID    int64  // 登录原始用户；-1 表示 unset
	UID     int64
	SES     int64 // -1 表示 unset
	PID     int64
	PPID    int64
	Exe     string
	Comm    string
	Argv    []string
	CWD     string
	TTY     string
	Key     string
	Success bool
	Paths   []string
	// Addr/Terminal/Result 来自 USER_LOGIN 一类记录。
	Addr     string
	Terminal string
	Result   string

	Truncated bool
}

// IsExec 判断本事件是否为一次 execve。
func (e *Event) IsExec() bool {
	for _, r := range e.Records {
		if r.Type == "EXECVE" {
			return true
		}
		if r.Type == "SYSCALL" && r.Fields["syscall"] == syscallExecve(r.Fields["arch"]) {
			return true
		}
	}
	return false
}

// syscallExecve 返回对应架构下 execve 的系统调用号（字符串形式）。
// x86_64=59，i386=11，aarch64=221。未知架构返回空串（永不匹配）。
func syscallExecve(arch string) string {
	switch arch {
	case "c000003e": // x86_64
		return "59"
	case "40000003": // i386
		return "11"
	case "c00000b7": // aarch64
		return "221"
	case "40000028": // arm
		return "11"
	}
	return ""
}
