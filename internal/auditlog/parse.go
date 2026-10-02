package auditlog

import (
	"encoding/hex"
	"errors"
	"strconv"
	"strings"
	"time"
)

var ErrNotAuditRecord = errors.New("不是 audit 记录")

// hexCapableFields 列出 auditd 在值含特殊字符时会改用十六进制编码的字段。
// 不在此表中的字段（uid、pid、ses 等数值字段）绝不能尝试十六进制解码——
// 例如 uid=1000 恰好是合法十六进制，误解码会得到垃圾。
var hexCapableFields = map[string]bool{
	"exe": true, "comm": true, "cwd": true, "name": true,
	"proctitle": true, "key": true, "cmd": true, "acct": true,
	"path": true, "dir": true, "old": true, "new": true,
	"old-disk": true, "new-disk": true, "old-fs": true, "new-fs": true,
	"device": true, "grp": true, "hostname": true, "obj": true,
}

// ParseLine 解析 audit.log 的一行。
// 行内容由被监控用户部分控制，任何输入都不得导致 panic。
func ParseLine(line string) (*Record, error) {
	if len(line) > MaxLineLen {
		line = line[:MaxLineLen]
	}
	line = strings.TrimRight(line, "\r\n")

	// 定位 msg=audit(SECS.MILLIS:SERIAL):
	const marker = "msg=audit("
	mi := strings.Index(line, marker)
	if mi < 0 {
		return nil, ErrNotAuditRecord
	}
	rest := line[mi+len(marker):]
	close := strings.Index(rest, "):")
	if close < 0 {
		return nil, ErrNotAuditRecord
	}
	stamp := rest[:close]
	body := rest[close+2:]

	ts, serial, err := parseStamp(stamp)
	if err != nil {
		return nil, err
	}

	rec := &Record{
		Type:   fieldBefore(line[:mi], "type="),
		Time:   ts,
		Serial: serial,
		Fields: make(map[string]string, 16),
	}
	if rec.Type == "" {
		return nil, ErrNotAuditRecord
	}

	rec.Truncated = parseFields(body, rec.Type, rec.Fields)
	if rec.Type == "EXECVE" {
		rec.Args = assembleArgs(rec.Fields)
	}
	return rec, nil
}

// parseStamp 解析 "1700000000.123:456"。
func parseStamp(s string) (time.Time, int64, error) {
	colon := strings.LastIndexByte(s, ':')
	if colon < 0 {
		return time.Time{}, 0, ErrNotAuditRecord
	}
	serial, err := strconv.ParseInt(s[colon+1:], 10, 64)
	if err != nil {
		return time.Time{}, 0, ErrNotAuditRecord
	}
	tpart := s[:colon]
	dot := strings.IndexByte(tpart, '.')
	var secs, millis int64
	if dot < 0 {
		secs, err = strconv.ParseInt(tpart, 10, 64)
		if err != nil {
			return time.Time{}, 0, ErrNotAuditRecord
		}
	} else {
		secs, err = strconv.ParseInt(tpart[:dot], 10, 64)
		if err != nil {
			return time.Time{}, 0, ErrNotAuditRecord
		}
		millis, _ = strconv.ParseInt(tpart[dot+1:], 10, 64)
		if millis < 0 || millis > 999 {
			millis = 0
		}
	}
	// 约束到合理范围，避免畸形时间戳产生极端 time.Time。
	if secs < 0 || secs > 4102444800 { // 2100-01-01
		return time.Time{}, 0, ErrNotAuditRecord
	}
	return time.Unix(secs, millis*int64(time.Millisecond)).UTC(), serial, nil
}

// fieldBefore 从 "type=SYSCALL " 这类前缀中取出 key 对应的值。
func fieldBefore(prefix, key string) string {
	i := strings.Index(prefix, key)
	if i < 0 {
		return ""
	}
	v := prefix[i+len(key):]
	if j := strings.IndexAny(v, " \t"); j >= 0 {
		v = v[:j]
	}
	return v
}

// parseFields 把 "k=v k=\"v v\" k=68656C" 解析进 dst，返回是否发生截断。
// recType 用于判断 a0..aN 的语义：EXECVE 中是字符串参数，SYSCALL 中是寄存器值。
func parseFields(s string, recType string, dst map[string]string) bool {
	truncated := false
	i := 0
	for i < len(s) {
		// 跳过分隔符。0x1d 是 ENRICHED 格式的字段组分隔符。
		for i < len(s) && (s[i] == ' ' || s[i] == '\t' || s[i] == 0x1d) {
			i++
		}
		if i >= len(s) {
			break
		}
		// 读 key
		ks := i
		for i < len(s) && s[i] != '=' && s[i] != ' ' && s[i] != 0x1d {
			i++
		}
		if i >= len(s) || s[i] != '=' {
			// 没有 '=' 的孤立 token，跳过
			continue
		}
		key := s[ks:i]
		i++ // 跳过 '='
		if key == "" {
			continue
		}

		var val string
		var quoted bool
		switch {
		case i < len(s) && s[i] == '"':
			i++
			vs := i
			for i < len(s) && s[i] != '"' {
				i++
			}
			val = s[vs:i]
			if i < len(s) {
				i++ // 跳过收尾引号
			}
			quoted = true
		case i < len(s) && s[i] == '\'':
			// 嵌套消息，如 USER_LOGIN 的 msg='op=login ... res=success'
			i++
			vs := i
			for i < len(s) && s[i] != '\'' {
				i++
			}
			inner := s[vs:i]
			if i < len(s) {
				i++
			}
			if parseFields(inner, recType, dst) {
				truncated = true
			}
			continue
		default:
			vs := i
			for i < len(s) && s[i] != ' ' && s[i] != '\t' && s[i] != 0x1d {
				i++
			}
			val = s[vs:i]
		}

		if len(val) > MaxFieldLen {
			val = val[:MaxFieldLen]
			truncated = true
		}
		if !quoted {
			if val == "(null)" || val == "?" {
				val = ""
			} else if isHexField(key, recType) {
				if d, ok := decodeHex(val); ok {
					val = d
				}
			}
		}
		dst[key] = val
	}
	return truncated
}

// isHexField 判断该字段的无引号值是否应按十六进制解码。
func isHexField(key, recType string) bool {
	if hexCapableFields[key] {
		return true
	}
	// EXECVE 中的 a0/a1/... 是字符串参数；SYSCALL 中同名字段是寄存器值，不可解码。
	if recType == "EXECVE" && len(key) >= 2 && key[0] == 'a' {
		body := key[1:]
		if j := strings.IndexByte(body, '['); j >= 0 {
			body = body[:j]
		}
		if body == "" {
			return false
		}
		for k := 0; k < len(body); k++ {
			if body[k] < '0' || body[k] > '9' {
				return false
			}
		}
		return true
	}
	return false
}

// decodeHex 仅在整串为偶数长度的十六进制时解码。
func decodeHex(s string) (string, bool) {
	if len(s) == 0 || len(s)%2 != 0 {
		return "", false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F') {
			return "", false
		}
	}
	b, err := hex.DecodeString(s)
	if err != nil {
		return "", false
	}
	// auditd 用 0x00 分隔 proctitle 内的参数，统一转为空格便于展示。
	for i := range b {
		if b[i] == 0 {
			b[i] = ' '
		}
	}
	return string(b), true
}

// assembleArgs 还原 EXECVE 的参数数组，处理超长参数被拆成 aN[0]、aN[1] 的情况。
func assembleArgs(f map[string]string) []string {
	argc := 0
	if v, ok := f["argc"]; ok {
		if n, err := strconv.Atoi(v); err == nil && n >= 0 {
			argc = n
		}
	}
	if argc > MaxArgs {
		argc = MaxArgs
	}
	args := make([]string, 0, argc)
	for i := 0; i < argc; i++ {
		base := "a" + strconv.Itoa(i)
		if v, ok := f[base]; ok {
			args = append(args, v)
			continue
		}
		// 拆分形式：a1_len=N a1[0]=... a1[1]=...
		var sb strings.Builder
		for part := 0; part < MaxArgs; part++ {
			v, ok := f[base+"["+strconv.Itoa(part)+"]"]
			if !ok {
				break
			}
			if sb.Len()+len(v) > MaxFieldLen {
				break
			}
			sb.WriteString(v)
		}
		args = append(args, sb.String())
	}
	return args
}
