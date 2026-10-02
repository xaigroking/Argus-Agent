// Package rules 管理 auditd 规则文件的下发与校验。
package rules

import (
	"bufio"
	"bytes"
	_ "embed"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

//go:embed data/50-argus.rules
var embedded []byte

const (
	// InstallPath 是规则文件的安装位置。
	InstallPath = "/etc/audit/rules.d/50-argus.rules"
	// Keys 是本项目使用的全部规则标记。
	KeyExec        = "argus_exec"
	KeySensitive   = "argus_sensitive"
	KeyPriv        = "argus_priv"
	KeySelfProtect = "argus_selfprotect"
)

// Embedded 返回内置规则内容。
func Embedded() []byte { return append([]byte(nil), embedded...) }

// Install 把内置规则写到 path，必要时先备份已有的非 Argus 规则。
// 不静默覆盖：若目标存在且内容不同，会先写一份带时间戳的备份。
func Install(path string, dryRun bool) (changed bool, backup string, err error) {
	if path == "" {
		path = InstallPath
	}
	if old, rerr := os.ReadFile(path); rerr == nil {
		if bytes.Equal(old, embedded) {
			return false, "", nil
		}
		backup = fmt.Sprintf("%s.bak.%s", path, time.Now().Format("20060102-150405"))
		if !dryRun {
			if werr := os.WriteFile(backup, old, 0o640); werr != nil {
				return false, "", fmt.Errorf("备份旧规则: %w", werr)
			}
		}
	} else if !os.IsNotExist(rerr) {
		return false, "", fmt.Errorf("读取 %s: %w", path, rerr)
	}
	if dryRun {
		return true, backup, nil
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return false, backup, err
	}
	if err := os.WriteFile(path, embedded, 0o640); err != nil {
		return false, backup, fmt.Errorf("写入 %s: %w", path, err)
	}
	return true, backup, nil
}

// Uninstall 移除规则文件。
func Uninstall(path string) error {
	if path == "" {
		path = InstallPath
	}
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

// BackupExisting 导出当前内核中已加载的规则，供安装前留底。
// 规则文件以 -D 开头会清空其他用途的规则，因此安装前必须先备份。
func BackupExisting(dir string) (string, error) {
	out, err := exec.Command("auditctl", "-l").Output()
	if err != nil {
		return "", fmt.Errorf("执行 auditctl -l: %w", err)
	}
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return "", err
	}
	path := filepath.Join(dir, "auditctl-l."+time.Now().Format("20060102-150405")+".txt")
	if err := os.WriteFile(path, out, 0o640); err != nil {
		return "", err
	}
	return path, nil
}

// Status 是 auditctl -s 的解析结果。
type Status struct {
	Enabled    int
	Lost       int64
	Backlog    int64
	BacklogMax int64
	Failure    int
	Raw        string
	Available  bool // auditctl 是否可用
}

// QueryStatus 读取内核审计状态。
func QueryStatus() (Status, error) {
	var s Status
	out, err := exec.Command("auditctl", "-s").Output()
	if err != nil {
		return s, fmt.Errorf("执行 auditctl -s: %w", err)
	}
	s.Available = true
	s.Raw = string(out)
	sc := bufio.NewScanner(bytes.NewReader(out))
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) < 2 {
			continue
		}
		switch f[0] {
		case "enabled":
			fmt.Sscanf(f[1], "%d", &s.Enabled)
		case "failure":
			fmt.Sscanf(f[1], "%d", &s.Failure)
		case "lost":
			fmt.Sscanf(f[1], "%d", &s.Lost)
		case "backlog":
			fmt.Sscanf(f[1], "%d", &s.Backlog)
		case "backlog_limit":
			fmt.Sscanf(f[1], "%d", &s.BacklogMax)
		}
	}
	return s, nil
}

// LoadedKeys 返回当前内核中已加载的 Argus 规则标记集合。
func LoadedKeys() (map[string]bool, error) {
	out, err := exec.Command("auditctl", "-l").Output()
	if err != nil {
		return nil, fmt.Errorf("执行 auditctl -l: %w", err)
	}
	keys := map[string]bool{}
	sc := bufio.NewScanner(bytes.NewReader(out))
	for sc.Scan() {
		line := sc.Text()
		for _, k := range []string{KeyExec, KeySensitive, KeyPriv, KeySelfProtect} {
			if strings.Contains(line, "-k "+k) || strings.Contains(line, "key="+k) {
				keys[k] = true
			}
		}
	}
	return keys, nil
}

// Reload 调用 augenrules 重新加载规则。
func Reload() error {
	if _, err := exec.LookPath("augenrules"); err == nil {
		if out, err := exec.Command("augenrules", "--load").CombinedOutput(); err != nil {
			return fmt.Errorf("augenrules --load: %w: %s", err, strings.TrimSpace(string(out)))
		}
		return nil
	}
	if out, err := exec.Command("auditctl", "-R", InstallPath).CombinedOutput(); err != nil {
		return fmt.Errorf("auditctl -R: %w: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}
