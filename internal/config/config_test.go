package config

import (
	"os"
	"path/filepath"
	"testing"
)

// 没有配置文件时必须能跑：这是“安装后无需配置”的前提。
func TestDefaultWithoutFile(t *testing.T) {
	cfg, err := Load(filepath.Join(t.TempDir(), "不存在.json"))
	if err != nil {
		t.Fatalf("配置文件缺失不应报错: %v", err)
	}
	if cfg.AuditLog == "" || cfg.DBPath == "" || cfg.Listen == "" {
		t.Error("默认值不完整")
	}
	if len(cfg.Agents) == 0 {
		t.Error("默认 Agent 规则为空")
	}
}

// 默认只监听本机。改成对外监听必须是用户的显式选择。
func TestDefaultListensOnLoopbackOnly(t *testing.T) {
	if got := Default().Listen; got != "127.0.0.1:8873" {
		t.Errorf("默认监听地址 = %q，必须是回环地址", got)
	}
}

// 部分覆盖：文件中未出现的字段保留默认值，
// 这样升级新增配置项时不会要求用户改文件。
func TestPartialOverrideKeepsDefaults(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "config.json")
	if err := os.WriteFile(p, []byte(`{"retention_days": 7}`), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(p)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.RetentionDays != 7 {
		t.Errorf("retention_days = %d，期望 7", cfg.RetentionDays)
	}
	d := Default()
	if cfg.AuditLog != d.AuditLog || cfg.Listen != d.Listen || len(cfg.Agents) != len(d.Agents) {
		t.Error("未在文件中出现的字段应保留默认值")
	}
}

func TestInvalidConfigRejected(t *testing.T) {
	dir := t.TempDir()
	for name, body := range map[string]string{
		"相对路径":   `{"db_path": "argus.db"}`,
		"保留期为零":  `{"retention_days": 0}`,
		"保留期过大":  `{"retention_days": 99999}`,
		"跟踪表过小":  `{"max_tracked_procs": 10}`,
		"非法JSON": `{not json`,
	} {
		p := filepath.Join(dir, "c.json")
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
		if _, err := Load(p); err == nil {
			t.Errorf("%s: 应报错但通过了", name)
		}
	}
}

// 用户可只覆盖 Agent 列表，不动主配置。
func TestLoadAgentsOverride(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "agents.json")
	if err := os.WriteFile(p, []byte(`[{"name":"my-bot","exe":["mybot"]}]`), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg := Default()
	if err := cfg.LoadAgents(p); err != nil {
		t.Fatal(err)
	}
	if len(cfg.Agents) != 1 || cfg.Agents[0].Name != "my-bot" {
		t.Errorf("Agent 规则未被覆盖: %+v", cfg.Agents)
	}
	// 文件不存在时保留内置规则
	cfg2 := Default()
	if err := cfg2.LoadAgents(filepath.Join(dir, "无.json")); err != nil {
		t.Fatal(err)
	}
	if len(cfg2.Agents) == 0 {
		t.Error("文件缺失时应保留内置 Agent 规则")
	}
}
