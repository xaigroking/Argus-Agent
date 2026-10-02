// Package config 提供全部内置默认值。
//
// 设计约束：安装后无需任何配置即可运行。配置文件是可选的覆盖层，
// 每个字段都有默认值，升级永不要求用户手工改配置。
package config

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

const (
	DefaultPath   = "/etc/argus/config.json"
	DefaultAgents = "/etc/argus/agents.json"
)

// AgentRule 用于识别一个 AI Agent 进程。
type AgentRule struct {
	Name string `json:"name"`
	// Exe 匹配可执行文件名（basename），不区分路径。
	Exe []string `json:"exe"`
}

type Config struct {
	AuditLog      string `json:"audit_log"`
	DBPath        string `json:"db_path"`
	StatePath     string `json:"state_path"`
	Listen        string `json:"listen"`
	RetentionDays int    `json:"retention_days"`
	// MaxTrackedProcs 限制血缘跟踪表的大小，防止内存无界增长。
	MaxTrackedProcs int `json:"max_tracked_procs"`
	// FlushInterval 为写入批次的最长间隔（秒）。
	FlushIntervalSec int         `json:"flush_interval_sec"`
	Agents           []AgentRule `json:"agents"`
}

// Default 返回内置默认配置。安装包不写任何用户态配置也能直接运行。
func Default() Config {
	return Config{
		AuditLog:         "/var/log/audit/audit.log",
		DBPath:           "/var/lib/argus/argus.db",
		StatePath:        "/var/lib/argus/state.json",
		Listen:           "127.0.0.1:8873",
		RetentionDays:    30,
		MaxTrackedProcs:  200000,
		FlushIntervalSec: 2,
		Agents:           DefaultAgentRules(),
	}
}

// DefaultAgentRules 是内置的 AI Agent 识别规则。
// 进阶用户可通过 /etc/argus/agents.json 覆盖或扩充。
func DefaultAgentRules() []AgentRule {
	return []AgentRule{
		{Name: "claude-code", Exe: []string{"claude"}},
		{Name: "codex", Exe: []string{"codex"}},
		{Name: "gemini-cli", Exe: []string{"gemini"}},
		{Name: "cursor-agent", Exe: []string{"cursor-agent"}},
		{Name: "aider", Exe: []string{"aider"}},
		{Name: "opencode", Exe: []string{"opencode"}},
		{Name: "copilot-cli", Exe: []string{"copilot"}},
	}
}

func (c Config) FlushInterval() time.Duration {
	if c.FlushIntervalSec <= 0 {
		return 2 * time.Second
	}
	return time.Duration(c.FlushIntervalSec) * time.Second
}

// Load 读取配置文件并覆盖默认值。文件不存在不是错误——这是预期的常见情况。
func Load(path string) (Config, error) {
	cfg := Default()
	if path == "" {
		path = DefaultPath
	}
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return cfg, nil
		}
		return cfg, fmt.Errorf("读取配置 %s: %w", path, err)
	}
	// 覆盖式解码：文件中未出现的字段保留默认值。
	if err := json.Unmarshal(data, &cfg); err != nil {
		return Default(), fmt.Errorf("解析配置 %s: %w", path, err)
	}
	if err := cfg.validate(); err != nil {
		return Default(), err
	}
	return cfg, nil
}

// LoadAgents 单独加载 Agent 识别规则，便于用户只覆盖这一部分。
func (c *Config) LoadAgents(path string) error {
	if path == "" {
		path = DefaultAgents
	}
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("读取 %s: %w", path, err)
	}
	var rules []AgentRule
	if err := json.Unmarshal(data, &rules); err != nil {
		return fmt.Errorf("解析 %s: %w", path, err)
	}
	if len(rules) > 0 {
		c.Agents = rules
	}
	return nil
}

func (c Config) validate() error {
	if c.AuditLog == "" || !filepath.IsAbs(c.AuditLog) {
		return fmt.Errorf("audit_log 必须是绝对路径")
	}
	if c.DBPath == "" || !filepath.IsAbs(c.DBPath) {
		return fmt.Errorf("db_path 必须是绝对路径")
	}
	if c.RetentionDays < 1 || c.RetentionDays > 3650 {
		return fmt.Errorf("retention_days 须在 1..3650 之间")
	}
	if c.MaxTrackedProcs < 1000 {
		return fmt.Errorf("max_tracked_procs 不得小于 1000")
	}
	return nil
}

// WriteDefault 写出一份完整的默认配置，供进阶用户修改。
func WriteDefault(path string, v any) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(data, '\n'), 0o644)
}
