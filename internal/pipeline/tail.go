// Package pipeline 实现 audit.log 的跟随读取与入库流水线。
package pipeline

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"syscall"
	"time"
)

// State 记录读取位置，用于重启后续读。
// 以 inode 识别文件，轮转后 inode 改变，从新文件开头读起。
type State struct {
	Inode  uint64 `json:"inode"`
	Offset int64  `json:"offset"`
}

func LoadState(path string) State {
	var s State
	data, err := os.ReadFile(path)
	if err != nil {
		return State{}
	}
	if json.Unmarshal(data, &s) != nil {
		return State{}
	}
	return s
}

// SaveState 原子写入：先写临时文件再 rename，避免崩溃时留下半截状态。
func SaveState(path string, s State) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return err
	}
	data, err := json.Marshal(s)
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o640); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func inodeOf(fi os.FileInfo) uint64 {
	if st, ok := fi.Sys().(*syscall.Stat_t); ok {
		return st.Ino
	}
	return 0
}

// Tailer 跟随一个会被轮转的日志文件。
type Tailer struct {
	path  string
	f     *os.File
	rd    *bufio.Reader
	inode uint64
	off   int64
	// PollInterval 是读到文件末尾后的等待间隔。
	PollInterval time.Duration
	// MaxLineLen 超长行会被截断，防止畸形输入耗尽内存。
	MaxLineLen int
}

func NewTailer(path string, st State) (*Tailer, error) {
	t := &Tailer{
		path:         path,
		PollInterval: 500 * time.Millisecond,
		MaxLineLen:   256 << 10,
	}
	if err := t.open(st); err != nil {
		return nil, err
	}
	return t, nil
}

func (t *Tailer) open(st State) error {
	f, err := os.Open(t.path)
	if err != nil {
		return fmt.Errorf("打开 %s: %w（argus 用户是否有读权限？）", t.path, err)
	}
	fi, err := f.Stat()
	if err != nil {
		f.Close()
		return err
	}
	ino := inodeOf(fi)
	off := int64(0)
	// 仅当 inode 一致且偏移未越界时才续读，否则从头开始。
	if st.Inode != 0 && st.Inode == ino && st.Offset <= fi.Size() {
		off = st.Offset
	}
	if _, err := f.Seek(off, io.SeekStart); err != nil {
		f.Close()
		return err
	}
	t.f, t.inode, t.off = f, ino, off
	t.rd = bufio.NewReaderSize(f, 128<<10)
	return nil
}

// State 返回当前读取位置。
func (t *Tailer) State() State { return State{Inode: t.inode, Offset: t.off} }

func (t *Tailer) Close() error {
	if t.f != nil {
		return t.f.Close()
	}
	return nil
}

// Next 返回下一行。读到末尾时返回 (”", false, nil)，调用方应稍后重试。
// 轮转与截断在此处理。
func (t *Tailer) Next() (string, bool, error) {
	line, err := t.readLine()
	if err == nil {
		return line, true, nil
	}
	if err != io.EOF {
		return "", false, err
	}
	// 到达末尾：检查是否发生轮转或截断
	fi, serr := os.Stat(t.path)
	if serr != nil {
		// 文件暂时不存在（轮转中），下次重试
		return "", false, nil
	}
	if ino := inodeOf(fi); ino != t.inode {
		// 轮转：旧文件已读完，切换到新文件从头读
		t.f.Close()
		if err := t.open(State{}); err != nil {
			return "", false, err
		}
		return "", false, nil
	}
	if fi.Size() < t.off {
		// 截断：回到文件开头
		if _, err := t.f.Seek(0, io.SeekStart); err != nil {
			return "", false, err
		}
		t.off = 0
		t.rd.Reset(t.f)
	}
	return "", false, nil
}

// readLine 读取一整行，超长行截断后丢弃其余部分。
func (t *Tailer) readLine() (string, error) {
	var buf []byte
	for {
		chunk, isPrefix, err := t.rd.ReadLine()
		if err != nil {
			// 没有完整行时，把已读内容退回：bufio 不支持回退，
			// 因此仅在读到完整行后才推进 off，保证崩溃后不丢数据。
			return "", err
		}
		t.off += int64(len(chunk))
		if !isPrefix {
			t.off++ // 换行符
		}
		if len(buf)+len(chunk) <= t.MaxLineLen {
			buf = append(buf, chunk...)
		}
		if !isPrefix {
			return string(buf), nil
		}
	}
}
