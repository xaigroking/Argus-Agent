// Command argus 是 Argus-Agent 的单一可执行文件。
//
// 以不同子命令、不同系统用户运行，构成多个权限域：
//
//	argus rules   root，仅安装时运行
//	argus parse   非特权 argus 用户，处理敌意输入
//	argus serve   非特权 argus 用户，只读数据库
package main

import (
	"os"

	"github.com/xaigroking/argus-agent/internal/cli"
)

func main() { os.Exit(cli.Main(os.Args)) }
