//go:build linux || darwin || freebsd

package gamelane

import (
	"os/exec"
	"path/filepath"
	"strings"
)

// processAliveByName 判断指定进程名是否存活（Linux/macOS/FreeBSD 实现）：
// pgrep -x 按进程名精确匹配（-f 场景不适用：记忆存的是可执行名）。
// name 可能为完整可执行路径，先取 basename。查询失败保守返回 true
// （不淘汰，避免探测失败误杀游戏目标）。
func processAliveByName(name string) bool {
	if name == "" {
		return false
	}
	base := strings.TrimSpace(filepath.Base(name))
	if base == "" {
		return false
	}
	if err := exec.Command("pgrep", "-x", base).Run(); err != nil {
		// pgrep 退出码 1 = 无匹配（进程已退出）；其它错误（命令不存在等）
		// 保守视为存活，不因探测失败误杀。
		if ee, ok := err.(*exec.ExitError); ok && ee.ExitCode() == 1 {
			return false
		}
		return true
	}
	return true
}
