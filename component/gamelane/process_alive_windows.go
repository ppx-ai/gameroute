//go:build windows

package gamelane

import (
	"os/exec"
	"path/filepath"
	"strings"
)

// processAliveByName 判断指定进程名是否存活（Windows 实现）：
// tasklist 按映像名精确匹配（大小写不敏感），返回 "No tasks are running"
// 即进程不存在。name 可能为完整可执行路径（findProcess 返回 QueryFullProcessImageNameW
// 结果），先取 basename 再查询。查询失败保守返回 true（不淘汰，避免探测
// 失败误杀游戏目标）。
func processAliveByName(name string) bool {
	if name == "" {
		return false
	}
	base := strings.TrimSpace(filepath.Base(name))
	if base == "" {
		return false
	}
	out, err := exec.Command("tasklist", "/FI", "IMAGENAME eq "+base, "/NH").Output()
	if err != nil {
		return true
	}
	return !strings.Contains(string(out), "No tasks are running")
}
