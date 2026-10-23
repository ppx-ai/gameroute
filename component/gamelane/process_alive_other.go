//go:build !windows && !linux && !darwin && !freebsd

package gamelane

// processAliveByName 非目标平台 stub：无法探测进程存活，保守返回 true
// （当作进程存活，不淘汰），避免误杀游戏目标。
func processAliveByName(name string) bool {
	return name != ""
}
