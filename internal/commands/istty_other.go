//go:build !linux

package commands

import "os"

// isTerminal não tem ioctl portátil fora do Linux: um dispositivo de caractere
// conta como terminal, como process.stdin.isTTY.
func isTerminal(file *os.File) bool {
	info, err := file.Stat()
	if err != nil {
		return false
	}
	return info.Mode()&os.ModeCharDevice != 0
}
