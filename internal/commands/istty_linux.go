//go:build linux

package commands

import (
	"os"
	"syscall"
	"unsafe"
)

// ioctlReadTermios é TCGETS no Linux.
const ioctlReadTermios = 0x5401

// isTerminal informa se o arquivo é um terminal. TCGETS falha com ENOTTY em
// arquivo comum, pipe e /dev/null, como isTTY no Node.
func isTerminal(file *os.File) bool {
	var termios syscall.Termios
	_, _, errno := syscall.Syscall6(
		syscall.SYS_IOCTL,
		file.Fd(),
		ioctlReadTermios,
		uintptr(unsafe.Pointer(&termios)),
		0,
		0,
		0,
	)
	return errno == 0
}
