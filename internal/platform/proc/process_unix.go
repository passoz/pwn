//go:build unix

package proc

import (
	"os/exec"
	"syscall"
)

// ConfigureProcessGroup coloca o comando em um grupo de processos próprio,
// equivalente a detached: true no processo-pool.ts.
func ConfigureProcessGroup(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
}

// KillProcessGroup mata o grupo inteiro. O fallback cobre processo já fora do
// grupo (por exemplo, setsid feito pelo próprio filho). A falha do fallback é
// intencionalmente descartada: o timeout já fixa o status 137 e a espera pelo
// Wait detecta a morte real do processo.
func KillProcessGroup(cmd *exec.Cmd) {
	if cmd.Process == nil {
		return
	}
	if err := syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL); err != nil {
		_ = cmd.Process.Kill()
	}
}
