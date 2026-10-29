//go:build !unix

package proc

import "os/exec"

// ConfigureProcessGroup é vazio fora do Unix: não existe grupo de processos
// equivalente. Limitação documentada: netos podem sobreviver ao timeout.
func ConfigureProcessGroup(cmd *exec.Cmd) {}

func KillProcessGroup(cmd *exec.Cmd) {
	if cmd.Process != nil {
		_ = cmd.Process.Kill()
	}
}
