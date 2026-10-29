//go:build !unix

package proc

import "os/exec"

// configureProcessGroup é vazio fora do Unix: não existe grupo de processos
// equivalente. Limitação documentada: netos podem sobreviver ao timeout.
func configureProcessGroup(cmd *exec.Cmd) {}

func killProcessGroup(cmd *exec.Cmd) {
	if cmd.Process != nil {
		_ = cmd.Process.Kill()
	}
}
