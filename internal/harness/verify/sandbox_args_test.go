package verify

import (
	"strings"
	"testing"
)

func indexOf(values []string, wanted string) int {
	for index, value := range values {
		if value == wanted {
			return index
		}
	}
	return -1
}

// O bug original: uma montagem de dependência antes de `--bind workDir` é
// encoberta pelo bind da árvore e `node_modules` desaparece do sandbox.
func TestSandboxArgsMountDependenciesAfterWorkDir(t *testing.T) {
	policy := BuildSandboxPolicy("/opt/runtime/bin/bun", nil, nil)
	workDir := "/tmp/pwn-verify/candidate"
	extra := [][2]string{
		{"/home/op/.cache/bun", "/home/op/.cache/bun"},
		{"/repo/node_modules", workDir + "/node_modules"},
	}
	args := sandboxArgs(policy, workDir, extra, []string{"/opt/runtime/bin/bun", "test"})

	workBind := indexOf(args, "--bind")
	if workBind < 0 || workBind+2 >= len(args) || args[workBind+1] != workDir || args[workBind+2] != workDir {
		t.Fatalf("bind da árvore ausente: %v", args)
	}
	dependencyBind := -1
	for index := 0; index+2 < len(args); index++ {
		if args[index] == "--ro-bind" && args[index+2] == workDir+"/node_modules" {
			dependencyBind = index
			break
		}
	}
	if dependencyBind < 0 {
		t.Fatalf("montagem de node_modules ausente: %v", args)
	}
	if dependencyBind < workBind {
		t.Fatalf("node_modules foi montado antes de --bind %s: %v", workDir, args)
	}

	chdir := indexOf(args, "--chdir")
	if chdir < dependencyBind {
		t.Fatalf("--chdir deve vir depois das montagens extras: %v", args)
	}
	for _, required := range []string{"--unshare-user", "--unshare-pid", "--unshare-net", "--die-with-parent", "--clearenv"} {
		if indexOf(args, required) < 0 {
			t.Errorf("falta %s em %v", required, args)
		}
	}
	if home := args[indexOf(args, "--setenv")+1]; home != "HOME" {
		t.Errorf("primeiro --setenv = %q, quer HOME", home)
	}
}

func TestSandboxArgsHomeAndPolicy(t *testing.T) {
	policy := BuildSandboxPolicy("/usr/bin/bun", nil, nil)
	args := sandboxArgs(policy, "/work", nil, []string{"/usr/bin/bun"})
	if indexOf(args, "--dir") >= 0 {
		t.Errorf("HOME /nonexistent não deve criar --dir: %v", args)
	}
	home := indexOf(args, "--setenv")
	if args[home+2] != "/nonexistent" {
		t.Errorf("HOME = %q, quer /nonexistent", args[home+2])
	}

	project := &ProjectSandboxConfig{
		MountsRO:    []string{"/opt/modules"},
		Mounts:      []ProjectMount{{Source: "/cache", Dest: "/pwn-home/cache"}},
		Home:        "/pwn-home",
		PathPrepend: []string{"/opt/toolchain/bin"},
		Env:         map[string]string{"GOPROXY": "off"},
	}
	custom := BuildSandboxPolicy("/usr/bin/bun", nil, project)
	customArgs := sandboxArgs(custom, "/work", nil, []string{"/usr/bin/bun"})
	dir := indexOf(customArgs, "--dir")
	if dir < 0 || customArgs[dir+1] != "/pwn-home" {
		t.Fatalf("--dir do HOME ausente: %v", customArgs)
	}
	mountIndex := -1
	for index := 0; index+2 < len(customArgs); index++ {
		if customArgs[index] == "--dir" && customArgs[index+1] == "/pwn-home/cache" {
			mountIndex = index
			break
		}
	}
	if mountIndex < 0 || mountIndex < dir {
		t.Errorf("a montagem do projeto deve vir depois da criação do HOME: %v", customArgs)
	}
	pathValue := ""
	for index := 0; index+2 < len(customArgs); index++ {
		if customArgs[index] == "--setenv" && customArgs[index+1] == "PATH" {
			pathValue = customArgs[index+2]
		}
	}
	if !strings.HasPrefix(pathValue, "/opt/toolchain/bin:/usr/bin:/bin") {
		t.Errorf("PATH = %q", pathValue)
	}
	if indexOf(customArgs, "GOPROXY") < 0 {
		t.Errorf("env do projeto ausente: %v", customArgs)
	}
}

func TestSortedUnique(t *testing.T) {
	values := sortedUnique([]string{"/lib", "/usr", "/bin", "/usr"})
	want := []string{"/bin", "/lib", "/usr"}
	if len(values) != len(want) {
		t.Fatalf("values = %v", values)
	}
	for index := range want {
		if values[index] != want[index] {
			t.Fatalf("values = %v, quer %v", values, want)
		}
	}
}

// Nas verificações o cache é overlay com escrita em tmpfs; só o aquecimento o
// grava de fato. Trocar os dois modos deixaria o código avaliado envenenar o cache.
func TestSandboxArgsOverlayModes(t *testing.T) {
	policy := BuildSandboxPolicy("/usr/bin/bun", nil, &ProjectSandboxConfig{
		Overlays: []ProjectMount{{Source: "/var/warm", Dest: "/tmp/gocache"}},
	})
	command := []string{"/usr/bin/go", "test"}

	verification := strings.Join(sandboxArgsFor(policy, "/work", nil, false, command), " ")
	if !strings.Contains(verification, "--overlay-src /var/warm --tmp-overlay /tmp/gocache") {
		t.Errorf("verificação sem overlay: %s", verification)
	}
	if strings.Contains(verification, "--bind /var/warm") {
		t.Errorf("verificação não pode montar o cache com escrita: %s", verification)
	}
	if strings.Index(verification, "--tmpfs /tmp") > strings.Index(verification, "--tmp-overlay") {
		t.Errorf("o overlay precisa vir depois de --tmpfs /tmp: %s", verification)
	}

	warm := strings.Join(sandboxArgsFor(policy, "/work", nil, true, command), " ")
	if !strings.Contains(warm, "--bind /var/warm /tmp/gocache") || strings.Contains(warm, "--overlay-src") {
		t.Errorf("aquecimento deve montar o cache com escrita: %s", warm)
	}
}
