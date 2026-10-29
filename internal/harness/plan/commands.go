package plan

import (
	"os"
	"path"
	"regexp"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/passoz/pwn/internal/platform/shellwords"
)

// SplitCommandLine tokeniza uma linha de comando no subconjunto POSIX usado nos
// planos. Devolve ok=false quando as aspas não fecham.
func SplitCommandLine(command string) ([]string, bool) {
	return shellwords.Split(command)
}

// NormalizeCommand devolve a forma canônica de um comando para comparação.
func NormalizeCommand(command string) string {
	return shellwords.Normalize(command)
}

// DisplayCommand devolve a representação legível de um argv para mensagens.
func DisplayCommand(argv []string) string {
	return shellwords.Display(argv)
}

// CommandMatches informa se o argv do operador corresponde ao comando do plano.
func CommandMatches(planned string, argv []string) bool {
	return shellwords.Match(planned, argv)
}

// vacuousPrograms são os programas que não exercitam comportamento.
var vacuousPrograms = map[string]bool{
	"true": true, ":": true, "echo": true, "printf": true, "exit": true, "yes": true,
}

var shells = map[string]bool{"sh": true, "bash": true, "zsh": true, "dash": true}

var shellControl = regexp.MustCompile(`[;&|<>]`)

// VacuousCommandReason devolve o motivo pelo qual o comando não exercita
// comportamento algum (`true`, `echo ok`...), ou "" quando não há motivo.
func VacuousCommandReason(command string) string {
	tokens, ok := SplitCommandLine(strings.TrimSpace(command))
	if !ok || len(tokens) == 0 {
		return "comando vazio ou com aspas desbalanceadas"
	}
	program := path.Base(tokens[0])
	if vacuousPrograms[program] {
		return "`" + program + "` não exercita comportamento"
	}
	if shells[program] && len(tokens) == 3 && tokens[1] == "-c" && !shellControl.MatchString(tokens[2]) {
		return VacuousCommandReason(tokens[2])
	}
	return ""
}

// suiteRunners são os runners cuja execução sem alvo roda a suíte inteira.
var suiteRunners = [][]string{
	{"bun", "test"}, {"bun", "run", "test"},
	{"npm", "test"}, {"npm", "t"}, {"npm", "run", "test"},
	{"pnpm", "test"}, {"pnpm", "run", "test"},
	{"yarn", "test"}, {"yarn", "run", "test"},
	{"npx", "vitest", "run"}, {"npx", "vitest"}, {"vitest", "run"}, {"vitest"},
	{"npx", "jest"}, {"jest"},
	{"node", "--test"},
	{"deno", "test"},
	{"go", "test"},
	{"cargo", "test"},
	{"python", "-m", "pytest"}, {"python3", "-m", "pytest"}, {"pytest"},
	{"mvn", "test"}, {"gradle", "test"}, {"./gradlew", "test"},
	{"dotnet", "test"}, {"mix", "test"}, {"bundle", "exec", "rspec"}, {"rspec"}, {"phpunit"}, {"vendor/bin/phpunit"},
	{"make", "test"}, {"make", "check"},
}

// nonSelectingValueFlags são flags de runner que recebem valor sem estreitar a
// seleção de testes.
var nonSelectingValueFlags = map[string]bool{
	"--timeout": true, "-timeout": true, "--reporter": true, "--reporters": true,
	"--rerun-each": true, "--seed": true, "--bail": true, "--preload": true,
	"--coverage-reporter": true, "--coverage-dir": true, "--max-concurrency": true,
	"--config": true, "-c": true, "--project": true, "-count": true,
	"-p": true, "--maxfail": true, "--workers": true, "-j": true, "--jobs": true,
	"--parallel": true, "-parallel": true,
}

var allDigits = regexp.MustCompile(`^[0-9]+$`)

// IsWholeSuiteCommand informa se o comando roda a suíte inteira de um runner
// conhecido, sem arquivo, filtro ou pacote alvo.
func IsWholeSuiteCommand(command string) bool {
	tokens, ok := SplitCommandLine(strings.TrimSpace(command))
	if !ok || len(tokens) == 0 {
		return false
	}
	var runner []string
	for _, prefix := range suiteRunners {
		if len(tokens) < len(prefix) {
			continue
		}
		matched := true
		for index, token := range prefix {
			if tokens[index] != token {
				matched = false
				break
			}
		}
		if matched {
			runner = prefix
			break
		}
	}
	if runner == nil {
		return false
	}
	rest := tokens[len(runner):]
	for index := 0; index < len(rest); index++ {
		arg := rest[index]
		if arg == "--" {
			continue
		}
		if strings.HasPrefix(arg, "-") {
			if !strings.Contains(arg, "=") && nonSelectingValueFlags[arg] {
				index++
			}
			continue
		}
		if arg == "./..." || arg == "." || arg == "..." || allDigits.MatchString(arg) {
			continue
		}
		return false
	}
	return true
}

// GenericCommandReason devolve o motivo pelo qual o comando não serve como
// critério de aceite de uma task: vazio ou vácuo, repetição de um gate global
// ou suíte inteira sem alvo.
func GenericCommandReason(command string, gateCommands []string) string {
	if vacuous := VacuousCommandReason(command); vacuous != "" {
		return vacuous
	}
	normalized := NormalizeCommand(command)
	for _, gate := range gateCommands {
		if NormalizeCommand(gate) == normalized {
			return "repete um gate global/comando de regressão — gate não é critério de aceite da task"
		}
	}
	if IsWholeSuiteCommand(command) {
		return "roda a suíte inteira sem alvo — não prova o comportamento da task"
	}
	return ""
}

// genericExpect são marcadores do runner que não identificam a asserção.
var genericExpect = map[string]bool{
	"(fail)": true, "fail": true, "fail:": true, "failed": true, "failure": true,
	"failing": true, "error": true, "error:": true, "errors": true,
	"assertionerror": true, "assertion": true, "assert": true, "expected": true,
	"received": true, "expect(received)": true, "tobe": true, "not ok": true,
	"panic": true, "traceback": true, "exception": true, "fatal": true,
	"false": true, "undefined": true, "null": true,
}

// GenericExpectReason devolve o motivo pelo qual o texto de `--expect` é
// genérico demais para identificar a asserção da task, ou "".
func GenericExpectReason(expect string) string {
	text := strings.TrimSpace(expect)
	if genericExpect[strings.ToLower(text)] {
		return `"` + text + `" é marcador genérico do runner, não a asserção da task`
	}
	if length := utf8.RuneCountInString(text); length < 6 {
		return `"` + text + `" tem ` + strconv.Itoa(length) + " caractere(s); use o identificador da asserção (mínimo 6)"
	}
	return ""
}

var (
	globMarkers     = regexp.MustCompile(`[*?[\]{}]`)
	placeholderPath = regexp.MustCompile(`<[^>]*>|\bTODO\b|\bTBD\b`)
)

// PlaceholderPathReason devolve o motivo pelo qual um caminho declarado não é
// um arquivo concreto (diretório, glob, placeholder), ou "".
func PlaceholderPathReason(filePath string) string {
	value := strings.TrimSpace(filePath)
	if value == "" {
		return "caminho vazio"
	}
	if value == "." || value == ".." || strings.HasSuffix(value, "/") || strings.HasSuffix(value, string(os.PathSeparator)) {
		return "é diretório, não arquivo"
	}
	if globMarkers.MatchString(value) {
		return "é glob, não arquivo"
	}
	if placeholderPath.MatchString(value) {
		return "é placeholder"
	}
	return ""
}

// FirstInlineCommand devolve o primeiro trecho em crase de um texto, ou o texto
// inteiro quando não há crase. ok=false quando o texto é vazio.
func FirstInlineCommand(text string) (string, bool) {
	match := inlineCodePattern.FindStringSubmatch(text)
	if match != nil {
		return strings.TrimSpace(match[1]), true
	}
	plain := strings.TrimSpace(text)
	if plain == "" {
		return "", false
	}
	return plain, true
}
