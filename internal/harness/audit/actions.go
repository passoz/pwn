package audit

import (
	"fmt"
	"os"
	"regexp"
	"slices"
	"strings"

	"github.com/passoz/pwn/internal/harness/plan"
)

func (a *auditor) baseline(args *parsedArgs) (int, error) {
	loaded, err := loadPlanTask(args.work, args.task)
	if err != nil {
		return 0, err
	}
	drift, err := planDrift(args.work, loaded.text)
	if err != nil {
		return 0, err
	}
	if drift != "" {
		return 0, fmt.Errorf("%s", drift)
	}

	implementation := loaded.task.ImplementationFiles
	tests := loaded.task.TestFiles
	problems := make([]string, 0, 4)
	if len(implementation) == 0 {
		problems = append(problems, fmt.Sprintf("a task %s não declara **Implementation files:** no plano", args.task))
	}
	if len(tests) == 0 {
		problems = append(problems, fmt.Sprintf("a task %s não declara **Test files:** no plano", args.task))
	}
	declared := append(append([]string{}, implementation...), tests...)
	for _, filePath := range declared {
		if reason := plan.PlaceholderPathReason(filePath); reason != "" {
			problems = append(problems, fmt.Sprintf("%s %s: declare arquivos concretos no plano", filePath, reason))
		}
	}
	if len(args.implementation) > 0 && !sameSet(args.implementation, implementation) {
		problems = append(problems, fmt.Sprintf(
			"--implementation diverge do plano (plano: %s; operador: %s)",
			joinOrDash(implementation), joinOrDash(args.implementation),
		))
	}
	if len(args.tests) > 0 && !sameSet(args.tests, tests) {
		problems = append(problems, fmt.Sprintf(
			"--tests diverge do plano (plano: %s; operador: %s)",
			joinOrDash(tests), joinOrDash(args.tests),
		))
	}
	if len(problems) > 0 {
		return a.reportViolations(problems), nil
	}

	if err := ensureDisjoint(implementation, tests); err != nil {
		return 0, err
	}
	if err := requireCleanBaseline(declared); err != nil {
		return 0, err
	}
	commit, err := gitHead()
	if err != nil {
		return 0, err
	}
	for _, filePath := range implementation {
		if _, statErr := os.Stat(filePath); statErr != nil {
			continue
		}
		if err := requireTracked(filePath); err != nil {
			return 0, err
		}
	}

	contract, err := loadContractInfo(args.work, args.task)
	if err != nil {
		return 0, err
	}
	frozen := make([]FrozenTest, 0)
	if contract != nil {
		frozen = nonNilFrozen(contract.FrozenTests)
	}
	frozenOverlap := make([]string, 0)
	for _, entry := range frozen {
		if contains(implementation, entry.Path) {
			frozenOverlap = append(frozenOverlap, entry.Path)
		}
	}
	if len(frozenOverlap) > 0 {
		return 0, fmt.Errorf("teste congelado declarado como implementação: %s", strings.Join(frozenOverlap, ", "))
	}
	frozenProblems, err := frozenTestViolations(frozen)
	if err != nil {
		return 0, err
	}
	if len(frozenProblems) > 0 {
		return a.reportViolations(frozenProblems), nil
	}

	implementationSnapshot, err := snapshot(implementation)
	if err != nil {
		return 0, err
	}
	testsSnapshot, err := snapshot(tests)
	if err != nil {
		return 0, err
	}
	var contractRef *ContractRef
	if contract != nil {
		contractRef = &ContractRef{ID: contract.ID, SHA256: contract.SHA256}
	}
	state := &State{
		Task:                   args.task,
		CreatedAt:              nowISO(),
		StateVersion:           stateVersion,
		BaselineCommit:         commit,
		PlanPath:               loaded.path,
		TaskDefinitionSHA256:   plan.TaskDefinitionDigest(loaded.text, loaded.task),
		Contract:               contractRef,
		FrozenTests:            frozen,
		ImplementationFiles:    implementation,
		TestFiles:              tests,
		BaselineImplementation: implementationSnapshot,
		BaselineTests:          testsSnapshot,
	}
	if err := saveState(a.paths, state); err != nil {
		return 0, err
	}
	fmt.Fprintf(a.out, "PASS: baseline captured for %s (arquivos e comandos amarrados a %s)\n", args.task, loaded.path)
	return ExitOK, nil
}

func (a *auditor) red(args *parsedArgs) (int, error) {
	state, reason := tryLoadState(a.paths, args.task)
	if state == nil {
		return a.reportIncomplete([]string{fmt.Sprintf("baseline (%s)", reason)}), nil
	}
	loaded, err := guardDefinition(state, args.work, args.task)
	if err != nil {
		return 0, err
	}
	if loaded.task.Red == nil {
		return 0, fmt.Errorf("a task %s não declara comando em **RED:** no plano", args.task)
	}
	if !plan.CommandMatches(loaded.task.Red.Command, args.command) {
		return 0, fmt.Errorf(
			"RED invalid: comando diverge do plano (plano: `%s`; operador: `%s`)",
			loaded.task.Red.Command, plan.DisplayCommand(args.command),
		)
	}

	implementationChanges, err := snapshotChanges(state.BaselineImplementation, state.ImplementationFiles)
	if err != nil {
		return 0, err
	}
	if len(implementationChanges) > 0 {
		return 0, fmt.Errorf("RED invalid: implementation changed before RED: %s", strings.Join(implementationChanges, ", "))
	}

	testNow, err := snapshot(state.TestFiles)
	if err != nil {
		return 0, err
	}
	testChanges := changed(state.BaselineTests, testNow)
	if len(testChanges) == 0 {
		return 0, fmt.Errorf("RED invalid: no test file changed since baseline")
	}

	contractVersion := contractVersionOf(loaded.text)
	strict := contractVersion >= 3
	genericExpect := plan.GenericExpectReason(args.expect)
	if genericExpect != "" {
		if strict {
			fmt.Fprintf(a.err, "FAIL: --expect genérico: %s\n", genericExpect)
			return ExitViolation, nil
		}
		fmt.Fprintf(a.err, "WARNING: --expect genérico aceito pelo contrato legado v%d: %s\n", contractVersion, genericExpect)
	}

	// No contrato v3 o texto esperado precisa estar escrito no teste congelado.
	literalRequired := strict || args.expectLiteral
	literalInTests := true
	if literalRequired {
		literalInTests = false
		for _, filePath := range state.TestFiles {
			data, readErr := os.ReadFile(filePath)
			if readErr != nil {
				continue
			}
			if strings.Contains(string(data), args.expect) {
				literalInTests = true
				break
			}
		}
	}
	if !literalInTests {
		fmt.Fprintln(a.err, "FAIL: --expect não é literal nos arquivos de teste congelados")
		return ExitViolation, nil
	}

	result, err := run(args.command)
	if err != nil {
		return 0, err
	}
	relevant := strings.Contains(result.output, args.expect)
	if result.exitCode != 0 && relevant && IsToolchainError(result.output, args.expect) {
		if strict {
			logPath, logErr := writeLog(a.paths, args.task, "RED", args.command, result.exitCode, result.output, "FAIL", "")
			if logErr != nil {
				return 0, logErr
			}
			fmt.Fprintf(
				a.err,
				"FAIL: RED rejected — output matches a toolchain/environment error pattern without evidence of an assertion firing; rewrite the task so the baseline contains a compilable but incorrect implementation and the test assertion fails; evidence: %s\n",
				logPath,
			)
			return ExitViolation, nil
		}
		fmt.Fprintf(a.err, "WARNING: RED accepted due to legacy contract v%d, but output matches an incidental environment failure.\n", contractVersion)
	}

	verdict := "FAIL"
	if result.exitCode != 0 && relevant {
		verdict = "PASS"
	}
	logPath, err := writeLog(a.paths, args.task, "RED", args.command, result.exitCode, result.output, verdict, "")
	if err != nil {
		return 0, err
	}
	if verdict == "FAIL" {
		fmt.Fprintf(
			a.err,
			"FAIL: RED needs non-zero exit and output containing %s; evidence: %s\n",
			jsonQuote(args.expect), logPath,
		)
		return ExitViolation, nil
	}

	state.RedTests = &testNow
	state.RedCommand = args.command
	state.RedExpect = args.expect
	if err := saveState(a.paths, state); err != nil {
		return 0, err
	}
	fmt.Fprintf(a.out, "PASS: RED captured and tests frozen; evidence: %s\n", logPath)
	return ExitOK, nil
}

func (a *auditor) green(args *parsedArgs) (int, error) {
	state, reason := tryLoadState(a.paths, args.task)
	if state == nil {
		return a.reportIncomplete([]string{fmt.Sprintf("baseline (%s)", reason)}), nil
	}
	if state.RedTests == nil {
		return a.reportIncomplete([]string{fmt.Sprintf("RED (RED evidence not found for task %s)", args.task)}), nil
	}
	if _, err := guardDefinition(state, args.work, args.task); err != nil {
		return 0, err
	}
	redCommand := state.RedCommand
	redExpect := state.RedExpect

	testNow, err := snapshot(state.TestFiles)
	if err != nil {
		return 0, err
	}
	if testChanges := changed(*state.RedTests, testNow); len(testChanges) > 0 {
		return 0, fmt.Errorf("GREEN invalid: test files changed after RED: %s", strings.Join(testChanges, ", "))
	}

	implementationNow, err := snapshot(state.ImplementationFiles)
	if err != nil {
		return 0, err
	}
	if implementationChanges := changed(state.BaselineImplementation, implementationNow); len(implementationChanges) == 0 {
		return 0, fmt.Errorf("GREEN invalid: no implementation file changed since baseline")
	}

	command := args.command
	if !slices.Equal(command, redCommand) {
		return 0, fmt.Errorf("GREEN invalid: command differs from RED command")
	}
	result, err := run(command)
	if err != nil {
		return 0, err
	}
	relevant := !args.expectSet || strings.Contains(result.output, args.expect)
	if result.exitCode != 0 || !relevant {
		logPath, logErr := writeLog(a.paths, args.task, "GREEN", command, result.exitCode, result.output, "FAIL", "")
		if logErr != nil {
			return 0, logErr
		}
		fmt.Fprintf(a.err, "FAIL: GREEN command did not pass expected output; evidence: %s\n", logPath)
		return ExitViolation, nil
	}

	mutation, err := withoutImplementation(state, func() (execResult, error) {
		return run(command)
	})
	if err != nil {
		return 0, err
	}
	if mutation.exitCode == 0 || !strings.Contains(mutation.output, redExpect) {
		return 0, fmt.Errorf("mutation check failed: test still passes or no longer reports the RED assertion without implementation diff")
	}
	extra := fmt.Sprintf(
		"MUTATION_EXIT: %d\nMUTATION_OUTPUT:\n%s\nMUTATION_VERDICT: PASS\n",
		mutation.exitCode, mutation.output,
	)
	logPath, err := writeLog(a.paths, args.task, "GREEN", command, result.exitCode, result.output, "PASS", extra)
	if err != nil {
		return 0, err
	}

	state.GreenImplementation = implementationNow
	state.GreenTests = testNow
	state.GreenExpect = nil
	if args.expectSet {
		expect := args.expect
		state.GreenExpect = &expect
	}
	if err := saveState(a.paths, state); err != nil {
		return 0, err
	}
	fmt.Fprintf(a.out, "PASS: GREEN captured with frozen tests and production diff; evidence: %s\n", logPath)
	return ExitOK, nil
}

func (a *auditor) verify(args *parsedArgs) (int, error) {
	state, reason := tryLoadState(a.paths, args.task)
	if state == nil {
		return a.reportIncomplete([]string{fmt.Sprintf("baseline (%s)", reason)}), nil
	}
	if _, err := guardDefinition(state, args.work, args.task); err != nil {
		return 0, err
	}
	if state.GreenImplementation == nil || state.GreenTests == nil {
		return a.reportIncomplete([]string{fmt.Sprintf("GREEN (GREEN evidence not found for task %s)", args.task)}), nil
	}
	if len(state.RedCommand) == 0 {
		return a.reportIncomplete([]string{fmt.Sprintf("RED (comando RED não registrado no estado da task %s)", args.task)}), nil
	}
	if !slices.Equal(args.command, state.RedCommand) {
		return 0, fmt.Errorf(
			"verification invalidated: command differs from RED command (estado: %s; operador: %s)",
			shellQuote(strings.Join(state.RedCommand, " ")),
			shellQuote(strings.Join(args.command, " ")),
		)
	}

	testChanges, err := snapshotChanges(state.GreenTests, state.TestFiles)
	if err != nil {
		return 0, err
	}
	implementationChanges, err := snapshotChanges(state.GreenImplementation, state.ImplementationFiles)
	if err != nil {
		return 0, err
	}
	if len(testChanges) > 0 || len(implementationChanges) > 0 {
		details := make([]string, 0, 2)
		if len(testChanges) > 0 {
			details = append(details, "tests changed: "+strings.Join(testChanges, ", "))
		}
		if len(implementationChanges) > 0 {
			details = append(details, "implementation changed: "+strings.Join(implementationChanges, ", "))
		}
		return 0, fmt.Errorf("verification invalidated: %s", strings.Join(details, "; "))
	}

	result, err := run(args.command)
	if err != nil {
		return 0, err
	}
	relevant := state.GreenExpect == nil || *state.GreenExpect == "" || strings.Contains(result.output, *state.GreenExpect)
	verdict := "FAIL"
	if result.exitCode == 0 && relevant {
		verdict = "PASS"
	}
	logPath, err := writeLog(a.paths, args.task, "VERIFY", args.command, result.exitCode, result.output, verdict, "")
	if err != nil {
		return 0, err
	}
	if verdict == "FAIL" {
		fmt.Fprintf(a.err, "FAIL: current focused test no longer passes; evidence: %s\n", logPath)
		return ExitViolation, nil
	}
	fmt.Fprintf(a.out, "PASS: evidence matches working tree and focused test passes for %s; evidence: %s\n", args.task, logPath)
	return ExitOK, nil
}

var auditCheckNamePattern = regexp.MustCompile(`^(?:AC-[1-9]\d*|VISUAL|DOCUMENTATION|LOCAL-GATES|REGRESSION)$`)

func (a *auditor) check(args *parsedArgs) (int, error) {
	if !auditCheckNamePattern.MatchString(args.name) {
		return 0, fmt.Errorf("invalid audit check name: %s", args.name)
	}
	if len(args.command) == 0 {
		return 0, fmt.Errorf("audit check command is required after --")
	}
	if args.expectLiteral && !args.expectSet {
		return 0, fmt.Errorf("--expect-literal requires --expect")
	}
	state, reason := tryLoadState(a.paths, args.task)
	if state == nil {
		return a.reportIncomplete([]string{fmt.Sprintf("baseline (%s)", reason)}), nil
	}
	if state.GreenImplementation == nil || state.GreenTests == nil {
		return a.reportIncomplete([]string{fmt.Sprintf("GREEN (o check %s roda sobre o snapshot do GREEN da task %s)", args.name, args.task)}), nil
	}
	loaded, err := guardDefinition(state, args.work, args.task)
	if err != nil {
		return 0, err
	}

	drifted := make([]string, 0)
	implementationDrift, err := snapshotChanges(state.GreenImplementation, state.ImplementationFiles)
	if err != nil {
		return 0, err
	}
	testDrift, err := snapshotChanges(state.GreenTests, state.TestFiles)
	if err != nil {
		return 0, err
	}
	drifted = append(drifted, implementationDrift...)
	drifted = append(drifted, testDrift...)
	if len(drifted) > 0 {
		return 0, fmt.Errorf("check invalidated: arquivos mudaram depois do GREEN (%s); refaça o GREEN", strings.Join(drifted, ", "))
	}

	allowed := plan.AllowedCheckCommands(loaded.text, loaded.task, args.name)
	if allowed.Error != "" {
		return 0, fmt.Errorf("%s", allowed.Error)
	}
	matched := false
	for _, planned := range allowed.Commands {
		if plan.CommandMatches(planned, args.command) {
			matched = true
			break
		}
	}
	if !matched {
		quoted := make([]string, len(allowed.Commands))
		for index, planned := range allowed.Commands {
			quoted[index] = "`" + planned + "`"
		}
		return 0, fmt.Errorf(
			"%s: comando diverge do plano (plano: %s; operador: `%s`)",
			args.name, strings.Join(quoted, " | "), plan.DisplayCommand(args.command),
		)
	}

	result, err := run(args.command)
	if err != nil {
		return 0, err
	}
	relevant := !args.expectSet || strings.Contains(result.output, args.expect)
	verdict := "FAIL"
	if result.exitCode == 0 && relevant {
		verdict = "PASS"
	}
	extra := ""
	var vacuity *Vacuity
	if verdict == "PASS" && strings.HasPrefix(args.name, "AC-") {
		// Um critério de aceite que continua passando sem a implementação não
		// aceita nada.
		without, mutationErr := withoutImplementation(state, func() (execResult, error) {
			return run(args.command)
		})
		if mutationErr != nil {
			return 0, mutationErr
		}
		passesWithout := without.exitCode == 0 && (!args.expectSet || strings.Contains(without.output, args.expect))
		vacuityVerdict := "PASS"
		if passesWithout {
			vacuityVerdict = "FAIL"
			verdict = "FAIL"
		}
		vacuity = &Vacuity{ExitCode: without.exitCode, Verdict: vacuityVerdict}
		extra = fmt.Sprintf(
			"MUTATION_EXIT: %d\nMUTATION_OUTPUT:\n%s\nMUTATION_VERDICT: %s\n",
			without.exitCode, without.output, vacuityVerdict,
		)
	}
	logPath, err := writeLog(a.paths, args.task, args.name, args.command, result.exitCode, result.output, verdict, extra)
	if err != nil {
		return 0, err
	}

	logDigest, err := digest(logPath)
	if err != nil {
		return 0, err
	}
	record := AuditCheckRecord{
		Command:     args.command,
		ExitCode:    result.exitCode,
		Verdict:     verdict,
		Log:         logPath,
		LogSHA256:   logDigest.SHA256,
		RecordedAt:  nowISO(),
		GreenSHA256: greenDigest(state),
		Vacuity:     vacuity,
	}
	if args.expectSet {
		expect := args.expect
		record.Expect = &expect
	}
	if state.AuditChecks == nil {
		state.AuditChecks = make(map[string]AuditCheckRecord)
	}
	state.AuditChecks[args.name] = record
	if err := saveState(a.paths, state); err != nil {
		return 0, err
	}

	if verdict == "FAIL" {
		if vacuity != nil && vacuity.Verdict == "FAIL" {
			fmt.Fprintf(
				a.err,
				"FAIL: %s é vácuo — passa também com a implementação removida, então não prova o comportamento da task; evidence: %s\n",
				args.name, logPath,
			)
		} else {
			fmt.Fprintf(a.err, "FAIL: %s did not produce the expected successful result; evidence: %s\n", args.name, logPath)
		}
		return ExitViolation, nil
	}
	fmt.Fprintf(a.out, "PASS: %s captured for %s/%s; evidence: %s\n", args.name, args.work, args.task, logPath)
	return ExitOK, nil
}

func jsonQuote(value string) string {
	data, err := jsonCanonical(value)
	if err != nil {
		return fmt.Sprintf("%q", value)
	}
	return string(data)
}
