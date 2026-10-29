package batch_test

import (
	"strings"
	"testing"

	"github.com/passoz/pwn/internal/harness/batch"
)

func schedulable(id string, mutate func(*batch.SchedulableTask)) batch.SchedulableTask {
	task := batch.SchedulableTask{
		ID:         id,
		Title:      "task " + id,
		DependsOn:  []string{},
		Components: []string{"comp-" + id},
		WriteAllow: []string{"src/" + id + "/**"},
		Risk:       "L2",
		Marker:     " ",
		Stage:      "not started",
		Approved:   true,
	}
	if mutate != nil {
		mutate(&task)
	}
	return task
}

func ids(tasks []batch.SchedulableTask) []string {
	result := make([]string, 0, len(tasks))
	for _, task := range tasks {
		result = append(result, task.ID)
	}
	return result
}

func reasonOf(schedule batch.Schedule, id string) string {
	return findDeferral(schedule, id)
}

func equalIDs(t *testing.T, label string, got, want []string) {
	t.Helper()
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("%s = %v, queria %v", label, got, want)
	}
}

func TestPlanNextBatchOrderAndJobLimit(t *testing.T) {
	schedule := batch.PlanNextBatch([]batch.SchedulableTask{
		schedulable("1.1", nil), schedulable("1.2", nil), schedulable("1.3", nil),
	}, 2, "0001", nil)
	equalIDs(t, "batch", ids(schedule.Batch), []string{"1.1", "1.2"})
	if reason := reasonOf(schedule, "1.3"); !strings.Contains(reason, "limite de 2") {
		t.Fatalf("motivo de 1.3 = %q", reason)
	}
}

func TestPlanNextBatchDependenciesAndIntegrated(t *testing.T) {
	schedule := batch.PlanNextBatch([]batch.SchedulableTask{
		schedulable("1.1", func(task *batch.SchedulableTask) { task.Stage = "GREEN" }),
		schedulable("1.2", func(task *batch.SchedulableTask) { task.DependsOn = []string{"0001/1.1"} }),
		schedulable("1.3", func(task *batch.SchedulableTask) { task.DependsOn = []string{"1.2"} }),
		schedulable("1.4", func(task *batch.SchedulableTask) { task.DependsOn = []string{"9.9"} }),
	}, 4, "0001", nil)
	equalIDs(t, "integradas", schedule.Integrated, []string{"1.1"})
	equalIDs(t, "batch", ids(schedule.Batch), []string{"1.2"})
	if reason := reasonOf(schedule, "1.3"); !strings.Contains(reason, "depende de 1.2, ainda não integrada") {
		t.Fatalf("motivo de 1.3 = %q", reason)
	}
	if reason := reasonOf(schedule, "1.4"); !strings.Contains(reason, "não existe no plano") {
		t.Fatalf("motivo de 1.4 = %q", reason)
	}
}

func TestPlanNextBatchScopeAndComponentConflicts(t *testing.T) {
	schedule := batch.PlanNextBatch([]batch.SchedulableTask{
		schedulable("1.1", func(task *batch.SchedulableTask) { task.WriteAllow = []string{"src/**"} }),
		schedulable("1.2", func(task *batch.SchedulableTask) { task.WriteAllow = []string{"src/a.ts"} }),
		schedulable("1.3", func(task *batch.SchedulableTask) {
			task.Components = []string{"comp-1.1"}
			task.WriteAllow = []string{"lib/**"}
		}),
		schedulable("1.4", func(task *batch.SchedulableTask) { task.WriteAllow = []string{"docs/**"} }),
	}, 4, "0001", nil)
	equalIDs(t, "batch", ids(schedule.Batch), []string{"1.1", "1.4"})
	if reason := reasonOf(schedule, "1.2"); !strings.Contains(reason, "escopo pode sobrepor 1.1 (src/a.ts × src/**)") {
		t.Fatalf("motivo de 1.2 = %q", reason)
	}
	if reason := reasonOf(schedule, "1.3"); !strings.Contains(reason, "componente compartilhado com 1.1") {
		t.Fatalf("motivo de 1.3 = %q", reason)
	}
}

func TestPlanNextBatchSoloLots(t *testing.T) {
	late := batch.PlanNextBatch([]batch.SchedulableTask{
		schedulable("1.1", nil),
		schedulable("1.2", func(task *batch.SchedulableTask) { task.Risk = "L4" }),
	}, 4, "0001", nil)
	equalIDs(t, "batch", ids(late.Batch), []string{"1.1"})
	if reason := reasonOf(late, "1.2"); !strings.Contains(reason, "execução isolada (risco L4") {
		t.Fatalf("motivo de 1.2 = %q", reason)
	}

	first := batch.PlanNextBatch([]batch.SchedulableTask{
		schedulable("1.1", func(task *batch.SchedulableTask) {
			task.WriteAllow = []string{"package.json", "src/1.1/**"}
		}),
		schedulable("1.2", nil),
	}, 4, "0001", nil)
	equalIDs(t, "batch", ids(first.Batch), []string{"1.1"})
	if reason := reasonOf(first, "1.2"); !strings.Contains(reason, "aguarda: 1.1 exige execução isolada") {
		t.Fatalf("motivo de 1.2 = %q", reason)
	}
}

func TestPlanNextBatchEligibility(t *testing.T) {
	schedule := batch.PlanNextBatch([]batch.SchedulableTask{
		schedulable("1.1", func(task *batch.SchedulableTask) { task.Approved = false }),
		schedulable("1.2", func(task *batch.SchedulableTask) { task.Stage = "RED" }),
		schedulable("1.3", func(task *batch.SchedulableTask) { task.Marker = "!" }),
		schedulable("1.4", func(task *batch.SchedulableTask) { task.CrossWorkBlockers = []string{"0002/1.1"} }),
	}, 4, "0001", nil)
	if len(schedule.Batch) != 0 {
		t.Fatalf("batch = %v", ids(schedule.Batch))
	}
	if reason := reasonOf(schedule, "1.1"); !strings.Contains(reason, "sem aprovação vigente") {
		t.Fatalf("motivo de 1.1 = %q", reason)
	}
	if reason := reasonOf(schedule, "1.2"); !strings.Contains(reason, "já iniciada") || !strings.Contains(reason, "RED") {
		t.Fatalf("motivo de 1.2 = %q", reason)
	}
	if reason := reasonOf(schedule, "1.3"); !strings.Contains(reason, "bloqueada no plano") {
		t.Fatalf("motivo de 1.3 = %q", reason)
	}
	if reason := reasonOf(schedule, "1.4"); !strings.Contains(reason, "entre Works") || !strings.Contains(reason, "0002/1.1") {
		t.Fatalf("motivo de 1.4 = %q", reason)
	}
}

func TestPlanNextBatchOnlyRestrictsCandidates(t *testing.T) {
	only := map[string]bool{"1.2": true, "1.3": true}
	schedule := batch.PlanNextBatch([]batch.SchedulableTask{
		schedulable("1.1", nil),
		schedulable("1.2", func(task *batch.SchedulableTask) { task.DependsOn = []string{"1.1"} }),
		schedulable("1.3", nil),
	}, 4, "0001", only)
	equalIDs(t, "batch", ids(schedule.Batch), []string{"1.3"})
	if reason := reasonOf(schedule, "1.2"); !strings.Contains(reason, "depende de 1.1") {
		t.Fatalf("motivo de 1.2 = %q", reason)
	}
	if reason := reasonOf(schedule, "1.1"); reason != "" {
		t.Fatalf("1.1 não deveria ser adiada: %q", reason)
	}
}
