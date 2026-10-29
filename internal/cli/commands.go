package cli

// commandSpec descreve um comando de topo e os subcomandos que ele aceita.
// Subcommands vazio indica comando sem subcomando (init, validate, self-check).
type commandSpec struct {
	name        string
	subcommands []string
	usage       string
}

var commandSpecs = []commandSpec{
	{
		name:  "init",
		usage: "pwn init [--decider <provedor:modelo>] [--decider-key-env VAR] [--decider-max-risk L0..L4] [--decider-endpoint URL] [--no-decider]",
	},
	{
		name:        "decider",
		subcommands: []string{"show", "set", "remove", "log"},
		usage:       "pwn decider <show|set|remove|log>",
	},
	{
		name: "work",
		subcommands: []string{
			"init", "import", "scaffold", "reconcile", "gate", "specify", "contract",
			"plan", "run", "run-all", "batch", "audit", "status", "sync",
		},
		usage: "pwn work <init|import|scaffold|reconcile|gate|specify|contract|plan|run|run-all|batch|audit|status|sync>",
	},
	{
		name:        "task",
		subcommands: []string{"run", "capsule"},
		usage:       "pwn task <run|capsule>",
	},
	{
		name:        "target",
		subcommands: []string{"list", "materialize"},
		usage:       "pwn target <list|materialize>",
	},
	{
		name:        "metrics",
		subcommands: []string{"list", "optimize"},
		usage:       "pwn metrics <list|optimize>",
	},
	{
		name:        "queue",
		subcommands: []string{"list", "approve", "reject"},
		usage:       "pwn queue <list|approve|reject>",
	},
	{
		name:        "verify",
		subcommands: []string{"init", "approve", "run", "run-all", "status", "show"},
		usage:       "pwn verify <init|approve|run|run-all|status|show>",
	},
	{
		name:  "validate",
		usage: "pwn validate [--work NNNN]",
	},
	{
		name:  "self-check",
		usage: "pwn self-check [--mutate [--work NNNN]]",
	},
}

func lookupCommand(name string) (commandSpec, bool) {
	for _, spec := range commandSpecs {
		if spec.name == name {
			return spec, true
		}
	}
	return commandSpec{}, false
}

func containsSubcommand(spec commandSpec, name string) bool {
	for _, subcommand := range spec.subcommands {
		if subcommand == name {
			return true
		}
	}
	return false
}
