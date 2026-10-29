package cli

// commandSpec descreve um comando de topo. takesSubcommand é falso nos comandos
// sem subcomando (init, validate, self-check). O handler de cada comando valida
// o subcomando e imprime o próprio uso, como o switch de src/cli.ts.
type commandSpec struct {
	name            string
	takesSubcommand bool
}

var commandSpecs = []commandSpec{
	{name: "init"},
	{name: "decider", takesSubcommand: true},
	{name: "work", takesSubcommand: true},
	{name: "task", takesSubcommand: true},
	{name: "target", takesSubcommand: true},
	{name: "metrics", takesSubcommand: true},
	{name: "queue", takesSubcommand: true},
	{name: "verify", takesSubcommand: true},
	{name: "validate"},
	{name: "self-check"},
}

func lookupCommand(name string) (commandSpec, bool) {
	for _, spec := range commandSpecs {
		if spec.name == name {
			return spec, true
		}
	}
	return commandSpec{}, false
}
