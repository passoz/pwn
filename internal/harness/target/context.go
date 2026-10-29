package target

import (
	"strings"

	"github.com/passoz/pwn/internal/harness/contract"
)

// ContractContext é o escopo derivado dos contratos V4 congelados de um Work.
type ContractContext struct {
	WriteAllow         []string           `json:"writeAllow"`
	WriteDeny          []string           `json:"writeDeny"`
	AcceptanceCommands []string           `json:"acceptanceCommands"`
	RiskLevel          contract.RiskLevel `json:"riskLevel"`
	TaskCount          int                `json:"taskCount"`
}

// CollectContractContext agrega os contratos V4 de um Work.
//
// O risco é o mais alto da lista, e cada lista de caminhos ou comandos mantém a
// primeira ocorrência na ordem dos contratos. Work sem contrato resulta em
// risco L0 e contagem zero.
func CollectContractContext(contracts []contract.TaskContractV4) ContractContext {
	highest := contract.RiskL0
	writeAllow := make([]string, 0)
	writeDeny := make([]string, 0)
	commands := make([]string, 0)

	for _, taskContract := range contracts {
		if taskContract.Risk.Level.Rank() > highest.Rank() {
			highest = taskContract.Risk.Level
		}
		writeAllow = append(writeAllow, taskContract.ScopeContract.WriteAllow...)
		writeDeny = append(writeDeny, taskContract.ScopeContract.WriteDeny...)
		commands = append(commands, taskContract.AcceptanceContract.Commands...)
	}

	return ContractContext{
		WriteAllow:         uniqueStrings(writeAllow),
		WriteDeny:          uniqueStrings(writeDeny),
		AcceptanceCommands: uniqueStrings(commands),
		RiskLevel:          highest,
		TaskCount:          len(contracts),
	}
}

// uniqueStrings remove duplicatas e preserva a ordem da primeira ocorrência.
func uniqueStrings(values []string) []string {
	seen := make(map[string]struct{}, len(values))
	unique := make([]string, 0, len(values))
	for _, value := range values {
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		unique = append(unique, value)
	}
	return unique
}

// RenderAcceptanceProtocol devolve o protocolo de aceitação que o agente precisa
// seguir. Cada passo é conferido pelo harness (comandos e arquivos amarrados ao
// plano, atestação assinada); o texto existe para o agente não descobrir as
// regras pelo erro.
func RenderAcceptanceProtocol() string {
	return strings.Join([]string{
		"",
		"## Protocolo de aceitação (obrigatório — o harness confere cada passo)",
		"Uma task só está concluída com o recibo do verificador independente (`pwn verify run`).",
		"Marcar `[x]` sem o recibo deixa o Work em INCONSISTENT STATE; \"testes passando\" e o audit local não são conclusão.",
		"O pacote aprovado (comandos + testes de aceitação) fica fora do repositório: alterá-los aqui não muda o que é executado.",
		"",
		"1. Antes de tocar em qualquer arquivo: `pwn work audit baseline --work <W> --task <T>` (os arquivos vêm do plano).",
		"2. Escreva o teste que falha e rode `pwn work audit red --work <W> --task <T> --expect \"<ID da asserção>\" -- <comando RED do plano>`.",
		"   O texto de `--expect` precisa estar escrito no arquivo de teste e aparecer só na falha (nada de \"fail\" ou \"Error\").",
		"3. Implemente e rode `pwn work audit green --work <W> --task <T> -- <comando RED do plano>`.",
		"4. Para cada AC do plano: `pwn work audit check --work <W> --task <T> --name AC-<n> -- <comando do AC-n, idêntico ao plano>`.",
		"   O harness roda o AC também sem a sua implementação: AC que passa assim é recusado como vácuo.",
		"5. `pwn work audit check --work <W> --task <T> --name REGRESSION -- <comando de regressão do plano>`.",
		"6. Peça a aceitação ao operador: `pwn verify run --work <W> --task <T>` (o verificador executa os testes APROVADOS no isolamento).",
		"7. Ao fim do Work, para cada gate global: `pwn verify run --work <W> --global G-<n>`.",
		"",
		"Aprovação e decisor (vale igual em Pi, OpenCode e omp):",
		"- A aprovação dos critérios (`pwn verify approve`) e as filas (`pwn queue`) são do operador, ou do decisor configurado no projeto. Nunca aprove por conta própria: não use `--by`, `--operator`, `pwn decider` nem `pwn queue approve`.",
		"- Saída `[DECISOR] REJEITADO` (exit 1): corrija os testes congelados ou o plano e peça de novo. Saída `PARA O OPERADOR` ou exit 3: pare e reporte; não tente contornar, o operador decide.",
		"",
		"Proibido: editar plano, contrato ou testes de aceitação congelados para a task passar; trocar os comandos do plano;",
		"alterar testes depois do RED; implementar fora do que os ACs exigem e chamar de pronto.",
	}, "\n")
}

// RenderScopeSection devolve a seção de escopo do contrato. Work sem task não
// gera seção.
func RenderScopeSection(context ContractContext) string {
	if context.TaskCount == 0 {
		return ""
	}

	lines := make([]string, 0, 8+len(context.WriteAllow)+len(context.WriteDeny)+len(context.AcceptanceCommands))
	lines = append(lines, "", "## Escopo do contrato (V4 congelado)", "WRITE ALLOW:")
	for _, allow := range context.WriteAllow {
		lines = append(lines, "  + "+allow)
	}
	lines = append(lines, "WRITE DENY:")
	for _, deny := range context.WriteDeny {
		lines = append(lines, "  - "+deny)
	}
	lines = append(lines, "VALIDATION COMMANDS:")
	for _, command := range context.AcceptanceCommands {
		lines = append(lines, "  $ "+command)
	}
	lines = append(lines, "RISK LEVEL: "+string(context.RiskLevel))
	return strings.Join(lines, "\n")
}
