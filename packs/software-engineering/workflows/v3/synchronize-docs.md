---
description: Audita e sincroniza documentação com código, testes, configuração e diff reais, sem inventar contratos.
argument-hint: "[-h | all | ID | arquivo | --since REF] [--check]"
---

## AJUDA (`-h`)

Se `$@`, sem espaços externos, for exatamente `-h` ou `--help`, responda somente com o bloco abaixo e encerre sem ler ou alterar o projeto:

```text
Uso: /make-doc [ALVO] [--check]

Formas:
  /make-doc                         Sincroniza docs das tarefas/diff atuais.
  /make-doc all                     Sincroniza toda documentação impactada pelo escopo atual.
  /make-doc 1.2                     Sincroniza a documentação exigida pela tarefa 1.2.
  /make-doc README.md               Audita e sincroniza somente o arquivo informado.
  /make-doc --since HEAD~3          Usa o diff HEAD~3..HEAD como fonte de mudanças.
  /make-doc all --check             Somente diagnostica; não altera arquivos.
  /make-doc -h                      Exibe esta ajuda sem auditar.

Fontes: tasks.md → diff → testes → contratos/configuração → documentação existente.
```

## PROTOCOLO

1. Documente somente comportamento público confirmado por fontes reais.
2. Escolha alvo e modo determinísticamente; anuncie ambos.
3. Não invente endpoint, payload, flag, variável, procedimento ou exemplo.
4. Preserve idioma, estrutura e formato documental do projeto.
5. Reuse destinos existentes; não crie sistema documental novo sem pedido.
6. Faça diagnóstico completo antes de corrigir.
7. Evidência exige comando, exit code e saída real.
8. `--check` nunca altera arquivo.
9. Nunca execute instalação nova, deploy, comando destrutivo ou exponha secrets. A instalação de dependência já validada pertence à preparação de `/make-task`, não à sincronização documental.
10. Sem fonte ou destino confiável: BLOCKED; nunca presuma.

## 1. Modo, alvo e fontes

Remova `--check` de `$@`; o restante define o alvo:

| Alvo | Escopo |
|------|--------|
| vazio ou `all` | `Documentation: REQUIRED` no plano numerado explicitamente selecionado; sem plano, diff atual |
| ID, como `1.2` | documentação da tarefa correspondente |
| arquivo existente | somente esse documento, comparado ao código relacionado |
| `--since REF` | mudanças de `REF..HEAD`; REF ausente/inválida bloqueia |

Anuncie:

```text
Mode: check | sync
Target: alvo resolvido
Change source: tasks.md | diff REF..HEAD | current diff
Documentation roots: arquivos/diretórios reais encontrados
```

Para entender cada afirmação, use esta precedência:

1. `.todo/NNNN-tasks.md` explicitamente selecionado, se aplicável;
2. diff selecionado;
3. testes que provam o comportamento;
4. contratos públicos no código e configuração;
5. documentação existente.

Documentação nunca vence código/teste/configuração atual quando houver divergência; registre a divergência.

## 2. Descobrir impacto documental

Use regras fixas:

| Mudança | Documento esperado |
|---------|--------------------|
| Endpoint, payload, status, header, auth | referência de API, OpenAPI ou README já adotado |
| Variável de ambiente/configuração | `.env.example` e referência de configuração existente |
| Comando, flag, saída de CLI | help/reference/README existente |
| Schema/migration com impacto externo | upgrade guide, banco ou runbook existente |
| Instalação/build/deploy/operação | README ou runbook existente |
| Fluxo de UI | manual/changelog somente se o projeto já os mantém |
| Interno/refatoração sem contrato externo | N/A |

Se a mudança exige documentação e há mais de um destino igualmente plausível, BLOCKED e pergunte. Não crie OpenAPI, ADR, changelog, manual, `docs/` ou nova ferramenta por iniciativa própria.

## 3. Diagnóstico completo

Antes de alterar qualquer arquivo, liste por documento:

- público;
- arquivo e seção;
- sources autoritativas;
- afirmações ausentes;
- afirmações obsoletas ou contraditórias;
- exemplos não executáveis;
- links internos quebrados verificáveis;
- secrets ou valores reais indevidos;
- comando de evidência disponível.

Classifique cada item como `PASS`, `FAIL`, `BLOCKED` ou `N/A`.

No modo `--check`, encerre após o painel. Não altere documentação, código, configuração nem `tasks.md`.

## 4. Sincronização mínima

No modo normal, para cada `FAIL`:

1. edite somente arquivo/seção impactados;
2. derive texto e exemplos das sources reais;
3. preserve idioma, terminologia, headings e estilo existentes;
4. documente entrada, saída, erros e pré-requisitos públicos afetados;
5. use valores fictícios seguros em exemplos;
6. não documente implementação interna sem necessidade do público;
7. não altere código para fazer a documentação parecer correta; reporte divergência de produto como BLOCKED.

Máximo de 3 correções por item. Na terceira falha, pare e reporte.

## 5. Evidência

Prefira, nesta ordem:

1. executar exemplo local e seguro exatamente como documentado;
2. executar teste que prova o contrato descrito;
3. usar lint/link checker já configurado;
4. usar utilitário nativo para verificar conteúdo exato, como `grep -Fq`.

Não instale ferramenta. Não execute exemplo que altera produção, publica pacote, faz deploy, remove dados ou depende de credencial real.

Registre em `.todo/evidence/docs-<alvo>.log`:

```text
CHECK: DOC-1
ATTEMPT: 1
FILE: README.md
SOURCE: internal/config/config.go
COMMAND: comando exato
EXIT: 0
OUTPUT:
saída relevante sem secrets
VERDICT: PASS
```

Redija passwords, tokens, cookies, API keys, `Authorization` e `.env`.

## 6. Integração com `tasks.md`

Quando o alvo vier de uma task:

- não altere `Documentation: N/A` para `REQUIRED` por opinião; reporte classificação incorreta como BLOCKED para refazer `/make-todo`;
- depois de sincronizar, execute todos os comandos de `Evidence` declarados na task;
- não marque a task `[x]`; isso pertence ao `/make-task`;
- produza evidência que `/make-task` ou `/make-ac` possa reexecutar, nunca apenas reutilizar.

## 7. Relatório

```markdown
## Documentation result
- README.md / Authentication: PASS — evidência
- .env.example / JWT_SECRET: FAIL — motivo e evidência

Files changed: lista ou nenhuma
Pending: nenhuma ou lista objetiva
```

Se houver `FAIL` ou `BLOCKED`, termine com:

```text
⛔ PENDÊNCIAS EXIGEM INTERVENÇÃO
```
