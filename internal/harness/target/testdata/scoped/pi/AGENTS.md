# Regras do Pi Harness (Pi Target)

> Configuração materializada via `pwn target materialize --target pi`

## Invariantes Globais
- **Precedência**: Seguir AGENTS.md e especificações normativas JSON.
- **Segurança**: Respeitar allowlist de escrita de arquivos.
- **Validação**: Conclusão só com a atestação do audit — siga o protocolo abaixo.

## Protocolo de aceitação (obrigatório — o harness confere cada passo)
Uma task só está concluída com o recibo do verificador independente (`pwn verify run`).
Marcar `[x]` sem o recibo deixa o Work em INCONSISTENT STATE; "testes passando" e o audit local não são conclusão.
O pacote aprovado (comandos + testes de aceitação) fica fora do repositório: alterá-los aqui não muda o que é executado.

1. Antes de tocar em qualquer arquivo: `pwn work audit baseline --work <W> --task <T>` (os arquivos vêm do plano).
2. Escreva o teste que falha e rode `pwn work audit red --work <W> --task <T> --expect "<ID da asserção>" -- <comando RED do plano>`.
   O texto de `--expect` precisa estar escrito no arquivo de teste e aparecer só na falha (nada de "fail" ou "Error").
3. Implemente e rode `pwn work audit green --work <W> --task <T> -- <comando RED do plano>`.
4. Para cada AC do plano: `pwn work audit check --work <W> --task <T> --name AC-<n> -- <comando do AC-n, idêntico ao plano>`.
   O harness roda o AC também sem a sua implementação: AC que passa assim é recusado como vácuo.
5. `pwn work audit check --work <W> --task <T> --name REGRESSION -- <comando de regressão do plano>`.
6. Peça a aceitação ao operador: `pwn verify run --work <W> --task <T>` (o verificador executa os testes APROVADOS no isolamento).
7. Ao fim do Work, para cada gate global: `pwn verify run --work <W> --global G-<n>`.

Aprovação e decisor (vale igual em Pi, OpenCode e omp):
- A aprovação dos critérios (`pwn verify approve`) e as filas (`pwn queue`) são do operador, ou do decisor configurado no projeto. Nunca aprove por conta própria: não use `--by`, `--operator`, `pwn decider` nem `pwn queue approve`.
- Saída `[DECISOR] REJEITADO` (exit 1): corrija os testes congelados ou o plano e peça de novo. Saída `PARA O OPERADOR` ou exit 3: pare e reporte; não tente contornar, o operador decide.

Proibido: editar plano, contrato ou testes de aceitação congelados para a task passar; trocar os comandos do plano;
alterar testes depois do RED; implementar fora do que os ACs exigem e chamar de pronto.

## Escopo do contrato (V4 congelado)
WRITE ALLOW:
  + src/**
WRITE DENY:
  - schemas/**
VALIDATION COMMANDS:
  $ bun test
RISK LEVEL: L2
