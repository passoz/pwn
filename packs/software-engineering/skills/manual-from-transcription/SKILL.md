---
name: manual-from-transcription
description: Cria manuais operacionais a partir de transcrições de áudio, capturas de tela e documentos existentes. Cruza múltiplas fontes, resolve contradições, e produz um documento estruturado com changelog de versões.
---

# Manual from Transcription

## Table of Contents

- [Overview](#overview)
- [When to Use](#when-to-use)
- [Quick Start](#quick-start)
- [The Methodology](#the-methodology)
- [Output Structure](#output-structure)
- [Best Practices](#best-practices)

## Overview

Transforma fontes brutas (transcrições de treinamento, capturas de tela de sistemas, manuais existentes) em um **manual operacional estruturado** — fiel às fontes, com versões numeradas, changelog, e reconciliação explícita de discrepâncias.

O caso de uso típico é um treinamento gravado onde um especialista (ex.: Erica, Mateus) explica um fluxo de cadastro, e você precisa consolidar o conhecimento em um documento de referência.

## When to Use

- Treinamento operacional gravado → manual escrito
- Fluxo de sistema documentado apenas em vídeo/áudio
- Manual existente (v1) que precisa ser corrigido contra fontes primárias
- Processo com múltiplas fontes (tela + áudio + documento) que precisam ser reconciliadas
- Qualquer tarefa que envolva extrair um procedimento passo a passo de uma gravação

## Quick Start

O usuário fornece:

1. **Fontes opcionais**: manual v1 existente, prints de tela, anotações
2. **Transcrição**: texto da gravação do treinamento (pode ter lacunas)
3. **Correções do usuário**: durante a revisão

Você produz um único arquivo `.md` com:

```markdown
> **Versão:** 2.0
> **Data:** DD/MM/AAAA
> **Mudanças em relação à v1:** descrição das mudanças

## Seções do manual

...
## Apêndice A — Changelog v1 → v2
```

### Processo completo (5 passos)

```
FONTES CRUAS
  ├─ v1 manual (opcional)
  ├─ Screenshots (opcional)
  └─ Transcrição (principal)
         │
         ▼
  1. EXTRAIR campos, valores, fluxos da transcrição
  2. LER imagens (OCR / leitura direta) para validar
  3. CRUZAR fontes → marcar contradições como "em disputa"
  4. CONSTRUIR manual estruturado
  5. ITERAR com o usuário → atualizar changelog a cada versão
```

## The Methodology

### Step 1 — Absorver as fontes

Leia **todas** as fontes fornecidas antes de começar a escrever:

- **Manual v1**: identifique a estrutura existente, seções, campos
- **Transcrição**: extraia valores fixos, regras, exceções, nomes de campos
- **Screenshots**: leia diretamente (o model lê imagens). Extraia:
  - Nomes exatos dos campos no sistema
  - Valores preenchidos
  - Dropdowns e opções disponíveis
  - Menus e caminhos de navegação
  - Templates de e-mail

### Step 2 — Mapear campo a campo

Crie uma tabela mental ou anotada de **cada campo do fluxo**:

| Campo | Valor na transcrição | Valor na tela | Valor no v1 | Decisão |
|-------|---------------------|---------------|-------------|---------|
| Causa Raiz | pontinho (.) | (não visível) | "Raiz" separado | **Causa Raiz = pontinho** |
| Problemático | Erica: branco / Mateus: preenche | Não | "sempre preencher" | **"Não" (fixo)** / debate documentado |

**Quando fontes divergem:**
1. **Tela manda** — se a tela mostra um valor, a tela é a fonte mais confiável (é o sistema real)
2. **Transcrição depois** — o especialista explicando tem autoridade, mas pode estar errado (ex.: Erica fala "Baixa cliente", a tela mostra "Pasta Cliente")
3. **v1 por último** — o manual anterior pode conter erros copiados
4. **Marque o debate** — se duas pessoas treinadas discordam, documente as duas posições

### Step 3 — Construir o manual

Seções obrigatórias:

1. **Visão Geral** — contexto, objetivo, equipe envolvida
2. **Pré-cadastro** — verificação antes de abrir o sistema
3. **Tabelas de referência** — comarcas, tipos, valores fixos
4. **Cadastro (campo a campo)** — tabela com nome, valor, observação
5. **Cadastro da audiência** — aba específica
6. **Upload de documentos** — tipos, mapeamento
7. **Tramitações** — cada tramitação como subseção
8. **Planilha de controle** — se aplicável
9. **Automação / Robô** — envios em lote
10. **Fluxo Resumido** — passo a passo em ASCII art
11. **Exemplo Prático** — caso real preenchido
12. **Observações e Dicas** — pegadinhas, atalhos, lembretes
13. **Apêndice A — Changelog** — histórico completo de versões

### Step 4 — Iterar com versões

A cada rodada de correção do usuário:

1. **Incremente a versão** (v1 → v2 → v2.1 → v2.2 → v2.3)
2. **Atualize o changelog** no Apêndice A, com tabela "Antes × Depois"
3. **Atualize o cabeçalho** com a versão e data
4. **Nunca crie arquivos novos** — sobrescreva o mesmo arquivo

Formato do changelog:

```markdown
### Itens corrigidos nesta v2.2 (vs v2.1)

| v2.1 | v2.2 (correto) | Fonte |
|------|----------------|-------|
| Campo "Raiz" separado | **Causa Raiz = pontinho** | transcrição 4:06 |
| Problemático: "debater" | **Problemático = Não** | vídeo do usuário |
```

### Step 5 — Registrar lacunas

Se alguma fonte estiver incompleta (ex.: parte da transcrição entre 3:25–12:21 está faltando), **documente no manual** com uma nota "Não verificado contra transcrição" ou marque como bloqueado. Não invente valores.

## Output Structure

```
manual-<nome>-procon-v<versao>.md
├── Cabeçalho (versão, data, mudanças)
├── Visão Geral
├── 1. Documentos Necessários
├── 2. Verificação Pré-Cadastro
├── 3. Tabelas de Referência (comarcas, etc.)
├── 4. Cadastro (campo a campo)
│   ├── 4.1 Linha 1 — ...
│   ├── 4.2 Linha 2 — ...
│   └── ...
├── 5. Aba Audiências
├── 6. Upload de Documentos
├── 7. Tramitação
│   ├── 7.1 Tramitação 1 — ...
│   ├── 7.2 Tramitação 2 — ...
│   └── ...
├── 8. Planilha de Controle
├── 9. Automação / Robô
├── 10. Fluxo Resumido (passo a passo)
├── 11. Exemplo Prático
├── 12. Observações e Dicas
└── Apêndice A — Changelog
    ├── Campos adicionados
    ├── Seções novas
    ├── Templates incluídos
    ├── Itens confirmados sem alteração
    └── Itens corrigidos por versão
```

## Best Practices

### ✅ DO

- **Leia todas as imagens primeiro** — extraia nomes de campos exatos, valores de dropdown, caminhos de menu
- **Marque contradições como "em disputa"** — se duas fontes discordam, não escolha um lado sem confirmação do usuário
- **Use bullet points e tabelas** — manuais são consultados, não lidos linearmente
- **Sobrescreva o mesmo arquivo** — nunca crie `-v2.md`, `-v3.md` separados; use o changelog
- **Documente a fonte** de cada correção (transcrição minuto:segundo, nome da imagem)
- **Confirme cada correção com o usuário** antes de aplicá-la
- **Inclua notas de "pegadinha"** — as coisas que o especialista esquece de mencionar mas que quebram o fluxo (ex.: "tabela sempre aberta", "CJUSC para judicial")
- **Adicione avisos visuais** — `> ℹ️`, `> ⚠️`, `> ❌` para chamar atenção

### ❌ DON'T

- **Não invente valores** de campos que não estão em nenhuma fonte — marque como "não verificado"
- **Não ignore o changelog** — cada iteração exige atualização
- **Não use nomes de campos diferentes dos que aparecem no sistema** — se a tela diz "Pasta Cliente", o manual deve dizer "Pasta Cliente"
- **Não misture tempos de resposta** — manual é instrução, não é conversa
- **Não apague notas de debate** — se Erica e Mateus discordam, registre; não esconda a controvérsia
- **Não crie versões paralelas** — sempre sobrescreva o mesmo arquivo
- **Não pule a seção de fluxo resumido** — é a parte mais consultada no dia a dia
