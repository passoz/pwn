#!/usr/bin/env bash

set -euo pipefail

PI_DIR="${PI_AGENT_DIR:-${HOME}/.pi/agent}"
REPO_DIR="$(cd "$(dirname "$0")" && pwd)"
SHARED_SKILLS_DIR="${AGENT_SKILLS_DIR:-${HOME}/.agents/skills}"
LEGACY_PI_SKILLS_DIR="${PI_DIR}/skills"
PROMPTS_DIR="${PI_DIR}/prompts"

link_entry() {
  local source="$1"
  local destination="$2"

  if [ -e "$destination" ] || [ -L "$destination" ]; then
    if [ -L "$destination" ] && [ "$(readlink -f "$destination")" = "$(readlink -f "$source")" ]; then
      printf '  = %s\n' "$destination"
      return
    fi
    printf 'Refusing to replace existing path: %s\n' "$destination" >&2
    printf 'Remove or relocate it explicitly, then run this installer again.\n' >&2
    exit 1
  fi

  ln -s "$source" "$destination"
  printf '  + %s -> %s\n' "$destination" "$source"
}

link_shared_skill() {
  local source="$1"
  local destination="$2"

  if [ -e "$destination" ] || [ -L "$destination" ]; then
    if [ -L "$destination" ] && [ "$(readlink -f "$destination")" = "$(readlink -f "$source")" ]; then
      printf '  = %s\n' "$destination"
      return
    fi
    printf '  ~ %s (existing shared skill preserved)\n' "$destination"
    return
  fi

  ln -s "$source" "$destination"
  printf '  + %s -> %s\n' "$destination" "$source"
}

remove_owned_link() {
  local source="$1"
  local destination="$2"
  if [ -L "$destination" ] && [ "$(readlink -f "$destination")" = "$(readlink -f "$source")" ]; then
    unlink "$destination"
    printf '  - legacy %s\n' "$destination"
  fi
}

mkdir -p "$SHARED_SKILLS_DIR" "$PROMPTS_DIR"

printf 'Installing shared skills into %s\n' "$SHARED_SKILLS_DIR"
for source in "$REPO_DIR"/skills/*; do
  [ -d "$source" ] || continue
  link_shared_skill "$source" "$SHARED_SKILLS_DIR/$(basename "$source")"
done

printf 'Removing legacy Pi-local skill links owned by this repository\n'
for source in "$REPO_DIR"/skills/*; do
  [ -d "$source" ] || continue
  remove_owned_link "$source" "$LEGACY_PI_SKILLS_DIR/$(basename "$source")"
done

printf 'Installing Pi adapters into %s\n' "$PROMPTS_DIR"
for source in "$REPO_DIR"/adapters/pi/prompts/*.md; do
  [ -f "$source" ] || continue
  link_entry "$source" "$PROMPTS_DIR/$(basename "$source")"
done

printf '\nInstalled ai-engineering-skills. Reload Pi or start a new session.\n'
