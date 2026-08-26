#!/usr/bin/env bash

set -euo pipefail

PI_DIR="${PI_AGENT_DIR:-${HOME}/.pi/agent}"
REPO_DIR="$(cd "$(dirname "$0")" && pwd)"
SHARED_SKILLS_DIR="${AGENT_SKILLS_DIR:-${HOME}/.agents/skills}"

remove_owned_link() {
  local source="$1"
  local destination="$2"
  if [ -L "$destination" ] && [ "$(readlink -f "$destination")" = "$(readlink -f "$source")" ]; then
    unlink "$destination"
    printf '  - %s\n' "$destination"
  fi
}

for source in "$REPO_DIR"/skills/*; do
  [ -d "$source" ] || continue
  remove_owned_link "$source" "$SHARED_SKILLS_DIR/$(basename "$source")"
  remove_owned_link "$source" "$PI_DIR/skills/$(basename "$source")"
done

for source in "$REPO_DIR"/adapters/pi/prompts/*.md; do
  [ -f "$source" ] || continue
  remove_owned_link "$source" "$PI_DIR/prompts/$(basename "$source")"
done

printf 'Removed links owned by ai-engineering-skills.\n'
