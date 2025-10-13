#!/usr/bin/env bash
set -euo pipefail

collect_editor_cli() {
  local -n _out=$1
  _out=()
  if command -v code >/dev/null 2>&1; then
    _out+=(code)
  fi
  if command -v code-server >/dev/null 2>&1; then
    _out+=(code-server)
  fi

  local server_root="${VSCODE_AGENT_FOLDER:-$HOME/.vscode-server}"
  if [[ -d "$server_root/bin" ]]; then
    while IFS= read -r candidate; do
      _out+=("$candidate")
    done < <(find "$server_root/bin" -maxdepth 3 -type f \( -name code -o -name code-server \) 2>/dev/null)
  fi
}

install_extension() {
  local label="$1" extension="$2" success=0
  local -a cli=()
  collect_editor_cli cli
  if (( ${#cli[@]} == 0 )); then
    echo "No VS Code/Cursor CLI binaries found; skipping $label update." >&2
    return 1
  fi

  local tool
  for tool in "${cli[@]}"; do
    if "$tool" --install-extension "$extension" --force >/dev/null 2>&1; then
      echo "$label updated via $tool."
      success=1
    else
      echo "$label update failed via $tool." >&2
    fi
  done

  if (( success )); then
    return 0
  fi
  echo "Unable to update $label using available CLI binaries." >&2
  return 1
}

if install_extension "OpenAI Codex" "openai.chatgpt"; then
  :
fi
if install_extension "Claude Code" "anthropic.claude-code"; then
  :
fi

echo "Editor extension update process finished."
