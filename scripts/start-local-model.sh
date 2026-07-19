set -eu

project_directory="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
export OLLAMA_MODELS="$project_directory/.ollama/models"
export OLLAMA_HOST="127.0.0.1:11434"
if [ -x "$project_directory/.runtime/bin/ollama" ]; then
    ollama_binary="$project_directory/.runtime/bin/ollama"
elif command -v ollama >/dev/null 2>&1; then
    ollama_binary="$(command -v ollama)"
else
    printf '%s\n' "Ollama executable was not found."
    exit 1
fi
exec "$ollama_binary" serve
