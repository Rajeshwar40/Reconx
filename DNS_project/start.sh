#!/usr/bin/env zsh
# ReconX Platform Launcher
# Powered by Rajeshwar Singh

CYAN='\033[0;36m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
RED='\033[0;31m'
BOLD='\033[1m'
RESET='\033[0m'

ROOT="$(cd "$(dirname "$0")" && pwd)"

# Prepend Homebrew paths so env/subshells can find node
export PATH="/opt/homebrew/bin:/opt/homebrew/sbin:/usr/local/bin:/usr/local/sbin:/usr/bin:/bin:/usr/sbin:/sbin:$HOME/go/bin:$HOME/.local/bin:$HOME/bin:$PATH"

# Resolve absolute paths now — used everywhere below
NODE_BIN="$(command -v node 2>/dev/null)"
NPM_BIN="$(command -v npm 2>/dev/null)"

echo ""
echo "${CYAN}${BOLD}  ReconX Platform  •  Powered by Rajeshwar Singh${RESET}"
echo "  ────────────────────────────────────────────────"
echo ""

# Check Node
if [[ -z "$NODE_BIN" ]]; then
  echo "${RED}✗ Node.js not found. Install: brew install node${RESET}"
  exit 1
fi
echo "${GREEN}✓ Node $("$NODE_BIN" --version)${RESET}"

# Install deps
if [[ ! -d "$ROOT/backend/node_modules" ]]; then
  echo "${YELLOW}Installing backend dependencies…${RESET}"
  cd "$ROOT/backend" && "$NPM_BIN" install --silent
  cd "$ROOT"
fi
if [[ ! -d "$ROOT/frontend/node_modules" ]]; then
  echo "${YELLOW}Installing frontend dependencies…${RESET}"
  cd "$ROOT/frontend" && "$NPM_BIN" install --silent
  cd "$ROOT"
fi

# Connectivity check
if ping -c1 -W2 1.1.1.1 &>/dev/null; then
  echo "${GREEN}✓ Internet connectivity OK${RESET}"
else
  echo "${YELLOW}⚠ No internet – passive sources may return fewer results${RESET}"
fi

# Port conflict check
for port in 2000 4000; do
  if lsof -ti tcp:$port &>/dev/null; then
    echo "${RED}✗ Port $port already in use. Free it with: lsof -ti tcp:$port | xargs kill -9${RESET}"
    exit 1
  fi
done

# Tool detection — search common install locations explicitly
TOOL_PATHS=(
  "/opt/homebrew/bin"
  "/usr/local/bin"
  "$HOME/go/bin"
  "$HOME/.local/bin"
  "$HOME/bin"
)

find_tool() {
  local name="$1"
  # First try command -v (respects current PATH)
  local found="$(command -v "$name" 2>/dev/null)"
  if [[ -n "$found" ]]; then echo "$found"; return; fi
  # Then check known directories directly
  for dir in "${TOOL_PATHS[@]}"; do
    if [[ -x "$dir/$name" ]]; then echo "$dir/$name"; return; fi
  done
}

echo ""
echo "Tool detection:"
for tool in subfinder assetfinder amass dnsx httpx nuclei shuffledns; do
  path="$(find_tool "$tool")"
  if [[ -n "$path" ]]; then
    # Add tool's directory to PATH so the backend can also find it
    export PATH="$(dirname "$path"):$PATH"
    echo "  ${GREEN}✓ $tool${RESET} → $path"
  else
    echo "  ${YELLOW}⚠ $tool not found${RESET}"
  fi
done
echo ""

# Start backend
echo "${CYAN}Starting backend on port 2000…${RESET}"
cd "$ROOT/backend"
"$NODE_BIN" index.js > "$ROOT/backend.log" 2>&1 &
BACKEND_PID=$!
cd "$ROOT"

# Wait up to 8s for backend
for i in {1..8}; do
  if curl -s http://localhost:2000/api/health &>/dev/null; then
    echo "${GREEN}✓ Backend ready${RESET}"
    break
  fi
  /bin/sleep 1
done

# Start frontend — call next binary directly with resolved node path.
# This avoids "env: node: No such file or directory" on macOS zsh
# when npm scripts are backgrounded.
echo "${CYAN}Starting frontend on port 4000…${RESET}"
NEXT_BIN="$ROOT/frontend/node_modules/.bin/next"
cd "$ROOT/frontend"
"$NODE_BIN" "$NEXT_BIN" dev -p 4000 > "$ROOT/frontend.log" 2>&1 &
FRONTEND_PID=$!
cd "$ROOT"

# Wait up to 20s for frontend
echo -n "  Waiting for Next.js"
for i in {1..20}; do
  if curl -s http://localhost:4000 &>/dev/null; then
    echo ""
    echo "${GREEN}✓ Frontend ready${RESET}"
    break
  fi
  echo -n "."
  /bin/sleep 1
done
echo ""

# Open browser
echo "${GREEN}${BOLD}✓ ReconX is running!${RESET}"
echo "  Backend  → http://localhost:2000/api/health"
echo "  Frontend → http://localhost:4000"
echo "  Logs     → backend.log  |  frontend.log"
echo ""
open http://localhost:4000 2>/dev/null || true

# Clean shutdown
trap "echo ''; echo '${YELLOW}Shutting down…${RESET}'; kill $BACKEND_PID $FRONTEND_PID 2>/dev/null; exit 0" INT TERM

echo "Press Ctrl+C to stop"
wait
