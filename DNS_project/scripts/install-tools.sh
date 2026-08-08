#!/usr/bin/env bash
# Detects the host's OS/distro/architecture and installs the recon tool
# chain (subfinder, assetfinder, amass, dnsx, httpx, nuclei, shuffledns)
# via the right package manager + `go install`. Idempotent — safe to re-run.
set -euo pipefail

GO_VERSION="1.22.5"
REQUIRED_TOOLS=(subfinder assetfinder amass dnsx httpx nuclei)
OPTIONAL_TOOLS=(shuffledns)

log()  { printf '\033[1;36m[install]\033[0m %s\n' "$1"; }
warn() { printf '\033[1;33m[warn]\033[0m %s\n' "$1"; }
err()  { printf '\033[1;31m[error]\033[0m %s\n' "$1" >&2; }

# ── sudo handling ────────────────────────────────────────────────────
SUDO=""
if [ "$(id -u)" -ne 0 ]; then
  if command -v sudo >/dev/null 2>&1; then
    SUDO="sudo"
  else
    err "Not running as root and sudo not found — system package steps may fail."
  fi
fi

# ── Detect OS + architecture ─────────────────────────────────────────
OS_RAW="$(uname -s)"
ARCH_RAW="$(uname -m)"

case "$ARCH_RAW" in
  x86_64|amd64)  ARCH="amd64" ;;
  aarch64|arm64) ARCH="arm64" ;;
  *) err "Unsupported architecture: $ARCH_RAW"; exit 1 ;;
esac

DISTRO="unknown"
PKG_MANAGER=""
OS_LC="$(echo "$OS_RAW" | tr '[:upper:]' '[:lower:]')"

if [ "$OS_RAW" = "Darwin" ]; then
  DISTRO="macos"
  PKG_MANAGER="brew"
elif [ "$OS_RAW" = "Linux" ]; then
  if [ -f /etc/os-release ]; then
    # shellcheck disable=SC1091
    . /etc/os-release
    DISTRO="${ID:-unknown}"
  fi
  if command -v apt-get >/dev/null 2>&1; then PKG_MANAGER="apt-get"
  elif command -v dnf    >/dev/null 2>&1; then PKG_MANAGER="dnf"
  elif command -v yum    >/dev/null 2>&1; then PKG_MANAGER="yum"
  elif command -v apk    >/dev/null 2>&1; then PKG_MANAGER="apk"
  elif command -v pacman >/dev/null 2>&1; then PKG_MANAGER="pacman"
  else
    err "No supported package manager found (apt/dnf/yum/apk/pacman)."
    exit 1
  fi
else
  err "Unsupported OS: $OS_RAW"
  exit 1
fi

log "Detected OS=$OS_RAW distro=$DISTRO arch=$ARCH pkg_manager=$PKG_MANAGER"

# ── Base prerequisites ───────────────────────────────────────────────
install_prereqs() {
  log "Installing prerequisites (curl, git, tar, unzip, ca-certificates)…"
  case "$PKG_MANAGER" in
    apt-get)
      $SUDO apt-get update -y
      $SUDO apt-get install -y curl git tar unzip ca-certificates
      ;;
    dnf) $SUDO dnf install -y curl git tar unzip ca-certificates ;;
    yum) $SUDO yum install -y curl git tar unzip ca-certificates ;;
    apk) $SUDO apk add --no-cache curl git tar unzip ca-certificates bash ;;
    pacman) $SUDO pacman -Sy --noconfirm curl git tar unzip ca-certificates ;;
    brew)
      command -v brew >/dev/null 2>&1 || { err "Homebrew not found — install from https://brew.sh first"; exit 1; }
      brew install curl git
      ;;
  esac
}

# ── Go toolchain ──────────────────────────────────────────────────────
ensure_go() {
  if command -v go >/dev/null 2>&1; then
    log "Go already installed: $(go version | awk '{print $3}')"
    return
  fi

  if [ "$PKG_MANAGER" = "brew" ]; then
    log "Installing Go via Homebrew…"
    brew install go
    return
  fi

  log "Installing Go ${GO_VERSION} for ${OS_LC}/${ARCH}…"
  local tarball="go${GO_VERSION}.${OS_LC}-${ARCH}.tar.gz"
  curl -fsSL "https://go.dev/dl/${tarball}" -o "/tmp/${tarball}"
  $SUDO rm -rf /usr/local/go
  $SUDO tar -C /usr/local -xzf "/tmp/${tarball}"
  rm -f "/tmp/${tarball}"

  export PATH="/usr/local/go/bin:$PATH"
  for profile in /etc/profile "$HOME/.bashrc" "$HOME/.zshrc"; do
    [ -f "$profile" ] || continue
    grep -q '/usr/local/go/bin' "$profile" 2>/dev/null || \
      echo 'export PATH=$PATH:/usr/local/go/bin' | $SUDO tee -a "$profile" >/dev/null
  done
}

# ── Security tools ────────────────────────────────────────────────────
install_go_tool() {
  local bin="$1" pkg="$2" required="$3"
  if command -v "$bin" >/dev/null 2>&1; then
    log "$bin already installed — skipping"
    return
  fi
  log "Installing $bin ($pkg)…"
  if GOBIN="$GOBIN_DIR" go install "$pkg" 2>"/tmp/install_${bin}.log"; then
    log "$bin installed"
  elif [ "$required" = "required" ]; then
    err "$bin failed to install — see /tmp/install_${bin}.log"
  else
    warn "$bin (optional) failed to install — skipping"
  fi
}

# amass and nuclei have larger dependency trees than the other tools here and
# have been observed to fail `go install` on resource-constrained or
# flaky-network machines (timeout, OOM during compile, module fetch hiccups).
# Retry once, then fall back to the OS package manager — both are packaged
# in Kali/Debian/Arch repos.
install_go_tool_with_fallback() {
  local bin="$1" pkg="$2" pkgname="${3:-$bin}"
  if command -v "$bin" >/dev/null 2>&1; then
    log "$bin already installed — skipping"
    return
  fi
  log "Installing $bin ($pkg)…"
  local attempt
  for attempt in 1 2; do
    if GOBIN="$GOBIN_DIR" go install "$pkg" 2>"/tmp/install_${bin}.log"; then
      log "$bin installed via go install"
      return
    fi
    [ "$attempt" -eq 1 ] && warn "$bin: go install attempt 1 failed, retrying once…"
  done
  warn "go install for $bin failed twice, trying system package manager…"
  case "$PKG_MANAGER" in
    apt-get) $SUDO apt-get install -y "$pkgname" || true ;;
    dnf)     $SUDO dnf install -y "$pkgname" || true ;;
    yum)     $SUDO yum install -y "$pkgname" || true ;;
    apk)     $SUDO apk add --no-cache "$pkgname" || true ;;
    pacman)  $SUDO pacman -S --noconfirm "$pkgname" || true ;;
    brew)    brew install "$pkgname" || true ;;
  esac
  command -v "$bin" >/dev/null 2>&1 || err "$bin installation failed via all methods — see /tmp/install_${bin}.log"
}

main() {
  install_prereqs
  ensure_go
  hash -r

  GOBIN_DIR="$(go env GOPATH 2>/dev/null || echo "$HOME/go")/bin"
  export PATH="$PATH:$GOBIN_DIR"

  install_go_tool subfinder   github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest required
  install_go_tool assetfinder github.com/tomnomnom/assetfinder@latest                        required
  install_go_tool_with_fallback amass github.com/owasp-amass/amass/v4/cmd/amass@latest amass
  install_go_tool dnsx        github.com/projectdiscovery/dnsx/cmd/dnsx@latest                required
  install_go_tool httpx       github.com/projectdiscovery/httpx/cmd/httpx@latest              required
  install_go_tool_with_fallback nuclei github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest nuclei
  install_go_tool shuffledns  github.com/projectdiscovery/shuffledns/cmd/shuffledns@latest     optional

  if command -v nuclei >/dev/null 2>&1; then
    log "Updating nuclei templates…"
    nuclei -update-templates -silent || warn "nuclei template update failed (check network)"
  fi

  echo ""
  log "── Tool status ──────────────────────────"
  for t in "${REQUIRED_TOOLS[@]}" "${OPTIONAL_TOOLS[@]}"; do
    if command -v "$t" >/dev/null 2>&1; then
      printf '  \033[1;32m\xe2\x9c\x93\033[0m %-12s %s\n' "$t" "$(command -v "$t")"
    else
      printf '  \033[1;31m\xe2\x9c\x97\033[0m %-12s NOT FOUND\n' "$t"
    fi
  done
  echo ""
  log "Done. If PATH wasn't already exported in this shell, run: export PATH=\$PATH:${GOBIN_DIR}"
}

main "$@"
