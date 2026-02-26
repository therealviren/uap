#!/usr/bin/env bash
set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
YELLOW='\033[0;33m'
NC='\033[0m'

print() {
  printf "%b\n" "$1"
}

detect_platform() {
  if [ -n "${PREFIX-}" ] && [ -d "/data/data/com.termux/files/home" ]; then
    echo "termux"
    return
  fi
  unameOut="$(uname -s 2>/dev/null || true)"
  case "${unameOut}" in
    Linux*) echo "linux" ;;
    Darwin*) echo "macos" ;;
    FreeBSD*) echo "freebsd" ;;
    *) echo "unknown" ;;
  esac
}

detect_pkg_mgr() {
  if command -v pkg >/dev/null 2>&1 && [ -d "/data/data/com.termux/files/home" ]; then
    echo "pkg"
    return
  fi
  if command -v apt-get >/dev/null 2>&1; then echo "apt"; return; fi
  if command -v dnf >/dev/null 2>&1; then echo "dnf"; return; fi
  if command -v yum >/dev/null 2>&1; then echo "yum"; return; fi
  if command -v pacman >/dev/null 2>&1; then echo "pacman"; return; fi
  if command -v apk >/dev/null 2>&1; then echo "apk"; return; fi
  if command -v brew >/dev/null 2>&1; then echo "brew"; return; fi
  if command -v zypper >/dev/null 2>&1; then echo "zypper"; return; fi
  echo "none"
}

install_packages() {
  mgr="$(detect_pkg_mgr)"
  deps=("$@")
  case "$mgr" in
    pkg)
      for d in "${deps[@]}"; do pkg install -y "$d" || true; done
      ;;
    apt)
      sudo apt-get update -y || true
      sudo apt-get install -y "${deps[@]}" || true
      ;;
    dnf)
      sudo dnf install -y "${deps[@]}" || true
      ;;
    yum)
      sudo yum install -y "${deps[@]}" || true
      ;;
    pacman)
      sudo pacman -S --noconfirm "${deps[@]}" || true
      ;;
    apk)
      sudo apk add "${deps[@]}" || true
      ;;
    brew)
      brew install "${deps[@]}" || true
      ;;
    zypper)
      sudo zypper install -y "${deps[@]}" || true
      ;;
    *)
      return 1
      ;;
  esac
}

choose_compiler_and_flags() {
  if command -v gcc >/dev/null 2>&1; then
    CC=gcc
  elif command -v clang >/dev/null 2>&1; then
    CC=clang
  else
    CC=cc
  fi
  BASE_CFLAGS="-O2 -pipe -fstack-protector-strong -D_FORTIFY_SOURCE=2 -fPIC -Wno-deprecated-declarations"
  BASE_LDFLAGS="-lcrypto"
  if command -v pkg-config >/dev/null 2>&1 && pkg-config --exists openssl >/dev/null 2>&1; then
    PKG_CFLAGS="$(pkg-config --cflags openssl 2>/dev/null || true)"
    PKG_LIBS="$(pkg-config --libs openssl 2>/dev/null || true)"
    CFLAGS="$BASE_CFLAGS $PKG_CFLAGS"
    LDFLAGS="$PKG_LIBS"
  else
    CFLAGS="$BASE_CFLAGS"
    LDFLAGS="$BASE_LDFLAGS"
  fi
}

compile_uap() {
  builddir="$1"
  outbin="$2"
  mkdir -p "$builddir"
  files=(src/uap.c src/util.c src/build.c src/install.c src/run.c src/list_info_uninstall.c)
  objs=()
  for f in "${files[@]}"; do
    if [ ! -f "$f" ]; then
      print "${YELLOW}warning:${NC} missing source $f, skipping"
      continue
    fi
    base="$(basename "$f" .c)"
    obj="$builddir/$base.o"
    "$CC" $CFLAGS -c "$f" -o "$obj"
    objs+=("$obj")
  done
  if [ "${#objs[@]}" -eq 0 ]; then
    print "${RED}error:${NC} no object files produced"
    return 1
  fi
  IFS=' ' read -r -a LDFLAGS_ARR <<< "$LDFLAGS"
  "$CC" "${objs[@]}" "${LDFLAGS_ARR[@]}" -o "$outbin"
}

install_binary() {
  bin="$1"
  prefer_dest="$2"
  if [ -w "$prefer_dest" ] || { [ ! -e "$prefer_dest" ] && [ -w "$(dirname "$prefer_dest")" ]; }; then
    mv "$bin" "$prefer_dest"
    chmod +x "$prefer_dest"
    print "${GREEN}installed:${NC} $prefer_dest"
    return 0
  fi
  if command -v sudo >/dev/null 2>&1; then
    sudo mv "$bin" "$prefer_dest"
    sudo chmod +x "$prefer_dest"
    print "${GREEN}installed with sudo:${NC} $prefer_dest"
    return 0
  fi
  localuserbin="${HOME}/.local/bin"
  mkdir -p "$localuserbin"
  mv "$bin" "$localuserbin/uap"
  chmod +x "$localuserbin/uap"
  print "${GREEN}installed to user location:${NC} $localuserbin/uap"
  if ! echo "$PATH" | grep -q "$localuserbin"; then
    print "${YELLOW}hint:${NC} add $localuserbin to your PATH"
  fi
}

main() {
  print "${CYAN}Universal Application Package Installer (UAP 2)${NC}"
  platform="$(detect_platform)"
  print "platform: $platform"
  pkgmgr="$(detect_pkg_mgr)"
  print "package manager: $pkgmgr"
  case "$platform" in
    termux)
      deps=(clang make tar openssl pkg-config)
      ;;
    macos)
      deps=(make tar pkg-config)
      ;;
    linux|freebsd|unknown)
      deps=(gcc make tar pkg-config)
      ;;
  esac
  missing=()
  for d in "${deps[@]}"; do
    if ! command -v "$d" >/dev/null 2>&1; then
      missing+=("$d")
    fi
  done
  if [ "${#missing[@]}" -ne 0 ]; then
    print "${YELLOW}Missing:${NC} ${missing[*]}"
    if [ "$pkgmgr" = "none" ]; then
      print "${YELLOW}Please install:${NC} ${missing[*]}"
    else
      print "${CYAN}Attempting to install:${NC} ${missing[*]}"
      case "$pkgmgr" in
        pkg) install_packages "${missing[@]}" || true ;;
        apt) install_packages build-essential libssl-dev "${missing[@]}" || true ;;
        dnf|yum) install_packages "${missing[@]}" openssl-devel make || true ;;
        pacman) install_packages base-devel openssl "${missing[@]}" || true ;;
        apk) install_packages build-base openssl-dev "${missing[@]}" || true ;;
        brew) install_packages "${missing[@]}" || true ;;
        zypper) install_packages "${missing[@]}" libopenssl-devel || true ;;
      esac
    fi
  fi
  choose_compiler_and_flags
  builddir="$(mktemp -d 2>/dev/null || mktemp -d -t uap_build)"
  trap 'rm -rf "$builddir" >/dev/null 2>&1 || true' EXIT
  outbin="$(pwd)/uap.tmp.$$.bin"
  print "${CYAN}Compiling using $CC${NC}"
  if compile_uap "$builddir" "$outbin"; then
    print "${GREEN}Build succeeded${NC}"
  else
    print "${RED}Build failed${NC}"
    exit 1
  fi
  if [ "$platform" = "termux" ]; then
    preferred_dest="${PREFIX:-/data/data/com.termux/files/usr}/bin/uap"
  else
    if [ -w "/usr/bin" ] || command -v sudo >/dev/null 2>&1; then
      preferred_dest="/usr/bin/uap"
    else
      preferred_dest="${HOME}/.local/bin/uap"
    fi
  fi
  print "${CYAN}Installing to $preferred_dest${NC}"
  install_binary "$outbin" "$preferred_dest"
  print "${GREEN}Installation finished${NC}"
  if ! command -v uap >/dev/null 2>&1; then
    if [ -f "$preferred_dest" ]; then
      print "${CYAN}Run:${NC} $preferred_dest"
    else
      print "${YELLOW}uap installed in user directory but not in PATH${NC}"
    fi
  else
    print "${GREEN}uap available in PATH${NC}"
  fi
}

main "$@"