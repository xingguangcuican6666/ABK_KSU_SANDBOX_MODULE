#!/usr/bin/env bash

abk_log() {
  printf '[ABK module] %s\n' "$*"
}

abk_warn() {
  printf '[ABK module][warn] %s\n' "$*" >&2
}

abk_die() {
  printf '[ABK module][error] %s\n' "$*" >&2
  exit 1
}

abk_require_env() {
  local name
  for name in "$@"; do
    if [ -z "${!name:-}" ]; then
      abk_die "required environment variable is empty: $name"
    fi
  done
}

abk_common_dir() {
  abk_require_env KERNEL_ROOT
  printf '%s/common\n' "$KERNEL_ROOT"
}

abk_require_file() {
  local path="$1"
  [ -f "$path" ] || abk_die "required file not found: $path"
}

abk_require_dir() {
  local path="$1"
  [ -d "$path" ] || abk_die "required directory not found: $path"
}

abk_kernel_make_value() {
  local key="$1"
  local makefile
  makefile="$(abk_common_dir)/Makefile"
  abk_require_file "$makefile"
  awk -v key="$key" '$1 == key && $2 == "=" { print $3; exit }' "$makefile"
}

abk_kernel_version() {
  local version patchlevel sublevel
  version="$(abk_kernel_make_value VERSION)"
  patchlevel="$(abk_kernel_make_value PATCHLEVEL)"
  sublevel="$(abk_kernel_make_value SUBLEVEL)"
  printf '%s.%s.%s\n' "$version" "$patchlevel" "$sublevel"
}

abk_set_config() {
  local symbol="$1"
  local value="$2"
  local file="${3:-${DEFCONFIG:-}}"
  local clean_symbol tmp

  [ -n "$file" ] || abk_die "DEFCONFIG is empty"
  abk_require_file "$file"
  clean_symbol="${symbol#CONFIG_}"
  tmp="$(mktemp)"
  grep -v -E "^(CONFIG_${clean_symbol}=|# CONFIG_${clean_symbol} is not set$)" "$file" > "$tmp" || true
  if [ "$value" = n ]; then
    printf '# CONFIG_%s is not set\n' "$clean_symbol" >> "$tmp"
  else
    printf 'CONFIG_%s=%s\n' "$clean_symbol" "$value" >> "$tmp"
  fi
  mv "$tmp" "$file"
  abk_log "set CONFIG_${clean_symbol}=$value in $file"
}

abk_enable_config() {
  abk_set_config "$1" y "${2:-${DEFCONFIG:-}}"
}

abk_enable_lsm() {
  local lsm="${1:-abk_ksu_sandbox}"
  local file="${2:-${DEFCONFIG:-}}"
  local kconfig default_condition default_lsms normalized seen token value
  local -a default_security_lines lsm_lines parsed_lsms

  [ -n "$file" ] || abk_die "DEFCONFIG is empty"
  abk_require_file "$file"
  mapfile -t lsm_lines < <(grep -E '^CONFIG_LSM=' "$file" || true)
  case "${#lsm_lines[@]}" in
    0)
      kconfig="$(abk_common_dir)/security/Kconfig"
      abk_require_file "$kconfig"
      mapfile -t default_security_lines < <(
        grep -E '^CONFIG_DEFAULT_SECURITY_(SELINUX|SMACK|TOMOYO|APPARMOR|DAC)=y$' \
          "$file" || true
      )
      if [ "${#default_security_lines[@]}" -gt 1 ]; then
        abk_die "multiple CONFIG_DEFAULT_SECURITY choices found in $file"
      fi
      default_condition=""
      if [ "${#default_security_lines[@]}" -eq 1 ] && \
        [ "${default_security_lines[0]}" != "CONFIG_DEFAULT_SECURITY_SELINUX=y" ]; then
        default_condition="${default_security_lines[0]#CONFIG_}"
        default_condition="${default_condition%=y}"
      fi
      default_lsms="$(awk -v condition="$default_condition" '
        $1 == "config" && $2 == "LSM" { in_lsm = 1; next }
        in_lsm && $1 == "config" { exit }
        in_lsm && $1 == "default" &&
          ((condition == "" && $0 !~ /[[:space:]]if[[:space:]]/) ||
           (condition != "" &&
            $0 ~ ("[[:space:]]if[[:space:]]+" condition "([[:space:]]|$)"))) {
          if (match($0, /"[^"]+"/)) {
            print substr($0, RSTART + 1, RLENGTH - 2)
            exit
          }
        }
      ' "$kconfig")"
      [ -n "$default_lsms" ] || \
        abk_die "unable to determine the default CONFIG_LSM list from $kconfig"
      value="$default_lsms"
      ;;
    1)
      case "${lsm_lines[0]}" in
        CONFIG_LSM=\"*\")
          value="${lsm_lines[0]#CONFIG_LSM=\"}"
          value="${value%\"}"
          ;;
        *)
          abk_die "malformed CONFIG_LSM assignment: ${lsm_lines[0]}"
          ;;
      esac
      ;;
    *)
      abk_die "multiple CONFIG_LSM assignments found in $file"
      ;;
  esac

  case "$value" in
    ""|*[!A-Za-z0-9_,.-]*)
      abk_die "invalid CONFIG_LSM list: $value"
      ;;
  esac
  if [[ ",$value," == *,,* ]]; then
    abk_die "CONFIG_LSM contains an empty entry"
  fi
  IFS=',' read -r -a parsed_lsms <<< "$value"
  seen=""
  normalized=""
  for token in "${parsed_lsms[@]}"; do
    [ -n "$token" ] || abk_die "CONFIG_LSM contains an empty entry"
    if [[ ",$seen," == *",$token,"* ]]; then
      abk_die "CONFIG_LSM contains a duplicate entry: $token"
    fi
    seen="${seen:+$seen,}$token"
    if [ "$token" != "$lsm" ]; then
      normalized="${normalized:+$normalized,}$token"
    fi
  done
  if [[ ",$value," != *,selinux,* ]]; then
    abk_die "CONFIG_LSM must include selinux"
  fi
  value="${normalized:+$normalized,}$lsm"
  abk_set_config CONFIG_LSM "\"$value\"" "$file"
}
