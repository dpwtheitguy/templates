#!/usr/bin/env bash
#
# Description: Explain what this script does
# SPDX-License-Identifier: None
# email <email@domain.com> 
# ver 6.9.2020.1 / Shellcheck+Bashlint Pass Date
# Style guide: https://google.github.io/styleguide/shellguide.html

### TODO/Bugs/Change
# TODO(NAME): Thing I need to do (JIRA #)
# CHANGE(NAME): Thing I did and why (JIRA #)

### Security
# Exit on fail, unset variables, disallow ?/* globbing, fail when piped commands fail
#
# The -e option causes the shell to immediately exit if any command fails (i.e., exits with a non-zero status).
# The -u option causes the shell to treat unset variables as an error and exit immediately if any unset variable is used in a command.
# The -f option disables file name generation (i.e., disables globbing).
# The -o pipefail option sets the exit status of a pipeline to the status of the last command that exits with a non-zero status.
  set -euf -o pipefail

# File operations security: prevent cd operations.
  set -r

### Debug Mode
  # set -x

### Global Variables/Capture Arguments
# Constants in UPPERCASE, variables with _ in front (_myvar) are sensitive
# declare -r for global readonly, readonly for local scope read only
# Always double-quote for variable expansion to prevent word splitting.
  declare argument_one
  argument_one="$1"
  readonly argument_one
  
  declare src_ip
  src_ip=$(hostname -I)
  readonly src_ip

  declare verbose_logging=0

#######################################
# initialize_args
# Capture arguments from the CLI
# Globals:
#   None
# Arguments:
#   "$@"
# Docs:
#   None
#######################################
function initialize_args() {
  local arr=("$@")
  case "${arr[@]}" in
    -v|--verbose)
      verbose_logging=1 ;;
    -h|--help)
      show_help ;;
    *)
      echo "Unrecognized argument" ;;
  esac
}

#######################################
# show_help
# Show help message
# Globals:
#   None
# Arguments:
#   None
# Docs:
#   None
#######################################
function show_help() {
  echo "Usage: $0 [-v | --verbose] [-h | --help]"
  echo "  -v | --verbose  Enable verbose mode"
  echo "  -h | --help     Display this help message"
  exit 0
}

#######################################
# write_log
# Log in a Splunk-friendly way.
# Globals:
#   None
# Arguments:
#   Severity (str) and Message (str)
# Docs:
#  write-log "INFORMATIONAL" "This is an informational message"
#######################################
function write_log() {
  local severity="$1"
  shift
  if $verbose_logging; then
    echo "[$(date +'%Y-%m-%dT%H:%M:%S%z')]: severity=${severity} src_ip=${src_ip} user=$(whoami) pwd=$(pwd) app=${0##*/} $*" >&2
  fi
  logger "severity=${severity} user=$(whoami) pwd=$(pwd) app=${0##*/} $*"
}

#######################################
# initialize_flightcheck
# Common sense env checks to ensure the script is safe to run
# Globals:
#   None
# Arguments:
#   None
# Docs:
#   None
#######################################
function initialize_flightcheck() {
  SCRIPT_START=$(date +%s)
  is_debian=0
  is_centos=0

  # Check OS
  if grep -qi "debian" /etc/os-release; then
    is_debian=1
  elif grep -qi "centos" /etc/os-release; then
    is_centos=1
  fi

  # Ensure we're running on Debian
  if [[ $is_debian -eq 0 ]]; then
    echo "This script requires Debian." >&2
    exit 1
  fi

  # Ensure root user
  if [[ $EUID -ne 0 ]]; then
    echo "This script must be run as root." >&2
    exit 1
  fi

  # Ensure hostname doesn't contain 'splunk'
  if [[ $(hostname) == *"splunk"* ]]; then
    echo "This script cannot be run on hosts with 'splunk' in the hostname." >&2
    exit 1
  fi

  # Capture MD5 hash of the script for integrity check
  if ! command -v md5sum &> /dev/null; then
    echo "md5sum is required but not found." >&2
    exit 1
  fi
  script_md5=$(md5sum "$0" | awk '{ print $1 }') 
}

#######################################
# close_out
# Cleanup and store script runtime
# Globals:
#   SCRIPT_START (unix time)
# Arguments:
#   None
# Docs:
#   None
#######################################
function close_out() {
  # Log script runtime and exit status
  SCRIPT_END=$(date +%s)
  SCRIPT_RUNTIME=$((SCRIPT_END - SCRIPT_START))
  write_log "INFO" "Script runtime: ${SCRIPT_RUNTIME} seconds"
}

#######################################
# verb_noun
# Simple explanation of what this function does
# Globals:
#   None
# Arguments:
#   Input argument
# Docs:
#   https://learn.microsoft.com/en-us/powershell/scripting/developer/cmdlet/approved-verbs-for-windows-powershell-commands?view=powershell-7.3
#######################################
function verb_noun() {
  readonly myvar
  local myothervar
  echo 'Doing the thing'
}

### Main
function main() {
  initialize_args "$@"
  initialize_flightcheck
  verb_noun
  close_out
}
main "$@"
