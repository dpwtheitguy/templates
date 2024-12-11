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
# Exit on fail, unset variables, disallow ?/* globbing, fail when piped commands fails
#
# NOTE: this will cause exits on (( i++ )), for example.  Use (( ++i )) where possible.
#
# The -e option causes the shell to immediately exit if any command fails (i.e., exits with a non-zero status).
# The -u option causes the shell to treat unset variables as an error and exit immediately if any unset variable is used in a command.
# The -f option disables file name generation (i.e., disables globbing).
# The -o pipefail option sets the exit status of a pipeline to the status of the last command that exits with a non-zero status
  set -euf -o pipefail

# File operations security: prevent cd operatons. (like old school /bin/bash -r)
  set -r

### Debug Mode
  # set -x

### Global Variables/Capture Arguments
# use PEP8 friendly as a base (https://peps.python.org/pep-0008/#naming-conventions)
# CIM vars are nice (https://docs.splunk.com/Documentation/CIM/5.1.0/User/CIMfields)
# constants UPPERCASE
# Variables with _ in front (_myvar) are to never be logged or directly addressed
# _var style signals "if you're touching this you're probably doing it wrong"
# declare -r for global readonly
# readonly for local scope read only
# double quote for variable expansion
# single quote for no variable expansion plz
# use good sense, practicality beats purity
  declare argument_one
  argument_one="$1"
  readonly argument_one
  
  declare src_ip
  src_ip=$(hostname -I)
  readonly src_ip

  declare verbose_logging=0

#######################################
# initialize-args
# Captures arguments from the CLI
# Globals:
#   None
# Arguments:
#   "$@"
# Docs:
#  None
#######################################
function initialize-args() 
  {
    # parse the arguments, then call other functions or set variables that change execution behavior
    local arr=("$@")
    case "${arr[@]}" in
      -v|--verbose)
        verbose_logging=1;;
      -h|--help)
        show-help;;
      *)
        echo "unrecognized argument";;
     esac
  }

#######################################
# show-help
# Shows help at the CLI
# Globals:
#   None
# Arguments:
#   None
# Docs:
#  None
#######################################
function show-help() 
  {
    # add other 
    echo "Usage: $0 [-v | --verbose] [-h || --help] "
    echo "  -v | --verbose  enable verbose mode"
    echo "  -h | --help     display this help message"
    exit 0
  }


#######################################
# write-log
# Log in a Splunk-friendly way.
# Globals:
#   None
# Arguments:
#   Severity (str) and Message (str)
# Docs:
#  write-log "INFORMATIONAL" "This is an informational message"
#######################################
function write-log()
{
  severity=$1
  shift
  # comment out this echo if you don't want users to see this, maybe we can use a argument in the future?
  if $verbose_logging ; then
    echo "[$(date +'%Y-%m-%dT%H:%M:%S%z')]: severity=${severity} src_ip=${src_ip} user=$(whoami) pwd=$(pwd) app=${0##*/} $*" >&2
  fi
  logger "severity=${severity} user=$(whoami) pwd=$(pwd) app=${0##*/} $*"
}

#######################################
# initialize-flightcheck
# Does common sense env checks to make sure this script is safe to run
# Globals:
# Arguments:
#   None
# Docs:
#   None
#######################################
function perform-flightcheck()
{
  # Use good sense to make sure your script is running where it should
  # Correct OS, correct user, has the apps it needs
  # Log out md5 and change details at start and end of scripts
  SCRIPT_START=$(date +%s)
  is_debian=0
  is_centos=0

  # Check the system information to set the values of the constants
  if grep -q "Debian" /etc/os-release; then
    is_debian=1
  elif grep -q "CentOS" /etc/os-release; then
    is_centos=1
  fi

  # Check if running on Debian
  if ! grep -qi "debian" /etc/os-release; then
    echo "This script requires Debian." >&2
    exit 1
  fi

  # Check if running as root
  if [[ $EUID -ne 0 ]]; then
    echo "This script must be run as root." >&2
   exit 1
    fi

  # Check if hostname is not "splunk"
  if [[ $(hostname) == *"splunk"* ]]; then
    echo "This script cannot be run on hosts with 'splunk' in the hostname." >&2
    exit 1
  fi

  # Capture my own MD5 just in case.
  if ! command -v md5sum &> /dev/null; then
    script_md5=$(md5sum "$0" | awk '{ print $1 }') >&2
    exit 1
  fi
}

#######################################
# close-out
# Any sort of cleanup you need to do. Store script runtime.
# Globals:
#  _script_start (unix time)
# Arguments:
#   None
# Docs:
#   None
#######################################
function finalize-script() {
  # Destroy any vars that are sensitive
  # unset my_api_key
  # unset mypassword
  SCRIPT_END=$(date +%s)
  SCRIPT_RUNTIME=$(($SCRIPT_END - $SCRIPT_START))
}

#######################################
# check-system-health
# Example of a function performing a task related to system status
# Globals:
#   Global variables this function relies on
# Arguments:
#   None
# Docs:
#  None
#######################################
function check-system-health()
{
  echo "Checking system health"
}

### Main
function main()
{
  initialize-args "${@}"
  perform-flightcheck
  check-system-health
  finalize-script
}
main "$@"
