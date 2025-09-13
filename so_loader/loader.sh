#!/bin/bash
set -euo pipefail

if [[ $# -lt 2 ]]; then
  echo "Usage: $0 <PID> <ABSOLUTE_PATH_TO_SO>"
  exit 1
fi

PID="$1"
SO="$2"

if [[ "${SO:0:1}" != "/" ]]; then
  echo "Please pass absolute path to .so"
  exit 1
fi

if ! ps -p "$PID" > /dev/null 2>&1; then
  echo "Error: Process with PID $PID does not exist."
  exit 1
fi

if [[ ! -f "$SO" ]]; then
  echo "Error: File $SO does not exist."
  exit 1
fi

echo "Injecting $SO into process $PID..."

if gdb -q -n -batch -p "$PID" \
   -ex "call (void*)__libc_dlopen_mode(\"$SO\", 1)" \
   -ex "detach" \
   -ex "quit" 2>&1 | grep -q "\$1 ="; then
  echo "Successfully injected $SO into PID $PID using __libc_dlopen_mode"
  exit 0
fi

  echo "Injection failed"
  exit 1
fi