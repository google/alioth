#!/bin/sh
# Connects to the Alpine Linux guest started by `run-linux.sh`.
# See also:
#   ./ssh-into-motor-os.sh
#   ./ssh-into-nested-motor-os.sh
#   ./ssh-into-nested-linux.sh

exec ssh -o ProxyCommand=none root@192.168.8.2 "$@"
