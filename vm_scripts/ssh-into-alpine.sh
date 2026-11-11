#!/bin/sh
# Connects to the Alpine Linux guest started by `run-linux.sh`.
# For Motor OS (`run-motor-os.sh`), use:
#   ../../motor-dev/motor-os/vm_images/release/ssh-into-motor-os-vm.sh

exec ssh -o ProxyCommand=none root@192.168.8.2 "$@"
