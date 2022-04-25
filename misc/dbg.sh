#!/bin/bash
gdb-multiarch -q linux338.vmlinux.elf -ex 'target remote localhost:1234'