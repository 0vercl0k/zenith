#!/bin/bash
qemu-system-mips -m 128M -nographic -append "root=/dev/sda1 mem=128M" -kernel linux338.vmlinux.elf -M malta -cpu 74Kf -s -hda debian_wheezy_mips_standard.qcow2 -net nic,netdev=network0 -netdev user,id=network0,hostfwd=tcp:127.0.0.1:20005-10.0.2.15:20005,hostfwd=tcp:127.0.0.1:33344-10.0.2.15:33344,hostfwd=tcp:127.0.0.1:31337-10.0.2.15:31337
