.syntax unified

.code 32

.global start
.section .text.start
start:
    mov sp, #0x42000000
    blx main

.global restart_lk
.type restart_lk, %function
restart_lk:
    // main() retains a large local frame while re-entering LK.  Reclaim the
    // normal LK app stack before the ARM32 DT/FDT path runs.
    mov sp, #0x42000000
    bx r0
