/*
 * start.S - Entry point for BROM payload
 * 
 * This is the first code that executes when the payload is loaded.
 * It switches from ARM mode to Thumb mode and calls main().
 * 
 * Based on mtkclient start.S (B.Kerler, k4y0z 2021)
 */

.syntax unified

.code 32

.global start
.section .text.start
start:
    add r3, pc, #1
    bx r3
