/* SPDX-License-Identifier: GPL-2.0 */
#include <linux/linkage.h>
#include <linux/objtool.h>
#include <asm/asm.h>
#include <asm/nospec-branch.h>

.section .noinstr.text, "ax"

/*
 * void airlock_svm_vmrun(u64 *gprs, u64 vmcb_pa, u64 host_vmsave_pa)
 *   %rdi = gprs ([u64; 16])
 *   %rsi = vmcb_pa
 *   %rdx = host_vmsave_pa
 *
 * Caller holds `GIF=0` (`clgi`) with host `EFER.SVME=1` and `MSR_VM_HSAVE_PA`
 * pointing to this CPU's Airlock host save area.
 */
SYM_FUNC_START(airlock_svm_vmrun)
	push %rbp
	mov  %rsp, %rbp
	push %r15
	push %r14
	push %r13
	push %r12
	push %rbx

	push %rdx		/* [rsp + 16] = host_vmsave_pa */
	push %rsi		/* [rsp + 8]  = vmcb_pa        */
	push %rdi		/* [rsp + 0]  = gprs           */

	mov  16(%rsp), %rax
	vmsave %rax

	mov   8(%rsp), %rax
	vmload %rax

	mov   8(%rdi), %rcx
	mov  16(%rdi), %rdx
	mov  24(%rdi), %rbx
	mov  40(%rdi), %rbp
	mov  48(%rdi), %rsi
	mov  64(%rdi), %r8
	mov  72(%rdi), %r9
	mov  80(%rdi), %r10
	mov  88(%rdi), %r11
	mov  96(%rdi), %r12
	mov 104(%rdi), %r13
	mov 112(%rdi), %r14
	mov 120(%rdi), %r15
	mov  56(%rdi), %rdi

	vmrun %rax

	push %rdi
	mov   8(%rsp), %rdi
	mov  %rcx,   8(%rdi)
	mov  %rdx,  16(%rdi)
	mov  %rbx,  24(%rdi)
	mov  %rbp,  40(%rdi)
	mov  %rsi,  48(%rdi)
	mov  %r8,   64(%rdi)
	mov  %r9,   72(%rdi)
	mov  %r10,  80(%rdi)
	mov  %r11,  88(%rdi)
	mov  %r12,  96(%rdi)
	mov  %r13, 104(%rdi)
	mov  %r14, 112(%rdi)
	mov  %r15, 120(%rdi)
	pop  %rax
	mov  %rax,  56(%rdi)

	mov   8(%rsp), %rax
	vmsave %rax
	mov  16(%rsp), %rax
	vmload %rax

	FILL_RETURN_BUFFER %rax, RSB_CLEAR_LOOPS, X86_FEATURE_RSB_VMEXIT
	VALIDATE_UNRET_END
	CALL_UNTRAIN_RET

	xor  %ecx, %ecx
	xor  %edx, %edx
	xor  %esi, %esi
	xor  %edi, %edi
	xor  %r8d, %r8d
	xor  %r9d, %r9d
	xor  %r10d, %r10d
	xor  %r11d, %r11d

	add  $24, %rsp
	pop  %rbx
	pop  %r12
	pop  %r13
	pop  %r14
	pop  %r15
	pop  %rbp
	RET
SYM_FUNC_END(airlock_svm_vmrun)
STACK_FRAME_NON_STANDARD airlock_svm_vmrun
