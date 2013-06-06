/*
 * Copyright (c) 2011, Intel Corporation
 * Authors: Fenghua Yu <fenghua.yu@intel.com>,
 *          H. Peter Anvin <hpa@linux.intel.com>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin St - Fifth Floor, Boston, MA 02110-1301 USA.
 *
 */

#define ENTRY(x)	  \
	.balign	64	; \
	.globl	x	; \
x:

#define ENDPROC(x)		  \
	.size	x, .-x		; \
	.type	x, @function

#define RDRAND_RETRY_LIMIT	10

#if defined(__x86_64__)

ENTRY(x86_rdrand_nlong)
1:
	mov	$RDRAND_RETRY_LIMIT, %eax
2:
	.byte	0x48,0x0f,0xc7,0xf2	/* rdrand %rdx */
	jnc	3f
	mov	%rdx, (%rdi)
	add	$8, %rdi
	sub	$1, %esi
	jnz	1b
	ret
3:
	sub	$1, %eax
	rep;nop
	jnz	2b
	ret
ENDPROC(x86_rdrand_nlong)

#define SETPTR(var,ptr)	leaq var(%rip),ptr
#define PTR0	%rdi
#define PTR1	%rsi
#define PTR2	%rcx
#define NPTR2	1	/* %rcx = %r1, only 0-7 valid here */

#elif defined(__i386__)

ENTRY(x86_rdrand_nlong)
	push	%ebp
	mov	%esp, %ebp
	push	%edi
	movl	8(%ebp), %ecx
	movl	12(%ebp), %edx
1:
	mov	$RDRAND_RETRY_LIMIT, %eax
2:
	.byte	0x0f,0xc7,0xf7		/* rdrand %edi */
	jnc	3f
	mov	%edi, (%ecx)
	add	$4, %ecx
	sub	$1, %edx
	jnz	2b
	pop	%edi
	pop	%ebp
	ret
3:
	sub	$1, %eax
	rep;nop
	jnz	2b
	pop %edi
	pop	%ebp
	ret
ENDPROC(x86_rdrand_nlong)

#define SETPTR(var,ptr)	movl $(var),ptr
#define PTR0	%eax
#define PTR1	%edx
#define PTR2	%ecx
#define NPTR2	1	/* %rcx = %r1 */

#endif

#if defined(__i386__) || defined(__x86_64__)

ENTRY(x86_aes_mangle)
#if defined(__i386__)
	push	%ebp
	mov	%esp, %ebp
	movl	8(%ebp), %eax
	movl	12(%ebp), %edx
#endif

	SETPTR(aes_round_keys, PTR2)

	movdqa	(0*16)(PTR0), %xmm0
	movdqa	(1*16)(PTR0), %xmm1
	movdqa	(2*16)(PTR0), %xmm2
	movdqa	(3*16)(PTR0), %xmm3
	movdqa	(4*16)(PTR0), %xmm4
	movdqa	(5*16)(PTR0), %xmm5
	movdqa	(6*16)(PTR0), %xmm6
	movdqa	(7*16)(PTR0), %xmm7

	pxor	(0*16)(PTR1), %xmm0
	pxor	(1*16)(PTR1), %xmm1
	pxor	(2*16)(PTR1), %xmm2
	pxor	(3*16)(PTR1), %xmm3
	pxor	(4*16)(PTR1), %xmm4
	pxor	(5*16)(PTR1), %xmm5
	pxor	(6*16)(PTR1), %xmm6
	pxor	(7*16)(PTR1), %xmm7

	.rept 10
	.byte	0x66,0x0f,0x38,0xdc,0x00+NPTR2	/* aesenc (PTR2), %xmm0 */
	.byte	0x66,0x0f,0x38,0xdc,0x08+NPTR2	/* aesenc (PTR2), %xmm1 */
	.byte	0x66,0x0f,0x38,0xdc,0x10+NPTR2	/* aesenc (PTR2), %xmm2 */
	.byte	0x66,0x0f,0x38,0xdc,0x18+NPTR2	/* aesenc (PTR2), %xmm3 */
	.byte	0x66,0x0f,0x38,0xdc,0x20+NPTR2	/* aesenc (PTR2), %xmm4 */
	.byte	0x66,0x0f,0x38,0xdc,0x28+NPTR2	/* aesenc (PTR2), %xmm5 */
	.byte	0x66,0x0f,0x38,0xdc,0x30+NPTR2	/* aesenc (PTR2), %xmm6 */
	.byte	0x66,0x0f,0x38,0xdc,0x38+NPTR2	/* aesenc (PTR2), %xmm7 */
	add	$16, PTR2
	.endr

	.byte	0x66,0x0f,0x38,0xdd,0x00+NPTR2	/* aesenclast (PTR2), %xmm0 */
	.byte	0x66,0x0f,0x38,0xdd,0x08+NPTR2	/* aesenclast (PTR2), %xmm1 */
	.byte	0x66,0x0f,0x38,0xdd,0x10+NPTR2	/* aesenclast (PTR2), %xmm2 */
	.byte	0x66,0x0f,0x38,0xdd,0x18+NPTR2	/* aesenclast (PTR2), %xmm3 */
	.byte	0x66,0x0f,0x38,0xdd,0x20+NPTR2	/* aesenclast (PTR2), %xmm4 */
	.byte	0x66,0x0f,0x38,0xdd,0x28+NPTR2	/* aesenclast (PTR2), %xmm5 */
	.byte	0x66,0x0f,0x38,0xdd,0x30+NPTR2	/* aesenclast (PTR2), %xmm6 */
	.byte	0x66,0x0f,0x38,0xdd,0x38+NPTR2	/* aesenclast (PTR2), %xmm7 */

	movdqa	%xmm0, (0*16)(PTR0)
	movdqa	%xmm1, (1*16)(PTR0)
	movdqa	%xmm2, (2*16)(PTR0)
	movdqa	%xmm3, (3*16)(PTR0)
	movdqa	%xmm4, (4*16)(PTR0)
	movdqa	%xmm5, (5*16)(PTR0)
	movdqa	%xmm6, (6*16)(PTR0)
	movdqa	%xmm7, (7*16)(PTR0)

	movdqa	%xmm0, (0*16)(PTR1)
	movdqa	%xmm1, (1*16)(PTR1)
	movdqa	%xmm2, (2*16)(PTR1)
	movdqa	%xmm3, (3*16)(PTR1)
	movdqa	%xmm4, (4*16)(PTR1)
	movdqa	%xmm5, (5*16)(PTR1)
	movdqa	%xmm6, (6*16)(PTR1)
	movdqa	%xmm7, (7*16)(PTR1)

#if defined(__i386__)
	pop	%ebp
#endif
	ret
ENDPROC(x86_aes_mangle)
	/*
	 * AES round keys for an arbitrary key:
	 * 00102030405060708090A0B0C0D0E0F0
	 */
	.section ".rodata","a"
	.balign	16
aes_round_keys:
	.long	0x30201000, 0x70605040, 0xB0A09080, 0xF0E0D0C0
	.long	0x8AACF171, 0xFACCA131, 0x4A6C31B1, 0xBA8CE171
	.long	0x2958958B, 0xD39434BA, 0x99F8050B, 0x2374E47A
	.long	0xF37E07E6, 0x20EA335C, 0xB9123657, 0x9A66D22D
	.long	0x2BC6345B, 0x0B2C0707, 0xB23E3150, 0x2858E37D
	.long	0xD4F25E5A, 0xDFDE595D, 0x6DE0680D, 0x45B88B70
	.long	0x859C3247, 0x5A426B1A, 0x37A20317, 0x721A8867
	.long	0x00DC90C3, 0x5A9EFBD9, 0x6D3CF8CE, 0x1F2670A9
	.long	0xD31C6712, 0x89829CCB, 0xE4BE6405, 0xFB9814AC
	.long	0x421321F3, 0xCB91BD38, 0x2F2FD93D, 0xD4B7CD91
	.long	0xC35B8878, 0x08CA3540, 0x27E5EC7D, 0xF35221EC
	.size	aes_round_keys, .-aes_round_keys

	.bss
	.balign 16
aes_fwd_state:
	.space	16
	.size	aes_fwd_state, .-aes_fwd_state

#endif /* i386 or x86_64 */

/*
 * This is necessary to keep the whole executable
 * from needing a writable stack.
 */
                .section        .note.GNU-stack,"",%progbits
