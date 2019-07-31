#include <string.h>
#include <stdbool.h>

#include <stdio.h>
#include <stdlib.h>

#include "bitops.h"
#include "cpu.h"
#include "log.h"
#include "err.h"

#undef	LOG_PREFIX
#define LOG_PREFIX "cpu: "

#define __ins_bit(__l, __v)	(1u << ((__v) - 32u * (__l)))

static uint32_t __maybe_unused x86_ins_capability_mask[NCAPINTS] = {
	[CPUID_1_EDX] =
		__ins_bit(CPUID_1_EDX, X86_FEATURE_FPU)				|
		__ins_bit(CPUID_1_EDX, X86_FEATURE_TSC)				|
		__ins_bit(CPUID_1_EDX, X86_FEATURE_CX8)				|
		__ins_bit(CPUID_1_EDX, X86_FEATURE_SEP)				|
		__ins_bit(CPUID_1_EDX, X86_FEATURE_CMOV)			|
		__ins_bit(CPUID_1_EDX, X86_FEATURE_CLFLUSH)			|
		__ins_bit(CPUID_1_EDX, X86_FEATURE_MMX)				|
		__ins_bit(CPUID_1_EDX, X86_FEATURE_FXSR)			|
		__ins_bit(CPUID_1_EDX, X86_FEATURE_XMM)				|
		__ins_bit(CPUID_1_EDX, X86_FEATURE_XMM2),

	[CPUID_8000_0001_EDX] =
		__ins_bit(CPUID_8000_0001_EDX, X86_FEATURE_SYSCALL)		|
		__ins_bit(CPUID_8000_0001_EDX, X86_FEATURE_MMXEXT)		|
		__ins_bit(CPUID_8000_0001_EDX, X86_FEATURE_RDTSCP)		|
		__ins_bit(CPUID_8000_0001_EDX, X86_FEATURE_3DNOWEXT)		|
		__ins_bit(CPUID_8000_0001_EDX, X86_FEATURE_3DNOW),

	[CPUID_LNX_1] =
		__ins_bit(CPUID_LNX_1, X86_FEATURE_REP_GOOD)			|
		__ins_bit(CPUID_LNX_1, X86_FEATURE_NOPL),

	[CPUID_1_ECX] =
		__ins_bit(CPUID_1_ECX, X86_FEATURE_XMM3)			|
		__ins_bit(CPUID_1_ECX, X86_FEATURE_PCLMULQDQ)			|
		__ins_bit(CPUID_1_ECX, X86_FEATURE_MWAIT)			|
		__ins_bit(CPUID_1_ECX, X86_FEATURE_SSSE3)			|
		__ins_bit(CPUID_1_ECX, X86_FEATURE_CX16)			|
		__ins_bit(CPUID_1_ECX, X86_FEATURE_XMM4_1)			|
		__ins_bit(CPUID_1_ECX, X86_FEATURE_XMM4_2)			|
		__ins_bit(CPUID_1_ECX, X86_FEATURE_MOVBE)			|
		__ins_bit(CPUID_1_ECX, X86_FEATURE_POPCNT)			|
		__ins_bit(CPUID_1_ECX, X86_FEATURE_AES)				|
		__ins_bit(CPUID_1_ECX, X86_FEATURE_XSAVE)			|
		__ins_bit(CPUID_1_ECX, X86_FEATURE_OSXSAVE)			|
		__ins_bit(CPUID_1_ECX, X86_FEATURE_AVX)				|
		__ins_bit(CPUID_1_ECX, X86_FEATURE_F16C)			|
		__ins_bit(CPUID_1_ECX, X86_FEATURE_RDRAND),

	[CPUID_8000_0001_ECX] =
		__ins_bit(CPUID_8000_0001_ECX, X86_FEATURE_ABM)			|
		__ins_bit(CPUID_8000_0001_ECX, X86_FEATURE_SSE4A)		|
		__ins_bit(CPUID_8000_0001_ECX, X86_FEATURE_MISALIGNSSE)		|
		__ins_bit(CPUID_8000_0001_ECX, X86_FEATURE_3DNOWPREFETCH)	|
		__ins_bit(CPUID_8000_0001_ECX, X86_FEATURE_XOP)			|
		__ins_bit(CPUID_8000_0001_ECX, X86_FEATURE_FMA4)		|
		__ins_bit(CPUID_8000_0001_ECX, X86_FEATURE_TBM),

	[CPUID_7_0_EBX] =
		__ins_bit(CPUID_7_0_EBX, X86_FEATURE_FSGSBASE)			|
		__ins_bit(CPUID_7_0_EBX, X86_FEATURE_BMI1)			|
		__ins_bit(CPUID_7_0_EBX, X86_FEATURE_HLE)			|
		__ins_bit(CPUID_7_0_EBX, X86_FEATURE_AVX2)			|
		__ins_bit(CPUID_7_0_EBX, X86_FEATURE_BMI2)			|
		__ins_bit(CPUID_7_0_EBX, X86_FEATURE_ERMS)			|
		__ins_bit(CPUID_7_0_EBX, X86_FEATURE_RTM)			|
		__ins_bit(CPUID_7_0_EBX, X86_FEATURE_MPX)			|
		__ins_bit(CPUID_7_0_EBX, X86_FEATURE_AVX512F)			|
		__ins_bit(CPUID_7_0_EBX, X86_FEATURE_AVX512DQ)			|
		__ins_bit(CPUID_7_0_EBX, X86_FEATURE_RDSEED)			|
		__ins_bit(CPUID_7_0_EBX, X86_FEATURE_ADX)			|
		__ins_bit(CPUID_7_0_EBX, X86_FEATURE_CLFLUSHOPT)		|
		__ins_bit(CPUID_7_0_EBX, X86_FEATURE_AVX512PF)			|
		__ins_bit(CPUID_7_0_EBX, X86_FEATURE_AVX512ER)			|
		__ins_bit(CPUID_7_0_EBX, X86_FEATURE_AVX512CD)			|
		__ins_bit(CPUID_7_0_EBX, X86_FEATURE_SHA_NI)			|
		__ins_bit(CPUID_7_0_EBX, X86_FEATURE_AVX512BW)			|
		__ins_bit(CPUID_7_0_EBX, X86_FEATURE_AVX512VL),

	[CPUID_D_1_EAX] =
		__ins_bit(CPUID_D_1_EAX, X86_FEATURE_XSAVEOPT)			|
		__ins_bit(CPUID_D_1_EAX, X86_FEATURE_XSAVEC)			|
		__ins_bit(CPUID_D_1_EAX, X86_FEATURE_XGETBV1),

	[CPUID_7_0_ECX] =
		__ins_bit(CPUID_7_0_ECX, X86_FEATURE_AVX512VBMI)		|
		__ins_bit(CPUID_7_0_ECX, X86_FEATURE_AVX512_VBMI2)		|
		__ins_bit(CPUID_7_0_ECX, X86_FEATURE_GFNI)			|
		__ins_bit(CPUID_7_0_ECX, X86_FEATURE_VAES)			|
		__ins_bit(CPUID_7_0_ECX, X86_FEATURE_VPCLMULQDQ)		|
		__ins_bit(CPUID_7_0_ECX, X86_FEATURE_AVX512_VNNI)		|
		__ins_bit(CPUID_7_0_ECX, X86_FEATURE_AVX512_BITALG)		|
		__ins_bit(CPUID_7_0_ECX, X86_FEATURE_TME)			|
		__ins_bit(CPUID_7_0_ECX, X86_FEATURE_AVX512_VPOPCNTDQ)		|
		__ins_bit(CPUID_7_0_ECX, X86_FEATURE_RDPID),

	[CPUID_8000_0008_EBX] =
		__ins_bit(CPUID_8000_0008_EBX, X86_FEATURE_CLZERO),

	[CPUID_7_0_EDX] =
		__ins_bit(CPUID_7_0_EDX, X86_FEATURE_AVX512_4VNNIW)		|
		__ins_bit(CPUID_7_0_EDX, X86_FEATURE_AVX512_4FMAPS),
};

#undef __ins_bit

void set_cpu_cap(cpuinfo_x86_t *c, unsigned int feature)
{
	if (likely(feature < NCAPINTS_BITS))
		set_bit(feature, (unsigned long *)c->x86_capability);
}

void clear_cpu_cap(cpuinfo_x86_t *c, unsigned int feature)
{
	if (likely(feature < NCAPINTS_BITS))
		clear_bit(feature, (unsigned long *)c->x86_capability);
}

int test_cpu_cap(cpuinfo_x86_t *c, unsigned int feature)
{
	if (likely(feature < NCAPINTS_BITS))
		return test_bit(feature, (unsigned long *)c->x86_capability);
	return 0;
}

int test_fpu_cap(cpuinfo_x86_t *c, unsigned int feature)
{
	if (likely(feature < XFEATURE_MAX))
		return (c->xfeatures_mask & (1UL << feature));
	return 0;
}

void init_cpuid(cpuinfo_x86_t *c)
{
	memset(c, 0, sizeof(*c));
	init_fpuid(c);
}

int fetch_cpuid(cpuinfo_x86_t *c)
{
	x86_cpuid_call_trace_t *ct = &c->cpuid_call_trace;
	const cpuid_ops_t *cpuid_ops = cpuid_get_ops();
	uint32_t eax, ebx, ecx, edx;

	init_cpuid(c);

#define __zap_regs() eax = ebx = ecx = edx = 0

	/*
	 * See cpu_detect() in the kernel, also
	 * read cpuid specs not only from general
	 * SDM but for extended instructions set
	 * reference.
	 */

	/* Get vendor name */
	cpuid_ops->cpuid(0x00000000,
			 (unsigned int *)&c->cpuid_level,
			 (unsigned int *)&c->x86_vendor_id[0],
			 (unsigned int *)&c->x86_vendor_id[8],
			 (unsigned int *)&c->x86_vendor_id[4], ct);

	if (!strcmp((char *)c->x86_vendor_id, "GenuineIntel")) {
		c->x86_vendor = X86_VENDOR_INTEL;
	} else if (!strcmp((char *)c->x86_vendor_id, "AuthenticAMD")) {
		c->x86_vendor = X86_VENDOR_AMD;
	} else {
		pr_err("Unsupported CPU vendor %s\n",
		       c->x86_vendor_id);
		return -1;
	}

	c->x86_family = 4;

	/* Intel-defined flags: level 0x00000001 */
	if (c->cpuid_level >= 0x00000001) {
		__zap_regs();
		cpuid_ops->cpuid(0x00000001, &eax, &ebx, &ecx, &edx, ct);
		c->x86_family = (eax >> 8) & 0xf;
		c->x86_model = (eax >> 4) & 0xf;
		c->x86_mask = eax & 0xf;

		if (c->x86_family == 0xf)
			c->x86_family += (eax >> 20) & 0xff;
		if (c->x86_family >= 0x6)
			c->x86_model += ((eax >> 16) & 0xf) << 4;

		c->x86_capability[CPUID_1_EDX] = edx;
		c->x86_capability[CPUID_1_ECX] = ecx;
	}

	/* Thermal and Power Management Leaf: level 0x00000006 (eax) */
	if (c->cpuid_level >= 0x00000006)
		c->x86_capability[CPUID_6_EAX] = cpuid_ops->cpuid_eax(0x00000006, ct);

	/* Additional Intel-defined flags: level 0x00000007 */
	if (c->cpuid_level >= 0x00000007) {
		__zap_regs();
		cpuid_ops->cpuid_count(0x00000007, 0, &eax, &ebx, &ecx, &edx, ct);
		c->x86_capability[CPUID_7_0_EBX] = ebx;
		c->x86_capability[CPUID_7_0_ECX] = ecx;
		c->x86_capability[CPUID_7_0_EDX] = edx;
	}

	/* Extended state features: level 0x0000000d */
	if (c->cpuid_level >= 0x0000000d) {
		__zap_regs();
		cpuid_ops->cpuid_count(0x0000000d, 1, &eax, &ebx, &ecx, &edx, ct);
		c->x86_capability[CPUID_D_1_EAX] = eax;
	}

	/* Additional Intel-defined flags: level 0x0000000F */
	if (c->cpuid_level >= 0x0000000F) {
		__zap_regs();
		/* QoS sub-leaf, EAX=0Fh, ECX=0 */
		cpuid_ops->cpuid_count(0x0000000F, 0, &eax, &ebx, &ecx, &edx, ct);
		c->x86_capability[CPUID_F_0_EDX] = edx;

		if (test_cpu_cap(c, X86_FEATURE_CQM_LLC)) {
			__zap_regs();
			/* QoS sub-leaf, EAX=0Fh, ECX=1 */
			cpuid_ops->cpuid_count(0x0000000F, 1, &eax, &ebx, &ecx, &edx, ct);
			c->x86_capability[CPUID_F_1_EDX] = edx;
		}
	}

	/* AMD-defined flags: level 0x80000001 */
	eax = cpuid_ops->cpuid_eax(0x80000000, ct);
	c->extended_cpuid_level = eax;

	if ((eax & 0xffff0000) == 0x80000000) {
		if (eax >= 0x80000001) {
			__zap_regs();
			cpuid_ops->cpuid(0x80000001, &eax, &ebx, &ecx, &edx, ct);

			c->x86_capability[CPUID_8000_0001_ECX] = ecx;
			c->x86_capability[CPUID_8000_0001_EDX] = edx;
		}
	}

	/*
	 * We're don't care about scattered features for now,
	 * otherwise look into init_scattered_cpuid_features()
	 * in kernel.
	 *
	 * Same applies to speculation control. Look into
	 * init_speculation_control() otherwise.
	 */

	if (c->extended_cpuid_level >= 0x80000004) {
		unsigned int *v;
		char *p, *q;
		v = (unsigned int *)c->x86_model_id;
		cpuid_ops->cpuid(0x80000002, &v[0], &v[1], &v[2], &v[3], ct);
		cpuid_ops->cpuid(0x80000003, &v[4], &v[5], &v[6], &v[7], ct);
		cpuid_ops->cpuid(0x80000004, &v[8], &v[9], &v[10], &v[11], ct);
		c->x86_model_id[48] = 0;

		/*
		 * Intel chips right-justify this string for some dumb reason;
		 * undo that brain damage:
		 */
		p = q = (char *)&c->x86_model_id[0];
		while (*p == ' ')
			p++;
		if (p != q) {
			while (*p)
				*q++ = *p++;
			while (q <= (char *)&c->x86_model_id[48])
				*q++ = '\0';	/* Zero-pad the rest */
		}
	}

	if (c->extended_cpuid_level >= 0x80000007) {
		__zap_regs();
		cpuid_ops->cpuid(0x80000007, &eax, &ebx, &ecx, &edx, ct);

		c->x86_capability[CPUID_8000_0007_EBX] = ebx;
		c->x86_power = edx;
	}

	if (c->extended_cpuid_level >= 0x8000000a)
		c->x86_capability[CPUID_8000_000A_EDX] = cpuid_ops->cpuid_edx(0x8000000a, ct);

	if (c->extended_cpuid_level >= 0x80000008)
		c->x86_capability[CPUID_8000_0008_EBX] = cpuid_ops->cpuid_ebx(0x80000008, ct);

	/* On x86-64 CPUID is always present */
	set_cpu_cap(c, X86_FEATURE_CPUID);

	/* On x86-64 NOP is always present */
	set_cpu_cap(c, X86_FEATURE_NOPL);

	/*
	 * On x86-64 syscalls32 are enabled but we don't
	 * set it yet for backward compatibility reason
	 */
	//set_cpu_cap(c, X86_FEATURE_SYSCALL32);

	/* See filter_cpuid_features in kernel */
	if ((int32_t)c->cpuid_level < (int32_t)0x0000000d)
		clear_cpu_cap(c, X86_FEATURE_XSAVE);

	/*
	 * We only care about small subset from c_early_init:
	 * early_init_amd and early_init_intel
	 */
	switch (c->x86_vendor) {
	case X86_VENDOR_INTEL:
		/*
		 * Strictly speaking we need to read MSR_IA32_MISC_ENABLE
		 * here but on ring3 it's impossible.
		 */
		if (c->x86_family == 15) {
			clear_cpu_cap(c, X86_FEATURE_REP_GOOD);
			clear_cpu_cap(c, X86_FEATURE_ERMS);
		} else if (c->x86_family == 6) {
			/* On x86-64 rep is fine */
			set_cpu_cap(c, X86_FEATURE_REP_GOOD);
		}

		break;
	case X86_VENDOR_AMD:
		/*
		 * Bit 31 in normal CPUID used for nonstandard 3DNow ID;
		 * 3DNow is IDd by bit 31 in extended CPUID (1*32+31) anyway
		 */
		clear_cpu_cap(c, 0 * 32 + 31);
		if (c->x86_family >= 0x10)
			set_cpu_cap(c, X86_FEATURE_REP_GOOD);
		if (c->x86_family == 0xf) {
			uint32_t level;

			/* On C+ stepping K8 rep microcode works well for copy/memset */
			level = cpuid_ops->cpuid_eax(1, ct);
			if ((level >= 0x0f48 && level < 0x0f50) || level >= 0x0f58)
				set_cpu_cap(c, X86_FEATURE_REP_GOOD);
		}
		break;
	}

	pr_debug("x86_family %u x86_vendor_id %s x86_model_id %s\n",
		 c->x86_family, c->x86_vendor_id, c->x86_model_id);

	return fetch_fpuid(c);
#undef __zap_regs
}
