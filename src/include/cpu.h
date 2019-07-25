#ifndef VZCPUIDCTL_CPU_H__
#define VZCPUIDCTL_CPU_H__

#include <stdint.h>
#include <stdbool.h>

#include <sys/types.h>

#include "compiler.h"
#include "log.h"

/*
 * Adopted from linux kernel and enhanced from Intel/AMD manuals.
 * Note these bits are not ABI for linux kernel but they _are_
 * for us, so make sure they are at proper position between
 * versions.
 *
 * In particular since we already used leaf 11 we have
 * to keep it here, since it's an ABI now.
 */
enum cpuid_leafs {
	CPUID_1_EDX		= 0,
	CPUID_8000_0001_EDX	= 1,
	CPUID_8086_0001_EDX	= 2,
	CPUID_LNX_1		= 3,
	CPUID_1_ECX		= 4,
	CPUID_C000_0001_EDX	= 5,
	CPUID_8000_0001_ECX	= 6,
	CPUID_LNX_2		= 7,
	CPUID_LNX_3		= 8,
	CPUID_7_0_EBX		= 9,
	CPUID_D_1_EAX		= 10,
	CPUID_7_0_ECX		= 11,
	CPUID_F_1_EDX		= 12,
	CPUID_8000_0008_EBX	= 13,
	CPUID_6_EAX		= 14,
	CPUID_8000_000A_EDX	= 15,
	CPUID_F_0_EDX		= 16,
	CPUID_8000_0007_EBX	= 17,
	CPUID_7_0_EDX		= 18,
};

#define NCAPINTS_V1		12
#define NCAPINTS_V2		19

#define NCAPINTS			(NCAPINTS_V2) /* N 32-bit words worth of info */
#define NCAPINTS_BITS			(NCAPINTS * 32)

/* Intel-defined CPU features, CPUID level 0x00000001 (EDX), word 0 */
#define X86_FEATURE_FPU			(0*32+ 0) /* Onboard FPU */
#define X86_FEATURE_VME			(0*32+ 1) /* Virtual Mode Extensions */
#define X86_FEATURE_DE			(0*32+ 2) /* Debugging Extensions */
#define X86_FEATURE_PSE			(0*32+ 3) /* Page Size Extensions */
#define X86_FEATURE_TSC			(0*32+ 4) /* Time Stamp Counter */
#define X86_FEATURE_MSR			(0*32+ 5) /* Model-Specific Registers */
#define X86_FEATURE_PAE			(0*32+ 6) /* Physical Address Extensions */
#define X86_FEATURE_MCE			(0*32+ 7) /* Machine Check Exception */
#define X86_FEATURE_CX8			(0*32+ 8) /* CMPXCHG8 instruction */
#define X86_FEATURE_APIC		(0*32+ 9) /* Onboard APIC */
#define X86_FEATURE_SEP			(0*32+11) /* SYSENTER/SYSEXIT */
#define X86_FEATURE_MTRR		(0*32+12) /* Memory Type Range Registers */
#define X86_FEATURE_PGE			(0*32+13) /* Page Global Enable */
#define X86_FEATURE_MCA			(0*32+14) /* Machine Check Architecture */
#define X86_FEATURE_CMOV		(0*32+15) /* CMOV instructions (plus FCMOVcc, FCOMI with FPU) */
#define X86_FEATURE_PAT			(0*32+16) /* Page Attribute Table */
#define X86_FEATURE_PSE36		(0*32+17) /* 36-bit PSEs */
#define X86_FEATURE_PN			(0*32+18) /* Processor serial number */
#define X86_FEATURE_CLFLUSH		(0*32+19) /* CLFLUSH instruction */
#define X86_FEATURE_DS			(0*32+21) /* "dts" Debug Store */
#define X86_FEATURE_ACPI		(0*32+22) /* ACPI via MSR */
#define X86_FEATURE_MMX			(0*32+23) /* Multimedia Extensions */
#define X86_FEATURE_FXSR		(0*32+24) /* FXSAVE/FXRSTOR, CR4.OSFXSR */
#define X86_FEATURE_XMM			(0*32+25) /* "sse" */
#define X86_FEATURE_XMM2		(0*32+26) /* "sse2" */
#define X86_FEATURE_SELFSNOOP		(0*32+27) /* "ss" CPU self snoop */
#define X86_FEATURE_HT			(0*32+28) /* Hyper-Threading */
#define X86_FEATURE_ACC			(0*32+29) /* "tm" Automatic clock control */
#define X86_FEATURE_IA64		(0*32+30) /* IA-64 processor */
#define X86_FEATURE_PBE			(0*32+31) /* Pending Break Enable */

/* AMD-defined CPU features, CPUID level 0x80000001, word 1 */
/* Don't duplicate feature flags which are redundant with Intel! */
#define X86_FEATURE_SYSCALL		(1*32+11) /* SYSCALL/SYSRET */
#define X86_FEATURE_MP			(1*32+19) /* MP Capable */
#define X86_FEATURE_NX			(1*32+20) /* Execute Disable */
#define X86_FEATURE_MMXEXT		(1*32+22) /* AMD MMX extensions */
#define X86_FEATURE_FXSR_OPT		(1*32+25) /* FXSAVE/FXRSTOR optimizations */
#define X86_FEATURE_GBPAGES		(1*32+26) /* "pdpe1gb" GB pages */
#define X86_FEATURE_RDTSCP		(1*32+27) /* RDTSCP */
#define X86_FEATURE_LM			(1*32+29) /* Long Mode (x86-64, 64-bit support) */
#define X86_FEATURE_3DNOWEXT		(1*32+30) /* AMD 3DNow extensions */
#define X86_FEATURE_3DNOW		(1*32+31) /* 3DNow */

/* Transmeta-defined CPU features, CPUID level 0x80860001, word 2 */
#define X86_FEATURE_RECOVERY		(2*32+ 0) /* CPU in recovery mode */
#define X86_FEATURE_LONGRUN		(2*32+ 1) /* Longrun power control */
#define X86_FEATURE_LRTI		(2*32+ 3) /* LongRun table interface */

/* Other features, Linux-defined mapping, word 3 */
/* This range is used for feature bits which conflict or are synthesized */
#define X86_FEATURE_CXMMX		(3*32+ 0) /* Cyrix MMX extensions */
#define X86_FEATURE_K6_MTRR		(3*32+ 1) /* AMD K6 nonstandard MTRRs */
#define X86_FEATURE_CYRIX_ARR		(3*32+ 2) /* Cyrix ARRs (= MTRRs) */
#define X86_FEATURE_CENTAUR_MCR		(3*32+ 3) /* Centaur MCRs (= MTRRs) */

/* CPU types for specific tunings: */
#define X86_FEATURE_K8			(3*32+ 4) /* "" Opteron, Athlon64 */
#define X86_FEATURE_K7			(3*32+ 5) /* "" Athlon */
#define X86_FEATURE_P3			(3*32+ 6) /* "" P3 */
#define X86_FEATURE_P4			(3*32+ 7) /* "" P4 */
#define X86_FEATURE_CONSTANT_TSC	(3*32+ 8) /* TSC ticks at a constant rate */
#define X86_FEATURE_UP			(3*32+ 9) /* SMP kernel running on UP */
#define X86_FEATURE_ART			(3*32+10) /* Always running timer (ART) */
#define X86_FEATURE_ARCH_PERFMON	(3*32+11) /* Intel Architectural PerfMon */
#define X86_FEATURE_PEBS		(3*32+12) /* Precise-Event Based Sampling */
#define X86_FEATURE_BTS			(3*32+13) /* Branch Trace Store */
#define X86_FEATURE_SYSCALL32		(3*32+14) /* "" syscall in IA32 userspace */
#define X86_FEATURE_SYSENTER32		(3*32+15) /* "" sysenter in IA32 userspace */
#define X86_FEATURE_REP_GOOD		(3*32+16) /* REP microcode works well */
#define X86_FEATURE_MFENCE_RDTSC	(3*32+17) /* "" MFENCE synchronizes RDTSC */
#define X86_FEATURE_LFENCE_RDTSC	(3*32+18) /* "" LFENCE synchronizes RDTSC */
#define X86_FEATURE_ACC_POWER		(3*32+19) /* AMD Accumulated Power Mechanism */
#define X86_FEATURE_NOPL		(3*32+20) /* The NOPL (0F 1F) instructions */
#define X86_FEATURE_ALWAYS		(3*32+21) /* "" Always-present feature */
#define X86_FEATURE_XTOPOLOGY		(3*32+22) /* CPU topology enum extensions */
#define X86_FEATURE_TSC_RELIABLE	(3*32+23) /* TSC is known to be reliable */
#define X86_FEATURE_NONSTOP_TSC		(3*32+24) /* TSC does not stop in C states */
#define X86_FEATURE_CPUID		(3*32+25) /* CPU has CPUID instruction itself */
#define X86_FEATURE_EXTD_APICID		(3*32+26) /* Extended APICID (8 bits) */
#define X86_FEATURE_AMD_DCM		(3*32+27) /* AMD multi-node processor */
#define X86_FEATURE_APERFMPERF		(3*32+28) /* P-State hardware coordination feedback capability (APERF/MPERF MSRs) */
#define X86_FEATURE_NONSTOP_TSC_S3	(3*32+30) /* TSC doesn't stop in S3 state */
#define X86_FEATURE_TSC_KNOWN_FREQ	(3*32+31) /* TSC has known frequency */

/* Intel-defined CPU features, CPUID level 0x00000001 (ECX), word 4 */
#define X86_FEATURE_XMM3		(4*32+ 0) /* "pni" SSE-3 */
#define X86_FEATURE_PCLMULQDQ		(4*32+ 1) /* PCLMULQDQ instruction */
#define X86_FEATURE_DTES64		(4*32+ 2) /* 64-bit Debug Store */
#define X86_FEATURE_MWAIT		(4*32+ 3) /* "monitor" MONITOR/MWAIT support */
#define X86_FEATURE_DSCPL		(4*32+ 4) /* "ds_cpl" CPL-qualified (filtered) Debug Store */
#define X86_FEATURE_VMX			(4*32+ 5) /* Hardware virtualization */
#define X86_FEATURE_SMX			(4*32+ 6) /* Safer Mode eXtensions */
#define X86_FEATURE_EST			(4*32+ 7) /* Enhanced SpeedStep */
#define X86_FEATURE_TM2			(4*32+ 8) /* Thermal Monitor 2 */
#define X86_FEATURE_SSSE3		(4*32+ 9) /* Supplemental SSE-3 */
#define X86_FEATURE_CID			(4*32+10) /* Context ID */
#define X86_FEATURE_SDBG		(4*32+11) /* Silicon Debug */
#define X86_FEATURE_FMA			(4*32+12) /* Fused multiply-add */
#define X86_FEATURE_CX16		(4*32+13) /* CMPXCHG16B instruction */
#define X86_FEATURE_XTPR		(4*32+14) /* Send Task Priority Messages */
#define X86_FEATURE_PDCM		(4*32+15) /* Perf/Debug Capabilities MSR */
#define X86_FEATURE_PCID		(4*32+17) /* Process Context Identifiers */
#define X86_FEATURE_DCA			(4*32+18) /* Direct Cache Access */
#define X86_FEATURE_XMM4_1		(4*32+19) /* "sse4_1" SSE-4.1 */
#define X86_FEATURE_XMM4_2		(4*32+20) /* "sse4_2" SSE-4.2 */
#define X86_FEATURE_X2APIC		(4*32+21) /* X2APIC */
#define X86_FEATURE_MOVBE		(4*32+22) /* MOVBE instruction */
#define X86_FEATURE_POPCNT		(4*32+23) /* POPCNT instruction */
#define X86_FEATURE_TSC_DEADLINE_TIMER	(4*32+24) /* TSC deadline timer */
#define X86_FEATURE_AES			(4*32+25) /* AES instructions */
#define X86_FEATURE_XSAVE		(4*32+26) /* XSAVE/XRSTOR/XSETBV/XGETBV instructions */
#define X86_FEATURE_OSXSAVE		(4*32+27) /* "" XSAVE instruction enabled in the OS */
#define X86_FEATURE_AVX			(4*32+28) /* Advanced Vector Extensions */
#define X86_FEATURE_F16C		(4*32+29) /* 16-bit FP conversions */
#define X86_FEATURE_RDRAND		(4*32+30) /* RDRAND instruction */
#define X86_FEATURE_HYPERVISOR		(4*32+31) /* Running on a hypervisor */

/* VIA/Cyrix/Centaur-defined CPU features, CPUID level 0xC0000001, word 5 */
#define X86_FEATURE_XSTORE		(5*32+ 2) /* "rng" RNG present (xstore) */
#define X86_FEATURE_XSTORE_EN		(5*32+ 3) /* "rng_en" RNG enabled */
#define X86_FEATURE_XCRYPT		(5*32+ 6) /* "ace" on-CPU crypto (xcrypt) */
#define X86_FEATURE_XCRYPT_EN		(5*32+ 7) /* "ace_en" on-CPU crypto enabled */
#define X86_FEATURE_ACE2		(5*32+ 8) /* Advanced Cryptography Engine v2 */
#define X86_FEATURE_ACE2_EN		(5*32+ 9) /* ACE v2 enabled */
#define X86_FEATURE_PHE			(5*32+10) /* PadLock Hash Engine */
#define X86_FEATURE_PHE_EN		(5*32+11) /* PHE enabled */
#define X86_FEATURE_PMM			(5*32+12) /* PadLock Montgomery Multiplier */
#define X86_FEATURE_PMM_EN		(5*32+13) /* PMM enabled */

/* More extended AMD flags: CPUID level 0x80000001, ECX, word 6 */
#define X86_FEATURE_LAHF_LM		(6*32+ 0) /* LAHF/SAHF in long mode */
#define X86_FEATURE_CMP_LEGACY		(6*32+ 1) /* If yes HyperThreading not valid */
#define X86_FEATURE_SVM			(6*32+ 2) /* Secure Virtual Machine */
#define X86_FEATURE_EXTAPIC		(6*32+ 3) /* Extended APIC space */
#define X86_FEATURE_CR8_LEGACY		(6*32+ 4) /* CR8 in 32-bit mode */
#define X86_FEATURE_ABM			(6*32+ 5) /* Advanced bit manipulation */
#define X86_FEATURE_SSE4A		(6*32+ 6) /* SSE-4A */
#define X86_FEATURE_MISALIGNSSE		(6*32+ 7) /* Misaligned SSE mode */
#define X86_FEATURE_3DNOWPREFETCH	(6*32+ 8) /* 3DNow prefetch instructions */
#define X86_FEATURE_OSVW		(6*32+ 9) /* OS Visible Workaround */
#define X86_FEATURE_IBS			(6*32+10) /* Instruction Based Sampling */
#define X86_FEATURE_XOP			(6*32+11) /* extended AVX instructions */
#define X86_FEATURE_SKINIT		(6*32+12) /* SKINIT/STGI instructions */
#define X86_FEATURE_WDT			(6*32+13) /* Watchdog timer */
#define X86_FEATURE_LWP			(6*32+15) /* Light Weight Profiling */
#define X86_FEATURE_FMA4		(6*32+16) /* 4 operands MAC instructions */
#define X86_FEATURE_TCE			(6*32+17) /* Translation Cache Extension */
#define X86_FEATURE_NODEID_MSR		(6*32+19) /* NodeId MSR */
#define X86_FEATURE_TBM			(6*32+21) /* Trailing Bit Manipulations */
#define X86_FEATURE_TOPOEXT		(6*32+22) /* Topology extensions CPUID leafs */
#define X86_FEATURE_PERFCTR_CORE	(6*32+23) /* Core performance counter extensions */
#define X86_FEATURE_PERFCTR_NB		(6*32+24) /* NB performance counter extensions */
#define X86_FEATURE_BPEXT		(6*32+26) /* Data breakpoint extension */
#define X86_FEATURE_PTSC		(6*32+27) /* Performance time-stamp counter */
#define X86_FEATURE_PERFCTR_LLC		(6*32+28) /* Last Level Cache performance counter extensions */
#define X86_FEATURE_MWAITX		(6*32+29) /* MWAIT extension (MONITORX/MWAITX instructions) */

/* Intel-defined CPU features, CPUID level 0x00000007:0 (EBX), word 9 */
#define X86_FEATURE_FSGSBASE		(9*32+ 0) /* RDFSBASE, WRFSBASE, RDGSBASE, WRGSBASE instructions*/
#define X86_FEATURE_TSC_ADJUST		(9*32+ 1) /* TSC adjustment MSR 0x3B */
#define X86_FEATURE_BMI1		(9*32+ 3) /* 1st group bit manipulation extensions */
#define X86_FEATURE_HLE			(9*32+ 4) /* Hardware Lock Elision */
#define X86_FEATURE_AVX2		(9*32+ 5) /* AVX2 instructions */
#define X86_FEATURE_SMEP		(9*32+ 7) /* Supervisor Mode Execution Protection */
#define X86_FEATURE_BMI2		(9*32+ 8) /* 2nd group bit manipulation extensions */
#define X86_FEATURE_ERMS		(9*32+ 9) /* Enhanced REP MOVSB/STOSB instructions */
#define X86_FEATURE_INVPCID		(9*32+10) /* Invalidate Processor Context ID */
#define X86_FEATURE_RTM			(9*32+11) /* Restricted Transactional Memory */
#define X86_FEATURE_CQM			(9*32+12) /* Cache QoS Monitoring */
#define X86_FEATURE_MPX			(9*32+14) /* Memory Protection Extension */
#define X86_FEATURE_RDT_A		(9*32+15) /* Resource Director Technology Allocation */
#define X86_FEATURE_AVX512F		(9*32+16) /* AVX-512 Foundation */
#define X86_FEATURE_AVX512DQ		(9*32+17) /* AVX-512 DQ (Double/Quad granular) Instructions */
#define X86_FEATURE_RDSEED		(9*32+18) /* RDSEED instruction */
#define X86_FEATURE_ADX			(9*32+19) /* ADCX and ADOX instructions */
#define X86_FEATURE_SMAP		(9*32+20) /* Supervisor Mode Access Prevention */
#define X86_FEATURE_AVX512IFMA		(9*32+21) /* AVX-512 Integer Fused Multiply-Add instructions */
#define X86_FEATURE_CLFLUSHOPT		(9*32+23) /* CLFLUSHOPT instruction */
#define X86_FEATURE_CLWB		(9*32+24) /* CLWB instruction */
#define X86_FEATURE_INTEL_PT		(9*32+25) /* Intel Processor Trace */
#define X86_FEATURE_AVX512PF		(9*32+26) /* AVX-512 Prefetch */
#define X86_FEATURE_AVX512ER		(9*32+27) /* AVX-512 Exponential and Reciprocal */
#define X86_FEATURE_AVX512CD		(9*32+28) /* AVX-512 Conflict Detection */
#define X86_FEATURE_SHA_NI		(9*32+29) /* SHA1/SHA256 Instruction Extensions */
#define X86_FEATURE_AVX512BW		(9*32+30) /* AVX-512 BW (Byte/Word granular) Instructions */
#define X86_FEATURE_AVX512VL		(9*32+31) /* AVX-512 VL (128/256 Vector Length) Extensions */

/* Extended state features, CPUID level 0x0000000d:1 (EAX), word 10 */
#define X86_FEATURE_XSAVEOPT		(10*32+ 0) /* XSAVEOPT instruction */
#define X86_FEATURE_XSAVEC		(10*32+ 1) /* XSAVEC instruction */
#define X86_FEATURE_XGETBV1		(10*32+ 2) /* XGETBV with ECX = 1 instruction */
#define X86_FEATURE_XSAVES		(10*32+ 3) /* XSAVES/XRSTORS instructions */

/* Intel-defined CPU features, CPUID level 0x00000007:0 (ECX), word 11 */
#define X86_FEATURE_PREFETCHWT1		(11*32+ 0) /* PREFETCHWT1 Intel® Xeon PhiTM only */
#define X86_FEATURE_AVX512VBMI		(11*32+ 1) /* AVX512 Vector Bit Manipulation instructions*/
#define X86_FEATURE_UMIP		(11*32+ 2) /* User Mode Instruction Protection */
#define X86_FEATURE_PKU			(11*32+ 3) /* Protection Keys for Userspace */
#define X86_FEATURE_OSPKE		(11*32+ 4) /* OS Protection Keys Enable */
#define X86_FEATURE_AVX512_VBMI2	(11*32+ 6) /* Additional AVX512 Vector Bit Manipulation Instructions */
#define X86_FEATURE_GFNI		(11*32+ 8) /* Galois Field New Instructions */
#define X86_FEATURE_VAES		(11*32+ 9) /* Vector AES */
#define X86_FEATURE_VPCLMULQDQ		(11*32+10) /* Carry-Less Multiplication Double Quadword */
#define X86_FEATURE_AVX512_VNNI		(11*32+11) /* Vector Neural Network Instructions */
#define X86_FEATURE_AVX512_BITALG	(11*32+12) /* Support for VPOPCNT[B,W] and VPSHUF-BITQMB instructions */
#define X86_FEATURE_TME			(11*32+13) /* Intel Total Memory Encryption */
#define X86_FEATURE_AVX512_VPOPCNTDQ	(11*32+14) /* POPCNT for vectors of DW/QW */
#define X86_FEATURE_LA57		(11*32+16) /* 5-level page tables */
#define X86_FEATURE_RDPID		(11*32+22) /* RDPID instruction */
#define X86_FEATURE_CLDEMOTE		(11*32+25) /* CLDEMOTE instruction */

/* Intel-defined CPU QoS Sub-leaf, CPUID level 0x0000000F:1 (EDX), word 12 */
#define X86_FEATURE_CQM_OCCUP_LLC	(12*32+ 0) /* LLC occupancy monitoring */
#define X86_FEATURE_CQM_MBM_TOTAL	(12*32+ 1) /* LLC Total MBM monitoring */
#define X86_FEATURE_CQM_MBM_LOCAL	(12*32+ 2) /* LLC Local MBM monitoring */

/* AMD-defined CPU features, CPUID level 0x80000008 (EBX), word 13 */
#define X86_FEATURE_CLZERO		(13*32+ 0) /* CLZERO instruction */
#define X86_FEATURE_IRPERF		(13*32+ 1) /* Instructions Retired Count */
#define X86_FEATURE_XSAVEERPTR		(13*32+ 2) /* Always save/restore FP error pointers */
#define X86_FEATURE_IBPB		(13*32+12) /* Indirect Branch Prediction Barrier */
#define X86_FEATURE_IBRS		(13*32+14) /* Indirect Branch Restricted Speculation */
#define X86_FEATURE_STIBP		(13*32+15) /* Single Thread Indirect Branch Predictors */

/* Thermal and Power Management Leaf, CPUID level 0x00000006 (EAX), word 14 */
#define X86_FEATURE_DTHERM		(14*32+ 0) /* Digital Thermal Sensor */
#define X86_FEATURE_IDA			(14*32+ 1) /* Intel Dynamic Acceleration */
#define X86_FEATURE_ARAT		(14*32+ 2) /* Always Running APIC Timer */
#define X86_FEATURE_PLN			(14*32+ 4) /* Intel Power Limit Notification */
#define X86_FEATURE_PTS			(14*32+ 6) /* Intel Package Thermal Status */
#define X86_FEATURE_HWP			(14*32+ 7) /* Intel Hardware P-states */
#define X86_FEATURE_HWP_NOTIFY		(14*32+ 8) /* HWP Notification */
#define X86_FEATURE_HWP_ACT_WINDOW	(14*32+ 9) /* HWP Activity Window */
#define X86_FEATURE_HWP_EPP		(14*32+10) /* HWP Energy Perf. Preference */
#define X86_FEATURE_HWP_PKG_REQ		(14*32+11) /* HWP Package Level Request */
#define X86_FEATURE_HDC			(14*32+13) /* HDC base registers present */

/* AMD SVM Feature Identification, CPUID level 0x8000000a (EDX), word 15 */
#define X86_FEATURE_NPT			(15*32+ 0) /* Nested Page Table support */
#define X86_FEATURE_LBRV		(15*32+ 1) /* LBR Virtualization support */
#define X86_FEATURE_SVML		(15*32+ 2) /* "svm_lock" SVM locking MSR */
#define X86_FEATURE_NRIPS		(15*32+ 3) /* "nrip_save" SVM next_rip save */
#define X86_FEATURE_TSCRATEMSR		(15*32+ 4) /* "tsc_scale" TSC scaling support */
#define X86_FEATURE_VMCBCLEAN		(15*32+ 5) /* "vmcb_clean" VMCB clean bits support */
#define X86_FEATURE_FLUSHBYASID		(15*32+ 6) /* flush-by-ASID support */
#define X86_FEATURE_DECODEASSISTS	(15*32+ 7) /* Decode Assists support */
#define X86_FEATURE_PAUSEFILTER		(15*32+10) /* filtered pause intercept */
#define X86_FEATURE_PFTHRESHOLD		(15*32+12) /* pause filter threshold */
#define X86_FEATURE_AVIC		(15*32+13) /* Virtual Interrupt Controller */
#define X86_FEATURE_V_VMSAVE_VMLOAD	(15*32+15) /* Virtual VMSAVE VMLOAD */
#define X86_FEATURE_VGIF		(15*32+16) /* Virtual GIF */

/* Intel-defined CPU QoS Sub-leaf, CPUID level 0x0000000F:0 (EDX), word 16 */
#define X86_FEATURE_CQM_LLC		(16*32+ 1) /* LLC QoS if 1 */

/* AMD-defined CPU features, CPUID level 0x80000007 (EBX), word 17 */
#define X86_FEATURE_OVERFLOW_RECOV	(17*32+ 0) /* MCA overflow recovery support */
#define X86_FEATURE_SUCCOR		(17*32+ 1) /* Uncorrectable error containment and recovery */
#define X86_FEATURE_SMCA		(17*32+ 3) /* Scalable MCA */

/* Intel-defined CPU features, CPUID level 0x00000007:0 (EDX), word 18 */
#define X86_FEATURE_AVX512_4VNNIW	(18*32+ 2) /* AVX-512 Neural Network Instructions */
#define X86_FEATURE_AVX512_4FMAPS	(18*32+ 3) /* AVX-512 Multiply Accumulation Single precision */
#define X86_FEATURE_PCONFIG		(18*32+18) /* Intel PCONFIG */
#define X86_FEATURE_SPEC_CTRL		(18*32+26) /* "" Speculation Control (IBRS + IBPB) */
#define X86_FEATURE_INTEL_STIBP		(18*32+27) /* "" Single Thread Indirect Branch Predictors */
#define X86_FEATURE_ARCH_CAPABILITIES	(18*32+29) /* IA32_ARCH_CAPABILITIES MSR (Intel) */
#define X86_FEATURE_SPEC_CTRL_SSBD	(18*32+31) /* "" Speculative Store Bypass Disable */

enum {
	X86_VENDOR_INTEL	= 0,
	X86_VENDOR_AMD		= 1,

	X86_VENDOR_MAX
};

#define FP_MIN_ALIGN_BYTES		64
#define FXSAVE_ALIGN_BYTES		16

#define FP_XSTATE_MAGIC1		0x46505853U
#define FP_XSTATE_MAGIC2		0x46505845U
#define FP_XSTATE_MAGIC2_SIZE		sizeof(FP_XSTATE_MAGIC2)

#define XSTATE_FP			0x1
#define XSTATE_SSE			0x2
#define XSTATE_YMM			0x4

#define FXSAVE_SIZE			512
#define XSAVE_SIZE			4096

#define XSAVE_HDR_SIZE			64
#define XSAVE_HDR_OFFSET		FXSAVE_SIZE

#define XSAVE_YMM_SIZE			256
#define XSAVE_YMM_OFFSET		(XSAVE_HDR_SIZE + XSAVE_HDR_OFFSET)

/*
 * List of XSAVE features Linux knows about:
 */
enum xfeature {
	XFEATURE_FP,
	XFEATURE_SSE,
	/*
	 * Values above here are "legacy states".
	 * Those below are "extended states".
	 */
	XFEATURE_YMM,
	XFEATURE_BNDREGS,
	XFEATURE_BNDCSR,
	XFEATURE_OPMASK,
	XFEATURE_ZMM_Hi256,
	XFEATURE_Hi16_ZMM,
	XFEATURE_PT,
	XFEATURE_PKRU,
	XFEATURE_HDC,

	XFEATURE_MAX,
};

#define XSTATE_CPUID			0x0000000d

#define XFEATURE_MASK_FP		(1 << XFEATURE_FP)
#define XFEATURE_MASK_SSE		(1 << XFEATURE_SSE)
#define XFEATURE_MASK_YMM		(1 << XFEATURE_YMM)
#define XFEATURE_MASK_BNDREGS		(1 << XFEATURE_BNDREGS)
#define XFEATURE_MASK_BNDCSR		(1 << XFEATURE_BNDCSR)
#define XFEATURE_MASK_OPMASK		(1 << XFEATURE_OPMASK)
#define XFEATURE_MASK_ZMM_Hi256		(1 << XFEATURE_ZMM_Hi256)
#define XFEATURE_MASK_Hi16_ZMM		(1 << XFEATURE_Hi16_ZMM)
#define XFEATURE_MASK_PT		(1 << XFEATURE_PT)
#define XFEATURE_MASK_PKRU		(1 << XFEATURE_PKRU)
#define XFEATURE_MASK_HDC		(1 << XFEATURE_HDC)
#define XFEATURE_MASK_MAX		(1 << XFEATURE_MAX)

#define XFEATURE_MASK_FPSSE		(XFEATURE_MASK_FP | XFEATURE_MASK_SSE)
#define XFEATURE_MASK_AVX512		(XFEATURE_MASK_OPMASK | XFEATURE_MASK_ZMM_Hi256 | XFEATURE_MASK_Hi16_ZMM)

#define FIRST_EXTENDED_XFEATURE		XFEATURE_YMM

/* Supervisor features */
#define XFEATURE_MASK_SUPERVISOR	(XFEATURE_MASK_PT | XFEATURE_MASK_HDC)

/* All currently supported features */
#define XCNTXT_MASK							  \
	(XFEATURE_MASK_FP		| XFEATURE_MASK_SSE		| \
	 XFEATURE_MASK_YMM		| XFEATURE_MASK_OPMASK		| \
	 XFEATURE_MASK_ZMM_Hi256	| XFEATURE_MASK_Hi16_ZMM	| \
	 XFEATURE_MASK_PKRU		| XFEATURE_MASK_BNDREGS		| \
	 XFEATURE_MASK_BNDCSR)

extern short xsave_cpuid_features[];
extern const char * const xfeature_names[];

struct fpx_sw_bytes {
	uint32_t			magic1;
	uint32_t			extended_size;
	uint64_t			xstate_bv;
	uint32_t			xstate_size;
	uint32_t			padding[7];
};

struct i387_fxsave_struct {
	uint16_t			cwd; /* Control Word			*/
	uint16_t			swd; /* Status Word			*/
	uint16_t			twd; /* Tag Word			*/
	uint16_t			fop; /* Last Instruction Opcode		*/
	union {
		struct {
			uint64_t	rip; /* Instruction Pointer		*/
			uint64_t	rdp; /* Data Pointer			*/
		};
		struct {
			uint32_t	fip; /* FPU IP Offset			*/
			uint32_t	fcs; /* FPU IP Selector			*/
			uint32_t	foo; /* FPU Operand Offset		*/
			uint32_t	fos; /* FPU Operand Selector		*/
		};
	};
	uint32_t			mxcsr;		/* MXCSR Register State */
	uint32_t			mxcsr_mask;	/* MXCSR Mask		*/

	/* 8*16 bytes for each FP-reg = 128 bytes				*/
	uint32_t			st_space[32];

	/* 16*16 bytes for each XMM-reg = 256 bytes				*/
	uint32_t			xmm_space[64];

	uint32_t			padding[12];

	union {
		uint32_t		padding1[12];
		uint32_t		sw_reserved[12];
	};

} __aligned(FXSAVE_ALIGN_BYTES);

struct xsave_hdr_struct {
	uint64_t			xstate_bv;
	uint64_t			xcomp_bv;
	uint64_t			reserved[6];
} __packed;

/*
 * xstate_header.xcomp_bv[63] indicates that the extended_state_area
 * is in compacted format.
 */
#define XCOMP_BV_COMPACTED_FORMAT	((uint64_t)1 << 63)

/*
 * State component 2:
 *
 * There are 16x 256-bit AVX registers named YMM0-YMM15.
 * The low 128 bits are aliased to the 16 SSE registers (XMM0-XMM15)
 * and are stored in 'struct fxregs_state::xmm_space[]' in the
 * "legacy" area.
 *
 * The high 128 bits are stored here.
 */
struct ymmh_struct {
	uint32_t                        ymmh_space[64];
} __packed;

/* Intel MPX support: */

struct mpx_bndreg {
	uint64_t			lower_bound;
	uint64_t			upper_bound;
} __packed;

/*
 * State component 3 is used for the 4 128-bit bounds registers
 */
struct mpx_bndreg_state {
	struct mpx_bndreg		bndreg[4];
} __packed;

/*
 * State component 4 is used for the 64-bit user-mode MPX
 * configuration register BNDCFGU and the 64-bit MPX status
 * register BNDSTATUS.  We call the pair "BNDCSR".
 */
struct mpx_bndcsr {
	uint64_t			bndcfgu;
	uint64_t			bndstatus;
} __packed;

/*
 * The BNDCSR state is padded out to be 64-bytes in size.
 */
struct mpx_bndcsr_state {
	union {
		struct mpx_bndcsr	bndcsr;
		uint8_t			pad_to_64_bytes[64];
	};
} __packed;

/* AVX-512 Components: */

/*
 * State component 5 is used for the 8 64-bit opmask registers
 * k0-k7 (opmask state).
 */
struct avx_512_opmask_state {
	uint64_t			opmask_reg[8];
} __packed;

/*
 * State component 6 is used for the upper 256 bits of the
 * registers ZMM0-ZMM15. These 16 256-bit values are denoted
 * ZMM0_H-ZMM15_H (ZMM_Hi256 state).
 */
struct avx_512_zmm_uppers_state {
	uint64_t			zmm_upper[16 * 4];
} __packed;

/*
 * State component 7 is used for the 16 512-bit registers
 * ZMM16-ZMM31 (Hi16_ZMM state).
 */
struct avx_512_hi16_state {
	uint64_t			hi16_zmm[16 * 8];
} __packed;

/*
 * State component 9: 32-bit PKRU register.  The state is
 * 8 bytes long but only 4 bytes is used currently.
 */
struct pkru_state {
	uint32_t			pkru;
	uint32_t			pad;
} __packed;

/*
 * This is our most modern FPU state format, as saved by the XSAVE
 * and restored by the XRSTOR instructions.
 *
 * It consists of a legacy fxregs portion, an xstate header and
 * subsequent areas as defined by the xstate header. Not all CPUs
 * support all the extensions, so the size of the extended area
 * can vary quite a bit between CPUs.
 *
 *
 * One page should be enough for the whole xsave state.
 */
#define EXTENDED_STATE_AREA_SIZE	(4096 - sizeof(struct i387_fxsave_struct) - sizeof(struct xsave_hdr_struct))

/*
 * cpu requires it to be 64 byte aligned
 */
struct xsave_struct {
	struct i387_fxsave_struct	i387;
	struct xsave_hdr_struct		xsave_hdr;
	union {
		/*
		 * This ymmh is unndeed, for
		 * backward compatibility.
		 */
		struct ymmh_struct	ymmh;
		uint8_t			extended_state_area[EXTENDED_STATE_AREA_SIZE];
	};
} __aligned(FP_MIN_ALIGN_BYTES) __packed;

typedef struct cpuinfo_x86 {
	/* cpu context */
	uint8_t			x86_family;
	uint8_t			x86_vendor;
	uint8_t			x86_model;
	uint8_t			x86_mask;
	uint32_t		x86_capability[NCAPINTS];
	uint32_t		x86_power;
	uint32_t		extended_cpuid_level;
	uint32_t		cpuid_level;
	uint8_t			x86_vendor_id[16];
	uint8_t			x86_model_id[64];

	/* fpu context */
	uint64_t		xfeatures_mask;
	uint32_t		xsave_size_max;
	uint32_t		xsave_size;
	uint32_t		xstate_offsets[XFEATURE_MAX];
	uint32_t		xstate_sizes[XFEATURE_MAX];

	uint32_t		xsaves_size;
	uint32_t		xstate_comp_offsets[XFEATURE_MAX];
	uint32_t		xstate_comp_sizes[XFEATURE_MAX];
} cpuinfo_x86_t;

extern int test_fpu_cap(cpuinfo_x86_t *c, unsigned int feature);
extern int test_cpu_cap(cpuinfo_x86_t *c, unsigned int feature);
extern void clear_cpu_cap(cpuinfo_x86_t *c, unsigned int feature);
extern void set_cpu_cap(cpuinfo_x86_t *c, unsigned int feature);

/*
 * VZ specific cpuid VE masking: the kernel provides
 * the following entry /proc/vz/cpuid_override which
 * carries text representation of cpuid masking which
 * which works via cpuid faulting inside kernel in the
 * next format:
 *
 *	op     count   eax    ebx    ecx    edx
 * 	0x%08x 0x%08x: 0x%08x 0x%08x 0x%08x 0x%08x
 *
 * the @count is optional.
 */

typedef struct {
	unsigned int	op;
	unsigned int	count;
	bool		has_count;
	unsigned int	eax;
	unsigned int	ebx;
	unsigned int	ecx;
	unsigned int	edx;
} vz_cpuid_override_entry_t;

extern vz_cpuid_override_entry_t *vz_cpuid_override_entries;
extern unsigned int nr_vz_cpuid_override_entries;

#define VZ_CPUID_OVERRIDE_PATH_DEFAULT "/proc/vz/cpuid_override"

static inline void native_cpuid(unsigned int *eax, unsigned int *ebx,
				unsigned int *ecx, unsigned int *edx)
{
	pr_debug("native_cpuid in : eax 0x%08x ebx 0x%08x ecx 0x%08x edx 0x%08x\n",
		 *eax, *ebx, *ecx, *edx);

	/* ecx is often an input as well as an output. */
	asm volatile("cpuid"
	    : "=a" (*eax),
	      "=b" (*ebx),
	      "=c" (*ecx),
	      "=d" (*edx)
	    : "0" (*eax), "2" (*ecx)
	    : "memory");

	pr_debug("native_cpuid out: eax 0x%08x ebx 0x%08x ecx 0x%08x edx 0x%08x\n",
		 *eax, *ebx, *ecx, *edx);
}

static inline void cpuid(unsigned int op,
			 unsigned int *eax, unsigned int *ebx,
			 unsigned int *ecx, unsigned int *edx)
{
	*eax = op;
	*ecx = 0;
	native_cpuid(eax, ebx, ecx, edx);
}

static inline void cpuid_count(unsigned int op, int count,
			       unsigned int *eax, unsigned int *ebx,
			       unsigned int *ecx, unsigned int *edx)
{
	*eax = op;
	*ecx = count;
	native_cpuid(eax, ebx, ecx, edx);
}

static inline unsigned int cpuid_eax(unsigned int op)
{
	unsigned int eax, ebx, ecx, edx;

	cpuid(op, &eax, &ebx, &ecx, &edx);
	return eax;
}

static inline unsigned int cpuid_ebx(unsigned int op)
{
	unsigned int eax, ebx, ecx, edx;

	cpuid(op, &eax, &ebx, &ecx, &edx);
	return ebx;
}

static inline unsigned int cpuid_ecx(unsigned int op)
{
	unsigned int eax, ebx, ecx, edx;

	cpuid(op, &eax, &ebx, &ecx, &edx);
	return ecx;
}

static inline unsigned int cpuid_edx(unsigned int op)
{
	unsigned int eax, ebx, ecx, edx;

	cpuid(op, &eax, &ebx, &ecx, &edx);
	return edx;
}

extern int vz_cpu_parse_cpuid_override(char *path);
extern int fetch_cpuid(cpuinfo_x86_t *c);

#endif /* VZCPUIDCTL_CPU_H__ */
