#include <string.h>
#include <stdbool.h>

#include <stdio.h>
#include <stdlib.h>

#include "bitops.h"
#include "cpu.h"
#include "log.h"

#undef	LOG_PREFIX
#define LOG_PREFIX "fpu: "

/*
 * Although we spell it out in here, the Processor Trace
 * xfeature is completely unused. We use other mechanisms
 * to save/restore PT state in Linux.
 */

static const char * const xfeature_names[] = {
	"x87 floating point registers"	,
	"SSE registers"			,
	"AVX registers"			,
	"MPX bounds registers"		,
	"MPX CSR"			,
	"AVX-512 opmask"		,
	"AVX-512 Hi256"			,
	"AVX-512 ZMM_Hi256"		,
	"Processor Trace"		,
	"Protection Keys User registers",
	"Hardware Duty Cycling"		,
};

static short xsave_cpuid_features[] = {
	X86_FEATURE_FPU,
	X86_FEATURE_XMM,
	X86_FEATURE_AVX,
	X86_FEATURE_MPX,
	X86_FEATURE_MPX,
	X86_FEATURE_AVX512F,
	X86_FEATURE_AVX512F,
	X86_FEATURE_AVX512F,
	X86_FEATURE_INTEL_PT,
	X86_FEATURE_PKU,
	X86_FEATURE_HDC,
};

void show_fpu_info(struct cpuinfo_x86 *c)
{
	size_t i;

	pr_info("xfeatures_mask 0x%llx xsave_size %u xsave_size_max %u xsaves_size %u\n",
		(unsigned long long)c->xfeatures_mask,
		c->xsave_size, c->xsave_size_max, c->xsaves_size);

	if (!pr_quelled(LOG_INFO)) {
		for (i = 0; i < ARRAY_SIZE(c->xstate_offsets); i++) {
			if (!(c->xfeatures_mask & (1UL << i)))
				continue;
			pr_info("%-32s xstate_offsets %6d / %-6d xstate_sizes %6d / %-6d\n",
				xfeature_names[i], c->xstate_offsets[i], c->xstate_comp_offsets[i],
				c->xstate_sizes[i], c->xstate_comp_sizes[i]);
		}
	}
}

int validate_fpu_caps(struct cpuinfo_x86 *c)
{
	if (!test_cpu_cap(c, X86_FEATURE_FPU)) {
		pr_err("No FPU detected\n");
		return -EINVAL;
	}

	if (!test_cpu_cap(c, X86_FEATURE_XSAVE)) {
		pr_err("XSAVE is not supported\n");
		return -EINVAL;
	}

	return 0;
}

int validate_fpu(struct cpuinfo_x86 *c)
{
	if (validate_fpu_caps(c))
		return -EINVAL;

	/*
	 * We've a bug in CRIU, XFEATURE_MASK_SUPERVISOR has been
	 * using XFEATURE_HDC instead of XFEATURE_MASK_HDC, in
	 * result bits XFEATURE_MASK_SSE and XFEATURE_MASK_BNDREGS
	 * got occasionally cleared.
	 */
	if (!(c->xfeatures_mask & XFEATURE_MASK_SSE)) {
		pr_debug("Fix sse missing bit bug\n");
		c->xfeatures_mask |= XFEATURE_MASK_SSE;
	}

	if ((c->xfeatures_mask & XFEATURE_MASK_FPSSE) != XFEATURE_MASK_FPSSE) {
		/*
		 * This indicates that something really unexpected happened
		 * with the enumeration.
		 */
		pr_err("FP/SSE not present amongst the CPU's xstate features: 0x%llx (0x%llx 0x%llx)\n",
		       (unsigned long long)c->xfeatures_mask,
		       (unsigned long long)(c->xfeatures_mask & XFEATURE_MASK_FPSSE),
		       (unsigned long long)XFEATURE_MASK_FPSSE);
		return -EINVAL;
	}

	return 0;
}

void init_fpuid(struct cpuinfo_x86 *c)
{
	/* Must be called after init_cpuid */
	memset(c->xstate_offsets,	0xff, sizeof(c->xstate_offsets));
	memset(c->xstate_sizes,		0xff, sizeof(c->xstate_sizes));
	memset(c->xstate_comp_offsets,	0xff, sizeof(c->xstate_comp_offsets));
	memset(c->xstate_comp_sizes,	0xff, sizeof(c->xstate_comp_sizes));

	/*
	 * The FP xstates and SSE xstates are legacy states. They are always
	 * in the fixed offsets in the xsave area in either compacted form
	 * or standard form.
	 */
	c->xstate_offsets[0]		= 0;
	c->xstate_sizes[0]		= offsetof(struct i387_fxsave_struct, xmm_space);
	c->xstate_offsets[1]		= c->xstate_sizes[0];
	c->xstate_sizes[1]		= FIELD_SIZEOF(struct i387_fxsave_struct, xmm_space);

	/*
	 * Compressed offsets/sizes for legacy states are fixed.
	 */
	c->xstate_comp_offsets[0]	= 0;
	c->xstate_comp_sizes[0]		= offsetof(struct i387_fxsave_struct, xmm_space);
	c->xstate_comp_offsets[1]	= c->xstate_comp_sizes[0];
	c->xstate_comp_sizes[1]		= FIELD_SIZEOF(struct i387_fxsave_struct, xmm_space);

}

int fetch_fpuid(struct cpuinfo_x86 *c)
{
	x86_cpuid_call_trace_t *ct = &c->cpuid_call_trace;
	const cpuid_ops_t *cpuid_ops = cpuid_get_ops();
	unsigned int last_good_offset;
	uint32_t eax, ebx, ecx, edx;
	size_t i;

	BUILD_BUG_ON(ARRAY_SIZE(xsave_cpuid_features) !=
		     ARRAY_SIZE(xfeature_names));

	if (validate_fpu_caps(c))
		return -1;

	init_fpuid(c);

	cpuid_ops->cpuid_count(XSTATE_CPUID, 0, &eax, &ebx, &ecx, &edx, ct);
	c->xfeatures_mask = eax + ((uint64_t)edx << 32);

	if ((c->xfeatures_mask & XFEATURE_MASK_FPSSE) != XFEATURE_MASK_FPSSE) {
		/*
		 * This indicates that something really unexpected happened
		 * with the enumeration.
		 */
		pr_err("FP/SSE not present amongst the CPU's xstate features: 0x%llx\n",
		       (unsigned long long)c->xfeatures_mask);
		return -1;
	}

	/*
	 * Clear XSAVE features that are disabled in the normal CPUID.
	 */
	for (i = 0; i < ARRAY_SIZE(xsave_cpuid_features); i++) {
		if (!test_cpu_cap(c, xsave_cpuid_features[i]))
			c->xfeatures_mask &= ~(1 << i);
	}

	c->xfeatures_mask &= XCNTXT_MASK;
	c->xfeatures_mask &= ~XFEATURE_MASK_SUPERVISOR;

	/*
	 * xsaves is not enabled in userspace, so
	 * xsaves is mostly for debug purpose.
	 */
	cpuid_ops->cpuid_count(XSTATE_CPUID, 0, &eax, &ebx, &ecx, &edx, ct);
	c->xsave_size = ebx;
	c->xsave_size_max = ecx;

	cpuid_ops->cpuid_count(XSTATE_CPUID, 1, &eax, &ebx, &ecx, &edx, ct);
	c->xsaves_size = ebx;

	if (c->xsave_size_max > sizeof(struct xsave_struct))
		pr_warn_once("max xsave frame exceed xsave_struct (%u %u)\n",
			     c->xsave_size_max, (unsigned)sizeof(struct xsave_struct));

	/* start at the beginnning of the "extended state" */
	last_good_offset = offsetof(struct xsave_struct, extended_state_area);

	for (i = FIRST_EXTENDED_XFEATURE; i < XFEATURE_MAX; i++) {
		if (!(c->xfeatures_mask & (1UL << i)))
			continue;

		/*
		 * If an xfeature is supervisor state, the offset
		 * in EBX is invalid. We leave it to -1.
		 *
		 * SDM says: If state component 'i' is a user state component,
		 * ECX[0] return 0; if state component i is a supervisor
		 * state component, ECX[0] returns 1.
		 */
		cpuid_ops->cpuid_count(XSTATE_CPUID, i, &eax, &ebx, &ecx, &edx, ct);
		if (!(ecx & 1))
			c->xstate_offsets[i] = ebx;

		c->xstate_sizes[i] = eax;

		/*
		 * In our xstate size checks, we assume that the
		 * highest-numbered xstate feature has the
		 * highest offset in the buffer.  Ensure it does.
		 */
		if (last_good_offset > c->xstate_offsets[i])
			pr_warn_once("misordered xstate %d %d\n",
				     last_good_offset, c->xstate_offsets[i]);

		last_good_offset = c->xstate_offsets[i];
	}

	BUILD_BUG_ON(sizeof(c->xstate_offsets) != sizeof(c->xstate_sizes));
	BUILD_BUG_ON(sizeof(c->xstate_comp_offsets) != sizeof(c->xstate_comp_sizes));

	if (!test_cpu_cap(c, X86_FEATURE_XSAVES)) {
		for (i = FIRST_EXTENDED_XFEATURE; i < XFEATURE_MAX; i++) {
			if ((c->xfeatures_mask & (1UL << i))) {
				c->xstate_comp_offsets[i] = c->xstate_offsets[i];
				c->xstate_comp_sizes[i] = c->xstate_sizes[i];
			}
		}
	} else {
		c->xstate_comp_offsets[FIRST_EXTENDED_XFEATURE] =
			FXSAVE_SIZE + XSAVE_HDR_SIZE;

		for (i = FIRST_EXTENDED_XFEATURE; i < XFEATURE_MAX; i++) {
			if ((c->xfeatures_mask & (1UL << i)))
				c->xstate_comp_sizes[i] = c->xstate_sizes[i];
			else
				c->xstate_comp_sizes[i] = 0;

			if (i > FIRST_EXTENDED_XFEATURE) {
				c->xstate_comp_offsets[i] = c->xstate_comp_offsets[i-1]
					+ c->xstate_comp_sizes[i-1];

				/*
				 * The value returned by ECX[1] indicates the alignment
				 * of state component 'i' when the compacted format
				 * of the extended region of an XSAVE area is used:
				 */
				cpuid_ops->cpuid_count(XSTATE_CPUID, i, &eax, &ebx, &ecx, &edx, ct);
				if (ecx & 2)
					c->xstate_comp_offsets[i] = ALIGN(c->xstate_comp_offsets[i], 64);
			}
		}
	}

	show_fpu_info(c);
	return 0;
}
