#include <string.h>
#include <stdbool.h>

#include <stdio.h>
#include <stdlib.h>

#include "bitops.h"
#include "cpu.h"
#include "log.h"

#undef	LOG_PREFIX
#define LOG_PREFIX "cpu: "

vz_cpuid_override_entry_t *vz_cpuid_override_entries;
unsigned int nr_vz_cpuid_override_entries;

int vz_cpu_parse_cpuid_override(char *path)
{
	int ret = -1;
	char s[256];
	FILE *f;

	if (!path) {
		pr_err("No path provided\n");
		return -1;
	}

	pr_debug("Parsing %s\n", path);

	f = fopen(path, "r");
	if (!f) {
		pr_info("Can't access %s, ignoring\n", path);
		return 0;
	}

	while (fgets(s, sizeof(s), f)) {
		static vz_cpuid_override_entry_t *new;

		vz_cpuid_override_entry_t e;

		if (sscanf(s, "%x %x: %x %x %x %x",
			   &e.op, &e.count, &e.eax,
			   &e.ebx, &e.ecx, &e.edx) == 6) {
			e.has_count = true;
		} else if (sscanf(s, "%x: %x %x %x %x",
				&e.op, &e.eax, &e.ebx,
				&e.ecx, &e.edx) == 5) {
			e.count = 0;
			e.has_count = false;
		} else {
			pr_warn("Unexpected format in %s (%s)\n", path, s);
			break;
		}

		new = realloc(vz_cpuid_override_entries,
			      (nr_vz_cpuid_override_entries + 1) * sizeof(e));
		if (!new) {
			pr_err("No memory for cpuid override (%d entries)\n",
			       nr_vz_cpuid_override_entries + 1);
			goto out;
		}
		vz_cpuid_override_entries = new;

		pr_debug("Got cpuid override: %x %x: %x %x %x %x\n",
			   e.op, e.count, e.eax, e.ebx, e.ecx, e.edx);

		vz_cpuid_override_entries[nr_vz_cpuid_override_entries++] = e;
	}

	ret = 0;
out:
	fclose(f);
	return ret;
}

static vz_cpuid_override_entry_t *
vz_cpuid_override_lookup(unsigned int op, bool has_count, unsigned int count)
{
	size_t i;

	for (i = 0; i < nr_vz_cpuid_override_entries; i++) {
		if (vz_cpuid_override_entries[i].op != op ||
		    vz_cpuid_override_entries[i].has_count != has_count ||
		    count != vz_cpuid_override_entries[i].count)
			continue;
		return &vz_cpuid_override_entries[i];
	}

	return NULL;
}

static inline void vz_cpuid(unsigned int op,
			    unsigned int *eax, unsigned int *ebx,
			    unsigned int *ecx, unsigned int *edx)
{
	vz_cpuid_override_entry_t *e;

	e = vz_cpuid_override_lookup(op, false, 0);
	if (e) {
		*eax = e->eax;
		*ebx = e->ebx;
		*ecx = e->ecx;
		*edx = e->edx;
		pr_debug("vz_cpuid: op 0x%08x: eax 0x%08x ebx 0x%08x ecx 0x%08x edx 0x%08x\n",
			 op, *eax, *ebx, *ecx, *edx);
	} else
		cpuid(op, eax, ebx, ecx, edx);
}

static inline void vz_cpuid_count(unsigned int op, int count,
				  unsigned int *eax, unsigned int *ebx,
				  unsigned int *ecx, unsigned int *edx)
{
	vz_cpuid_override_entry_t *e;

	e = vz_cpuid_override_lookup(op, true, count);
	if (e) {
		*eax = e->eax;
		*ebx = e->ebx;
		*ecx = e->ecx;
		*edx = e->edx;
		pr_debug("vz_cpuid: op 0x%08x count 0x%08x: eax 0x%08x ebx 0x%08x ecx 0x%08x edx 0x%08x\n",
			 op, count, *eax, *ebx, *ecx, *edx);
	 } else
		 cpuid_count(op, count, eax, ebx, ecx, edx);
}

static inline unsigned int vz_cpuid_eax(unsigned int op)
{
	unsigned int eax = 0, ebx = 0, ecx = 0, edx = 0;
	vz_cpuid(op, &eax, &ebx, &ecx, &edx);
	return eax;
}

static inline unsigned int vz_cpuid_ebx(unsigned int op)
{
	unsigned int eax = 0, ebx = 0, ecx = 0, edx = 0;
	vz_cpuid(op, &eax, &ebx, &ecx, &edx);
	return ebx;
}

static inline unsigned int vz_cpuid_ecx(unsigned int op)
{
	unsigned int eax = 0, ebx = 0, ecx = 0, edx = 0;
	vz_cpuid(op, &eax, &ebx, &ecx, &edx);
	return ecx;
}

static inline unsigned int vz_cpuid_edx(unsigned int op)
{
	unsigned int eax = 0, ebx = 0, ecx = 0, edx = 0;
	vz_cpuid(op, &eax, &ebx, &ecx, &edx);
	return edx;
}

/*
 * Although we spell it out in here, the Processor Trace
 * xfeature is completely unused. We use other mechanisms
 * to save/restore PT state in Linux.
 */

const char * const xfeature_names[] = {
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

short xsave_cpuid_features[] = {
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

static int fetch_fpuid(cpuinfo_x86_t *c)
{
	unsigned int last_good_offset;
	uint32_t eax, ebx, ecx, edx;
	size_t i;

#define __zap_regs() eax = ebx = ecx = edx = 0

	BUILD_BUG_ON(ARRAY_SIZE(xsave_cpuid_features) !=
		     ARRAY_SIZE(xfeature_names));

	if (!test_cpu_cap(c, X86_FEATURE_FPU)) {
		pr_err("fpu: No FPU detected\n");
		return -1;
	}

	if (!test_cpu_cap(c, X86_FEATURE_XSAVE)) {
		pr_info("fpu: x87 FPU will use %s\n",
			test_cpu_cap(c, X86_FEATURE_FXSR) ?
			"FXSAVE" : "FSAVE");
		return 0;
	}

	__zap_regs();
	vz_cpuid_count(XSTATE_CPUID, 0, &eax, &ebx, &ecx, &edx);
	c->xfeatures_mask = eax + ((uint64_t)edx << 32);

	if ((c->xfeatures_mask & XFEATURE_MASK_FPSSE) != XFEATURE_MASK_FPSSE) {
		/*
		 * This indicates that something really unexpected happened
		 * with the enumeration.
		 */
		pr_err("fpu: FP/SSE not present amongst the CPU's xstate features: 0x%llx\n",
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
	__zap_regs();
	vz_cpuid_count(XSTATE_CPUID, 0, &eax, &ebx, &ecx, &edx);
	c->xsave_size = ebx;
	c->xsave_size_max = ecx;

	__zap_regs();
	vz_cpuid_count(XSTATE_CPUID, 1, &eax, &ebx, &ecx, &edx);
	c->xsaves_size = ebx;

	pr_debug("fpu: xfeatures_mask 0x%llx xsave_size %u xsave_size_max %u xsaves_size %u\n",
		 (unsigned long long)c->xfeatures_mask,
		 c->xsave_size, c->xsave_size_max, c->xsaves_size);

	if (c->xsave_size_max > sizeof(struct xsave_struct))
		pr_warn_once("fpu: max xsave frame exceed xsave_struct (%u %u)\n",
			     c->xsave_size_max, (unsigned)sizeof(struct xsave_struct));

	memset(c->xstate_offsets, 0xff, sizeof(c->xstate_offsets));
	memset(c->xstate_sizes, 0xff, sizeof(c->xstate_sizes));
	memset(c->xstate_comp_offsets, 0xff, sizeof(c->xstate_comp_offsets));
	memset(c->xstate_comp_sizes, 0xff, sizeof(c->xstate_comp_sizes));

	/* start at the beginnning of the "extended state" */
	last_good_offset = offsetof(struct xsave_struct, extended_state_area);

	/*
	 * The FP xstates and SSE xstates are legacy states. They are always
	 * in the fixed offsets in the xsave area in either compacted form
	 * or standard form.
	 */
	c->xstate_offsets[0]	= 0;
	c->xstate_sizes[0]	= offsetof(struct i387_fxsave_struct, xmm_space);
	c->xstate_offsets[1]	= c->xstate_sizes[0];
	c->xstate_sizes[1]	= FIELD_SIZEOF(struct i387_fxsave_struct, xmm_space);

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
		__zap_regs();
		vz_cpuid_count(XSTATE_CPUID, i, &eax, &ebx, &ecx, &edx);
		if (!(ecx & 1))
			c->xstate_offsets[i] = ebx;

		c->xstate_sizes[i] = eax;

		/*
		 * In our xstate size checks, we assume that the
		 * highest-numbered xstate feature has the
		 * highest offset in the buffer.  Ensure it does.
		 */
		if (last_good_offset > c->xstate_offsets[i])
			pr_warn_once("fpu: misordered xstate %d %d\n",
				     last_good_offset, c->xstate_offsets[i]);

		last_good_offset = c->xstate_offsets[i];
	}

	BUILD_BUG_ON(sizeof(c->xstate_offsets) != sizeof(c->xstate_sizes));
	BUILD_BUG_ON(sizeof(c->xstate_comp_offsets) != sizeof(c->xstate_comp_sizes));

	c->xstate_comp_offsets[0]	= 0;
	c->xstate_comp_sizes[0]		= offsetof(struct i387_fxsave_struct, xmm_space);
	c->xstate_comp_offsets[1]	= c->xstate_comp_sizes[0];
	c->xstate_comp_sizes[1]		= FIELD_SIZEOF(struct i387_fxsave_struct, xmm_space);

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
				__zap_regs();
				vz_cpuid_count(XSTATE_CPUID, i, &eax, &ebx, &ecx, &edx);
				if (ecx & 2)
					c->xstate_comp_offsets[i] = ALIGN(c->xstate_comp_offsets[i], 64);
			}
		}
	}

	if (!pr_quelled(LOG_DEBUG)) {
		for (i = 0; i < ARRAY_SIZE(c->xstate_offsets); i++) {
			if (!(c->xfeatures_mask & (1UL << i)))
				continue;
			pr_debug("fpu: %-32s xstate_offsets %6d / %-6d xstate_sizes %6d / %-6d\n",
				 xfeature_names[i], c->xstate_offsets[i], c->xstate_comp_offsets[i],
				 c->xstate_sizes[i], c->xstate_comp_sizes[i]);
		}
	}

	return 0;
#undef __zap_regs
}

int fetch_cpuid(cpuinfo_x86_t *c)
{
	uint32_t eax, ebx, ecx, edx;

#define __zap_regs() eax = ebx = ecx = edx = 0

	/*
	 * See cpu_detect() in the kernel, also
	 * read cpuid specs not only from general
	 * SDM but for extended instructions set
	 * reference.
	 */

	/* Get vendor name */
	vz_cpuid(0x00000000,
		 (unsigned int *)&c->cpuid_level,
		 (unsigned int *)&c->x86_vendor_id[0],
		 (unsigned int *)&c->x86_vendor_id[8],
		 (unsigned int *)&c->x86_vendor_id[4]);

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
		vz_cpuid(0x00000001, &eax, &ebx, &ecx, &edx);
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
		c->x86_capability[CPUID_6_EAX] = vz_cpuid_eax(0x00000006);

	/* Additional Intel-defined flags: level 0x00000007 */
	if (c->cpuid_level >= 0x00000007) {
		__zap_regs();
		vz_cpuid_count(0x00000007, 0, &eax, &ebx, &ecx, &edx);
		c->x86_capability[CPUID_7_0_EBX] = ebx;
		c->x86_capability[CPUID_7_0_ECX] = ecx;
		c->x86_capability[CPUID_7_0_EDX] = edx;
	}

	/* Extended state features: level 0x0000000d */
	if (c->cpuid_level >= 0x0000000d) {
		__zap_regs();
		vz_cpuid_count(0x0000000d, 1, &eax, &ebx, &ecx, &edx);
		c->x86_capability[CPUID_D_1_EAX] = eax;
	}

	/* Additional Intel-defined flags: level 0x0000000F */
	if (c->cpuid_level >= 0x0000000F) {
		__zap_regs();
		/* QoS sub-leaf, EAX=0Fh, ECX=0 */
		vz_cpuid_count(0x0000000F, 0, &eax, &ebx, &ecx, &edx);
		c->x86_capability[CPUID_F_0_EDX] = edx;

		if (test_cpu_cap(c, X86_FEATURE_CQM_LLC)) {
			__zap_regs();
			/* QoS sub-leaf, EAX=0Fh, ECX=1 */
			vz_cpuid_count(0x0000000F, 1, &eax, &ebx, &ecx, &edx);
			c->x86_capability[CPUID_F_1_EDX] = edx;
		}
	}

	/* AMD-defined flags: level 0x80000001 */
	eax = vz_cpuid_eax(0x80000000);
	c->extended_cpuid_level = eax;

	if ((eax & 0xffff0000) == 0x80000000) {
		if (eax >= 0x80000001) {
			__zap_regs();
			vz_cpuid(0x80000001, &eax, &ebx, &ecx, &edx);

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
		vz_cpuid(0x80000002, &v[0], &v[1], &v[2], &v[3]);
		vz_cpuid(0x80000003, &v[4], &v[5], &v[6], &v[7]);
		vz_cpuid(0x80000004, &v[8], &v[9], &v[10], &v[11]);
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
		vz_cpuid(0x80000007, &eax, &ebx, &ecx, &edx);

		c->x86_capability[CPUID_8000_0007_EBX] = ebx;
		c->x86_power = edx;
	}

	if (c->extended_cpuid_level >= 0x8000000a)
		c->x86_capability[CPUID_8000_000A_EDX] = vz_cpuid_edx(0x8000000a);

	if (c->extended_cpuid_level >= 0x80000008)
		c->x86_capability[CPUID_8000_0008_EBX] = vz_cpuid_ebx(0x80000008);

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
			level = vz_cpuid_eax(1);
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
