#ifndef VZCPUIDCTL_CPU_H__
#define VZCPUIDCTL_CPU_H__

#include <stdint.h>
#include <stdbool.h>

#include <sys/types.h>

#include "cpuid.h"
#include "fpu.h"

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

extern int fetch_cpuid(cpuinfo_x86_t *c);

#endif /* VZCPUIDCTL_CPU_H__ */
