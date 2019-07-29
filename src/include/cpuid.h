#ifndef VZCPUIDCTL_CPUID_H__
#define VZCPUIDCTL_CPUID_H__

#include <stdint.h>

#include "x86-cpuid.h"

#define CPUID_OVERRIDE_PATH_DEFAULT "/proc/vz/cpuid_override"

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
	uint32_t	op;
	uint32_t	count;
	uint32_t	has_count;
	uint32_t	eax;
	uint32_t	ebx;
	uint32_t	ecx;
	uint32_t	edx;
} cpuid_override_entry_t;

extern cpuid_override_entry_t *cpuid_override_entries;
extern unsigned int nr_cpuid_override_entries;

typedef struct {
	const char *description;

	void (*cpuid)(uint32_t op,
		      uint32_t *eax, uint32_t *ebx,
		      uint32_t *ecx, uint32_t *edx,
		      x86_cpuid_call_trace_t *ct);
	void (*cpuid_count)(uint32_t op, uint32_t count,
			    uint32_t *eax, uint32_t *ebx,
			    uint32_t *ecx, uint32_t *edx,
			    x86_cpuid_call_trace_t *ct);
	uint32_t (*cpuid_eax)(uint32_t op, x86_cpuid_call_trace_t *ct);
	uint32_t (*cpuid_ebx)(uint32_t op, x86_cpuid_call_trace_t *ct);
	uint32_t (*cpuid_ecx)(uint32_t op, x86_cpuid_call_trace_t *ct);
	uint32_t (*cpuid_edx)(uint32_t op, x86_cpuid_call_trace_t *ct);
} cpuid_ops_t;

extern const cpuid_ops_t cpuid_ops_native;
extern const cpuid_ops_t cpuid_ops_override;

extern int cpuid_override_init(char *override_path);
extern void cpuid_register(const cpuid_ops_t *ops);
extern const cpuid_ops_t *cpuid_get_ops(void);

extern int call_trace_find_idx_in(x86_cpuid_call_trace_t *ct,
				  uint32_t eax, uint32_t ebx,
				  uint32_t ecx, uint32_t edx);

#endif /* VZCPUIDCTL_CPUID_H__ */
