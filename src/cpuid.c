#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <stdbool.h>

#include "compiler.h"
#include "cpuid.h"
#include "log.h"
#include "bug.h"

#include "xmalloc.h"

#undef	LOG_PREFIX
#define LOG_PREFIX "cpuid: "

const cpuid_ops_t *cpuid_ops;

static void call_trace_put(x86_cpuid_call_trace_t *ct, bool in,
			   uint32_t *eax, uint32_t *ebx,
			   uint32_t *ecx, uint32_t *edx)
{
	if (ct) {
		x86_cpuid_args_t *args = in ?
			&ct->in[ct->nr_in] :
			&ct->out[ct->nr_out];

		BUG_ON(ct->nr_in >= (in ? ARRAY_SIZE(ct->in) : ARRAY_SIZE(ct->out)));

		args->eax = *eax;
		args->ebx = *ebx;
		args->ecx = *ecx;
		args->edx = *edx;

		if (in)
			ct->nr_in++;
		else
			ct->nr_out++;
	}
}

static void x86_native_cpuid_logged(uint32_t *eax, uint32_t *ebx,
				    uint32_t *ecx, uint32_t *edx,
				    x86_cpuid_call_trace_t *ct)
{
	pr_debug("x86_cpuid in : eax 0x%08x ebx 0x%08x ecx 0x%08x edx 0x%08x\n",
		 *eax, *ebx, *ecx, *edx);

	call_trace_put(ct, true, eax, ebx, ecx, edx);
	x86_native_cpuid(eax, ebx, ecx, edx);
	call_trace_put(ct, false, eax, ebx, ecx, edx);

	pr_debug("x86_cpuid out: eax 0x%08x ebx 0x%08x ecx 0x%08x edx 0x%08x\n",
		 *eax, *ebx, *ecx, *edx);
}

static void x86_cpuid(uint32_t op,
		      uint32_t *eax, uint32_t *ebx,
		      uint32_t *ecx, uint32_t *edx,
		      x86_cpuid_call_trace_t *ct)
{
	*eax = op, *ecx = 0;
	x86_native_cpuid_logged(eax, ebx, ecx, edx, ct);
}

static void x86_cpuid_count(uint32_t op, uint32_t count,
			    uint32_t *eax, uint32_t *ebx,
			    uint32_t *ecx, uint32_t *edx,
			    x86_cpuid_call_trace_t *ct)
{
	*eax = op, *ecx = count;
	x86_native_cpuid_logged(eax, ebx, ecx, edx, ct);
}

static uint32_t x86_cpuid_eax(uint32_t op, x86_cpuid_call_trace_t *ct)
{
	uint32_t eax, ebx = 0, ecx, edx = 0;
	x86_cpuid(op, &eax, &ebx, &ecx, &edx, ct);
	return eax;
}

static uint32_t x86_cpuid_ebx(uint32_t op, x86_cpuid_call_trace_t *ct)
{
	uint32_t eax, ebx = 0, ecx, edx = 0;
	x86_cpuid(op, &eax, &ebx, &ecx, &edx, ct);
	return ebx;
}

static uint32_t x86_cpuid_ecx(uint32_t op, x86_cpuid_call_trace_t *ct)
{
	uint32_t eax, ebx = 0, ecx, edx = 0;
	x86_cpuid(op, &eax, &ebx, &ecx, &edx, ct);
	return ecx;
}

static uint32_t x86_cpuid_edx(uint32_t op, x86_cpuid_call_trace_t *ct)
{
	uint32_t eax, ebx = 0, ecx, edx = 0;
	x86_cpuid(op, &eax, &ebx, &ecx, &edx, ct);
	return edx;
}

const cpuid_ops_t cpuid_ops_native = {
	.description	= "x86 native cpuid",
	.cpuid		= x86_cpuid,
	.cpuid_count	= x86_cpuid_count,
	.cpuid_eax	= x86_cpuid_eax,
	.cpuid_eax	= x86_cpuid_ebx,
	.cpuid_ecx	= x86_cpuid_ecx,
	.cpuid_edx	= x86_cpuid_edx,
};

cpuid_override_entry_t *cpuid_override_entries;
unsigned int nr_cpuid_override_entries;

static int parse_override(char *path)
{
	int ret = -1;
	char s[512];
	FILE *f;

	if (!path) {
		pr_err("cpuid_override: no override path provided\n");
		return -ENOENT;
	}

	pr_debug("cpuid_override: parsing %s\n", path);

	f = fopen(path, "r");
	if (!f) {
		pr_info("cpuid_override: can't access %s, ignoring\n", path);
		return 0;
	}

	while (fgets(s, sizeof(s), f)) {
		cpuid_override_entry_t e;
		size_t new_size;

		if (sscanf(s, "%x %x: %x %x %x %x",
			   &e.op, &e.count, &e.eax,
			   &e.ebx, &e.ecx, &e.edx) == 6) {
			e.has_count = 1;
		} else if (sscanf(s, "%x: %x %x %x %x",
				&e.op, &e.eax, &e.ebx,
				&e.ecx, &e.edx) == 5) {
			e.count = 0;
			e.has_count = 0;
		} else {
			pr_warn("cpuid_override: unexpected format in %s (%s)\n", path, s);
			goto out;
		}

		new_size = sizeof(e) * (nr_cpuid_override_entries + 1);

		if (xrealloc_safe(&cpuid_override_entries, new_size)) {
			pr_err("cpuid_override: no memory for cpuid override (%d entries)\n",
			       nr_cpuid_override_entries + 1);
			goto out;
		}

		cpuid_override_entries[nr_cpuid_override_entries++] = e;

		if (e.has_count) {
			pr_debug("cpuid_override: 0x%08x 0x%08x: 0x%08x 0x%08x 0x%08x 0x%08x\n",
				 e.op, e.count, e.eax, e.ebx, e.ecx, e.edx);
		} else {
			pr_debug("cpuid_override: 0x%08x: 0x%08x 0x%08x 0x%08x 0x%08x\n",
				 e.op, e.eax, e.ebx, e.ecx, e.edx);
		}
	}

	ret = 0;
out:
	fclose(f);
	return ret;
}

static cpuid_override_entry_t *
override_lookup(uint32_t op, uint32_t has_count, uint32_t count)
{
	size_t i;

	for (i = 0; i < nr_cpuid_override_entries; i++) {
		if (cpuid_override_entries[i].op != op		||
		    cpuid_override_entries[i].has_count != has_count	||
		    count != cpuid_override_entries[i].count)
			continue;
		return &cpuid_override_entries[i];
	}

	return NULL;
}

static void vz_cpuid_logged(uint32_t op,
			    uint32_t *eax, uint32_t *ebx,
			    uint32_t *ecx, uint32_t *edx,
			    x86_cpuid_call_trace_t *ct)
{
	cpuid_override_entry_t *e = override_lookup(op, 0, 0);
	if (e) {
		call_trace_put(ct, true, eax, ebx, ecx, edx);
		*eax = e->eax;
		*ebx = e->ebx;
		*ecx = e->ecx;
		*edx = e->edx;
		call_trace_put(ct, false, eax, ebx, ecx, edx);

		pr_debug("vz_cpuid out : op 0x%08x: eax 0x%08x ebx 0x%08x ecx 0x%08x edx 0x%08x\n",
			 op, *eax, *ebx, *ecx, *edx);
	} else
		cpuid_ops_native.cpuid(op, eax, ebx, ecx, edx, ct);
}

static void vz_cpuid_count_logged(uint32_t op, uint32_t count,
				  uint32_t *eax, uint32_t *ebx,
				  uint32_t *ecx, uint32_t *edx,
				  x86_cpuid_call_trace_t *ct)
{
	cpuid_override_entry_t *e = override_lookup(op, 1, count);
	if (e) {
		call_trace_put(ct, true, eax, ebx, ecx, edx);
		*eax = e->eax;
		*ebx = e->ebx;
		*ecx = e->ecx;
		*edx = e->edx;
		call_trace_put(ct, false, eax, ebx, ecx, edx);

		pr_debug("vz_cpuid out : op 0x%08x count 0x%08x: eax 0x%08x ebx 0x%08x ecx 0x%08x edx 0x%08x\n",
			 op, count, *eax, *ebx, *ecx, *edx);
	 } else
		 cpuid_ops_native.cpuid_count(op, count, eax, ebx, ecx, edx, ct);
}

static uint32_t vz_cpuid_eax(uint32_t op, x86_cpuid_call_trace_t *ct)
{
	uint32_t eax, ebx = 0, ecx, edx = 0;
	vz_cpuid_logged(op, &eax, &ebx, &ecx, &edx, ct);
	return eax;
}

static uint32_t vz_cpuid_ebx(uint32_t op, x86_cpuid_call_trace_t *ct)
{
	uint32_t eax, ebx = 0, ecx, edx = 0;
	vz_cpuid_logged(op, &eax, &ebx, &ecx, &edx, ct);
	return ebx;
}

static uint32_t vz_cpuid_ecx(uint32_t op, x86_cpuid_call_trace_t *ct)
{
	uint32_t eax, ebx = 0, ecx, edx = 0;
	vz_cpuid_logged(op, &eax, &ebx, &ecx, &edx, ct);
	return ecx;
}

static uint32_t vz_cpuid_edx(uint32_t op, x86_cpuid_call_trace_t *ct)
{
	uint32_t eax, ebx = 0, ecx, edx = 0;
	vz_cpuid_logged(op, &eax, &ebx, &ecx, &edx, ct);
	return edx;
}

const cpuid_ops_t cpuid_ops_override = {
	.description	= "vz override cpuid",
	.cpuid		= vz_cpuid_logged,
	.cpuid_count	= vz_cpuid_count_logged,
	.cpuid_eax	= vz_cpuid_eax,
	.cpuid_ebx	= vz_cpuid_ebx,
	.cpuid_ecx	= vz_cpuid_ecx,
	.cpuid_edx	= vz_cpuid_edx,
};

int cpuid_override_init(char *override_path)
{
	return parse_override(override_path);
}

void cpuid_register(const cpuid_ops_t *ops)
{
	pr_info("register: %s\n", ops->description);
	cpuid_ops = ops;
}

const cpuid_ops_t *cpuid_get_ops(void)
{
	return cpuid_ops;
}
