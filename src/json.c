#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <jansson.h>

#include "compiler.h"
#include "log.h"

#include "xmalloc.h"
#include "json.h"

#undef	LOG_PREFIX
#define LOG_PREFIX "json: "

static json_t *json_encode_cpuinfo(cpuinfo_x86_t *c)
{
	x86_cpuid_call_trace_t *ct = &c->cpuid_call_trace;
	json_t *root = json_object();
	json_t *json_arr;
	size_t i;

	json_object_set_new(root, "x86_family", json_integer(c->x86_family));
	json_object_set_new(root, "x86_vendor", json_integer(c->x86_vendor));
	json_object_set_new(root, "x86_model", json_integer(c->x86_model));
	json_object_set_new(root, "x86_mask", json_integer(c->x86_mask));

	json_arr = json_array();
	for (i = 0; i < ARRAY_SIZE(c->x86_capability); i++)
		json_array_append_new(json_arr, json_integer(c->x86_capability[i]));
	json_object_set_new(root, "x86_capability", json_arr);

	json_object_set_new(root, "x86_power", json_integer(c->x86_power));
	json_object_set_new(root, "extended_cpuid_level", json_integer(c->extended_cpuid_level));
	json_object_set_new(root, "cpuid_level", json_integer(c->cpuid_level));

	json_object_set_new(root, "x86_vendor_id", json_string((const char *)c->x86_vendor_id));
	json_object_set_new(root, "x86_model_id", json_string((const char *)c->x86_model_id));

	json_object_set_new(root, "xfeatures_mask", json_integer(c->xfeatures_mask));
	json_object_set_new(root, "xsave_size_max", json_integer(c->xsave_size_max));
	json_object_set_new(root, "xsave_size", json_integer(c->xsave_size));

	json_arr = json_array();
	for (i = 0; i < ARRAY_SIZE(c->xstate_offsets); i++) {
		if (c->xstate_offsets[i] != (uint32_t)-1) {
			json_t *json_subarr = json_array();

			json_array_append_new(json_subarr, json_integer(i));
			json_array_append_new(json_subarr, json_integer(c->xstate_offsets[i]));
			json_array_append_new(json_arr, json_subarr);
		}
	}
	json_object_set_new(root, "xstate_offsets", json_arr);

	json_arr = json_array();
	for (i = 0; i < ARRAY_SIZE(c->xstate_sizes); i++) {
		if (c->xstate_sizes[i] != (uint32_t)-1) {
			json_t *json_subarr = json_array();

			json_array_append_new(json_subarr, json_integer(i));
			json_array_append_new(json_subarr, json_integer(c->xstate_sizes[i]));
			json_array_append_new(json_arr, json_subarr);
		}
	}
	json_object_set_new(root, "xstate_sizes", json_arr);

	json_object_set_new(root, "xsaves_size", json_integer(c->xsaves_size));

	json_arr = json_array();
	for (i = 0; i < ARRAY_SIZE(c->xstate_comp_offsets); i++) {
		if (c->xstate_comp_offsets[i] != (uint32_t)-1) {
			json_t *json_subarr = json_array();

			json_array_append_new(json_subarr, json_integer(i));
			json_array_append_new(json_subarr, json_integer(c->xstate_comp_offsets[i]));
			json_array_append_new(json_arr, json_subarr);
		}
	}
	json_object_set_new(root, "xstate_comp_offsets", json_arr);

	json_arr = json_array();
	for (i = 0; i < ARRAY_SIZE(c->xstate_comp_sizes); i++) {
		if (c->xstate_comp_sizes[i] != (uint32_t)-1) {
			json_t *json_subarr = json_array();

			json_array_append_new(json_subarr, json_integer(i));
			json_array_append_new(json_subarr, json_integer(c->xstate_comp_sizes[i]));
			json_array_append_new(json_arr, json_subarr);
		}
	}
	json_object_set_new(root, "xstate_comp_sizes", json_arr);

	if (ct->nr_in > 0 && ct->nr_in == ct->nr_out) {
		json_t *call_trace_root = json_object();
		json_t *json_cpuid_args;

		json_arr = json_array();
		for (i = 0; i < ct->nr_in; i++) {
			json_cpuid_args = json_array();

			json_array_append_new(json_cpuid_args, json_integer(ct->in[i].eax));
			json_array_append_new(json_cpuid_args, json_integer(ct->in[i].ebx));
			json_array_append_new(json_cpuid_args, json_integer(ct->in[i].ecx));
			json_array_append_new(json_cpuid_args, json_integer(ct->in[i].edx));

			json_array_append_new(json_arr, json_cpuid_args);
		}

		json_object_set_new(call_trace_root, "in", json_arr);

		json_arr = json_array();
		for (i = 0; i < ct->nr_out; i++) {
			json_cpuid_args = json_array();

			json_array_append_new(json_cpuid_args, json_integer(ct->out[i].eax));
			json_array_append_new(json_cpuid_args, json_integer(ct->out[i].ebx));
			json_array_append_new(json_cpuid_args, json_integer(ct->out[i].ecx));
			json_array_append_new(json_cpuid_args, json_integer(ct->out[i].edx));

			json_array_append_new(json_arr, json_cpuid_args);
		}

		json_object_set_new(call_trace_root, "out", json_arr);

		json_object_set_new(root, "cpuid_call_trace", call_trace_root);
	}

	return root;
}

json_t *json_encode_cpuid_rec(cpuid_rec_t *rec)
{
	json_t *root = json_object();
	json_t *cpuinfo_root;

	json_object_set_new(root, "type", json_integer(rec->type));
	json_object_set_new(root, "fmt_version", json_integer(rec->fmt_version));

	cpuinfo_root = json_encode_cpuinfo(&rec->c);
	json_object_set_new(root, "cpu", cpuinfo_root);

	return root;
}

static int json_decode_cpuinfo(json_t *root, cpuinfo_x86_t *c)
{
	x86_cpuid_call_trace_t *ct = &c->cpuid_call_trace;
	json_t *jobj, *jsubobj;
	json_t *jval, *jct;
	size_t i;

	uint32_t idx, value;
	json_error_t jerr;
	int ret = -1;
	char *s;

	if (json_unpack_ex(root, &jerr, 0, "{s:I s:I s:I s:I}",
			   "x86_family", &c->x86_family,
			   "x86_vendor", &c->x86_vendor,
			   "x86_model", &c->x86_model,
			   "x86_mask", &c->x86_mask)) {
		pr_err("Can't unpack x86_family, x86_vendor, x86_model, x86_mask\n");
		goto out;
	}

	if (json_unpack_ex(root, &jerr, 0, "{s:[IIIIIIIIIIIIIIIIIII]}", "x86_capability",
			   &c->x86_capability[0], &c->x86_capability[1],
			   &c->x86_capability[2], &c->x86_capability[3],
			   &c->x86_capability[4], &c->x86_capability[5],
			   &c->x86_capability[6], &c->x86_capability[7],
			   &c->x86_capability[8], &c->x86_capability[9],
			   &c->x86_capability[10], &c->x86_capability[11],
			   &c->x86_capability[12], &c->x86_capability[13],
			   &c->x86_capability[14], &c->x86_capability[15],
			   &c->x86_capability[16], &c->x86_capability[17],
			   &c->x86_capability[18], &c->x86_capability[19])) {
		pr_err("Can't unpack x86_capability\n");
		goto out;
	}

	if (json_unpack_ex(root, &jerr, 0, "{s:I s:I s:I}",
			   "x86_power", &c->x86_power,
			   "extended_cpuid_level", &c->extended_cpuid_level,
			   "cpuid_level", &c->cpuid_level)) {
		pr_err("Can't unpack x86_power, extended_cpuid_level, cpuid_level\n");
		goto out;
	}

	if (json_unpack_ex(root, &jerr, 0, "{s:I s:I s:I}",
			   "x86_power", &c->x86_power,
			   "extended_cpuid_level", &c->extended_cpuid_level,
			   "cpuid_level", &c->cpuid_level)) {
		pr_err("Can't unpack x86_power, extended_cpuid_level, cpuid_level\n");
		goto out;
	}

	if (json_unpack_ex(root, &jerr, 0, "{s:s}", "x86_vendor_id", &s)) {
		pr_err("Can't unpack x86_vendor_id\n");
		goto out;
	}
	strncpy((void *)c->x86_vendor_id, s, sizeof(c->x86_vendor_id));

	if (json_unpack_ex(root, &jerr, 0, "{s:s}", "x86_model_id", &s)) {
		pr_err("Can't unpack x86_model_id\n");
		goto out;
	}
	strncpy((void *)c->x86_model_id, s, sizeof(c->x86_model_id));

	if (json_unpack_ex(root, &jerr, 0, "{s:I s:I s:I}",
			   "xfeatures_mask", &c->xfeatures_mask,
			   "xsave_size_max", &c->xsave_size_max,
			   "xsave_size", &c->xsave_size)) {
		pr_err("Can't unpack xfeatures_mask, xsave_size_max, xsave_size\n");
		goto out;
	}

	if (json_unpack_ex(root, &jerr, 0, "{s:o}", "xstate_offsets", &jobj)) {
		pr_err("Can't unpack xstate_offsets\n");
		goto out;
	}
	if (!json_is_array(jobj)) {
		pr_err("xstate_offsets is not an array\n");
		goto out;
	}

	json_array_foreach(jobj, i, jval) {
		if (!json_is_array(jval)) {
			pr_err("xstate_offsets is not an array\n");
			goto out;
		}

		if (json_array_size(jval) != 2) {
			pr_err("Wrong array length %zu\n", json_array_size(jval));
			goto out;
		}

		jsubobj = json_array_get(jval, 0);
		idx = json_integer_value(jsubobj);
		json_decref(jsubobj);

		if (idx >= ARRAY_SIZE(c->xstate_offsets)) {
			pr_err("Wrong index for xstate_offsets %u\n", idx);
			goto out;
		}

		jsubobj = json_array_get(jval, 1);
		value = json_integer_value(jsubobj);
		json_decref(jsubobj);

		c->xstate_offsets[idx] = value;
	}

	if (json_unpack_ex(root, &jerr, 0, "{s:o}", "xstate_sizes", &jobj)) {
		pr_err("Can't unpack xstate_sizes\n");
		goto out;
	}
	if (!json_is_array(jobj)) {
		pr_err("xstate_sizes is not an array\n");
		goto out;
	}
	json_array_foreach(jobj, i, jval) {
		if (!json_is_array(jval)) {
			pr_err("xstate_sizes is not an array\n");
			goto out;
		}

		if (json_array_size(jval) != 2) {
			pr_err("Wrong array length %zu\n", json_array_size(jval));
			goto out;
		}

		jsubobj = json_array_get(jval, 0);
		idx = json_integer_value(jsubobj);
		json_decref(jsubobj);

		if (idx >= ARRAY_SIZE(c->xstate_sizes)) {
			pr_err("Wrong index for xstate_sizes %u\n", idx);
			goto out;
		}

		jsubobj = json_array_get(jval, 1);
		value = json_integer_value(jsubobj);
		json_decref(jsubobj);

		c->xstate_sizes[idx] = value;
	}

	if (json_unpack_ex(root, &jerr, 0, "{s:I}", "xsaves_size", &c->xsaves_size)) {
		pr_err("Can't unpack xsaves_size\n");
		goto out;
	}

	if (json_unpack_ex(root, &jerr, 0, "{s:o}", "xstate_comp_offsets", &jobj)) {
		pr_err("Can't unpack xstate_comp_offsets\n");
		goto out;
	}
	if (!json_is_array(jobj)) {
		pr_err("xstate_comp_offsets is not an array\n");
		goto out;
	}
	json_array_foreach(jobj, i, jval) {
		if (!json_is_array(jval)) {
			pr_err("xstate_comp_offsets is not an array\n");
			goto out;
		}

		if (json_array_size(jval) != 2) {
			pr_err("Wrong array length %zu\n", json_array_size(jval));
			goto out;
		}

		jsubobj = json_array_get(jval, 0);
		idx = json_integer_value(jsubobj);
		json_decref(jsubobj);

		if (idx >= ARRAY_SIZE(c->xstate_comp_offsets)) {
			pr_err("Wrong index for xstate_comp_offsets %u\n", idx);
			goto out;
		}

		jsubobj = json_array_get(jval, 1);
		value = json_integer_value(jsubobj);
		json_decref(jsubobj);

		c->xstate_comp_offsets[idx] = value;
	}

	if (json_unpack_ex(root, &jerr, 0, "{s:o}", "xstate_comp_sizes", &jobj)) {
		pr_err("Can't unpack xstate_comp_sizes\n");
		goto out;
	}
	if (!json_is_array(jobj)) {
		pr_err("xstate_comp_sizes is not an array\n");
		goto out;
	}
	json_array_foreach(jobj, i, jval) {
		if (!json_is_array(jval)) {
			pr_err("xstate_comp_sizes is not an array\n");
			goto out;
		}

		if (json_array_size(jval) != 2) {
			pr_err("Wrong array length %zu\n", json_array_size(jval));
			goto out;
		}

		jsubobj = json_array_get(jval, 0);
		idx = json_integer_value(jsubobj);
		json_decref(jsubobj);

		if (idx >= ARRAY_SIZE(c->xstate_comp_sizes)) {
			pr_err("Wrong index for xstate_comp_sizes %u\n", idx);
			goto out;
		}

		jsubobj = json_array_get(jval, 1);
		value = json_integer_value(jsubobj);
		json_decref(jsubobj);

		c->xstate_comp_sizes[idx] = value;
	}

	if (json_unpack_ex(root, &jerr, 0, "{s:o}", "cpuid_call_trace", &jct)) {
		pr_err("Can't unpack cpuid_call_trace\n");
		goto out;
	}

	if (json_unpack_ex(jct, &jerr, 0, "{s:o}", "in", &jobj)) {
		pr_err("Can't unpack cpuid_call_trace::in\n");
		goto out;
	}
	if (!json_is_array(jobj)) {
		pr_err("cpuid_call_trace::in is not an array\n");
		goto out;
	}
	if (json_array_size(jobj) >= ARRAY_SIZE(ct->in)) {
			pr_err("cpuid_call_trace::in size %zu is too big\n",
			       json_array_size(jobj));
			goto out;
	}
	ct->nr_in = json_array_size(jobj);
	json_array_foreach(jobj, i, jval) {
		if (!json_is_array(jval)) {
			pr_err("cpuid_call_trace::in is not an array\n");
			goto out;
		}

		if (json_unpack_ex(jval, &jerr, 0, "[IIII]",
				   &ct->in[i].eax,
				   &ct->in[i].ebx,
				   &ct->in[i].ecx,
				   &ct->in[i].edx)) {
			pr_err("Can't unpack cpuid_call_trace::in eax/ebx/ecx/edx\n");
			goto out;
		}
	}

	if (json_unpack_ex(jct, &jerr, 0, "{s:o}", "out", &jobj)) {
		pr_err("Can't unpack cpuid_call_trace::out\n");
		goto out;
	}
	if (!json_is_array(jobj)) {
		pr_err("cpuid_call_trace::out is not an array\n");
		goto out;
	}
	if (json_array_size(jobj) >= ARRAY_SIZE(ct->out)) {
			pr_err("cpuid_call_trace::out size %zu is too big\n",
			       json_array_size(jobj));
			goto out;
	}
	ct->nr_out = json_array_size(jobj);
	json_array_foreach(jobj, i, jval) {
		if (!json_is_array(jval)) {
			pr_err("cpuid_call_trace::out is not an array\n");
			goto out;
		}

		if (json_unpack_ex(jval, &jerr, 0, "[IIII]",
				   &ct->out[i].eax,
				   &ct->out[i].ebx,
				   &ct->out[i].ecx,
				   &ct->out[i].edx)) {
			pr_err("Can't unpack cpuid_call_trace::out eax/ebx/ecx/edx\n");
			goto out;
		}
	}

	ret = 0;
out:
	return ret;
}

int json_decode_cpuid_rec(cpuid_rec_t *rec, const char *data, size_t len)
{
	json_t *root, *cpu;
	json_error_t jerr;
	int ret = -1;

	root = json_loadb(data, len, JSON_DISABLE_EOF_CHECK, &jerr);
	if (!root) {
		pr_err("Failed to decode data: %s\n", jerr.text);
		return -1;
	}

	if (json_unpack_ex(root, &jerr, 0, "{s:I s:I s:o}",
			   "type", &rec->type,
			   "fmt_version", &rec->fmt_version,
			   "cpu", &cpu)) {
		pr_err("Can't unpack type, fmt_version, cpu\n");
		goto out;
	}

	if (rec->type != CPUID_TYPE_FULL) {
		pr_err("Invalid record type %u\n", rec->type);
		goto out;
	}

	if (rec->fmt_version != CPUID_FMT_VERSION) {
		pr_err("Invalid format version %u\n", rec->fmt_version);
		goto out;
	}

	init_cpuid(&rec->c);
	ret = json_decode_cpuinfo(cpu, &rec->c);
out:
	json_decref(root);
	return ret;
}
