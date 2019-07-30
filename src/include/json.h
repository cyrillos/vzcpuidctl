#ifndef VZCPUIDCTL_JSON_H__
#define VZCPUIDCTL_JSON_H__

#include <jansson.h>

#include "cpu.h"
#include "cpuidctl.h"

extern json_t *json_encode_cpuid_rec(cpuid_rec_t *rec);
extern int json_decode_cpuid_rec(cpuid_rec_t *rec, const char *data, size_t len);

#endif /* VZCPUIDCTL_JSON_H__ */
