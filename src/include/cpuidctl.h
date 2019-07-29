#ifndef VZCPUIDCTL_H__
#define VZCPUIDCTL_H__

#include <stdint.h>

#include "cpu.h"
#include "list.h"

typedef struct {
	struct list_head	list;
	char			*str;
} str_entry_t;

typedef struct override_list_entry {
	struct list_head	list;
	cpuid_override_entry_t	entry;
} override_list_entry_t;

enum {
	SYNC_MODE_NONE		= 0,
	SYNC_MODE_FPU		= 1,
	SYNC_MODE_INS		= 2,

	SYNC_MODE_MAX,
};

typedef struct {
	char			*out_fd_path;

	int			log_level;
	char			*log_path;

	unsigned int		sync_mode;

	char			*cpuid_override_path;
	bool			parse_cpuid_override;
	bool			write_cpuid_override;

	struct list_head	list_data_decoded;
	struct list_head	list_data;
	struct list_head	list_data_path;
} opts_t;

extern opts_t opts;

enum {
	CPUID_TYPE_NONE		= 0,
	CPUID_TYPE_FULL		= 1,
	CPUID_TYPE_XSAVE	= 2,

	CPUID_TYPE_MAX,
};

#define	CPUID_FMT_VERSION	1

typedef struct {
	uint32_t		type;
	uint32_t		fmt_version;
	cpuinfo_x86_t		c;
} cpuid_rec_t;

typedef struct {
	struct list_head	list;
	cpuid_rec_t		rec;
} cpuid_rec_entry_t;

extern int cpuidctl_xsave_encode(opts_t *opts);
extern int cpuidctl_xsave_generate(opts_t *opts);

#endif /* VZCPUIDCTL_H__ */
