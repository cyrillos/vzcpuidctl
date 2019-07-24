#ifndef VZCPUIDCTL_H__
#define VZCPUIDCTL_H__

#include <stdint.h>

#include "cpu.h"
#include "list.h"

typedef struct {
	struct list_head	list;
	char			*str;
} str_entry_t;

typedef struct {
	char			*out_fd_path;
	int			log_level;
	bool			write_procfs;

	struct list_head	list_data_decoded;
	struct list_head	list_data;
	struct list_head	list_data_path;
} opts_t;

extern opts_t opts;

enum {
	VZCPUID_NONE		= 0,
	VZCPUID_FULL		= 1,
	VZCPUID_XSAVE		= 2,

	VZCPUID_MAX,
};

typedef struct {
	uint32_t		type;
	union {
		cpuinfo_x86_t	c;
	};
} vzcpuid_rec_t;

typedef struct {
	struct list_head	list;
	vzcpuid_rec_t		rec;
} vzcpuid_rec_entry_t;

extern int vzcpuidctl_xsave_encode(opts_t *opts);
extern int vzcpuidctl_xsave_generate(opts_t *opts);

#endif /* VZCPUIDCTL_H__ */
