#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include "cpu.h"
#include "log.h"
#include "xmalloc.h"
#include "base64.h"
#include "vzcpuidctl.h"

#undef	LOG_PREFIX
#define LOG_PREFIX "vzcpuidctl: "

int vzcpuidctl_xsave_encode(opts_t *opts)
{
	vzcpuid_rec_t rec = { };
	char *encoded = NULL;
	ssize_t ret = -1;
	int out_fd = -1;

	rec.type = VZCPUID_FULL;
	if (fetch_cpuid(&rec.c))
		return -1;

	encoded = b64_encode((void *)&rec, sizeof(rec));
	if (encoded == NULL) {
		pr_err("Can't encode cpuinfo\n");
		return -1;
	}

	if (!opts->out_fd_path) {
		pr_info("encoded cpuinfo data is on the next line:\n%s\n", encoded);
		ret = 0;
	} else {
		out_fd = open(opts->out_fd_path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
		if (out_fd < 0) {
			pr_perror("Can't open %s", opts->out_fd_path);
			goto out;
		}

		ret = write(out_fd, encoded, strlen(encoded));
		if (ret < 0) {
			pr_perror("Can't write encoded cpuinfo data into %s",
				  opts->out_fd_path);
			goto out;
		} else {
			pr_debug("Wrote encoded data into %s\n", opts->out_fd_path);
			ret = 0;
		}
	}

out:
	if (opts->out_fd_path && out_fd >= 0)
		close(out_fd);
	xfree(encoded);
	return ret;
}

static void show_fpu_info(cpuinfo_x86_t *c)
{
	size_t i;

	pr_info("fpu: xfeatures_mask 0x%llx xsave_size %u xsave_size_max %u xsaves_size %u\n",
		(unsigned long long)c->xfeatures_mask,
		c->xsave_size, c->xsave_size_max, c->xsaves_size);

	if (!pr_quelled(LOG_INFO)) {
		for (i = 0; i < ARRAY_SIZE(c->xstate_offsets); i++) {
			if (!(c->xfeatures_mask & (1UL << i)))
				continue;
			pr_info("fpu: %-32s xstate_offsets %6d / %-6d xstate_sizes %6d / %-6d\n",
				xfeature_names[i], c->xstate_offsets[i], c->xstate_comp_offsets[i],
				c->xstate_sizes[i], c->xstate_comp_sizes[i]);
		}
	}
}

static int generate_override_entry(char *where, size_t size, vz_cpuid_override_entry_t *e)
{
	if (e->has_count) {
		return snprintf(where, size,
				"0x%08x 0x%08x: 0x%08x 0x%08x 0x%08x 0x%08x\n",
				e->op, e->count, e->eax, e->ebx, e->ecx, e->edx);
	}

	return snprintf(where, size, "0x%08x: 0x%08x 0x%08x 0x%08x 0x%08x\n",
			e->op, e->eax, e->ebx, e->ecx, e->edx);
}

static int generate_cpuid_override(opts_t *opts, vzcpuid_rec_entry_t *entry)
{
	cpuinfo_x86_t *c =  &entry->rec.c;
	char *buf = NULL, *pos, *end;
	size_t buf_size = 0;
	int ret = -1;
	ssize_t len;
	int took;
	size_t i;

	struct override_list_entry {
		struct list_head		list;
		vz_cpuid_override_entry_t	entry;
	};

	struct override_list_entry *item, *tmp;
	vz_cpuid_override_entry_t *e;

	LIST_HEAD(override_entries_list);

	if (vz_cpuid_override_entries) {
		pr_err("override already read!\n");
		return -1;
	}

	if (!test_cpu_cap(c, X86_FEATURE_FPU)) {
		pr_err("fpu: No FPU detected\n");
		return -1;
	}

	if (!test_cpu_cap(c, X86_FEATURE_XSAVE)) {
		pr_err("fpu: XSAVE is not supported\n");
		return -1;
	}

	/*
	 * We've a bug in CRIU, XFEATURE_MASK_SUPERVISOR has been
	 * using XFEATURE_HDC instead of XFEATURE_MASK_HDC, in
	 * result bits XFEATURE_MASK_SSE and XFEATURE_MASK_BNDREGS
	 * got occasionally cleared.
	 */

	if (!(c->xfeatures_mask & XFEATURE_MASK_SSE)) {
		pr_debug("fpu: Fix sse missing bit bug\n");
		c->xfeatures_mask |= XFEATURE_MASK_SSE;
	}

	if ((c->xfeatures_mask & XFEATURE_MASK_FPSSE) != XFEATURE_MASK_FPSSE) {
		/*
		 * This indicates that something really unexpected happened
		 * with the enumeration.
		 */
		pr_err("fpu: FP/SSE not present amongst the CPU's xstate features: 0x%llx (0x%llx 0x%llx)\n",
		       (unsigned long long)c->xfeatures_mask,
		       (unsigned long long)(c->xfeatures_mask & XFEATURE_MASK_FPSSE),
		       (unsigned long long)XFEATURE_MASK_FPSSE);
		return -1;
	}

#define __alloc_entry(__item, __e)			\
	do {						\
		__item = xzalloc(sizeof(*__item));	\
		if (!__item)				\
			goto out;			\
		__e = &__item->entry;			\
	} while (0)

	__alloc_entry(item, e);

	e->op	= XSTATE_CPUID;
	e->eax	= c->xfeatures_mask & 0xffffffff;
	e->edx	= c->xfeatures_mask >> 32;
	e->ebx	= c->xsave_size;
	e->ecx	= c->xsave_size_max;

	list_add(&item->list, &override_entries_list);

	for (i = FIRST_EXTENDED_XFEATURE; i < XFEATURE_MAX; i++) {
		if (!(c->xfeatures_mask & (1UL << i)))
			continue;

		__alloc_entry(item, e);

		e->op		= XSTATE_CPUID;
		e->count	= i;
		e->has_count	= true;
		e->eax		= c->xstate_sizes[i];
		if (c->xstate_offsets[i] != 0xff)
			e->ecx	= 1;

		list_add(&item->list, &override_entries_list);
	}

	/* I'm too lazy to make it extendable :-) */
	buf_size = 1 << 20;
	buf = xmalloc(buf_size);
	if (!buf)
		goto out;
	end = buf + buf_size;
	pos = buf;

	for (i = 0; i < nr_vz_cpuid_override_entries; i++) {
		e = &vz_cpuid_override_entries[i];

		/* Skip old entries */
		if (e->op == XSTATE_CPUID)
			continue;

		took = generate_override_entry(pos, end - pos, e);
		pos += took;
		if (pos > end || (end - pos) < 128) {
			pr_err("Too many entries in the override list\n");
			goto out;
		}
	}

	list_for_each_entry(item, &override_entries_list, list) {
		e = &item->entry;

		took = generate_override_entry(pos, end - pos, e);
		pos += took;

		if (pos > end || (end - pos) < 128) {
			pr_err("Too many entries in the override list\n");
			goto out;
		}
	}

	pr_info("Generated:\n%s", buf);

	if (opts->out_fd_path) {
		int fd = open(opts->out_fd_path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
		if (fd < 0) {
			pr_perror("Can't open %s", opts->out_fd_path);
			goto out;
		}

		len = write(fd, buf, strlen(buf));
		close(fd);

		if (len != strlen(buf)) {
			pr_err("Wrote %zd bytes while %zu expected\n",
			       len, strlen(buf));
			goto out;
		}
	}

	ret = 0;
out:
	list_for_each_entry_safe(item, tmp, &override_entries_list, list)
		xfree(item);
	xfree(buf);
	return ret;

#undef __alloc_entry
}

static int read_data_files(opts_t *opts)
{
	size_t encoded_size = b64_encoded_size(sizeof(vzcpuid_rec_t));
	str_entry_t *sl, *new = NULL;
	struct stat st;
	int fd = -1;
	ssize_t ret;

	if (list_empty(&opts->list_data_path))
		return 0;

	list_for_each_entry(sl, &opts->list_data_path, list) {
		fd = open(sl->str, O_RDONLY);
		if (fd < 0) {
			pr_perror("Can't open %s", sl->str);
			return -1;
		}

		if (fstat(fd, &st)) {
			pr_perror("Stat failed on %s", sl->str);
			goto cant_read;
		}

		if (st.st_size < encoded_size) {
			pr_err("File %s is too small, at least %zd bytes needed\n",
			       sl->str, encoded_size);
			goto cant_read;
		}

		new = xzalloc(sizeof(*new));
		if (!new)
			goto cant_read;

		new->str = xmalloc(st.st_size + 1);
		if (!new->str)
			goto cant_read;

		ret = read(fd, new->str, st.st_size);
		if (ret != st.st_size) {
			pr_perror("Can't read %zu bytes from %s",
				  st.st_size, sl->str);
			goto cant_read;
		}

		new->str[st.st_size] = '\0';
		list_add(&new->list, &opts->list_data);

		close(fd), fd = -1;
		new = NULL;
	}

	return 0;

cant_read:
	if (fd >= 0)
		close(fd);
	if (new)
		xfree(new->str);
	xfree(new);
	return -1;
}

int vzcpuidctl_xsave_generate(opts_t *opts)
{
	size_t encoded_size = b64_encoded_size(sizeof(vzcpuid_rec_t));
	vzcpuid_rec_entry_t *entry, *tmp;
	size_t min_size = SIZE_MAX;
	LIST_HEAD(records_head);
	cpuinfo_x86_t *c;
	str_entry_t *sl;
	int ret = -1;

	if (read_data_files(opts))
		return -1;

	if (list_empty(&opts->list_data)) {
		pr_err("No data to generate from\n");
		return -1;
	}

	list_for_each_entry(sl, &opts->list_data, list) {
		size_t size = strlen(sl->str);
		if (size != encoded_size) {
			pr_err("Data encode corruption detected: got %zu but %zu expected\n",
			       size, encoded_size);
			goto out;
		}

		entry = xmalloc(size + sizeof(*entry));
		if (!entry)
			goto out;

		if (b64_decode(sl->str, (void *)&entry->rec, size) < 0) {
			pr_err("Can't decode data\n");
			xfree(entry);
			goto out;
		}

		if (entry->rec.type != VZCPUID_FULL) {
			pr_err("Corrupted data in record\n");
			xfree(entry);
			goto out;
		}

		list_add(&entry->list, &records_head);
	}

	entry = NULL;
	pr_info("Listing fpus\n");
	pr_info("---\n");
	list_for_each_entry(tmp, &records_head, list) {
		show_fpu_info(&tmp->rec.c);
		pr_info("---\n");
		if (tmp->rec.c.xsave_size < min_size) {
			min_size = tmp->rec.c.xsave_size;
			entry = tmp;
		}
	}

	if (!entry) {
		pr_err("Cant find entry to process\n");
		goto out;
	}

	c = &entry->rec.c;
	pr_info("Selected fpu\n");
	pr_info("---\n");
	show_fpu_info(c);
	pr_info("---\n");

	ret = generate_cpuid_override(opts, entry);
out:
	list_for_each_entry_safe(entry, tmp, &records_head, list)
		xfree(entry);
	return ret;
}
