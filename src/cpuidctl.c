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
#include "json.h"
#include "cpuidctl.h"

#undef	LOG_PREFIX
#define LOG_PREFIX "cpuidctl: "

int cpuidctl_xsave_encode(opts_t *opts)
{
	cpuid_rec_t rec = {
		.type		= CPUID_TYPE_FULL,
		.fmt_version	= CPUID_FMT_VERSION,
	};

	char *encoded = NULL;
	ssize_t ret = -1;
	int out_fd = -1;

	json_t *root;

	if (fetch_cpuid(&rec.c))
		return -1;

	root = json_encode_cpuid_rec(&rec);
	encoded = json_dumps(root, JSON_COMPACT);
	if (encoded == NULL) {
		pr_err("Can't encode cpuinfo\n");
		return -1;
	}

	if (!opts->out_fd_path) {
		pr_info("encoded cpuinfo data in json format:\n%s\n", encoded);
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

	json_decref(root);
	xfree(encoded);
	return ret;
}

static int write_cpuid_override(opts_t *opts, char *buf, size_t len)
{
	ssize_t ret;
	int fd;

	if (!opts->write_cpuid_override)
		return 0;

	fd = open(opts->cpuid_override_path, O_WRONLY);
	if (fd < 0) {
		pr_perror("Can't open %s", opts->cpuid_override_path);
		return -1;
	}

	ret = write(fd, "", 1);
	if (ret != 1) {
		pr_perror("Can't flush %s", opts->cpuid_override_path);
		goto err;
	}
	pr_info("Flushed %s\n", opts->cpuid_override_path);

	ret = write(fd, buf, len);
	if (ret != len) {
		pr_perror("Can't flush %s", opts->cpuid_override_path);
		goto err;
	}

	close(fd);
	pr_info("Updated %s\n", opts->cpuid_override_path);

	return 0;
err:
	close(fd);
	return -1;
}

static int generate_override_entry(char *where, size_t size, cpuid_override_entry_t *e)
{
	if (e->has_count) {
		return snprintf(where, size,
				"0x%08x 0x%08x: 0x%08x 0x%08x 0x%08x 0x%08x\n",
				e->op, e->count, e->eax, e->ebx, e->ecx, e->edx);
	}

	return snprintf(where, size, "0x%08x: 0x%08x 0x%08x 0x%08x 0x%08x\n",
			e->op, e->eax, e->ebx, e->ecx, e->edx);
}

static int generate_cpuid_override(opts_t *opts, cpuid_rec_entry_t *entry)
{
	cpuinfo_x86_t *c =  &entry->rec.c;
	char *buf = NULL, *pos, *end;
	size_t buf_size = 0, buf_len;
	int ret = -1;
	ssize_t len;
	int took;
	size_t i;

	struct override_list_entry *item, *tmp;
	cpuid_override_entry_t *e;

	LIST_HEAD(override_entries_list);

	if (rt_cpuid_override_entries) {
		pr_err("override already read!\n");
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

	for (i = 0; i < rt_nr_cpuid_override_entries; i++) {
		e = &rt_cpuid_override_entries[i];

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

	buf_len = pos - buf;
	pr_info("Generated:\n%s", buf);

	if (opts->out_fd_path) {
		int fd = open(opts->out_fd_path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
		if (fd < 0) {
			pr_perror("Can't open %s", opts->out_fd_path);
			goto out;
		}

		len = write(fd, buf, buf_len);
		close(fd);

		if (len != buf_len) {
			pr_err("Wrote %zd bytes to %s while %zu expected\n",
			       len, opts->out_fd_path, buf_len);
			goto out;
		}
	}

	ret = write_cpuid_override(opts, buf, buf_len);
out:
	list_for_each_entry_safe(item, tmp, &override_entries_list, list)
		xfree(item);
	xfree(buf);
	return ret;

#undef __alloc_entry
}

static int generate_fpu_override(opts_t *opts, struct list_head *records_head)
{
	cpuid_rec_entry_t *entry = NULL, *tmp;
	size_t min_size = SIZE_MAX;

	cpuinfo_x86_t *template = NULL;
	cpuinfo_x86_t *rt = NULL;
	x86_cpuid_call_trace_t *template_ct = NULL;

	char *buf = NULL, *pos, *end;
	size_t buf_size = 0, buf_len;
	ssize_t len;
	int took;
	size_t i, j;

	LIST_HEAD(override_entries_list);
	override_list_entry_t *item, *itmp;
	cpuid_override_entry_t *e;

	int ret = -1;

#define __alloc_entry(__item, __e)			\
	do {						\
		__item = xzalloc(sizeof(*__item));	\
		if (!__item)				\
			goto out;			\
		__e = &__item->entry;			\
	} while (0)

	pr_info("List of collected fpus\n");
	pr_info("---\n");

	list_for_each_entry(tmp, records_head, list) {
		show_fpu_info(&tmp->rec.c);
		pr_info("---\n");

		if (validate_fpu(&tmp->rec.c))
			return -EINVAL;

		/*
		 * Select the less powerfull.
		 */
		if (tmp->rec.c.xsave_size < min_size) {
			min_size = tmp->rec.c.xsave_size;
			entry = tmp;
		}
	}

	if (!entry) {
		pr_err("Cant find any fpu entry to process\n");
		return -ENOENT;
	}

	template = &entry->rec.c;
	template_ct = &template->cpuid_call_trace;

	pr_info("Selected fpu entry\n");
	pr_info("---\n");
	show_fpu_info(template);
	pr_info("---\n");

	pr_info("Fetching runtime cpuinfo\n");
	rt = xmalloc(sizeof(*rt));
	if (!rt)
		goto out;
	if (fetch_cpuid(rt))
		return -1;

	pr_info("Runtime fpu\n");
	pr_info("---\n");
	show_fpu_info(rt);
	pr_info("---\n");

	/* I'm too lazy to make it extendable :-) */
	buf_size = 1 << 20;
	buf = xmalloc(buf_size);
	if (!buf)
		goto out;
	end = buf + buf_size;
	pos = buf;

	/*
	 * First generate entries for all but XSTATE_CPUID
	 * if they were in systemwide rt_cpuid_override_entries.
	 */
	for (i = 0; i < rt_nr_cpuid_override_entries; i++) {
		e = &rt_cpuid_override_entries[i];

		if (e->op == XSTATE_CPUID)
			continue;

		took = generate_override_entry(pos, end - pos, e);
		pos += took;
		if (pos > end || (end - pos) < 128) {
			pr_err("Too many entries in the override list\n");
			goto out;
		}
	}

	/*
	 * Now generate entries for XSTATE_CPUID leaf, note that
	 * we have to modify only those fields which are to be
	 * updated and anythingelse should left from rt data
	 * untouched.
	 */
	__alloc_entry(item, e);

	e->op		= XSTATE_CPUID;
	e->count	= 0;
	e->has_count	= true;
	e->eax		= template->xfeatures_mask & 0xffffffff;
	e->edx		= template->xfeatures_mask >> 32;
	e->ebx		= template->xsave_size;
	e->ecx		= template->xsave_size_max;
	list_add(&item->list, &override_entries_list);

	for (i = FIRST_EXTENDED_XFEATURE; i < XFEATURE_MAX; i++) {
		if (!(template->xfeatures_mask & (1UL << i)))
			continue;

		j = call_trace_find_idx_in(template_ct,
					   XSTATE_CPUID, 0,
					   (uint32_t)i, 0);
		if (j < 0) {
			pr_err("No calltrace for xstate_offsets %zu\n", i);
			goto out;
		}

		__alloc_entry(item, e);

		e->op		= XSTATE_CPUID;
		e->count	= i;
		e->has_count	= true;
		e->eax		= template->xstate_sizes[i];
		e->ebx		= template_ct->out[j].ebx;

		if (template->xstate_offsets[i] != 0xff)
			e->ecx	= 1;
		else
			e->ecx	= template_ct->out[j].ecx;

		e->edx		= template_ct->out[j].edx;

		list_add(&item->list, &override_entries_list);
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

	buf_len = pos - buf;
	pr_info("Generated:\n%s", buf);

	if (opts->out_fd_path) {
		int fd = open(opts->out_fd_path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
		if (fd < 0) {
			pr_perror("Can't open %s", opts->out_fd_path);
			goto out;
		}

		len = write(fd, buf, buf_len);
		close(fd);

		if (len != buf_len) {
			pr_err("Wrote %zd bytes to %s while %zu expected\n",
			       len, opts->out_fd_path, buf_len);
			goto out;
		}
	}

	ret = write_cpuid_override(opts, buf, buf_len);
out:
	list_for_each_entry_safe(item, itmp, &override_entries_list, list)
		xfree(item);
	xfree(buf);
	xfree(rt);
	return ret;

#undef __alloc_entry
}

static int read_data_files(opts_t *opts)
{
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

int cpuidctl_xsave_generate(opts_t *opts)
{
	size_t encoded_size = b64_encoded_size(sizeof(cpuid_rec_t));
	cpuid_rec_entry_t *entry, *tmp;
	LIST_HEAD(records_head);
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

		entry = xzalloc(size + sizeof(*entry));
		if (!entry)
			goto out;

		if (json_decode_cpuid_rec(&entry->rec, sl->str, size + 1)) {
			pr_err("Can't decode data\n");
			xfree(entry);
			goto out;
		}

		if (entry->rec.type != CPUID_TYPE_FULL) {
			pr_err("Corrupted record type: got %#x but %#x expected\n",
			       entry->rec.type, CPUID_TYPE_FULL);
			xfree(entry);
			goto out;
		}

		if (entry->rec.fmt_version != CPUID_FMT_VERSION) {
			pr_err("Corrupted record version: got %#x but %#x expected\n",
			       entry->rec.fmt_version, CPUID_FMT_VERSION);
			xfree(entry);
			goto out;
		}

		list_add(&entry->list, &records_head);
	}

	switch (opts->sync_mode) {
	case SYNC_MODE_FPU:
		ret = generate_fpu_override(opts, &records_head);
		break;
	default:
		pr_err("Unsupported cpu sync mode: %d\n",
		       opts->sync_mode);
		goto out;
	}

	//ret = generate_cpuid_override(opts, entry);
out:
	list_for_each_entry_safe(entry, tmp, &records_head, list)
		xfree(entry);
	return ret;
}
