#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <getopt.h>

#include "log.h"
#include "cpu.h"
#include "vzcpuidctl.h"
#include "xmalloc.h"

opts_t opts = {
	.log_level	= DEFAULT_LOGLEVEL,
};

int main(int argc, char *argv[])
{
	static struct option long_opts[] = {
		{"verbosity",		optional_argument,	0,	'v' },
		{"help",		no_argument,		0,	'h' },
		{"write",		no_argument,		0,	'w' },
		{"data",		required_argument,	0,	'd' },
		{"data-file",		required_argument,	0,	'f' },
		{"output",		required_argument,	0,	'o' },
		{"use-cpuid_override",	no_argument,		0,	1000 },
		{"cpuid_override-path",	required_argument,	0,	1010 },
		{ },
	};
	int log_level = LOG_DEBUG;
	str_entry_t *s, *tmp;

	INIT_LIST_HEAD(&opts.list_data_decoded);
	INIT_LIST_HEAD(&opts.list_data);
	INIT_LIST_HEAD(&opts.list_data_path);

	if (argc < 2) {
		goto print_help;
		exit(1);
	}

	while (1) {
		int opt_index = 0;
		str_entry_t *sl;

		int c = getopt_long(argc, argv, "hv:d:o:f:", long_opts, &opt_index);
		if (c == -1)
			break;

		switch (c) {
		case 'v':
			if (optarg) {
				if (optarg[0] == 'v')
					/* handle -vvvvv */
					opts.log_level += strlen(optarg) + 1;
				else
					opts.log_level = atoi(optarg);
			} else
				opts.log_level++;
			break;
		case 'o':
			opts.out_fd_path = optarg;
			break;
		case 'f':
		case 'd':
			sl = xmalloc(sizeof(*sl));
			if (!sl)
				exit(1);

			INIT_LIST_HEAD(&sl->list);
			sl->str = xstrdup(optarg);
			if (!sl->str)
				exit(1);

			if (c == 'd')
				list_add(&sl->list, &opts.list_data);
			else
				list_add(&sl->list, &opts.list_data_path);
			break;
		case 'w':
			opts.write_procfs = true;
			break;
		case 'h':
			goto print_help;
			break;
		case 1000:
			opts.use_cpuid_override = true;
			break;
		case 1010:
			opts.cpuid_override_path = optarg;
			break;
		default:
			pr_err("?? getopt returned character code 0%o ??\n", c);
			exit(1);
			break;
		}
	}

	log_set_loglevel(log_level);

	if (optind >= argc)
		goto print_help;

	if (!opts.cpuid_override_path)
		opts.cpuid_override_path = VZ_CPUID_OVERRIDE_PATH_DEFAULT;

	if (opts.use_cpuid_override) {
		if (vz_cpu_parse_cpuid_override(opts.cpuid_override_path))
			exit(1);
	}

	if (!strcmp(argv[optind], "xsave-encode")) {
		if (vzcpuidctl_xsave_encode(&opts))
			exit(1);
	} else if (!strcmp(argv[optind], "xsave-generate")) {
		if (vzcpuidctl_xsave_generate(&opts))
			exit(1);
	}

	list_for_each_entry_safe(s, tmp, &opts.list_data, list) {
		xfree(s->str);
		xfree(s);
	}
	list_for_each_entry_safe(s, tmp, &opts.list_data_path, list)
		xfree(s);
	INIT_LIST_HEAD(&opts.list_data_decoded);
	INIT_LIST_HEAD(&opts.list_data);
	INIT_LIST_HEAD(&opts.list_data_path);

	return 0;

print_help:
	pr_msg(
"Commands\n"
"xsave-encode           Encode xsave related data\n"
"xsave-generate         Generate compatible cpuid_override entries\n"
	);

	return 0;
}
