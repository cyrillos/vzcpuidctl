#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <getopt.h>

#include "log.h"
#include "cpu.h"
#include "cpuidctl.h"
#include "xmalloc.h"

opts_t opts;

static void opts_init(opts_t *opts)
{
	memset(opts, 0, sizeof(*opts));

	INIT_LIST_HEAD(&opts->list_data_decoded);
	INIT_LIST_HEAD(&opts->list_data);
	INIT_LIST_HEAD(&opts->list_data_path);

	opts->sync_mode = SYNC_MODE_FPU;
	opts->log_level = DEFAULT_LOGLEVEL;
}

static void opts_fini(opts_t *opts)
{
	str_entry_t *s, *tmp;

	list_for_each_entry_safe(s, tmp, &opts->list_data, list) {
		xfree(s->str);
		xfree(s);
	}

	list_for_each_entry_safe(s, tmp, &opts->list_data_path, list)
		xfree(s);

	opts_init(opts);
}

int main(int argc, char *argv[])
{
	static struct option long_opts[] = {
		{"verbosity",		optional_argument,	0,	'v' },
		{"help",		no_argument,		0,	'h' },
		{"data",		required_argument,	0,	'd' },
		{"data-file",		required_argument,	0,	'f' },
		{"output",		required_argument,	0,	'o' },
		{"sync-mode",		required_argument,	0,	'm' },
		{"use-cpuid-override",	no_argument,		0,	1000 },
		{"cpuid-override-path",	required_argument,	0,	1010 },
		{"write-cpuid-override",no_argument,		0,	1020 },
		{"log-file",		required_argument,	0,	1030 },
		{ },
	};
	int log_level = LOG_DEBUG;
	int ret = 1;

	if (argc < 2) {
		goto print_help;
		exit(1);
	}

	opts_init(&opts);

	while (1) {
		int opt_index = 0;
		str_entry_t *sl;

		int c = getopt_long(argc, argv, "hv:d:o:f:m:", long_opts, &opt_index);
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
		case 'm':
			if (!strcmp(optarg, "fpu")) {
				opts.sync_mode = SYNC_MODE_FPU;
			} else {
				pr_err("Only 'fpu' mode is supported\n");
				exit(1);
			}
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
		case 'h':
			goto print_help;
			break;
		case 1000:
			opts.parse_cpuid_override = true;
			break;
		case 1010:
			opts.cpuid_override_path = optarg;
			break;
		case 1020:
			opts.write_cpuid_override = true;
			break;
		case 1030:
			opts.log_path = optarg;
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

	if (opts.log_path && log_open(opts.log_path))
		goto out;

	if (!opts.cpuid_override_path)
		opts.cpuid_override_path = CPUID_OVERRIDE_PATH_DEFAULT;

	if (opts.parse_cpuid_override) {
		if (cpuid_override_init(opts.cpuid_override_path))
			goto out;
		cpuid_register(&cpuid_ops_override);
	} else
		cpuid_register(&cpuid_ops_native);

	if (!strcmp(argv[optind], "xsave-encode")) {
		if (cpuidctl_xsave_encode(&opts))
			goto out;
	} else if (!strcmp(argv[optind], "xsave-generate")) {
		if (cpuidctl_xsave_generate(&opts))
			goto out;
	}

	ret = 0;
out:
	if (opts.parse_cpuid_override)
		cpuid_override_fini();
	log_close();
	opts_fini(&opts);
	return ret;

print_help:
	pr_msg(
"Commands\n"
"       xsave-encode    Encode xsave related data\n"
"       xsave-generate  Generate compatible cpuid_override entries\n"
"\n"
"Common options\n"
"       -v[level]       Verbosity level, [0-4]. Default: 4\n"
"       --log-file PATH Use PATH for log records output\n"
"       -h,--help       Print this help\n"
"\n"
"Options for xsave-encode command\n"
"  --cpuid-override-path PATH\n"
"       Use PATH for system cpuid_override procfs,\n"
"       instead of " CPUID_OVERRIDE_PATH_DEFAULT "\n"
"  --use-cpuid-override\n"
"       When parsing cpuid consider already masked values in cpuid_override procfs,\n"
"       otherwise native cpuid calls are used\n"
"  -o,--output FILE\n"
"       Write encoded data into a FILE\n"
"\n"
"Options for xsave-generate command\n"
"  --cpuid-override-path PATH\n"
"       Use PATH for system cpuid_override procfs,\n"
"       instead of " CPUID_OVERRIDE_PATH_DEFAULT "\n"
"  -d,--data STRING\n"
"       Use STRING as encoded data previously generated with xsave-encode\n"
"  -f,--data-file PATH\n"
"       Read encoded data from PATH file\n"
"  -o,--output PATH\n"
"       Write generated entries into PATH\n"
"  --write-cpuid-override\n"
"       Write generated entries into system cpuid_override\n"
"  -m,--sync-mode MODE\n"
"       When generating entries consider MODE related entires only.\n"
"       Supported modes are: fpu. Default: fpu\n"
	);

	return 0;
}
