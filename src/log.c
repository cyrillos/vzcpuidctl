#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <errno.h>
#include <unistd.h>
#include <stdbool.h>

#include "compiler.h"
#include "log.h"

#define DEFAULT_LOGFD		STDERR_FILENO
#define LOG_BUF_LEN		(8 * 1024)

static unsigned int current_loglevel = DEFAULT_LOGLEVEL;
static char buffer[LOG_BUF_LEN];

static int log_get_fd(void)
{
	return DEFAULT_LOGFD;
}

void log_set_loglevel(unsigned int level)
{
	current_loglevel = level;
}

unsigned int log_get_loglevel(void)
{
	return current_loglevel;
}

void vprint_on_level(unsigned int loglevel, const char *format, va_list params)
{
	int fd, size, ret, off = 0;
	int _errno = errno;

	if (unlikely(loglevel == LOG_MSG)) {
		fd = STDOUT_FILENO;
	} else {
		if (loglevel > current_loglevel)
			return;
		fd = log_get_fd();
	}

	size = vsnprintf(buffer, sizeof(buffer), format, params);
	while (off < size) {
		ret = write(fd, buffer + off, size - off);
		if (ret <= 0)
			break;
		off += ret;
	}

	errno =  _errno;
}

void print_on_level(unsigned int loglevel, const char *format, ...)
{
	va_list params;

	va_start(params, format);
	vprint_on_level(loglevel, format, params);
	va_end(params);
}
