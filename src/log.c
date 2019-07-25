#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <errno.h>
#include <unistd.h>
#include <stdbool.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include "compiler.h"
#include "log.h"

#define LOG_BUF_LEN		(8 * 1024)
#define DEFAULT_LOG_FD		STDERR_FILENO

static unsigned int current_loglevel = DEFAULT_LOGLEVEL;
static int current_fd = DEFAULT_LOG_FD;
static char buffer[LOG_BUF_LEN];

int log_open(const char *path)
{
	int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
	if (fd <= 0) {
		pr_perror("Can't open %s", path);
		return -1;
	}
	current_fd = fd;

	return 0;
}

void log_close(void)
{
	if (current_fd != DEFAULT_LOG_FD) {
		close(current_fd);
		current_fd = DEFAULT_LOG_FD;
	}
}

static int log_get_fd(void)
{
	return current_fd;
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
