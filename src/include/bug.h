#ifndef VZCPUIDCTL_BUG_H__
#define VZCPUIDCTL_BUG_H__

#include <signal.h>
#include <stdbool.h>

#include "compiler.h"

#ifndef BUG_ON_HANDLER
#define __raise() raise(SIGABRT)

#ifndef __clang_analyzer__
# ifndef pr_err
#  error pr_err macro must be defined
# endif
# define BUG_ON_HANDLER(condition)							\
	do {										\
		if ((condition)) {							\
			pr_err("BUG at %s:%d\n", __FILE__, __LINE__);			\
			__raise();							\
			*(volatile unsigned long *)NULL = 0xdead0000 + __LINE__;	\
		}									\
	} while (0)
#else
# define BUG_ON_HANDLER(condition)	\
	do {				\
		assert(!condition);	\
	} while (0)
#endif

#endif /* BUG_ON_HANDLER */

#define BUG_ON(condition)	BUG_ON_HANDLER((condition))
#define BUG()			BUG_ON(true)

#endif /* VZCPUIDCTL_BUG_H__ */
