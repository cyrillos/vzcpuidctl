#ifndef VZCPUIDCTL_XMALLOC_H__
#define VZCPUIDCTL_XMALLOC_H__

#include <stdlib.h>
#include <string.h>

#ifndef pr_err
#error "Macro pr_err is needed."
#endif

#define __xalloc(op, size, ...)						\
	({								\
		void *___p = op( __VA_ARGS__ );				\
		if (!___p) {						\
			pr_err("%s: Can't allocate %li bytes\n",	\
			       __func__, (long)(size));			\
		}							\
		___p;							\
	})

#define xstrdup(str)		__xalloc(strdup, strlen(str) + 1, str)
#define xmalloc(size)		__xalloc(malloc, size, size)
#define xzalloc(size)		__xalloc(calloc, size, 1, size)
#define xrealloc(p, size)	__xalloc(realloc, size, p, size)

#define xfree(p)		free(p)

#define xrealloc_safe(pptr, size)					\
	({								\
		int __ret = -1;						\
		void *new = xrealloc(*pptr, size);			\
		if (new) {						\
			*pptr = new;					\
			__ret = 0;					\
		}							\
		__ret;							\
	 })

#define xmemdup(ptr, size)						\
	({								\
		void *new = xmalloc(size);				\
		if (new)						\
			memcpy(new, ptr, size);				\
		new;							\
	 })

#endif /* VZCPUIDCTL_XMALLOC_H__ */
