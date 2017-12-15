#ifndef _ASM_LKL_UACCESS_H
#define _ASM_LKL_UACCESS_H

#include <linux/compiler.h>
#include <linux/types.h>
#include <linux/irqflags.h>
#include <linux/string.h>
#include <asm/errno.h>
#include <asm/thread_info.h>

#define __access_ok(addr, size) (1)

/* handle rump remote client */
static inline __must_check long raw_copy_from_user(void *to,
		const void __user *from, unsigned long n)
{
	int error = 0;
	struct thread_info *ti;

	ti = current_thread_info();

	if (unlikely(from == NULL && n))
		return n;

	if (!ti->rump.remote) /* local case */
		memcpy(to, from, n);
	else /* remote case */
		error = lkl_ops->sp_copyin(ti->rump.client, ti->task->pid,
					   from, to, n);

	return error;
}

static inline __must_check long raw_copy_to_user(void __user *to,
		const void *from, unsigned long n)
{
	int error = 0;
	struct thread_info *ti;

	ti = current_thread_info();

	if (unlikely(to == NULL && n))
		return n;

	if (!ti->rump.remote) /* local case */
		memcpy(to, from, n);
	else /* remote case */
		error = lkl_ops->sp_copyout(ti->rump.client, ti->task->pid,
					    from, to, n);

	return error;
}

#include <asm-generic/uaccess.h>

#endif /* _ASM_LKL_UACCESS_H */
