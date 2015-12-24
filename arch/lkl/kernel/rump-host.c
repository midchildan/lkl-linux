/*
 * Rump hypercall interface for Linux
 * Copyright (c) 2015 Hajime Tazaki
 *
 * Author: Hajime Tazaki <thehajime@gmail.com>
 */

#include <linux/stddef.h>
#include <linux/types.h>
#include "rump.h"

struct rumpuser_sem {
	struct rumpuser_mtx *lock;
	int count;
	struct rumpuser_cv *cond;
};

void *rump_sem_alloc(int count)
{
	struct rumpuser_sem *sem;

	rumpuser_malloc(sizeof(*sem), 0, (void **)&sem);
	if (!sem)
		return NULL;

	rumpuser_mutex_init(&sem->lock, RUMPUSER_MTX_SPIN);
	sem->count = count;
	rumpuser_cv_init(&sem->cond);

	return sem;
}

void rump_sem_free(void *_sem)
{
	struct rumpuser_sem *sem = (struct rumpuser_sem *)_sem;

	rumpuser_cv_destroy(sem->cond);
	rumpuser_mutex_destroy(sem->lock);
	rumpuser_free(sem, 0);
}

void rump_sem_up(void *_sem)
{
	struct rumpuser_sem *sem = (struct rumpuser_sem *)_sem;

	rumpuser_mutex_enter(sem->lock);
	sem->count++;
	if (sem->count > 0)
		rumpuser_cv_signal(sem->cond);
	rumpuser_mutex_exit(sem->lock);
}

void rump_sem_down(void *_sem)
{
	struct rumpuser_sem *sem = (struct rumpuser_sem *)_sem;

	rumpuser_mutex_enter(sem->lock);
	while (sem->count <= 0)
		rumpuser_cv_wait(sem->cond, sem->lock);
	sem->count--;
	rumpuser_mutex_exit(sem->lock);
}
