/*
 * Rump hypercall interface for Linux
 * Copyright (c) 2015 Hajime Tazaki
 *
 * Author: Hajime Tazaki <thehajime@gmail.com>
 */

#include <stdint.h>
#include <sys/types.h>

#include "rump.h"

#include <lkl.h>
#include <lkl_host.h>

static struct lwp *rump_lkl_lwproc_curlwp(void);
static int rump_lkl_lwproc_newlwp(pid_t pid);
static void rump_lkl_lwproc_switch(struct lwp *newlwp);
static void rump_lkl_lwproc_release(void);
static int rump_lkl_lwproc_rfork(void *priv, int flags, const char *comm);

void rump_schedule(void)
{
}

void rump_unschedule(void)
{
}

int rump_daemonize_begin(void)
{
	return 0;
}

int rump_daemonize_done(int error)
{
	return 0;
}


int rump_pub_lwproc_rfork(int arg1)
{
	int rv = 0;

	rump_schedule();
	rv = rump_lkl_lwproc_rfork(NULL, arg1, NULL);
	rump_unschedule();

	return rv;
}

int rump_pub_lwproc_newlwp(pid_t arg1)
{
	int rv;

	rump_schedule();
	rv = rump_lkl_lwproc_newlwp(arg1);
	rump_unschedule();

	return rv;
}

void rump_pub_lwproc_switch(struct lwp *arg1)
{

	rump_schedule();
	rump_lkl_lwproc_switch(arg1);
	rump_unschedule();
}

void rump_pub_lwproc_releaselwp(void)
{

	rump_schedule();
	rump_lkl_lwproc_release();
	rump_unschedule();
}

struct lwp *rump_pub_lwproc_curlwp(void)
{
	struct lwp *rv;

	rump_schedule();
	rv = rump_lkl_lwproc_curlwp();
	rump_unschedule();

	return rv;
}

int rump_syscall(int num, void *data, long *retval)
{
	int ret = 0;
	pid_t pid;

	pid = lkl_sysproxy_enter();
	ret = lkl_syscall(num, (long *)data);
	lkl_sysproxy_exit(pid);

	/* FIXME: need better err translation */
	if (ret < 0) {
		retval[0] = ret;
		ret = -1;
	} else {
		retval[0] = ret;
		ret = 0;
	}
	return ret;
}

static int rump_lkl_lwproc_rfork(void *priv, int flags, const char *comm)
{
	void *task;

	if (!priv)
		return 0;

	task = lkl_sysproxy_fork(priv);

	rumpuser_curlwpop(RUMPUSER_LWP_CLEAR, rumpuser_curlwp());
	rumpuser_curlwpop(RUMPUSER_LWP_SET, (struct lwp *)task);
	return 0;
}

static void rump_lkl_lwproc_release(void)
{
	void *task = rumpuser_curlwp();

	rumpuser_curlwpop(RUMPUSER_LWP_CLEAR, (struct lwp *)task);
}

static void rump_lkl_lwproc_switch(struct lwp *newlwp)
{
	void *task = rumpuser_curlwp();

	rumpuser_curlwpop(RUMPUSER_LWP_CLEAR, (struct lwp *)task);
	rumpuser_curlwpop(RUMPUSER_LWP_SET, (struct lwp *)newlwp);
}

/* find rump_task created by rfork */
static int rump_lkl_lwproc_newlwp(pid_t pid)
{
	void *task;

	task = lkl_sysproxy_newlwp(pid);
	/* set to currnet */
	rumpuser_curlwpop(RUMPUSER_LWP_CLEAR, rumpuser_curlwp());
	rumpuser_curlwpop(RUMPUSER_LWP_SET, (struct lwp *)task);

	return 0;
}

static struct lwp *rump_lkl_lwproc_curlwp(void)
{
	return rumpuser_curlwp();
}

static void rump_lkl_hyp_lwpexit(void)
{
	void *task = rumpuser_curlwp();

	rumpuser_curlwpop(RUMPUSER_LWP_DESTROY, (struct lwp *)task);
	lkl_sysproxy_lwpexit(task);
}

static pid_t loc_pid = 1000;
static pid_t rump_lkl_hyp_getpid(void)
{
	void *task = (struct thread_info *)rumpuser_curlwp();

	return task ? lkl_sysproxy_getpid(task) : loc_pid++;
}

static void rump_lkl_user_unschedule(int nlocks, int *countp,
				     void *interlock)
{
}

static void rump_lkl_user_schedule(int nlocks, void *interlock)
{
}

static void rump_lkl_hyp_execnotify(const char *comm)
{
}

const struct rumpuser_hyperup hyp = {
	.hyp_schedule		= rump_schedule,
	.hyp_unschedule		= rump_unschedule,
	.hyp_backend_unschedule	= rump_lkl_user_unschedule,
	.hyp_backend_schedule	= rump_lkl_user_schedule,

	.hyp_lwproc_switch	= rump_lkl_lwproc_switch,
	.hyp_lwproc_release	= rump_lkl_lwproc_release,
	.hyp_lwproc_newlwp	= rump_lkl_lwproc_newlwp,
	.hyp_lwproc_curlwp	= rump_lkl_lwproc_curlwp,

	.hyp_getpid		= rump_lkl_hyp_getpid,
	.hyp_syscall		= rump_syscall,
	.hyp_lwproc_rfork	= rump_lkl_lwproc_rfork,
	.hyp_lwpexit		= rump_lkl_hyp_lwpexit,
	.hyp_execnotify		= rump_lkl_hyp_execnotify,
};

