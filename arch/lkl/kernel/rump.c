/*
 * Rump hypercall interface for Linux
 * Copyright (c) 2015 Hajime Tazaki
 *
 * Author: Hajime Tazaki <thehajime@gmail.com>
 */

#include <linux/sched.h>
#include <asm/types.h>
#include <asm/unistd.h>
#include <asm/host_ops.h>
#include <asm/syscalls.h>

#include "rump.h"

/* FIXME: should be included from somewhere */
int rumpuser__errtrans(int);

static bool threads_are_go;
static struct rumpuser_mtx *thrmtx;
static struct rumpuser_cv *thrcv;

static struct lwp *rump_libos_lwproc_curlwp(void);
static int rump_libos_lwproc_newlwp(pid_t pid);
static void rump_libos_lwproc_switch(struct lwp *newlwp);
static void rump_libos_lwproc_release(void);
static int rump_libos_lwproc_rfork(void *priv, int flags, const char *comm);

void
rump_schedule(void)
{
}

void
rump_unschedule(void)
{
}

int
rump_daemonize_begin(void)
{
	return 0;
}

int
rump_daemonize_done(int error)
{
	return 0;
}

#define RUMP_TEMP_STUB
#ifdef RUMP_TEMP_STUB
enum rump_etfs_type {
	RUMP_ETFS_REG,
	RUMP_ETFS_BLK,
	RUMP_ETFS_CHR,
	RUMP_ETFS_DIR,
	RUMP_ETFS_DIR_SUBDIRS
};

void rump_boot_setsigmodel(int rump_sigmodel){}
int rump_pub_etfs_register(const char *key, const char *hostpath, enum rump_etfs_type ftype){return 0;}
int rump_pub_etfs_register_withsize(const char *key, const char *hostpath,
	enum rump_etfs_type ftype, uint64_t begin, uint64_t size) {return 0;}
int rump___sysimpl_mount50(const char *str, const char *str2, int i, void *p, size_t s){return 0;}
int rump___sysimpl_dup2(int i, int j){return 0;}
int rump___sysimpl_socket30(int i, int j, int k){return 0;}
int rump___sysimpl_unmount(const char *str, int i){return 0;}
void __assert13(const char *file, int line, const char *function, const char *failedexpr){}
int rump___sysimpl_close(int fd) {return -1;}
int rump___sysimpl_ioctl(int fd, u_long com, void * data) {return -1;}
int rump___sysimpl_mkdir(const char * path, mode_t mode) {return -1;}
int rump___sysimpl_open(const char *name, int flags, ...) {return -1;}

#endif /* RUMP_TEMP_STUB */

int
rump_pub_lwproc_rfork(int arg1)
{
	int rv = 0;

	rump_schedule();
//	rv = rump_libos_lwproc_rfork(arg1);
	rump_unschedule();

	return rv;
}

int
rump_pub_lwproc_newlwp(pid_t arg1)
{
	int rv;

	rump_schedule();
	rv = rump_libos_lwproc_newlwp(arg1);
	rump_unschedule();

	return rv;
}

void
rump_pub_lwproc_switch(struct lwp *arg1)
{

	rump_schedule();
	rump_libos_lwproc_switch(arg1);
	rump_unschedule();
}

void
rump_pub_lwproc_releaselwp(void)
{

	rump_schedule();
	rump_libos_lwproc_release();
	rump_unschedule();
}

struct lwp *
rump_pub_lwproc_curlwp(void)
{
	struct lwp * rv;

	rump_schedule();
	rv = rump_libos_lwproc_curlwp();
	rump_unschedule();

	return rv;
}

int
rump_syscall(int num, void *data, size_t dlen, long *retval)
{
	int ret = 0;

	ret = lkl_syscall(num, (long *)data);
	/* FIXME: need better err translation */
	if (ret < 0) {
		retval[0] = -ret;
		ret = -1;
	}
	return ret;
}


static int
rump_libos_hyp_syscall(int num, void *arg, long *retval)
{
	return rump_syscall(num, arg, 0, retval);
}

static int
rump_libos_lwproc_rfork(void *priv, int flags, const char *comm)
{
	/* FIXME: needs new task_struct instead of get_current() */
	struct thread_info *ti = task_thread_info(get_current());

	/* store struct spc_client */
	ti->rump_client = priv;

	rumpuser_curlwpop(RUMPUSER_LWP_CREATE, (struct lwp *)ti);
	rumpuser_curlwpop(RUMPUSER_LWP_SET, (struct lwp *)ti);

	return 0;
}

static void
rump_libos_lwproc_release(void)
{
	struct thread_info *ti = (struct thread_info *)rumpuser_curlwp();

	rumpuser_curlwpop(RUMPUSER_LWP_CLEAR, (struct lwp *)ti);
}

static void
rump_libos_lwproc_switch(struct lwp *newlwp)
{
	struct thread_info *ti = (struct thread_info *)rumpuser_curlwp();

	rumpuser_curlwpop(RUMPUSER_LWP_CLEAR, (struct lwp *)ti);
	rumpuser_curlwpop(RUMPUSER_LWP_SET, (struct lwp *)ti);
}

/* find rump_task created by rfork */
static int
rump_libos_lwproc_newlwp(pid_t pid)
{
	/* find rump_task */
	struct thread_info *ti = NULL;
	struct task_struct *p;

	for_each_process(p) {
		if (p->pid == pid) {
			ti = task_thread_info(p);
			break;
		}
	}

	if (!ti) {
		pr_warn("newlwp: could not find pid %d\n", pid);
		ti = current_thread_info();
		/* FIXME */
//		return ESRCH;
	}

	/* set to currnet */
	rumpuser_curlwpop(RUMPUSER_LWP_SET, (struct lwp *)ti);

	return 0;
}

static struct lwp *
rump_libos_lwproc_curlwp(void)
{
	return rumpuser_curlwp();
}

static void
rump_libos_hyp_lwpexit(void)
{
	struct thread_info *ti = (struct thread_info *)rumpuser_curlwp();

	rumpuser_curlwpop(RUMPUSER_LWP_DESTROY, (struct lwp *)ti);
	free_thread_info(ti);
}

static pid_t
rump_libos_hyp_getpid(void)
{
	struct thread_info *ti = (struct thread_info *)rumpuser_curlwp();

	return ti->task->pid;
}


static void rump_libos_user_unschedule(int nlocks, int *countp,
				       void *interlock) {}
static void rump_libos_user_schedule(int nlocks, void *interlock) {}
static void rump_libos_hyp_execnotify(const char *comm) {}

static const struct rumpuser_hyperup hyp = {
	.hyp_schedule		= rump_schedule,
	.hyp_unschedule		= rump_unschedule,
	.hyp_backend_unschedule	= rump_libos_user_unschedule,
	.hyp_backend_schedule	= rump_libos_user_schedule,
	.hyp_lwproc_switch	= rump_libos_lwproc_switch,
	.hyp_lwproc_release	= rump_libos_lwproc_release,
	.hyp_lwproc_newlwp	= rump_libos_lwproc_newlwp,
	.hyp_lwproc_curlwp	= rump_libos_lwproc_curlwp,

	.hyp_getpid		= rump_libos_hyp_getpid,
	.hyp_syscall		= rump_libos_hyp_syscall,
	.hyp_lwproc_rfork	= rump_libos_lwproc_rfork,
	.hyp_lwpexit		= rump_libos_hyp_lwpexit,
	.hyp_execnotify		= rump_libos_hyp_execnotify,
};


struct thrdesc {
	void (*f)(void *);
	void *arg;
	int canceled;
	void *thrid;
	struct timespec timeout;
	struct rumpuser_mtx *mtx;
	struct rumpuser_cv *cv;
};

static void *rump_timer_trampoline(void *arg)
{
	struct thrdesc *td = arg;
	void (*f)(void *);
	void *thrarg;
	int err;

	/* from src-netbsd/sys/rump/librump/rumpkern/thread.c */
	/* don't allow threads to run before all CPUs have fully attached */
	if (!threads_are_go) {
		rumpuser_mutex_enter_nowrap(thrmtx);
		while (!threads_are_go) {
			rumpuser_cv_wait_nowrap(thrcv, thrmtx);
		}
		rumpuser_mutex_exit(thrmtx);
	}

	f = td->f;
	thrarg = td->arg;
	if (td->timeout.tv_sec != 0 || td->timeout.tv_nsec != 0) {
		rumpuser_mutex_enter(td->mtx);
		err = rumpuser_cv_timedwait(td->cv, td->mtx,
					    td->timeout.tv_sec,
					    td->timeout.tv_nsec);
		if (td->canceled) {
			if (!td->thrid) {
				rumpuser_free(td, 0);
			}
			goto end;
		}
		rumpuser_mutex_exit(td->mtx);
		/* FIXME: we should not use rumpuser__errtrans here */
		/* FIXME: 60=>ETIMEDOUT(netbsd) rumpuser__errtrans(ETIMEDOUT)) */
		if (err && err != 60)
			goto end;
	}

	rumpuser_free(td, 0);
	f(thrarg);

	rumpuser_thread_exit();
end:
	return arg;
}

void *rump_add_timer(__u64 ns, void (*func) (void *arg), void *arg)
{
	int ret;
	struct thrdesc *td;

	rumpuser_malloc(sizeof(*td), 0, (void **)&td);

	memset(td, 0, sizeof(*td));
	td->f = func;
	td->arg = arg;
	td->timeout = (struct timespec){ .tv_sec = ns / NSEC_PER_SEC,
					 .tv_nsec = ns % NSEC_PER_SEC};

	rumpuser_mutex_init(&td->mtx, RUMPUSER_MTX_SPIN);
	rumpuser_cv_init(&td->cv);

	ret = rumpuser_thread_create(rump_timer_trampoline, td, "timer",
				     1, 0, -1, &td->thrid);
	if (ret) {
		rumpuser_free(td, 0);
		return NULL;
	}

	return td;
}

void rump_timer_cancel(void *timer)
{
	struct thrdesc *td = timer;

	if (td->canceled)
		return;

	td->canceled = 1;
	rumpuser_mutex_enter(td->mtx);
	rumpuser_cv_signal(td->cv);
	rumpuser_mutex_exit(td->mtx);

	rumpuser_mutex_destroy(td->mtx);
	rumpuser_cv_destroy(td->cv);

	if (td->thrid)
		rumpuser_thread_join(td->thrid);

	rumpuser_free(td, 0);
}

/* from src-netbsd/sys/rump/librump/rumpkern/thread.c */
void
rump_thread_allow(struct lwp *l)
{
	rumpuser_mutex_enter(thrmtx);
	if (l == NULL) {
		threads_are_go = true;
	}

	rumpuser_cv_broadcast(thrcv);
	rumpuser_mutex_exit(thrmtx);
}

#define LKL_MEM_SIZE 100 * 1024 * 1024
char *boot_cmdline = "";	/* FIXME: maybe we have rump_set_boot_cmdline? */
int __init rump_init(void)
{
	if (rumpuser_init(RUMPUSER_VERSION, &hyp) != 0) {
		pr_warn("rumpuser init failed\n");
		return EINVAL;
	}

	rumpuser_mutex_init(&thrmtx, RUMPUSER_MTX_SPIN);
	rumpuser_cv_init(&thrcv);
	threads_are_go = false;

	lkl_start_kernel(NULL, LKL_MEM_SIZE, boot_cmdline);

	rump_thread_allow(NULL);
	/* FIXME: rumprun doesn't have sysproxy.
	 * maybe outsourced and linked -lsysproxy for hijack case ? */
#ifdef ENABLE_SYSPROXY
	rump_sysproxy_init();
#endif
	pr_info("rumpuser started.\n");
	return 0;
}

void rump_exit(void)
{
	pr_info("rumpuser finishing.\n");
#ifdef ENABLE_SYSPROXY
	rump_sysproxy_fini();
#endif
	rumpuser_exit(0);
}
