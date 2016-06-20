/*
 * Rump hypercall interface for LKL
 * Copyright (c) 2015 Hajime Tazaki
 *
 * Author: Hajime Tazaki <thehajime@gmail.com>
 */

#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <time.h>
#include <errno.h>
#include <sys/types.h>

#include <unistd.h>
#include <poll.h>
#include <sys/uio.h>

/* FIXME */
#ifdef RUMPRUN
#define memset rumpns_memset
#endif

#include "rump.h"

#include <lkl_host.h>
#include "iomem.h"


/* FIXME */
#define clock_sleep(a, b, c) __sched_clock_sleep(a, b, c)
int clock_sleep(int clk, int64_t sec, long nsec);

#define container_of(ptr, type, member) \
	(type *)((char *)(ptr) - __builtin_offsetof(type, member))

/* FIXME */
int *__errno(void);
#undef errno
#define errno (*__errno())

#define NSEC_PER_SEC	1000000000L

/* console */
static void rump_print(const char *str, int len)
{
	while (len-- > 0) {
		rumpuser_putchar(*str);
		str++;
	}
}


/* semaphore/mutex */
struct rumpuser_sem {
	struct rumpuser_mtx *lock;
	int count;
	struct rumpuser_cv *cond;
};

struct lkl_mutex_t {
	struct rumpuser_mtx *mutex;
};

struct lkl_sem_t {
	struct rumpuser_sem sem;
};

static struct lkl_sem_t *rump_sem_alloc(int count)
{
	struct lkl_sem_t *sem;

	rumpuser_malloc(sizeof(*sem), 0, (void **)&sem);
	if (!sem)
		return NULL;

	rumpuser_mutex_init(&sem->sem.lock, RUMPUSER_MTX_SPIN);
	sem->sem.count = count;
	rumpuser_cv_init(&sem->sem.cond);

	return sem;
}

static void rump_sem_free(struct lkl_sem_t *_sem)
{
	struct rumpuser_sem *sem = (struct rumpuser_sem *)&_sem->sem;

	rumpuser_cv_destroy(sem->cond);
	rumpuser_mutex_destroy(sem->lock);
	rumpuser_free(sem, 0);
}

static void rump_sem_up(struct lkl_sem_t *_sem)
{
	struct rumpuser_sem *sem = (struct rumpuser_sem *)&_sem->sem;

	rumpuser_mutex_enter(sem->lock);
	sem->count++;
	if (sem->count > 0)
		rumpuser_cv_signal(sem->cond);
	rumpuser_mutex_exit(sem->lock);
}

static void rump_sem_down(struct lkl_sem_t *_sem)
{
	struct rumpuser_sem *sem = (struct rumpuser_sem *)&_sem->sem;

	rumpuser_mutex_enter(sem->lock);
	while (sem->count <= 0)
		rumpuser_cv_wait(sem->cond, sem->lock);
	sem->count--;
	rumpuser_mutex_exit(sem->lock);
}

static int rump_sem_get(struct lkl_sem_t *_sem)
{
	struct rumpuser_sem *sem = (struct rumpuser_sem *)&_sem->sem;
	int v = 0;

	rumpuser_mutex_enter(sem->lock);
	v = sem->count;
	rumpuser_mutex_exit(sem->lock);
	return v;
}

static struct lkl_mutex_t *rump_mutex_alloc(void)
{
	struct lkl_mutex_t *_mutex;

	rumpuser_malloc(sizeof(*_mutex), 0, (void **)&_mutex);
	if (!_mutex)
		return NULL;

	rumpuser_mutex_init(&_mutex->mutex, RUMPUSER_MTX_SPIN);

	return _mutex;
}

static void rump_mutex_lock(struct lkl_mutex_t *_mutex)
{
	rumpuser_mutex_enter(_mutex->mutex);
}

static void rump_mutex_unlock(struct lkl_mutex_t *_mutex)
{
	rumpuser_mutex_exit(_mutex->mutex);
}

static void rump_mutex_free(struct lkl_mutex_t *_mutex)
{
	rumpuser_mutex_destroy(_mutex->mutex);
	rumpuser_free(_mutex, 0);
}

/* XXX: dummy TLS */
static int rump_tls_alloc(unsigned int *key)
{
	return 0;
}

static int rump_tls_free(unsigned int key)
{
	return 0;
}

static int rump_tls_set(unsigned int key, void *data)
{
	rumpuser_curlwpop(RUMPUSER_LWP_SET, (struct lwp *)data);
	return 0;
}

static void *rump_tls_get(unsigned int key)
{
	return rumpuser_curlwp();
}


/* memory */
static void *rump_mem_alloc(size_t size)
{
	void *mem;

	rumpuser_malloc(size, 0, (void **)&mem);
	return mem;
}

static void rump_mem_free(void *mem)
{
	rumpuser_free(mem, 0);
}

/* thread */
static lkl_thread_t thread_create(void (*fn)(void *), void *arg)
{
	void *thrid;
	int ret;

	ret = rumpuser_thread_create((void * (*)(void *))fn, arg,
				     "lkl_thr", 0, 1, -1, &thrid);
	if (ret)
		return 0;

	return (lkl_thread_t) thrid;
}

static void thread_detach(void)
{
	/* NOP */
}

static void thread_exit(void)
{
	rumpuser_thread_exit();
}

/* time/timer */
/* FIXME: should be included from somewhere */
int rumpuser__errtrans(int);

static bool threads_are_go;
static struct rumpuser_mtx *thrmtx;
static struct rumpuser_cv *thrcv;

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

	f(thrarg);

	rumpuser_thread_exit();
end:
	return arg;
}

static void rump_timer_cancel(void *timer)
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
static void rump_thread_allow(struct lwp *l)
{
	rumpuser_mutex_enter(thrmtx);
	if (l == NULL) {
		threads_are_go = true;
	}

	rumpuser_cv_broadcast(thrcv);
	rumpuser_mutex_exit(thrmtx);
}

static unsigned long long time_ns(void)
{
	struct timespec ts;
	rumpuser_clock_gettime(RUMPUSER_CLOCK_RELWALL, (int64_t *)&ts.tv_sec,
			       &ts.tv_nsec);

	return ((unsigned long long) ts.tv_sec * NSEC_PER_SEC) + ts.tv_nsec;
}

static void *timer_alloc(void (*fn)(void *), void *arg)
{
	struct thrdesc *td;

	rumpuser_malloc(sizeof(*td), 0, (void **)&td);

	memset(td, 0, sizeof(*td));
	td->f = fn;
	td->arg = arg;

	rumpuser_mutex_init(&td->mtx, RUMPUSER_MTX_SPIN);
	rumpuser_cv_init(&td->cv);

	return td;
}

static int timer_set_oneshot(void *_timer, unsigned long ns)
{
	int ret;
	struct thrdesc *td = _timer;

	td->timeout = (struct timespec){ .tv_sec = ns / NSEC_PER_SEC,
					 .tv_nsec = ns % NSEC_PER_SEC};
	ret = rumpuser_thread_create(rump_timer_trampoline, td, "timer",
				     0, 0, -1, &td->thrid);

	return ret ? -1 : 0;
}

static void timer_free(void *_timer)
{
	rump_timer_cancel(_timer);
}

static void panic(void)
{
	rumpuser_exit(RUMPUSER_PANIC);
}

extern char lkl_virtio_devs[];
struct lkl_host_operations lkl_host_ops = {
	.panic = panic,
	.thread_create = thread_create,
	.thread_detach = thread_detach,
	.thread_exit = thread_exit,
	.sem_alloc = rump_sem_alloc,
	.sem_free = rump_sem_free,
	.sem_up = rump_sem_up,
	.sem_down = rump_sem_down,
	.sem_get = rump_sem_get,
	.mutex_alloc = rump_mutex_alloc,
	.mutex_free = rump_mutex_free,
	.mutex_lock = rump_mutex_lock,
	.mutex_unlock = rump_mutex_unlock,
	.tls_alloc = rump_tls_alloc,
	.tls_free = rump_tls_free,
	.tls_set = rump_tls_set,
	.tls_get = rump_tls_get,
	.time = time_ns,
	.timer_alloc = timer_alloc,
	.timer_set_oneshot = timer_set_oneshot,
	.timer_free = timer_free,
	.print = rump_print,
	.mem_alloc = rump_mem_alloc,
	.mem_free = rump_mem_free,
	.ioremap = lkl_ioremap,
	.iomem_access = lkl_iomem_access,
	.irq_request = rump_pci_irq_request,
	.irq_release = rump_pci_irq_release,
	.getparam = rumpuser_getparam,
#ifndef RUMPRUN
	.virtio_devices = lkl_virtio_devs,
#endif
};


/* entry/exit points */
#define LKL_MEM_SIZE 100 * 1024 * 1024
char *boot_cmdline = "";	/* FIXME: maybe we have rump_set_boot_cmdline? */
static char buf[256];
static int verbose;

int rump_init(void)
{
	if (rumpuser_init(RUMPUSER_VERSION, &hyp) != 0) {
		rumpuser_dprintf("rumpuser init failed\n");
		return EINVAL;
	}

	rumpuser_mutex_init(&thrmtx, RUMPUSER_MTX_SPIN);
	rumpuser_cv_init(&thrcv);
	threads_are_go = false;

	lkl_start_kernel(&lkl_host_ops, LKL_MEM_SIZE, boot_cmdline);

	rump_thread_allow(NULL);
	/* FIXME: rumprun doesn't have sysproxy.
	 * maybe outsourced and linked -lsysproxy for hijack case ? */
#ifdef ENABLE_SYSPROXY
	rump_sysproxy_init();
#endif
	if (rumpuser_getparam("RUMP_VERBOSE", buf, sizeof(buf)) == 0) {
		if (*buf != 0)
			verbose = 1;
	}

	if (verbose)
		rumpuser_dprintf("rumpuser started.\n");
	return 0;
}

void rump_exit(void)
{
	if (verbose)
		rumpuser_dprintf("rumpuser finishing.\n");

#ifdef ENABLE_SYSPROXY
	rump_sysproxy_fini();
#endif
	rumpuser_exit(0);
}

/* stub calls */
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

int rump___sysimpl_dup2(int i, int j)
{
	return 0;
	return lkl_sys_dup2(i, j);
}
int rump___sysimpl_socket30(int i, int j, int k){return 0;}
int rump___sysimpl_unmount(const char *str, int i){return 0;}
void __assert13(const char *file, int line, const char *function, const char *failedexpr){}
int rump___sysimpl_close(int fd) {return -1;}
int rump___sysimpl_ioctl(int fd, u_long com, void * data) {return -1;}
int rump___sysimpl_mkdir(const char * path, mode_t mode) {return -1;}
int rump___sysimpl_open(const char *name, int flags, ...) {return -1;}

#endif /* RUMP_TEMP_STUB */

#ifdef RUMPRUN
int lkl_netdevs_remove(void)
{
	return 0;
}
#else
/* FIXME */
static __inline long __syscall3(long n, long a1, long a2, long a3)
{
	unsigned long ret;
#ifdef __x86_64__
	__asm__ __volatile__ ("syscall" : "=a"(ret) : "a"(n), "D"(a1), "S"(a2),
						  "d"(a3) : "rcx", "r11", "memory");
#endif
	return ret;
}

#define SYS_lseek				8

static off_t x8664_lseek(int fd, off_t offset, int whence)
{
#ifdef SYS__llseek
	off_t result;
	return syscall(SYS__llseek, fd, offset>>32, offset, &result, whence) ? -1 : result;
#else
	return __syscall3(SYS_lseek, fd, offset, whence);
#endif
}
#define SEEK_SET 0
#define SEEK_CUR 1
#define SEEK_END 2


static int fd_get_capacity(union lkl_disk disk, unsigned long long *res)
{
	off_t off;

	/* FIXME */
	off = x8664_lseek(disk.fd, 0, SEEK_END);
	if (off < 0)
		return -1;

	*res = off;
	return 0;
}

static int blk_request(union lkl_disk disk, struct lkl_blk_req *req)
{
	int err = 0;
	struct iovec *iovec = (struct iovec *)req->buf;

	/* TODO: handle short reads/writes */
	switch (req->type) {
	case LKL_DEV_BLK_TYPE_READ:
		err = preadv(disk.fd, iovec, req->count, req->sector * 512);
		break;
	case LKL_DEV_BLK_TYPE_WRITE:
		err = pwritev(disk.fd, iovec, req->count, req->sector * 512);
		break;
	case LKL_DEV_BLK_TYPE_FLUSH:
	case LKL_DEV_BLK_TYPE_FLUSH_OUT:
#ifdef __linux__
		err = fdatasync(disk.fd);
#else
		err = fsync(disk.fd);
#endif
		break;
	default:
		return LKL_DEV_BLK_STATUS_UNSUP;
	}

	if (err < 0)
		return LKL_DEV_BLK_STATUS_IOERR;

	return LKL_DEV_BLK_STATUS_OK;
}

struct lkl_dev_blk_ops lkl_dev_blk_ops = {
	.get_capacity = fd_get_capacity,
	.request = blk_request,
};

struct lkl_netdev_rumpfd {
	struct lkl_netdev dev;
	/* TAP device */
	int fd;
};

static int net_tx(struct lkl_netdev *nd, void *data, int len)
{
	struct lkl_netdev_rumpfd *nd_rumpfd =
		container_of(nd, struct lkl_netdev_rumpfd, dev);
	int ret;

//	ret = write(nd_rumpfd->fd, data, len);
	ret = writev(nd_rumpfd->fd, (struct iovec *)data, len);
	if (ret <= 0 && errno == -EAGAIN)
		return -1;
	return 0;
}

static int net_rx(struct lkl_netdev *nd, void *data, int *len)
{
	struct lkl_netdev_rumpfd *nd_rumpfd =
		container_of(nd, struct lkl_netdev_rumpfd, dev);
	int ret;

	ret = read(nd_rumpfd->fd, data, *len);
	if (ret <= 0)
		return -1;
	*len = ret;
	return 0;
}

static int net_poll(struct lkl_netdev *nd, int events)
{
	struct lkl_netdev_rumpfd *nd_rumpfd =
		container_of(nd, struct lkl_netdev_rumpfd, dev);
	struct pollfd pfd = {
		.fd = nd_rumpfd->fd,
	};
	int ret = 0;

	if (events & LKL_DEV_NET_POLL_RX)
		pfd.events |= POLLIN;
	if (events & LKL_DEV_NET_POLL_TX)
		pfd.events |= POLLOUT;

	while (1) {
		/* XXX: this should be poll(pfd, 1, -1) but fiber thread
		 * needs to be done like this...
		 */
		int err = poll(&pfd, 1, 0);
		if (err < 0 && errno == EINTR)
			continue;
		if (err > 0)
			break;
		/* will be woken by poll */
		clock_sleep(CLOCK_REALTIME, 10, 0);
	}

	if (pfd.revents & (POLLHUP | POLLNVAL))
		return -1;

	if (pfd.revents & POLLIN)
		ret |= LKL_DEV_NET_POLL_RX;
	if (pfd.revents & POLLOUT)
		ret |= LKL_DEV_NET_POLL_TX;

	return ret;
}

struct lkl_dev_net_ops rumpfd_ops = {
	.tx = net_tx,
	.rx = net_rx,
	.poll = net_poll,
};

struct lkl_netdev *lkl_netdev_rumpfd_create(const char *ifname, int fd)
{
	struct lkl_netdev_rumpfd *nd;

	nd = (struct lkl_netdev_rumpfd *)
		malloc(sizeof(struct lkl_netdev_rumpfd));
	if (!nd) {
		lkl_printf("tap: failed to allocate memory\n");
		return NULL;
	}

	nd->fd = fd;
	nd->dev.ops = &rumpfd_ops;
	return (struct lkl_netdev *)nd;
}
#endif
