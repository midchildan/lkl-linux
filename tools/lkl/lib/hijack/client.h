#ifndef _LKL_CLIENT_INIT_H
#define _LKL_CLIENT_INIT_H

/* XXX: can be included from rumpclient.h */
int rumpclient_syscall(int sysnum, const void *data, size_t dlen,
		       register_t *retval);
int rumpclient_init(void);

#endif /* _LKL_CLIENT_INIT_H */
