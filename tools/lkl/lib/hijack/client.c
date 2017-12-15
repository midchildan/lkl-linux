#include <lkl.h>
#include <lkl_host.h>
#include "xlate.h"
#include "client.h"

int lkl_running;

void __attribute__((constructor(102)))
client_init(void)
{
	int i, ret;

	rumpclient_init();
	lkl_running = 1;

	/* fillup FDs up to LKL_FD_OFFSET */
	for (i = 3; i < LKL_FD_OFFSET; i++) {
		ret = lkl_sys_dup(0);
		if (ret > LKL_FD_OFFSET) {
			lkl_sys_close(ret);
			break;
		}
	}
}

void __attribute__((destructor))
client_fini(void)
{
}


long lkl_syscall(long no, long *params)
{
	long retval[2];

	rumpclient_syscall(no, params, sizeof(params)*6, retval);
	return lkl_set_errno(retval[0]);
}
