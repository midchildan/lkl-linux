/*
 * Rump system call proxy interface for Linux
 * Copyright (c) 2015 Hajime Tazaki
 *
 * Author: Hajime Tazaki <thehajime@gmail.com>
 */

#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>
#include <generated/utsrelease.h>

#include <lkl.h>
#include <lkl_host.h>

#include "rump.h"

int rump_sp_copyin(void *client, int pid, const void *from, void *to, int n)
{
	int ret;

	if (!client) {
		lkl_printf("NULL rump_client\n");
		rumpuser_exit(RUMPUSER_PANIC);
	}

	/* need to disable proxying during proxying */
	lkl_sysproxy_exit(pid);
	ret = rumpuser_sp_copyin(client, from, to, n);
	lkl_sysproxy_enter();

	return ret;
}

int rump_sp_copyout(void *client, int pid, const void *from, void *to, int n)
{
	int ret;

	if (!client) {
		lkl_printf("NULL rump_client\n");
		rumpuser_exit(RUMPUSER_PANIC);
	}

	/* need to disable proxying during proxying */
	lkl_sysproxy_exit(pid);
	ret = rumpuser_sp_copyout(client, from, to, n);
	lkl_sysproxy_enter();

	return ret;
}

int rump_init_server(const char *url)
{
	return rumpuser_sp_init(url, "Linux", UTS_RELEASE, "libos");
}
