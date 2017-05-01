/*
 * Rump hypercall interface for Linux
 * Copyright (c) 2015 Hajime Tazaki
 *
 * Author: Hajime Tazaki <thehajime@gmail.com>
 */

#ifndef __dead
#define __dead
#endif
#ifndef __printflike
#define __printflike(x, y)
#endif
#include <rump/rumpuser.h>

struct irq_data;

void rump_exit(void);

extern const struct rumpuser_hyperup hyp;

int rump_pci_irq_request(struct irq_data *data);
void rump_pci_irq_release(struct irq_data *data);

int rump_sp_copyin(void *client, int pid, const void *from, void *to, int n);
int rump_sp_copyout(void *client, int pid, const void *from, void *to, int n);

/* updated rumpuser hypcall */
void *rumpuser_thread_self(void);
void *rumpuser_getcookie(void);
void rumpuser_setcookie(void* cookie);
