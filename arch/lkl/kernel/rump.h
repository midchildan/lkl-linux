/*
 * Rump hypercall interface for Linux
 * Copyright (c) 2015 Hajime Tazaki
 *
 * Author: Hajime Tazaki <thehajime@gmail.com>
 */

#define __dead
#define __printflike(x,y)
#include <rump/rumpuser.h>

struct irq_data;

void *rump_sem_alloc(int count);
void rump_sem_free(void *sem);
void rump_sem_up(void *_sem);
void rump_sem_down(void *_sem);

int rump_init(void);
void rump_exit(void);

void rump_sysproxy_init(void);
void rump_sysproxy_fini(void);

void *rump_add_timer(__u64 ns, void (*func) (void *arg), void *arg);
void rump_timer_cancel(void *timer);

int rump_pci_irq_request(struct irq_data *data);
void rump_pci_irq_release(struct irq_data *data);
