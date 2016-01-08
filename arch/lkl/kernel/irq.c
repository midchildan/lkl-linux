#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/irq.h>
#include <linux/hardirq.h>
#include <asm/irq_regs.h>
#include <linux/sched.h>
#include <linux/seq_file.h>
#include <linux/tick.h>
#include <asm/irqflags.h>
#include <asm/host_ops.h>

#include "rump.h"
static bool irqs_enabled;
static bool irqs_triggered;

static struct irq_info {
	const char *user;
	bool triggered;
} irqs[NR_IRQS];

/**
 * DO NOT run any linux calls (e.g. printk) here as they may race with the
 * existing linux threads.
 */
int lkl_trigger_irq(int irq, void *data)
{
	int ret = 0;

	if (irq >= NR_IRQS)
		return -EINVAL;

	irqs[irq].triggered = true;
	__sync_synchronize();
	irqs_triggered = true;

	wakeup_cpu();

	return ret;
}

static void run_irqs(void)
{
	int i;

	if (!__sync_fetch_and_and(&irqs_triggered, 0))
		return;

	for (i = 1; i < NR_IRQS; i++) {
		if (__sync_fetch_and_and(&irqs[i].triggered, 0)) {
			irq_enter();
			generic_handle_irq(i);
			irq_exit();
		}
	}
}

int show_interrupts(struct seq_file *p, void *v)
{
	return 0;
}

int lkl_get_free_irq(const char *user)
{
	int i;
	int ret = -EBUSY;

	/* 0 is not a valid IRQ */
	for (i = 1; i < NR_IRQS; i++) {
		if (!irqs[i].user) {
			irqs[i].user = user;
			ret = i;
			break;
		}
	}

	return ret;
}

void lkl_put_irq(int i, const char *user)
{
	if (!irqs[i].user || strcmp(irqs[i].user, user) != 0) {
		WARN("%s tried to release %s's irq %d", user, irqs[i].user, i);
		return;
	}

	irqs[i].user = NULL;
}

unsigned long arch_local_save_flags(void)
{
	return irqs_enabled;
}

void arch_local_irq_restore(unsigned long flags)
{
	if (flags == ARCH_IRQ_ENABLED && irqs_enabled == ARCH_IRQ_DISABLED &&
	    !in_interrupt())
		run_irqs();
	irqs_enabled = flags;
}

static int lkl_irq_request_resource(struct irq_data *data)
{
	return rump_pci_irq_request(data);
}

static void lkl_irq_release_resource(struct irq_data *data)
{
	rump_pci_irq_release(data);
}

static void noop(struct irq_data *data) { }
static unsigned int noop_ret(struct irq_data *data)
{
	return 0;
}

struct irq_chip dummy_lkl_irq_chip = {
	.name		= "lkl_dummy",
	.irq_startup	= noop_ret,
	.irq_shutdown	= noop,
	.irq_enable	= noop,
	.irq_disable	= noop,
	.irq_ack	= noop,
	.irq_mask	= noop,
	.irq_unmask	= noop,
	.irq_request_resources = lkl_irq_request_resource,
	.irq_release_resources = lkl_irq_release_resource,
	.flags		= IRQCHIP_SKIP_SET_WAKE,
};

void init_IRQ(void)
{
	int i;

	for (i = 0; i < NR_IRQS; i++)
		irq_set_chip_and_handler(i, &dummy_lkl_irq_chip, handle_simple_irq);

	pr_info("lkl: irqs initialized\n");
}

void cpu_yield_to_irqs(void)
{
	cpu_relax();
}
