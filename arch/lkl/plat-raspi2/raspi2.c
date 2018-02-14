#include <linux/init.h>
#include <linux/of_platform.h>
#include <linux/of_fdt.h>
#include <linux/psci.h>

// lkl
#include <asm/host_ops.h>

// arm
#include <asm/mach/arch.h>
#include <asm/prom.h>

extern unsigned int __atags_pointer;
const struct machine_desc *machine_desc __initdata;

void __init lkl_setup_host(void) {
	const struct machine_desc *mdesc;
	mdesc = setup_machine_fdt(__atags_pointer);
	machine_desc = mdesc;
	dump_stack_set_arch_desc("%s", mdesc->name);

	unflatten_device_tree();
	arm_dt_init_cpu_maps();
	psci_dt_init();

	if (mdesc->init_early) {
		mdesc->init_early();
	}
}
