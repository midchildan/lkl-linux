#include <linux/init.h>
#include <linux/of_platform.h>
#include <linux/of_fdt.h>
#include <linux/psci.h>

// lkl
#include <asm/host_ops.h>

// arm
#include <asm/cputype.h>
#include <asm/mach/arch.h>
#include <asm/prom.h>

unsigned int __machine_arch_type __read_mostly;
EXPORT_SYMBOL(__machine_arch_type);

unsigned int __atags_pointer __initdata;
const struct machine_desc *machine_desc __initdata;
u32 __cpu_logical_map[NR_CPUS] = { [0 ... NR_CPUS-1] = MPIDR_INVALID };

void __init lkl_setup_host(void)
{
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
