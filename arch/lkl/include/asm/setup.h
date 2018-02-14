#ifndef _ASM_LKL_SETUP_H
#define _ASM_LKL_SETUP_H

#define COMMAND_LINE_SIZE 4096

#ifdef CONFIG_LKL_ARCH_ARM
#define early_print(args...) printk(args)
#define dump_machine_table() do {} while (0)
#endif

#endif
