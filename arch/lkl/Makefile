include arch/lkl/auto.conf

KBUILD_CFLAGS += -fno-builtin

ifeq ($(DEBUG),yes)
# This will make liblkl.a huge (180MB~?)
CFLAGS_KERNEL += -g3 -DDEBUG
endif

ifneq (,$(filter $(OUTPUT_FORMAT),elf64-x86-64 elf64-x86-64-freebsd elf32-littlearm))
KBUILD_CFLAGS += -fPIC
else ifeq ($(OUTPUT_FORMAT),pe-i386)
prefix=_
# workaround for #include_next<stdarg.h> errors
LINUXINCLUDE := -isystem arch/lkl/include/system $(LINUXINCLUDE)
else
$(error Unrecognized platform: $(OUTPUT_FORMAT))
endif

ifeq ($(OUTPUT_FORMAT),elf32-littlearm)
CFLAGS_ABI      :=-mabi=aapcs-linux -mno-thumb-interwork -mfpu=vfp
KBUILD_CFLAGS += $(CFLAGS_ABI)
endif

ifneq (,$(filter $(OUTPUT_FORMAT),elf64-x86-64-freebsd))
NPROC=$(shell sysctl -n hw.ncpu)
else
NPROC=$(shell nproc)
endif

# rump libraries
RUMP_PREFIX?=$(abspath $(srctree)/../librumpuser)
RUMP_INCLUDE?=$(RUMP_PREFIX)/
ifneq ($(wildcard $(RUMP_PREFIX)/.),)
KBUILD_CFLAGS += -I$(RUMP_INCLUDE) -DRUMPUSER -DLIBRUMPUSER -D_KERNEL
KBUILD_CFLAGS += -isystem $(RUMP_INCLUDE)
else
$(error "Couldn't found $(RUMP_PREFIX)")
endif

KBUILD_CFLAGS += -Iarch/lkl/kernel

LDFLAGS_vmlinux += -r
LKL_ENTRY_POINTS := lkl_start_kernel lkl_sys_halt lkl_syscall lkl_trigger_irq \
	lkl_get_free_irq lkl_put_irq rump_init

core-y += arch/lkl/kernel/
core-y += arch/lkl/drivers/

# objcopy trick is taken from rumpkernel
GCCSYMBOLS=__umoddi3|__udivdi3|__aeabi_idiv|__aeabi_idivmod|__aeabi_llsl|__aeabi_llsr|__aeabi_uidiv|__aeabi_uidivmod|__aeabi_uldivmod
VMLINUX_SYMS=__start___ex_table|__stop___ex_table|boot_cmdline
EXP_SYMRENAME=rump|RUMP|bmk_|lib_|nuse_|lkl_|__tls|__initcall_start|__initcall_end|__gcov|_end|_GLOBAL_OFFSET_TABLE|${GCCSYMBOLS}'${_SYMQUIRK}'${RUMP_SYM_NORENAME:D|${RUMP_SYM_NORENAME}}|${VMLINUX_SYMS}|__assert13

define make_ns_symbols
	${Q}echo "  OBJCPY	" $1 $2;	\
	${NM} -go $1 | awk ' 	\
	$$NF!~/^'${_PQ}'(${EXP_SYMRENAME})/ \
	{s=$$NF;sub(/^'${_PQ}'/, "&rumpns_", s); print $$NF, s}'\
	| sort | uniq  > $2.renametab; \
	$(OBJCOPY) -R .eh_frame -L __start___ex_table -L __stop___ex_table --preserve-dates \
	 --redefine-syms $2.renametab $1 $2; \
	rm -f $2.renametab
endef


all: lkl.o

lkl.o: vmlinux
	$(call make_ns_symbols,vmlinux,lkl.o)

arch/lkl/include/generated/uapi/asm/syscall_defs.h: vmlinux
	$(OBJCOPY) -j .syscall_defs -O binary --set-section-flags .syscall_defs=alloc $< $@

install: lkl.o __headers arch/lkl/include/generated/uapi/asm/syscall_defs.h
	@echo "  INSTALL	$(INSTALL_PATH)/lib/lkl.o"
	@cp lkl.o $(INSTALL_PATH)/lib/
	@$(srctree)/arch/lkl/scripts/headers_install.py \
		$(subst -j,-j$(NPROC),$(findstring -j,$(MAKEFLAGS))) \
		$(INSTALL_PATH)/include

archclean:
	$(Q)$(MAKE) $(clean)=$(boot)

define archhelp
  echo '  install	- Install library and headers to INSTALL_PATH/{lib,include}'
endef



