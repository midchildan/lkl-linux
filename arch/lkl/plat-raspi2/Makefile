ccflags-y += -I$(srctree)/arch/arm/include

obj-y += raspi2.o subarch.o
subarch-$(CONFIG_OF) += devtree.o board_bcm2835.o

$(obj)/devtree.c: $(srctree)/arch/arm/kernel/devtree.c
	$(call cmd,shipped)

$(obj)/board_bcm2835.c: $(srctree)/arch/arm/mach-bcm/board_bcm2835.c
	$(call cmd,shipped)

$(obj)/dts: $(srctree)/arch/arm/boot/dts
	$(call cmd,shipped)

archheaders:
	$(Q)$(MAKE) KBUILD_SRC= ARCH=arm archheaders

archprepare:
	$(Q)$(MAKE) $(build)=arch/arm/tools kapi

%.dtb: | scripts
	$(Q)$(MAKE) $(build)=arch/arm/boot/dts MACHINE=arch/arm/mach-bcm arch/arm/boot/dts/$@

PHONY += dtbs dtbs_install

dtbs: prepare scripts
	$(Q)$(MAKE) $(build)=arch/arm/boot/dts

dtbs_install:
	$(Q)$(MAKE) $(dtbinst)=arch/arm/boot/dts

subdir := dts
