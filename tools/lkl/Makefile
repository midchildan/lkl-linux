CFLAGS := -Iinclude -Wall -g -O2 -Wextra -Wno-unused-parameter \
	  -Wno-missing-field-initializers -fno-strict-aliasing \
	  -U_FORTIFY_SOURCE -fno-stack-protector

ifdef CROSS_COMPILE
CC=$(CROSS_COMPILE)gcc
AR=$(CROSS_COMPILE)ar
LD=$(CROSS_COMPILE)ld
else
CC=gcc
endif

OUTPUT_FORMAT=$(shell $(LD) -r -print-output-format)
RUMP_PREFIX?=$(abspath ../../../rumpobj/)
RUMP_LIB=$(RUMP_PREFIX)/rump/lib

lib_source = $(filter-out %-host.c,$(wildcard lib/*.c))
source = $(wildcard tests/*.c)
lib = lib/liblkl.a lib/liblinux.a
ifneq (,$(filter $(OUTPUT_FORMAT),elf64-x86-64 elf32-i386 elf64-x86-64-freebsd elf32-littlearm))
source += $(wildcard *.c)
lib_source += lib/posix-host.c
CFLAGS += -fPIC
LDFLAGS += -lpthread -lrt -ldl
source += $(wildcard *.c)
execs =  cpfromfs
lib += lib/liblkl.so
else ifeq ($(OUTPUT_FORMAT),pe-i386)
lib_source += lib/nt-host.c
KOPT="KALLSYMS_EXTRA_PASS=1"
else
$(error Unrecognized platform: $(OUTPUT_FORMAT))
endif

ifneq (,$(filter $(OUTPUT_FORMAT),elf64-x86-64 elf64-x86-64-freebsd))
CFLAGS += -D_FILE_OFFSET_BITS=64
endif

# XXX for frankenlibc, only build liblinux.a for now
lib_source =
source =
execs =
lib = lib/liblinux.a

lib_objs = $(patsubst %.c,%.o, $(lib_source))
objs = $(patsubst %.c,%.o, $(source))
execs += $(patsubst %.c,%, $(source))

# if there is no librumpuser.a, then skip execs build
ifeq (,$(wildcard $(RUMP_LIB)/librumpuser*))
execs =
else
LDFLAGS += -L$(RUMP_LIB) -Wl,-rpath,$(RUMP_LIB) -lrumpuser
endif

all: $(lib) $(execs)

install:
	install -D lib/liblinux.a ${DESTDIR}/lib/
	mkdir -p ${DESTDIR}/include/linux/
	install -D ../../arch/lkl/include/linux/rump_syscalls.h \
		${DESTDIR}/include/linux/

lib/liblkl.a: $(lib_objs) lib/lkl.o
	$(AR) -rc $@ $^

lib/liblkl.so: $(lib_objs) lib/lkl.o
	$(CC) -o $@ -shared $^

lib/liblinux.a: lib/lkl.o lib/fs.o
	$(AR) -rc $@ $^

lib/lkl.o:
	$(MAKE) -C ../.. ARCH=lkl defconfig
	$(MAKE) -C ../.. ARCH=lkl $(KOPT) install INSTALL_PATH=$(PWD)

%: %.o
	$(CC) -o $@ $^ $(LDFLAGS)

$(lib_objs): lib/lkl.o
$(objs): lib/lkl.o
$(execs): lib/liblkl.a

clean:
	-rm -rf include/lkl/ $(lib) $(lib_objs) lib/lkl.o $(objs) $(execs)
	$(MAKE) -C ../.. ARCH=lkl clean
	$(MAKE) -C tests clean

fs2tar: LDFLAGS += -larchive
lklfuse: LDFLAGS += -lfuse
ifneq (,$(filter $(OUTPUT_FORMAT),elf64-x86-64-freebsd))
cptofs: LDFLAGS += -largp
fs2tar: LDFLAGS += -largp
endif
cpfromfs: cptofs
	if ! [ -e $@ ]; then ln -s $< $@; fi

test:
	$(MAKE) -C tests

valgrind:
	$(MAKE) -C tests valgrind

.NOTPARALLEL : lib/lkl.o
.PHONY: install
