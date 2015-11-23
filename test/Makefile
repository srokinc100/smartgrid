MODULE_NAME := nsr_lac

EXTRA_CFLAGS += -I$(src)

ifeq ($(KERNELRELEASE),)
# 'Out-of-kernel' part

MODULE_SOURCES := \
	core.c \
	module.c \
	security.c \
	symbols.c \
	kernfunc.c \
	sysctl.c \
	hijacks.c


#KBUILD_DIR=$(shell sh ./scripts/find_kernel_src.sh)
KBUILD_DIR?=/lib/modules/$(shell uname -r)/build
UNAME=$(shell uname -r)
PWD := $(shell pwd)

all: $(MODULE_NAME).ko

$(MODULE_NAME).ko: $(MODULE_SOURCES)

	$(MAKE) -C $(KBUILD_DIR) M=$(PWD) modules

install: install_files

	rmmod $(MODULE_NAME) || :
	modprobe $(MODULE_NAME)

tarball:

	sh ./scripts/make_tarball.sh

clean:
	$(MAKE) -C $(KBUILD_DIR) M=$(PWD) clean

	rm -f Module* $(TESTS) tests.out

.PHONY: all clean tarball

else
# KBuild part. 
# It is used by the kernel build system to actually build the module.
ccflags-y :=  -I$(src)

obj-m := $(MODULE_NAME).o
$(MODULE_NAME)-y := \
	core.o \
	module.o \
	security.o \
	symbols.o \
	kernfunc.o \
	sysctl.o \
	hijacks.o

endif
