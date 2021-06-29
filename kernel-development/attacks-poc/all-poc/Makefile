ifneq ($(KERNELRELEASE),)
obj-m	:= attack.o
else
KDIR ?= /home/lore/MasterThesis/linux
all:
	make -C $(KDIR) M=$(shell pwd) modules
clean:
	make -C $(KDIR) M=$(shell pwd) clean

#all-host:
# make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

#clean-host:
#	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
endif