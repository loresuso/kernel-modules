obj-m:=read-msr.o
all:
	make -C /home/lore/MasterThesis/linux M=$(shell pwd) modules
clean:
	make -C /home/lore/MasterThesis/linux M=$(shell pwd) clean

#all:
#	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

#clean:
#	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
