CFLAGS  := -O0

obj-m:=fx-driver.o
all:
	make -C /home/lore/MasterThesis/linux M=$(shell pwd) modules
clean:
	make -C /home/lore/MasterThesis/linux M=$(shell pwd) clean
