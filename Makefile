obj-m += chaindbg.o

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

install:
	cp chaindbg.ko /lib/modules/$(shell uname -r)/misc
	depmod /lib/modules/$(shell uname -r)/misc/chaindbg.ko


clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
