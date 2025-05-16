KPATH := ${PWD}/linux/

obj-m := chall1_null_mod.o

all:
	make -C $(KPATH) M=$(PWD) modules

clean:
	make -C $(KPATH) M=$(PWD) clean
	