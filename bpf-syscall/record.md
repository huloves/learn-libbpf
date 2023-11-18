user1							user2
open(char dev)+激活	close(char dev)+未关闭功能	   

insmod(alloc)   rmmod(free mem)
-------------
memory
// ko(open(alloc mem)｜close(free mem))
kernel(panic)

> (维护ko的生存周期)ko->kernel->kprobe(trace_point)->icmp_echo

rust

生命周期 所属权A.c:a_t, B.A.a_t a

unsafe {
	int a, b;
} = c

extern c

rcore(rust + 微内核(进程间通信，功能分配，内核unsafe) + 模块化)

场景

safe(rust) user_program      |   unsafe(c, unsafe rust) kernel
--------------------------   |  ------------------------------
user space mem safely        |             mem(map)

math lib(task)
