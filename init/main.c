/*
 *  linux/init/main.c
 *
 *  Copyright (C) 1991, 1992  Linus Torvalds
 */

#include <stdarg.h>
#include <linux/version.h>

#if LINUX_VERSION_CODE > KERNEL_VERSION(3, 3, 0)
#include <asm/switch_to.h>
#else
#include <asm/system.h>
#endif


#include <asm/io.h>

#include <linux/types.h>
#include <linux/fcntl.h>
#include <linux/config.h>
#include <linux/sched.h>
#include <linux/tty.h>
#include <linux/head.h>
#include <linux/unistd.h>
#include <linux/string.h>
#include <linux/timer.h>
#include <linux/fs.h>
#include <linux/ctype.h>
#include <linux/delay.h>
#include <linux/utsname.h>
#include <linux/ioport.h>

extern unsigned long * prof_buffer;
extern unsigned long prof_len;
extern char edata, end;
extern char *linux_banner;
asmlinkage void lcall7(void);
struct desc_struct default_ldt;

/*
 * we need this inline - forking from kernel space will result
 * in NO COPY ON WRITE (!!!), until an execve is executed. This
 * is no problem, but for the stack. This is handled by not letting
 * main() use the stack at all after fork(). Thus, no function
 * calls - which means inline code for fork too, as otherwise we
 * would use the stack upon exit from 'fork()'.
 *
 * Actually only pause and fork are needed inline, so that there
 * won't be any messing with the stack from main(), but we define
 * some others too.
 */
#define __NR__exit __NR_exit
static inline _syscall0(int,idle)
static inline _syscall0(int,fork)
static inline _syscall0(int,pause)
static inline _syscall1(int,setup,void *,BIOS)
static inline _syscall0(int,sync)
static inline _syscall0(pid_t,setsid)
static inline _syscall3(int,write,int,fd,const char *,buf,off_t,count)
static inline _syscall1(int,dup,int,fd)
static inline _syscall3(int,execve,const char *,file,char **,argv,char **,envp)
static inline _syscall3(int,open,const char *,file,int,flag,int,mode)
static inline _syscall1(int,close,int,fd)
static inline _syscall1(int,_exit,int,exitcode)
static inline _syscall3(pid_t,waitpid,pid_t,pid,int *,wait_stat,int,options)

static inline pid_t wait(int * wait_stat)
{
	return waitpid(-1,wait_stat,0);
}

static char printbuf[1024];

extern int console_loglevel;

extern char empty_zero_page[PAGE_SIZE];
extern int vsprintf(char *,const char *,va_list);
extern void init(void);
extern void init_IRQ(void);
extern long kmalloc_init (long,long);
extern long blk_dev_init(long,long);
extern long chr_dev_init(long,long);
extern void floppy_init(void);
extern void sock_init(void);
extern long rd_init(long mem_start, int length);
unsigned long net_dev_init(unsigned long, unsigned long);
extern unsigned long simple_strtoul(const char *,char **,unsigned int);

extern void hd_setup(char *str, int *ints);
extern void bmouse_setup(char *str, int *ints);
extern void eth_setup(char *str, int *ints);
extern void xd_setup(char *str, int *ints);
extern void mcd_setup(char *str, int *ints);
extern void st0x_setup(char *str, int *ints);
extern void tmc8xx_setup(char *str, int *ints);
extern void t128_setup(char *str, int *ints);
extern void generic_NCR5380_setup(char *str, int *intr);
extern void aha152x_setup(char *str, int *ints);
extern void sound_setup(char *str, int *ints);
#ifdef CONFIG_SBPCD
extern void sbpcd_setup(char *str, int *ints);
#endif CONFIG_SBPCD

#ifdef CONFIG_SYSVIPC
extern void ipc_init(void);
#endif
#ifdef CONFIG_SCSI
extern unsigned long scsi_dev_init(unsigned long, unsigned long);
#endif

/*
 * This is set up by the setup-routine at boot-time
 */
#define PARAM	empty_zero_page
#define EXT_MEM_K (*(unsigned short *) (PARAM+2))
#define DRIVE_INFO (*(struct drive_info_struct *) (PARAM+0x80))
#define SCREEN_INFO (*(struct screen_info *) (PARAM+0))
#define MOUNT_ROOT_RDONLY (*(unsigned short *) (PARAM+0x1F2))
#define RAMDISK_SIZE (*(unsigned short *) (PARAM+0x1F8))
#define ORIG_ROOT_DEV (*(unsigned short *) (PARAM+0x1FC))
#define AUX_DEVICE_INFO (*(unsigned char *) (PARAM+0x1FF))

/*
 * Boot command-line arguments
 */
#define MAX_INIT_ARGS 8
#define MAX_INIT_ENVS 8
#define COMMAND_LINE ((char *) (PARAM+2048))

extern void time_init(void);

static unsigned long memory_start = 0;	/* After mem_init, stores the */
					/* amount of free user memory */
static unsigned long memory_end = 0;
static unsigned long low_memory_start = 0;

static char term[21];
int rows, cols;

static char * argv_init[MAX_INIT_ARGS+2] = { "init", NULL, };
static char * envp_init[MAX_INIT_ENVS+2] = { "HOME=/", term, NULL, };

static char * argv_rc[] = { "/bin/sh", NULL };
static char * envp_rc[] = { "HOME=/", term, NULL };

static char * argv[] = { "-/bin/sh",NULL };
static char * envp[] = { "HOME=/usr/root", term, NULL };

struct drive_info_struct { char dummy[32]; } drive_info;
struct screen_info screen_info;

unsigned char aux_device_present;
int ramdisk_size;
int root_mountflags = 0;

static char fpu_error = 0;

static char command_line[80] = { 0, };

char *get_options(char *str, int *ints) 
{
	char *cur = str;
	int i=1;

	while (cur && isdigit(*cur) && i <= 10) {
		ints[i++] = simple_strtoul(cur,NULL,0);
		if ((cur = strchr(cur,',')) != NULL)
			cur++;
	}
	ints[0] = i-1;
	return(cur);
}

struct {
	char *str;
	void (*setup_func)(char *, int *);
} bootsetups[] = {
	{ "reserve=", reserve_setup },
#ifdef CONFIG_INET
	{ "ether=", eth_setup },
#endif
#ifdef CONFIG_BLK_DEV_HD
	{ "hd=", hd_setup },
#endif
#ifdef CONFIG_BUSMOUSE
	{ "bmouse=", bmouse_setup },
#endif
#ifdef CONFIG_SCSI_SEAGATE
	{ "st0x=", st0x_setup },
	{ "tmc8xx=", tmc8xx_setup },
#endif
#ifdef CONFIG_SCSI_T128
	{ "t128=", t128_setup },
#endif
#ifdef CONFIG_SCSI_GENERIC_NCR5380
	{ "ncr5380=", generic_NCR5380_setup },
#endif
#ifdef CONFIG_SCSI_AHA152X
        { "aha152x=", aha152x_setup},
#endif
#ifdef CONFIG_BLK_DEV_XD
	{ "xd=", xd_setup },
#endif
#ifdef CONFIG_MCD
	{ "mcd=", mcd_setup },
#endif
#ifdef CONFIG_SOUND
	{ "sound=", sound_setup },
#endif
#ifdef CONFIG_SBPCD
	{ "sbpcd=", sbpcd_setup },
#endif CONFIG_SBPCD
	{ 0, 0 }
};

int checksetup(char *line)
{
	int i = 0;
	int ints[11];

	while (bootsetups[i].str) {
		int n = strlen(bootsetups[i].str);
		if (!strncmp(line,bootsetups[i].str,n)) {
			bootsetups[i].setup_func(get_options(line+n,ints), ints);
			return(0);
		}
		i++;
	}
	return(1);
}

unsigned long loops_per_sec = 1;

static void calibrate_delay(void)
{
	int ticks;

	printk("Calibrating delay loop.. ");
	while (loops_per_sec <<= 1) {
		ticks = jiffies;
		__delay(loops_per_sec);
		ticks = jiffies - ticks;
		if (ticks >= HZ) {
			__asm__("mull %1 ; divl %2"
				:"=a" (loops_per_sec)
				:"d" (HZ),
				 "r" (ticks),
				 "0" (loops_per_sec)
				:"dx");
			printk("ok - %lu.%02lu BogoMips\n",
				loops_per_sec/500000,
				(loops_per_sec/5000) % 100);
			return;
		}
	}
	printk("failed\n");
}
	

/*
 * This is a simple kernel command line parsing function: it parses
 * the command line, and fills in the arguments/environment to init
 * as appropriate. Any cmd-line option is taken to be an environment
 * variable if it contains the character '='.
 *
 *
 * This routine also checks for options meant for the kernel - currently
 * only the "root=XXXX" option is recognized. These options are not given
 * to init - they are for internal kernel use only.
 */
static void parse_options(char *line)
{
	char *next;
	char *devnames[] = { "hda", "hdb", "sda", "sdb", "sdc", "sdd", "sde", "fd", "xda", "xdb", NULL };
	int devnums[]    = { 0x300, 0x340, 0x800, 0x810, 0x820, 0x830, 0x840, 0x200, 0xC00, 0xC40, 0};
	int args, envs;

	if (!*line)
		return;
	args = 0;
	envs = 1;	/* TERM is set to 'console' by default */
	next = line;
	while ((line = next) != NULL) {
		if ((next = strchr(line,' ')) != NULL)
			*next++ = 0;
		/*
		 * check for kernel options first..
		 */
		if (!strncmp(line,"root=",5)) {
			int n;
			line += 5;
			if (strncmp(line,"/dev/",5)) {
				ROOT_DEV = simple_strtoul(line,NULL,16);
				continue;
			}
			line += 5;
			for (n = 0 ; devnames[n] ; n++) {
				int len = strlen(devnames[n]);
				if (!strncmp(line,devnames[n],len)) {
					ROOT_DEV = devnums[n]+simple_strtoul(line+len,NULL,16);
					break;
				}
			}
		} else if (!strcmp(line,"ro"))
			root_mountflags |= MS_RDONLY;
		else if (!strcmp(line,"rw"))
			root_mountflags &= ~MS_RDONLY;
		else if (!strcmp(line,"debug"))
			console_loglevel = 10;
		else if (!strcmp(line,"no387")) {
			hard_math = 0;
			__asm__("movl %%cr0,%%eax\n\t"
				"orl $0xE,%%eax\n\t"
				"movl %%eax,%%cr0\n\t" : : : "ax");
		} else
			checksetup(line);
		/*
		 * Then check if it's an environment variable or
		 * an option.
		 */	
		if (strchr(line,'=')) {
			if (envs >= MAX_INIT_ENVS)
				break;
			envp_init[++envs] = line;
		} else {
			if (args >= MAX_INIT_ARGS)
				break;
			argv_init[++args] = line;
		}
	}
	argv_init[args+1] = NULL;
	envp_init[envs+1] = NULL;
}

static void copy_options(char * to, char * from)
{
	char c = ' ';

	do {
		if (c == ' ' && !memcmp("mem=", from, 4))
			memory_end = simple_strtoul(from+4, &from, 0);
		c = *(to++) = *(from++);
	} while (c);
}

static void copro_timeout(void)
{
	fpu_error = 1;
	timer_table[COPRO_TIMER].expires = jiffies+100;
	timer_active |= 1<<COPRO_TIMER;
	printk("387 failed: trying to reset\n");
	send_sig(SIGFPE, last_task_used_math, 1);
	outb_p(0,0xf1);
	outb_p(0,0xf0);
}

/*
 * start_kernel() - Linux内核启动入口函数
 * 
 * 功能：内核启动的核心入口点，负责系统初始化的所有阶段
 * 
 * 启动阶段：
 * 1. 硬件环境初始化
 * 2. 内存管理初始化
 * 3. 设备驱动初始化
 * 4. 文件系统初始化
 * 5. 系统服务初始化
 * 6. 用户空间启动
 * 
 * 调用顺序：
 * 由bootloader调用 -> start_kernel() -> init() -> 用户空间init进程
 * 
 * 内存布局：
 * - 内核空间：0xC0000000以上（3GB以上）
 * - 用户空间：0x00000000-0xBFFFFFFF（3GB以下）
 * - 内核代码和数据：1MB开始
 * - 低内存：0-1MB（用于BIOS、硬件等）
 * 
 * 注意：此时中断仍然被禁用，需要完成基本设置后才能启用
 */
asmlinkage void start_kernel(void)
{
/*
 * 中断仍然被禁用。执行必要的设置，然后启用中断
 * 
 * 注意：此时处于实模式到保护模式的转换过程中
 */

	/* 第一阶段：基本硬件环境初始化 */
	/* 设置调用门，用于系统调用接口 */
	set_call_gate(&default_ldt,lcall7);
	
	/* 从BIOS获取基本硬件信息 */
 	ROOT_DEV = ORIG_ROOT_DEV;      /* 根设备号 */
 	drive_info = DRIVE_INFO;      /* 硬盘参数 */
 	screen_info = SCREEN_INFO;    /* 显示参数 */
 	aux_device_present = AUX_DEVICE_INFO; /* 辅助设备 */

	/* 第二阶段：内存配置和初始化 */
	/* 计算总内存大小：1MB基本内存 + 扩展内存 */
	memory_end = (1<<20) + (EXT_MEM_K<<10);
	memory_end &= PAGE_MASK;        /* 页面对齐 */
	ramdisk_size = RAMDISK_SIZE;      /* RAM盘大小 */

	/* 解析内核启动参数 */
	copy_options(command_line,COMMAND_LINE);

	/* 限制最大内存使用（16MB限制） */
#ifdef CONFIG_MAX_16M
	if (memory_end > 16*1024*1024)
		memory_end = 16*1024*1024;
#endif

	/* 处理根文件系统挂载选项 */
	if (MOUNT_ROOT_RDONLY)
		root_mountflags |= MS_RDONLY;

	/* 确定内核代码和数据的位置 */
	if ((unsigned long)&end >= (1024*1024)) {
		/* 内核超过1MB，从内核结束位置开始 */
		memory_start = (unsigned long) &end;
		low_memory_start = PAGE_SIZE;
	} else {
		/* 内核小于1MB，从1MB开始 */
		memory_start = 1024*1024;
		low_memory_start = (unsigned long) &end;
	}

	/* 第三阶段：核心系统初始化 */
	/* 内存管理初始化：设置页表和分页机制 */
	low_memory_start = PAGE_ALIGN(low_memory_start);
	memory_start = paging_init(memory_start,memory_end);

	/* 检测EISA总线 */
	if (strncmp((char*)0x0FFFD9, "EISA", 4) == 0)
		EISA_bus = 1;

	/* 中断和异常处理初始化 */
	trap_init();                 /* 设置中断描述符表 */
	init_IRQ();                  /* 初始化中断控制器 */

	/* 进程调度初始化 */
	sched_init();                /* 初始化任务调度器 */

	/* 再次解析启动参数（在调度器初始化后） */
	parse_options(command_line);

	/* 性能分析支持 */
#ifdef CONFIG_PROFILE
	prof_buffer = (unsigned long *) memory_start;
	prof_len = (unsigned long) &end;
	prof_len >>= 2;
	memory_start += prof_len * sizeof(unsigned long);
#endif

	/* 第四阶段：内存和设备初始化 */
	/* 内核内存分配器初始化 */
	memory_start = kmalloc_init(memory_start,memory_end);

	/* 字符设备初始化（控制台、串口等） */
	memory_start = chr_dev_init(memory_start,memory_end);

	/* 块设备初始化（硬盘、软盘等） */
	memory_start = blk_dev_init(memory_start,memory_end);

	/* 启用中断 */
	sti();

	/* 系统延迟校准 */
	calibrate_delay();

	/* 网络设备初始化 */
#ifdef CONFIG_INET
	memory_start = net_dev_init(memory_start,memory_end);
#endif

	/* SCSI设备初始化 */
#ifdef CONFIG_SCSI
	memory_start = scsi_dev_init(memory_start,memory_end);
#endif

	/* 第五阶段：文件系统和系统服务初始化 */
	/* inode表初始化 */
	memory_start = inode_init(memory_start,memory_end);

	/* 文件表初始化 */
	memory_start = file_table_init(memory_start,memory_end);

	/* 内存管理最终初始化 */
	mem_init(low_memory_start,memory_start,memory_end);

	/* 缓冲区缓存初始化 */
	buffer_init();

	/* 系统时间初始化 */
	time_init();

	/* 软盘驱动初始化 */
	floppy_init();

	/* 网络协议栈初始化 */
	sock_init();

	/* System V IPC支持 */
#ifdef CONFIG_SYSVIPC
	ipc_init();
#endif

	/* 再次确保中断启用 */
	sti();
	
	/* 第六阶段：数学协处理器检测 */
	/*
	 * 检查异常16是否正确工作。这是真正的恶意代码：
	 * 它禁用高8中断以确保irq13不会发生。但如果异常16
	 * 没有到达，这会导致死锁，因为它依赖于高8中断
	 * 将在下一个时钟滴答中重新启用。所以irq13最终会发生，
	 * 但异常16应该先到达。
	 */
	if (hard_math) {
		unsigned short control_word;

		printk("Checking 386/387 coupling... ");
		
		/* 设置定时器，用于检测数学协处理器异常 */
		timer_table[COPRO_TIMER].expires = jiffies+50;
		timer_table[COPRO_TIMER].fn = copro_timeout;
		timer_active |= 1<<COPRO_TIMER;
		
		/* 保存FPU状态并执行测试除法 */
		__asm__("clts ; fninit ; fnstcw %0 ; fwait":"=m" (*&control_word));
		control_word &= 0xffc0;
		__asm__("fldcw %0 ; fwait": "m" (*&control_word));
		outb_p(inb_p(0x21) | (1 << 2), 0x21);
		__asm__("fldz ; fld1 ; fdiv %st,%st(1) ; fwait");
		
		/* 清除定时器 */
		timer_active &= ~(1<<COPRO_TIMER);
		
		if (!fpu_error)
			printk("Ok, fpu using %s error reporting.\n",
					ignore_irq13?"exception 16":"irq13");
	}
#ifndef CONFIG_MATH_EMULATION
	else {
		/* 没有数学协处理器且没有数学仿真 */
		printk("No coprocessor found and no math emulation present.\n");
		printk("Giving up.\n");
		for (;;) ;  /* 无限循环，停止启动 */
	}
#endif

	/* 第七阶段：用户空间启动 */
	/* 显示Linux横幅信息 */
	system_utsname.machine[1] = '0' + x86;
	printk(linux_banner);

	/* 切换到用户模式 */
	move_to_user_mode();

	/* 创建init进程（PID=1） */
	if (!fork())		/* 我们指望这个正常进行 */
		init();

	/*
	 * task[0]被用作"空闲"任务：它不能睡眠，但
	 * 可能做一些通用的事情，如计算空闲页面或用于实现
	 * 分页例程的合理LRU算法：
	 * 任何有用的事情，但不应该占用真实进程的时间。
	 *
	 * 现在task[0]只是做一个无限空闲循环。
	 */
	for(;;)
		idle();
}

static int printf(const char *fmt, ...)
{
	va_list args;
	int i;

	va_start(args, fmt);
	write(1,printbuf,i=vsprintf(printbuf, fmt, args));
	va_end(args);
	return i;
}

/*
 * init() - 用户空间初始化函数（PID=1）
 * 
 * 功能：作为系统的第一个用户空间进程，负责完成系统启动和用户空间初始化
 * 
 * 启动流程：
 * 1. 系统设置和基本环境配置
 * 2. 尝试启动标准init程序
 * 3. 如果标准init失败，启动备用初始化序列
 * 4. 进入进程管理循环
 * 
 * 特点：
 * - 这是内核启动的第一个用户空间进程（PID=1）
 * - 永远不会退出，负责收养孤儿进程
 * - 负责系统初始化和服务管理
 * - 如果init进程死亡，系统通常会崩溃
 * 
 * 标准init程序搜索顺序：
 * 1. /etc/init  - 传统的System V init
 * 2. /bin/init  - 标准的init位置
 * 3. /sbin/init - 系统管理员常用的位置
 * 
 * 备用初始化（如果标准init都不存在）：
 * - 启动一个简单的shell脚本/etc/rc
 * - 然后进入交互式shell（作为最后的手段）
 */
void init(void)
{
	int pid,i;

	/* 第一阶段：基本系统设置 */
	/* 执行系统设置，包括文件系统挂载等 */
	setup((void *) &drive_info);

	/* 设置终端环境变量 */
	sprintf(term, "TERM=con%dx%d", ORIG_VIDEO_COLS, ORIG_VIDEO_LINES);

	/* 打开标准输入、输出、错误设备 */
	(void) open("/dev/tty1",O_RDWR,0);  /* 标准输入（文件描述符0） */
	(void) dup(0);                      /* 标准输出（文件描述符1） */
	(void) dup(0);                      /* 标准错误（文件描述符2） */

	/* 第二阶段：尝试启动标准init程序 */
	/* 按照传统Unix顺序尝试不同的init位置 */
	execve("/etc/init",argv_init,envp_init);   /* 传统位置 */
	execve("/bin/init",argv_init,envp_init);   /* 标准位置 */
	execve("/sbin/init",argv_init,envp_init);  /* 系统管理员位置 */
	/* 如果这些都失败，继续执行下面的备用初始化 */
	/* if this fails, fall through to original stuff */

	/* 第三阶段：备用初始化序列 */
	/* 如果标准init程序都不存在，执行简单的初始化 */
	if (!(pid=fork())) {
		/* 子进程：执行系统启动脚本 */
		close(0);  /* 关闭标准输入 */
		if (open("/etc/rc",O_RDONLY,0))  /* 尝试打开启动脚本 */
			_exit(1);  /* 如果失败，退出 */
		/* 执行shell来运行启动脚本 */
		execve("/bin/sh",argv_rc,envp_rc);
		_exit(2);  /* 如果execve失败，退出 */
	}
	/* 父进程：等待启动脚本完成 */
	if (pid>0)
		while (pid != wait(&i))  /* 等待子进程结束 */
			/* nothing */;

	/* 第四阶段：进入进程管理循环 */
	/* 这个循环负责收养孤儿进程和提供登录服务 */
	while (1) {
		/* 尝试创建新的登录进程 */
		if ((pid = fork()) < 0) {
			printf("Fork failed in init\n\r");
			continue;
		}
		if (!pid) {
			close(0);close(1);close(2);
			setsid();
			(void) open("/dev/tty1",O_RDWR,0);
			(void) dup(0);
			(void) dup(0);
			_exit(execve("/bin/sh",argv,envp));
		}
		while (1)
			if (pid == wait(&i))
				break;
		printf("\n\rchild %d died with code %04x\n\r",pid,i);
		sync();
	}
	_exit(0);
}