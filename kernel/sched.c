/*
 *  linux/kernel/sched.c
 *
 *  Copyright (C) 1991, 1992  Linus Torvalds
 */

/*
 * 'sched.c' is the main kernel file. It contains scheduling primitives
 * (sleep_on, wakeup, schedule etc) as well as a number of simple system
 * call functions (type getpid(), which just extracts a field from
 * current-task
 */

#include <linux/config.h>
#include <linux/signal.h>
#include <linux/sched.h>
#include <linux/timer.h>
#include <linux/kernel.h>
#include <linux/kernel_stat.h>
#include <linux/sys.h>
#include <linux/fdreg.h>
#include <linux/errno.h>
#include <linux/time.h>
#include <linux/ptrace.h>
#include <linux/segment.h>
#include <linux/delay.h>
#include <linux/interrupt.h>

#include <asm/system.h>
#include <asm/io.h>
#include <asm/segment.h>

#define TIMER_IRQ 0

#include <linux/timex.h>

/*
 * kernel variables
 */
long tick = 1000000 / HZ;               /* timer interrupt period */
volatile struct timeval xtime;		/* The current time */
int tickadj = 500/HZ;			/* microsecs */

/*
 * phase-lock loop variables
 */
int time_status = TIME_BAD;     /* clock synchronization status */
long time_offset = 0;           /* time adjustment (us) */
long time_constant = 0;         /* pll time constant */
long time_tolerance = MAXFREQ;  /* frequency tolerance (ppm) */
long time_precision = 1; 	/* clock precision (us) */
long time_maxerror = 0x70000000;/* maximum error */
long time_esterror = 0x70000000;/* estimated error */
long time_phase = 0;            /* phase offset (scaled us) */
long time_freq = 0;             /* frequency offset (scaled ppm) */
long time_adj = 0;              /* tick adjust (scaled 1 / HZ) */
long time_reftime = 0;          /* time at last adjustment (s) */

long time_adjust = 0;
long time_adjust_step = 0;

int need_resched = 0;

/*
 * Tell us the machine setup..
 */
int hard_math = 0;		/* set by boot/head.S */
int x86 = 0;			/* set by boot/head.S to 3 or 4 */
int ignore_irq13 = 0;		/* set if exception 16 works */
int wp_works_ok = 0;		/* set if paging hardware honours WP */ 

/*
 * Bus types ..
 */
int EISA_bus = 0;

extern int _setitimer(int, struct itimerval *, struct itimerval *);
unsigned long * prof_buffer = NULL;
unsigned long prof_len = 0;

#define _S(nr) (1<<((nr)-1))

extern void mem_use(void);

extern int timer_interrupt(void);
asmlinkage int system_call(void);

static unsigned long init_kernel_stack[1024];
struct task_struct init_task = INIT_TASK;

unsigned long volatile jiffies=0;

struct task_struct *current = &init_task;
struct task_struct *last_task_used_math = NULL;

struct task_struct * task[NR_TASKS] = {&init_task, };

long user_stack [ PAGE_SIZE>>2 ] ;

struct {
	long * a;
	short b;
	} stack_start = { & user_stack [PAGE_SIZE>>2] , KERNEL_DS };

struct kernel_stat kstat =
	{ 0, 0, 0, { 0, 0, 0, 0 }, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };

/*
 * int 0x80 entry points.. Moved away from the header file, as
 * iBCS2 may also want to use the '<linux/sys.h>' headers..
 */
#ifdef __cplusplus
extern "C" {
#endif

int sys_ni_syscall(void)
{
	return -EINVAL;
}

fn_ptr sys_call_table[] = { sys_setup, sys_exit, sys_fork, sys_read,
sys_write, sys_open, sys_close, sys_waitpid, sys_creat, sys_link,
sys_unlink, sys_execve, sys_chdir, sys_time, sys_mknod, sys_chmod,
sys_chown, sys_break, sys_stat, sys_lseek, sys_getpid, sys_mount,
sys_umount, sys_setuid, sys_getuid, sys_stime, sys_ptrace, sys_alarm,
sys_fstat, sys_pause, sys_utime, sys_stty, sys_gtty, sys_access,
sys_nice, sys_ftime, sys_sync, sys_kill, sys_rename, sys_mkdir,
sys_rmdir, sys_dup, sys_pipe, sys_times, sys_prof, sys_brk, sys_setgid,
sys_getgid, sys_signal, sys_geteuid, sys_getegid, sys_acct, sys_phys,
sys_lock, sys_ioctl, sys_fcntl, sys_mpx, sys_setpgid, sys_ulimit,
sys_olduname, sys_umask, sys_chroot, sys_ustat, sys_dup2, sys_getppid,
sys_getpgrp, sys_setsid, sys_sigaction, sys_sgetmask, sys_ssetmask,
sys_setreuid,sys_setregid, sys_sigsuspend, sys_sigpending,
sys_sethostname, sys_setrlimit, sys_getrlimit, sys_getrusage,
sys_gettimeofday, sys_settimeofday, sys_getgroups, sys_setgroups,
sys_select, sys_symlink, sys_lstat, sys_readlink, sys_uselib,
sys_swapon, sys_reboot, sys_readdir, sys_mmap, sys_munmap, sys_truncate,
sys_ftruncate, sys_fchmod, sys_fchown, sys_getpriority, sys_setpriority,
sys_profil, sys_statfs, sys_fstatfs, sys_ioperm, sys_socketcall,
sys_syslog, sys_setitimer, sys_getitimer, sys_newstat, sys_newlstat,
sys_newfstat, sys_uname, sys_iopl, sys_vhangup, sys_idle, sys_vm86,
sys_wait4, sys_swapoff, sys_sysinfo, sys_ipc, sys_fsync, sys_sigreturn,
sys_clone, sys_setdomainname, sys_newuname, sys_modify_ldt,
sys_adjtimex, sys_mprotect, sys_sigprocmask, sys_create_module,
sys_init_module, sys_delete_module, sys_get_kernel_syms, sys_quotactl,
sys_getpgid, sys_fchdir, sys_bdflush };

/* So we don't have to do any more manual updating.... */
int NR_syscalls = sizeof(sys_call_table)/sizeof(fn_ptr);

#ifdef __cplusplus
}
#endif

/*
 * math_state_restore - 数学协处理器状态恢复函数
 * 将当前数学信息保存在旧的数学状态数组中，并从当前任务获取新的状态
 * 
 * 此函数在进程切换时被调用，用于恢复或初始化数学协处理器的状态
 * 它实现了多任务环境下数学协处理器的状态管理，确保每个进程
 * 都有独立的数学协处理器状态，避免进程间相互干扰
 *
 * 注意：IBM设计的IRQ13行为存在问题。
 * 除非你真正了解它的工作原理，否则不要修改。
 */
asmlinkage void math_state_restore(void)
{
	/* 清除任务切换标志(TS)，允许使用数学协处理器 */
	__asm__ __volatile__("clts");
	/* 如果当前任务已经是最后一个使用数学协处理器的任务，无需恢复 */
	if (last_task_used_math == current)
		return;			/* 无需切换状态 */
	/* 设置协处理器定时器，50个时钟节拍后触发 */
	timer_table[COPRO_TIMER].expires = jiffies+50;
	/* 激活协处理器定时器 */
	timer_active |= 1<<COPRO_TIMER;	
	/* 如果有上一个任务使用了数学协处理器，保存其状态 */
	if (last_task_used_math)
		/* 保存上一个任务的数学协处理器状态到其TSS中 */
		__asm__("fnsave %0":"=m" (last_task_used_math->tss.i387));
	else
		/* 没有上一个任务，清除数学协处理器异常和状态 */
		__asm__("fnclex");
	/* 更新最后一个使用数学协处理器的任务为当前任务 */
	last_task_used_math = current;
	/* 检查当前任务是否已经使用过数学协处理器 */
	if (current->used_math) {
		/* 恢复当前任务的数学协处理器状态 */
		__asm__("frstor %0": :"m" (current->tss.i387));
	} else {
		/* 当前任务首次使用数学协处理器，初始化协处理器 */
		__asm__("fninit");		/* 初始化数学协处理器 */
		current->used_math=1;		/* 标记已使用数学协处理器 */
	}
	/* 清除协处理器定时器，完成状态切换 */
	timer_active &= ~(1<<COPRO_TIMER);
}

#ifndef CONFIG_MATH_EMULATION

asmlinkage void math_emulate(long arg)
{
  printk("math-emulation not enabled and no coprocessor found.\n");
  printk("killing %s.\n",current->comm);
  send_sig(SIGFPE,current,1);
  schedule();
}

#endif /* CONFIG_MATH_EMULATION */

unsigned long itimer_ticks = 0;
unsigned long itimer_next = ~0;
static unsigned long lost_ticks = 0;

/*
 * schedule - 内核调度器函数
 * 这是一个非常简单和优秀的调度器：它并不完美，但对于大多数情况
 * 肯定是有效的。你可能需要关注的是这里的信号处理程序代码。
 *
 *   注意！！任务0是'空闲'任务，当没有其他任务可以运行时被调用。
 * 它不能被杀死，也不能睡眠。任务0中的'state'信息从未被使用。
 *
 * "confuse_gcc" goto仅用于获得更好的汇编代码..
 * Djikstra可能讨厌我。
 */
asmlinkage void schedule(void)
{
	int c;				/* 临时变量，用于存储最高计数器值 */
	struct task_struct * p;		/* 任务结构体指针，用于遍历任务 */
	struct task_struct * next;		/* 下一个要运行的任务 */
	unsigned long ticks;			/* 临时存储定时器节拍数 */

/* 检查闹钟，唤醒任何收到信号的可中断任务 */

	/* 关中断，保护共享数据 */
	cli();
	/* 获取自上次调度以来的定时器节拍数 */
	ticks = itimer_ticks;
	/* 重置全局定时器计数器 */
	itimer_ticks = 0;
	/* 设置下一个定时器触发时间为最大值 */
	itimer_next = ~0;
	/* 开中断 */
	sti();
	/* 清除需要重新调度标志 */
	need_resched = 0;
	/* 从init_task开始遍历任务列表 */
	p = &init_task;
	/* 无限循环，处理所有任务的定时器和信号 */
	for (;;) {
		/* 移动到下一个任务，如果回到init_task则退出循环 */
		if ((p = p->next_task) == &init_task)
			goto confuse_gcc1;	/* 用于优化GCC生成的代码 */
		/* 处理实时定时器 */
		if (ticks && p->it_real_value) {
			/* 检查定时器是否已到期 */
			if (p->it_real_value <= ticks) {
				/* 发送SIGALRM信号给任务 */
				send_sig(SIGALRM, p, 1);
				/* 如果不是周期性定时器，清除定时器 */
				if (!p->it_real_incr) {
					p->it_real_value = 0;
					goto end_itimer;
				}
				/* 计算下一次定时器触发时间 */
				do {
					p->it_real_value += p->it_real_incr;
				} while (p->it_real_value <= ticks);
			}
			/* 减去已过去的节拍数 */
			p->it_real_value -= ticks;
			/* 更新全局下一个定时器触发时间 */
			if (p->it_real_value < itimer_next)
				itimer_next = p->it_real_value;
		}
end_itimer:
		/* 只处理可中断状态的任务 */
		if (p->state != TASK_INTERRUPTIBLE)
			continue;		/* 跳过不可中断的任务 */
		/* 检查任务是否有未阻塞的信号 */
		if (p->signal & ~p->blocked) {
			/* 将任务状态设置为运行中 */
			p->state = TASK_RUNNING;
			continue;		/* 继续处理下一个任务 */
		}
		/* 检查任务的超时是否已到期 */
		if (p->timeout && p->timeout <= jiffies) {
			/* 清除超时值 */
			p->timeout = 0;
			/* 将任务状态设置为运行中 */
			p->state = TASK_RUNNING;
		}
	}
confuse_gcc1:		/* 用于优化GCC生成的代码 */

/* 这是调度器的核心部分： */
#if 0
	/* 给进入睡眠的进程稍高优先级.. */
	/* 这取决于TASK_XXX的值 */
	/* 这对某些事情提供更平滑的调度，但 */
	/* 在某些情况下可能非常不公平，所以.. */
 	if (TASK_UNINTERRUPTIBLE >= (unsigned) current->state &&
	    current->counter < current->priority*2) {
		++current->counter;
	}
#endif
	/* 初始化最高计数器值 */
	c = -1;
	/* 初始化下一个要运行的任务和当前任务指针 */
	next = p = &init_task;
	/* 遍历所有任务，寻找具有最高计数器的可运行任务 */
	for (;;) {
		/* 移动到下一个任务，如果回到init_task则退出循环 */
		if ((p = p->next_task) == &init_task)
			goto confuse_gcc2;	/* 用于优化GCC生成的代码 */
		/* 如果任务处于运行状态且计数器值更高，则选择它 */
		if (p->state == TASK_RUNNING && p->counter > c)
			c = p->counter, next = p;	/* 更新最高计数器和下一个任务 */
	}
confuse_gcc2:		/* 用于优化GCC生成的代码 */
	/* 如果所有可运行任务的计数器都为0，需要重新计算 */
	if (!c) {
		/* 为所有任务重新计算计数器值 */
		for_each_task(p)
			/* 计数器 = (旧计数器/2) + 优先级 */
			p->counter = (p->counter >> 1) + p->priority;
	}
	/* 如果下一个任务不是当前任务，需要上下文切换 */
	if(current != next)
		/* 增加上下文切换计数器 */
		kstat.context_swtch++;
	/* 执行上下文切换，切换到下一个任务 */
	switch_to(next);
	/* 现在可能需要重新加载调试寄存器 */
	if(current->debugreg[7]){
		/* 加载调试寄存器0-3和6 */
		loaddebug(0);
		loaddebug(1);
		loaddebug(2);
		loaddebug(3);
		loaddebug(6);
	};
}

/*
 * sys_pause - 进程暂停系统调用
 * 使当前进程进入可中断睡眠状态，直到收到信号为止
 * 
 * 此函数实现POSIX pause()系统调用，用于暂停进程执行
 * 进程将保持睡眠状态，直到收到信号处理程序返回
 * 
 * 返回值: 总是返回-ERESTARTNOHAND，表示系统调用需要重启
 *          (当信号处理程序返回时，内核会自动重启系统调用)
 */
asmlinkage int sys_pause(void)
{
	/* 将当前进程状态设置为可中断睡眠 */
	current->state = TASK_INTERRUPTIBLE;
	/* 调用调度器，选择其他进程运行 */
	schedule();
	/* 返回-ERESTARTNOHAND，表示系统调用需要重启 */
	return -ERESTARTNOHAND;
}

/*
 * wake_up - 唤醒等待队列中的进程
 * 注意：此函数不会唤醒已停止的进程 - 它们必须通过信号或类似方式唤醒
 *
 * 注意：此函数不需要cli-sti对：中断不能直接更改等待队列结构，
 * 只能调用wake_up()来唤醒进程。进程本身在唤醒后必须从队列中移除。
 * 
 * 参数:
 * q - 指向等待队列头指针的指针
 */
void wake_up(struct wait_queue **q)
{
	struct wait_queue *tmp;	/* 临时指针，用于遍历等待队列 */
	struct task_struct * p;	/* 任务结构体指针 */

	/* 检查等待队列指针和队列是否有效 */
	if (!q || !(tmp = *q))
		return;			/* 无效队列，直接返回 */
	/* 遍历环形等待队列中的所有任务 */
	do {
		/* 获取等待队列项中的任务指针 */
		if ((p = tmp->task) != NULL) {
			/* 检查任务是否处于可唤醒状态 */
			if ((p->state == TASK_UNINTERRUPTIBLE) ||
			    (p->state == TASK_INTERRUPTIBLE)) {
				/* 将任务状态设置为运行中 */
				p->state = TASK_RUNNING;
				/* 如果被唤醒任务的优先级高于当前任务，设置需要重新调度标志 */
				if (p->counter > current->counter)
					need_resched = 1;
			}
		}
		/* 检查等待队列链表的完整性 */
		if (!tmp->next) {
			/* 打印等待队列错误信息 */
			printk("wait_queue is bad (eip = %08lx)\n",((unsigned long *) q)[-1]);
			printk("        q = %p\n",q);
			printk("       *q = %p\n",*q);
			printk("      tmp = %p\n",tmp);
			break;		/* 退出循环 */
		}
		/* 移动到下一个等待队列项 */
		tmp = tmp->next;
	} while (tmp != *q);	/* 循环直到回到队列头部 */
}

void wake_up_interruptible(struct wait_queue **q)
{
	struct wait_queue *tmp;
	struct task_struct * p;

	if (!q || !(tmp = *q))
		return;
	do {
		if ((p = tmp->task) != NULL) {
			if (p->state == TASK_INTERRUPTIBLE) {
				p->state = TASK_RUNNING;
				if (p->counter > current->counter)
					need_resched = 1;
			}
		}
		if (!tmp->next) {
			printk("wait_queue is bad (eip = %08lx)\n",((unsigned long *) q)[-1]);
			printk("        q = %p\n",q);
			printk("       *q = %p\n",*q);
			printk("      tmp = %p\n",tmp);
			break;
		}
		tmp = tmp->next;
	} while (tmp != *q);
}

void __down(struct semaphore * sem)
{
	struct wait_queue wait = { current, NULL };
	add_wait_queue(&sem->wait, &wait);
	current->state = TASK_UNINTERRUPTIBLE;
	while (sem->count <= 0) {
		schedule();
		current->state = TASK_UNINTERRUPTIBLE;
	}
	current->state = TASK_RUNNING;
	remove_wait_queue(&sem->wait, &wait);
}

static inline void __sleep_on(struct wait_queue **p, int state)
{
	unsigned long flags;
	struct wait_queue wait = { current, NULL };

	if (!p)
		return;
	if (current == task[0])
		panic("task[0] trying to sleep");
	current->state = state;
	add_wait_queue(p, &wait);
	save_flags(flags);
	sti();
	schedule();
	remove_wait_queue(p, &wait);
	restore_flags(flags);
}

void interruptible_sleep_on(struct wait_queue **p)
{
	__sleep_on(p,TASK_INTERRUPTIBLE);
}

void sleep_on(struct wait_queue **p)
{
	__sleep_on(p,TASK_UNINTERRUPTIBLE);
}

static struct timer_list * next_timer = NULL;

void add_timer(struct timer_list * timer)
{
	unsigned long flags;
	struct timer_list ** p;

	if (!timer)
		return;
	timer->next = NULL;
	p = &next_timer;
	save_flags(flags);
	cli();
	while (*p) {
		if ((*p)->expires > timer->expires) {
			(*p)->expires -= timer->expires;
			timer->next = *p;
			break;
		}
		timer->expires -= (*p)->expires;
		p = &(*p)->next;
	}
	*p = timer;
	restore_flags(flags);
}

int del_timer(struct timer_list * timer)
{
	unsigned long flags;
	unsigned long expires = 0;
	struct timer_list **p;

	p = &next_timer;
	save_flags(flags);
	cli();
	while (*p) {
		if (*p == timer) {
			if ((*p = timer->next) != NULL)
				(*p)->expires += timer->expires;
			timer->expires += expires;
			restore_flags(flags);
			return 1;
		}
		expires += (*p)->expires;
		p = &(*p)->next;
	}
	restore_flags(flags);
	return 0;
}

unsigned long timer_active = 0;
struct timer_struct timer_table[32];

/*
 * Hmm.. Changed this, as the GNU make sources (load.c) seems to
 * imply that avenrun[] is the standard name for this kind of thing.
 * Nothing else seems to be standardized: the fractional size etc
 * all seem to differ on different machines.
 */
unsigned long avenrun[3] = { 0,0,0 };

/*
 * Nr of active tasks - counted in fixed-point numbers
 */
static unsigned long count_active_tasks(void)
{
	struct task_struct **p;
	unsigned long nr = 0;

	for(p = &LAST_TASK; p > &FIRST_TASK; --p)
		if (*p && ((*p)->state == TASK_RUNNING ||
			   (*p)->state == TASK_UNINTERRUPTIBLE ||
			   (*p)->state == TASK_SWAPPING))
			nr += FIXED_1;
	return nr;
}

static inline void calc_load(void)
{
	unsigned long active_tasks; /* fixed-point */
	static int count = LOAD_FREQ;

	if (count-- > 0)
		return;
	count = LOAD_FREQ;
	active_tasks = count_active_tasks();
	CALC_LOAD(avenrun[0], EXP_1, active_tasks);
	CALC_LOAD(avenrun[1], EXP_5, active_tasks);
	CALC_LOAD(avenrun[2], EXP_15, active_tasks);
}

/*
 * this routine handles the overflow of the microsecond field
 *
 * The tricky bits of code to handle the accurate clock support
 * were provided by Dave Mills (Mills@UDEL.EDU) of NTP fame.
 * They were originally developed for SUN and DEC kernels.
 * All the kudos should go to Dave for this stuff.
 *
 * These were ported to Linux by Philip Gladstone.
 */
static void second_overflow(void)
{
	long ltemp;
	/* last time the cmos clock got updated */
	static long last_rtc_update=0;
	extern int set_rtc_mmss(unsigned long);

	/* Bump the maxerror field */
	time_maxerror = (0x70000000-time_maxerror < time_tolerance) ?
	  0x70000000 : (time_maxerror + time_tolerance);

	/* Run the PLL */
	if (time_offset < 0) {
		ltemp = (-(time_offset+1) >> (SHIFT_KG + time_constant)) + 1;
		time_adj = ltemp << (SHIFT_SCALE - SHIFT_HZ - SHIFT_UPDATE);
		time_offset += (time_adj * HZ) >> (SHIFT_SCALE - SHIFT_UPDATE);
		time_adj = - time_adj;
	} else if (time_offset > 0) {
		ltemp = ((time_offset-1) >> (SHIFT_KG + time_constant)) + 1;
		time_adj = ltemp << (SHIFT_SCALE - SHIFT_HZ - SHIFT_UPDATE);
		time_offset -= (time_adj * HZ) >> (SHIFT_SCALE - SHIFT_UPDATE);
	} else {
		time_adj = 0;
	}

	time_adj += (time_freq >> (SHIFT_KF + SHIFT_HZ - SHIFT_SCALE))
	    + FINETUNE;

	/* Handle the leap second stuff */
	switch (time_status) {
		case TIME_INS:
		/* ugly divide should be replaced */
		if (xtime.tv_sec % 86400 == 0) {
			xtime.tv_sec--; /* !! */
			time_status = TIME_OOP;
			printk("Clock: inserting leap second 23:59:60 GMT\n");
		}
		break;

		case TIME_DEL:
		/* ugly divide should be replaced */
		if (xtime.tv_sec % 86400 == 86399) {
			xtime.tv_sec++;
			time_status = TIME_OK;
			printk("Clock: deleting leap second 23:59:59 GMT\n");
		}
		break;

		case TIME_OOP:
		time_status = TIME_OK;
		break;
	}
	if (xtime.tv_sec > last_rtc_update + 660)
	  if (set_rtc_mmss(xtime.tv_sec) == 0)
	    last_rtc_update = xtime.tv_sec;
}

/*
 * disregard lost ticks for now.. We don't care enough.
 */
static void timer_bh(void * unused)
{
	unsigned long mask;
	struct timer_struct *tp;

	cli();
	while (next_timer && next_timer->expires == 0) {
		void (*fn)(unsigned long) = next_timer->function;
		unsigned long data = next_timer->data;
		next_timer = next_timer->next;
		sti();
		fn(data);
		cli();
	}
	sti();
	
	for (mask = 1, tp = timer_table+0 ; mask ; tp++,mask += mask) {
		if (mask > timer_active)
			break;
		if (!(mask & timer_active))
			continue;
		if (tp->expires > jiffies)
			continue;
		timer_active &= ~mask;
		tp->fn();
		sti();
	}
}

/*
 * The int argument is really a (struct pt_regs *), in case the
 * interrupt wants to know from where it was called. The timer
 * irq uses this to decide if it should update the user or system
 * times.
 */
static void do_timer(struct pt_regs * regs)
{
	unsigned long mask;
	struct timer_struct *tp;

	long ltemp;

	/* Advance the phase, once it gets to one microsecond, then
	 * advance the tick more.
	 */
	time_phase += time_adj;
	if (time_phase < -FINEUSEC) {
		ltemp = -time_phase >> SHIFT_SCALE;
		time_phase += ltemp << SHIFT_SCALE;
		xtime.tv_usec += tick + time_adjust_step - ltemp;
	}
	else if (time_phase > FINEUSEC) {
		ltemp = time_phase >> SHIFT_SCALE;
		time_phase -= ltemp << SHIFT_SCALE;
		xtime.tv_usec += tick + time_adjust_step + ltemp;
	} else
		xtime.tv_usec += tick + time_adjust_step;

	if (time_adjust)
	{
	    /* We are doing an adjtime thing. 
	     *
	     * Modify the value of the tick for next time.
	     * Note that a positive delta means we want the clock
	     * to run fast. This means that the tick should be bigger
	     *
	     * Limit the amount of the step for *next* tick to be
	     * in the range -tickadj .. +tickadj
	     */
	     if (time_adjust > tickadj)
	       time_adjust_step = tickadj;
	     else if (time_adjust < -tickadj)
	       time_adjust_step = -tickadj;
	     else
	       time_adjust_step = time_adjust;
	     
	    /* Reduce by this step the amount of time left  */
	    time_adjust -= time_adjust_step;
	}
	else
	    time_adjust_step = 0;

	if (xtime.tv_usec >= 1000000) {
	    xtime.tv_usec -= 1000000;
	    xtime.tv_sec++;
	    second_overflow();
	}

	jiffies++;
	calc_load();
	if ((VM_MASK & regs->eflags) || (3 & regs->cs)) {
		current->utime++;
		if (current != task[0]) {
			if (current->priority < 15)
				kstat.cpu_nice++;
			else
				kstat.cpu_user++;
		}
		/* Update ITIMER_VIRT for current task if not in a system call */
		if (current->it_virt_value && !(--current->it_virt_value)) {
			current->it_virt_value = current->it_virt_incr;
			send_sig(SIGVTALRM,current,1);
		}
	} else {
		current->stime++;
		if(current != task[0])
			kstat.cpu_system++;
#ifdef CONFIG_PROFILE
		if (prof_buffer && current != task[0]) {
			unsigned long eip = regs->eip;
			eip >>= 2;
			if (eip < prof_len)
				prof_buffer[eip]++;
		}
#endif
	}
	if (current == task[0] || (--current->counter)<=0) {
		current->counter=0;
		need_resched = 1;
	}
	/* Update ITIMER_PROF for the current task */
	if (current->it_prof_value && !(--current->it_prof_value)) {
		current->it_prof_value = current->it_prof_incr;
		send_sig(SIGPROF,current,1);
	}
	for (mask = 1, tp = timer_table+0 ; mask ; tp++,mask += mask) {
		if (mask > timer_active)
			break;
		if (!(mask & timer_active))
			continue;
		if (tp->expires > jiffies)
			continue;
		mark_bh(TIMER_BH);
	}
	cli();
	itimer_ticks++;
	if (itimer_ticks > itimer_next)
		need_resched = 1;
	if (next_timer) {
		if (next_timer->expires) {
			next_timer->expires--;
			if (!next_timer->expires)
				mark_bh(TIMER_BH);
		} else {
			lost_ticks++;
			mark_bh(TIMER_BH);
		}
	}
	sti();
}

asmlinkage int sys_alarm(long seconds)
{
	struct itimerval it_new, it_old;

	it_new.it_interval.tv_sec = it_new.it_interval.tv_usec = 0;
	it_new.it_value.tv_sec = seconds;
	it_new.it_value.tv_usec = 0;
	_setitimer(ITIMER_REAL, &it_new, &it_old);
	return(it_old.it_value.tv_sec + (it_old.it_value.tv_usec / 1000000));
}

asmlinkage int sys_getpid(void)
{
	return current->pid;
}

asmlinkage int sys_getppid(void)
{
	return current->p_opptr->pid;
}

asmlinkage int sys_getuid(void)
{
	return current->uid;
}

asmlinkage int sys_geteuid(void)
{
	return current->euid;
}

asmlinkage int sys_getgid(void)
{
	return current->gid;
}

asmlinkage int sys_getegid(void)
{
	return current->egid;
}

asmlinkage int sys_nice(long increment)
{
	int newprio;

	if (increment < 0 && !suser())
		return -EPERM;
	newprio = current->priority - increment;
	if (newprio < 1)
		newprio = 1;
	if (newprio > 35)
		newprio = 35;
	current->priority = newprio;
	return 0;
}

static void show_task(int nr,struct task_struct * p)
{
	static char * stat_nam[] = { "R", "S", "D", "Z", "T", "W" };

	printk("%-8s %3d ", p->comm, (p == current) ? -nr : nr);
	if (((unsigned) p->state) < sizeof(stat_nam)/sizeof(char *))
		printk(stat_nam[p->state]);
	else
		printk(" ");
	if (p == current)
		printk(" current  ");
	else
		printk(" %08lX ", ((unsigned long *)p->tss.esp)[3]);
	printk("%5lu %5d %6d ",
		p->tss.esp - p->kernel_stack_page, p->pid, p->p_pptr->pid);
	if (p->p_cptr)
		printk("%5d ", p->p_cptr->pid);
	else
		printk("      ");
	if (p->p_ysptr)
		printk("%7d", p->p_ysptr->pid);
	else
		printk("       ");
	if (p->p_osptr)
		printk(" %5d\n", p->p_osptr->pid);
	else
		printk("\n");
}

void show_state(void)
{
	int i;

	printk("                         free                        sibling\n");
	printk("  task             PC    stack   pid father child younger older\n");
	for (i=0 ; i<NR_TASKS ; i++)
		if (task[i])
			show_task(i,task[i]);
}

/*
 * sched_init - 调度器初始化函数
 * 初始化内核调度器和定时器，设置必要的描述符和中断处理程序
 * 此函数在系统启动时被调用，完成多任务环境的基础设置
 */
void sched_init(void)
{
	int i;				/* 循环计数器 */
	struct desc_struct * p;		/* 描述符结构体指针 */

	/* 设置定时器底半处理程序 */
	bh_base[TIMER_BH].routine = timer_bh;
	/* 检查sigaction结构体大小是否为16字节 */
	if (sizeof(struct sigaction) != 16)
		panic("Struct sigaction MUST be 16 bytes");	/* 结构体大小错误 */
	/* 在GDT中设置init任务的TSS描述符 */
	set_tss_desc(gdt+FIRST_TSS_ENTRY,&init_task.tss);
	/* 在GDT中设置默认LDT描述符 */
	set_ldt_desc(gdt+FIRST_LDT_ENTRY,&default_ldt,1);
	/* 设置系统调用中断门(0x80) */
	set_system_gate(0x80,&system_call);
	/* 初始化GDT中剩余的任务描述符 */
	p = gdt+2+FIRST_TSS_ENTRY;	/* 指向第一个可用的TSS描述符 */
	/* 遍历所有可能的任务槽位 */
	for(i=1 ; i<NR_TASKS ; i++) {
		/* 清空任务指针 */
		task[i] = NULL;
		/* 清空TSS描述符 */
		p->a=p->b=0;
		p++;				/* 移动到下一个描述符 */
		/* 清空LDT描述符 */
		p->a=p->b=0;
		p++;				/* 移动到下一个描述符 */
	}
/* 清除EFLAGS中的NT标志，避免后续出现问题 */
	__asm__("pushfl ; andl $0xffffbfff,(%esp) ; popfl");
	/* 加载任务0的TSS */
	load_TR(0);
	/* 加载任务0的LDT */
	load_ldt(0);
	/* 初始化8253/8254可编程间隔定时器 */
	outb_p(0x34,0x43);		/* 二进制模式，模式2，LSB/MSB，通道0 */
	outb_p(LATCH & 0xff , 0x40);	/* 写入低字节 */
	outb(LATCH >> 8 , 0x40);	/* 写入高字节 */
	/* 请求定时器中断 */
	if (request_irq(TIMER_IRQ,(void (*)(int)) do_timer)!=0)
		panic("Could not allocate timer IRQ!");	/* 定时器IRQ分配失败 */
}