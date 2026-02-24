/*
 *  linux/kernel/signal.c
 *
 *  Copyright (C) 1991, 1992  Linus Torvalds
 */

#include <linux/sched.h>
#include <linux/kernel.h>
#include <linux/signal.h>
#include <linux/errno.h>
#include <linux/wait.h>
#include <linux/ptrace.h>
#include <linux/unistd.h>

#include <asm/segment.h>

#define _S(nr) (1<<((nr)-1))

#define _BLOCKABLE (~(_S(SIGKILL) | _S(SIGSTOP)))

extern int core_dump(long signr,struct pt_regs * regs);

asmlinkage int do_signal(unsigned long oldmask, struct pt_regs * regs);

struct sigcontext_struct {
	unsigned short gs, __gsh;
	unsigned short fs, __fsh;
	unsigned short es, __esh;
	unsigned short ds, __dsh;
	unsigned long edi;
	unsigned long esi;
	unsigned long ebp;
	unsigned long esp;
	unsigned long ebx;
	unsigned long edx;
	unsigned long ecx;
	unsigned long eax;
	unsigned long trapno;
	unsigned long err;
	unsigned long eip;
	unsigned short cs, __csh;
	unsigned long eflags;
	unsigned long esp_at_signal;
	unsigned short ss, __ssh;
	unsigned long i387;
	unsigned long oldmask;
	unsigned long cr2;
};

asmlinkage int sys_sigprocmask(int how, sigset_t *set, sigset_t *oset)
{
	sigset_t new_set, old_set = current->blocked;
	int error;

	if (set) {
		error = verify_area(VERIFY_READ, set, sizeof(sigset_t));
		if (error)
			return error;
		new_set = get_fs_long((unsigned long *) set) & _BLOCKABLE;
		switch (how) {
		case SIG_BLOCK:
			current->blocked |= new_set;
			break;
		case SIG_UNBLOCK:
			current->blocked &= ~new_set;
			break;
		case SIG_SETMASK:
			current->blocked = new_set;
			break;
		default:
			return -EINVAL;
		}
	}
	if (oset) {
		error = verify_area(VERIFY_WRITE, oset, sizeof(sigset_t));
		if (error)
			return error;
		put_fs_long(old_set, (unsigned long *) oset);
	}
	return 0;
}

asmlinkage int sys_sgetmask(void)
{
	return current->blocked;
}

asmlinkage int sys_ssetmask(int newmask)
{
	int old=current->blocked;

	current->blocked = newmask & _BLOCKABLE;
	return old;
}

asmlinkage int sys_sigpending(sigset_t *set)
{
	int error;
	/* fill in "set" with signals pending but blocked. */
	error = verify_area(VERIFY_WRITE, set, 4);
	if (!error)
		put_fs_long(current->blocked & current->signal, (unsigned long *)set);
	return error;
}

/*
 * atomically swap in the new signal mask, and wait for a signal.
 */
asmlinkage int sys_sigsuspend(int restart, unsigned long oldmask, unsigned long set)
{
	unsigned long mask;
	struct pt_regs * regs = (struct pt_regs *) &restart;

	mask = current->blocked;
	current->blocked = set & _BLOCKABLE;
	regs->eax = -EINTR;
	while (1) {
		current->state = TASK_INTERRUPTIBLE;
		schedule();
		if (do_signal(mask,regs))
			return -EINTR;
	}
}

/*
 * POSIX 3.3.1.3:
 *  "Setting a signal action to SIG_IGN for a signal that is pending
 *   shall cause the pending signal to be discarded, whether or not
 *   it is blocked" (but SIGCHLD is unspecified: linux leaves it alone).
 *
 *  "Setting a signal action to SIG_DFL for a signal that is pending
 *   and whose default action is to ignore the signal (for example,
 *   SIGCHLD), shall cause the pending signal to be discarded, whether
 *   or not it is blocked"
 *
 * Note the silly behaviour of SIGCHLD: SIG_IGN means that the signal
 * isn't actually ignored, but does automatic child reaping, while
 * SIG_DFL is explicitly said by POSIX to force the signal to be ignored..
 */
static void check_pending(int signum)
{
	struct sigaction *p;

	p = signum - 1 + current->sigaction;
	if (p->sa_handler == SIG_IGN) {
		if (signum == SIGCHLD)
			return;
		current->signal &= ~_S(signum);
		return;
	}
	if (p->sa_handler == SIG_DFL) {
		if (signum != SIGCONT && signum != SIGCHLD && signum != SIGWINCH)
			return;
		current->signal &= ~_S(signum);
		return;
	}	
}

asmlinkage int sys_signal(int signum, unsigned long handler)
{
	struct sigaction tmp;

	if (signum<1 || signum>32 || signum==SIGKILL || signum==SIGSTOP)
		return -EINVAL;
	if (handler >= TASK_SIZE)
		return -EFAULT;
	tmp.sa_handler = (void (*)(int)) handler;
	tmp.sa_mask = 0;
	tmp.sa_flags = SA_ONESHOT | SA_NOMASK;
	tmp.sa_restorer = NULL;
	handler = (long) current->sigaction[signum-1].sa_handler;
	current->sigaction[signum-1] = tmp;
	check_pending(signum);
	return handler;
}

asmlinkage int sys_sigaction(int signum, const struct sigaction * action,
	struct sigaction * oldaction)
{
	struct sigaction new_sa, *p;

	if (signum<1 || signum>32 || signum==SIGKILL || signum==SIGSTOP)
		return -EINVAL;
	p = signum - 1 + current->sigaction;
	if (action) {
		int err = verify_area(VERIFY_READ, action, sizeof(*action));
		if (err)
			return err;
		memcpy_fromfs(&new_sa, action, sizeof(struct sigaction));
		if (new_sa.sa_flags & SA_NOMASK)
			new_sa.sa_mask = 0;
		else {
			new_sa.sa_mask |= _S(signum);
			new_sa.sa_mask &= _BLOCKABLE;
		}
		if (TASK_SIZE <= (unsigned long) new_sa.sa_handler)
			return -EFAULT;
	}
	if (oldaction) {
		int err = verify_area(VERIFY_WRITE, oldaction, sizeof(*oldaction));
		if (err)
			return err;
		memcpy_tofs(oldaction, p, sizeof(struct sigaction));
	}
	if (action) {
		*p = new_sa;
		check_pending(signum);
	}
	return 0;
}

asmlinkage int sys_waitpid(pid_t pid,unsigned long * stat_addr, int options);

/*
 * sys_sigreturn - 信号返回系统调用
 * 从信号处理程序返回，恢复进程的执行上下文
 * 
 * 注意：即使我们实际上还没有使用信号栈，这里也会设置regs->esp..
 * 
 * 此函数在信号处理程序完成后被调用，用于恢复进程的原始执行状态
 * 它从用户空间栈中保存的信号上下文结构中恢复寄存器值
 * 
 * 参数:
 * __unused - 未使用的参数，实际上是指向pt_regs结构的指针
 * 
 * 返回值: 返回信号处理程序的返回值
 */
asmlinkage int sys_sigreturn(unsigned long __unused)
{
/* 定义复制寄存器值的宏 */
#define COPY(x) regs->x = context.x
/* 定义复制段寄存器的宏(允许0值) */
#define COPY_SEG(x) \
if ((context.x & 0xfffc) && (context.x & 3) != 3) goto badframe; COPY(x);
/* 定义严格复制段寄存器的宏(不允许0值) */
#define COPY_SEG_STRICT(x) \
if (!(context.x & 0xfffc) || (context.x & 3) != 3) goto badframe; COPY(x);
	struct sigcontext_struct context;	/* 信号上下文结构体 */
	struct pt_regs * regs;		/* 寄存器结构体指针 */

	/* 获取寄存器结构体指针 */
	regs = (struct pt_regs *) &__unused;
	/* 验证用户空间栈中的信号上下文结构的可读性 */
	if (verify_area(VERIFY_READ, (void *) regs->esp, sizeof(context)))
		goto badframe;		/* 栈帧无效 */
	/* 从用户空间栈中复制信号上下文结构 */
	memcpy_fromfs(&context,(void *) regs->esp, sizeof(context));
	/* 恢复进程的信号掩码(只允许恢复可阻塞的信号) */
	current->blocked = context.oldmask & _BLOCKABLE;
	/* 恢复段寄存器值 */
	COPY_SEG(ds);			/* 数据段寄存器 */
	COPY_SEG(es);			/* 附加段寄存器 */
	COPY_SEG(fs);			/* FS段寄存器 */
	COPY_SEG(gs);			/* GS段寄存器 */
	/* 严格恢复关键段寄存器值 */
	COPY_SEG_STRICT(ss);		/* 栈段寄存器 */
	COPY_SEG_STRICT(cs);		/* 代码段寄存器 */
	/* 恢复通用寄存器值 */
	COPY(eip);			/* 指令指针 */
	COPY(ecx); COPY(edx);		/* ECX和EDX寄存器 */
	COPY(ebx);			/* EBX寄存器 */
	COPY(esp); COPY(ebp);		/* ESP和EBP寄存器 */
	COPY(edi); COPY(esi);		/* EDI和ESI寄存器 */
	/* 恢复标志寄存器(只恢复可修改的位) */
	regs->eflags &= ~0xCD5;	/* 清除可修改的标志位 */
	regs->eflags |= context.eflags & 0xCD5;	/* 设置保存的标志位 */
	/* 禁用系统调用检查 */
	regs->orig_eax = -1;		/* 禁用系统调用检查 */
	/* 返回信号处理程序的返回值 */
	return context.eax;
badframe:			/* 错误处理 */
	do_exit(SIGSEGV);
}

/*
 * setup_frame - 设置信号帧
 * 在用户栈上设置信号帧，使栈看起来像iBCS2期望的样子
 * 
 * 此函数在信号处理前被调用，用于在用户栈上构建信号帧
 * 信号帧包含信号处理程序需要的所有信息，包括原始寄存器状态
 * 
 * 参数:
 * sa - 信号动作结构体指针
 * fp - 指向栈指针的指针
 * eip - 信号处理程序入口地址
 * regs - 当前寄存器状态
 * signr - 信号编号
 * oldmask - 原始信号掩码
 */
static void setup_frame(struct sigaction * sa, unsigned long ** fp, unsigned long eip,
	struct pt_regs * regs, int signr, unsigned long oldmask)
{
	unsigned long * frame;	/* 信号帧指针 */

/* 定义返回代码在信号帧中的位置 */
#define __CODE ((unsigned long)(frame+24))
/* 定义访问返回代码的宏 */
#define CODE(x) ((unsigned long *) ((x)+__CODE))
	/* 获取当前栈指针 */
	frame = *fp;
	/* 如果当前不在用户栈，使用信号恢复函数地址 */
	if (regs->ss != USER_DS)
		frame = (unsigned long *) sa->sa_restorer;
	/* 为信号帧分配空间(32个长字) */
	frame -= 32;
	/* 验证用户空间栈的可写性 */
	if (verify_area(VERIFY_WRITE,frame,32*4))
		do_exit(SIGSEGV);	/* 栈空间无效 */
/* 设置信号处理程序看到的"正常"栈(iBCS2格式) */
	/* 位置0: 返回代码地址 */
	put_fs_long(__CODE,frame);
	/* 位置1: 信号编号 */
	put_fs_long(signr, frame+1);
	/* 位置2-5: 段寄存器 */
	put_fs_long(regs->gs, frame+2);	/* GS寄存器 */
	put_fs_long(regs->fs, frame+3);	/* FS寄存器 */
	put_fs_long(regs->es, frame+4);	/* ES寄存器 */
	put_fs_long(regs->ds, frame+5);	/* DS寄存器 */
	/* 位置6-13: 通用寄存器 */
	put_fs_long(regs->edi, frame+6);	/* EDI寄存器 */
	put_fs_long(regs->esi, frame+7);	/* ESI寄存器 */
	put_fs_long(regs->ebp, frame+8);	/* EBP寄存器 */
	put_fs_long((long)*fp, frame+9);	/* 原始栈指针 */
	put_fs_long(regs->ebx, frame+10);	/* EBX寄存器 */
	put_fs_long(regs->edx, frame+11);	/* EDX寄存器 */
	put_fs_long(regs->ecx, frame+12);	/* ECX寄存器 */
	put_fs_long(regs->eax, frame+13);	/* EAX寄存器 */
	/* 位置14-15: 异常信息 */
	put_fs_long(current->tss.trap_no, frame+14);	/* 陷阱编号 */
	put_fs_long(current->tss.error_code, frame+15);	/* 错误码 */
	/* 位置16-20: 执行状态 */
	put_fs_long(eip, frame+16);		/* 指令指针 */
	put_fs_long(regs->cs, frame+17);		/* 代码段 */
	put_fs_long(regs->eflags, frame+18);	/* 标志寄存器 */
	put_fs_long(regs->esp, frame+19);	/* 栈指针 */
	put_fs_long(regs->ss, frame+20);	/* 栈段 */
	/* 位置21: 协处理器状态(未实现) */
	put_fs_long(0,frame+21);		/* 387状态指针 - 未实现*/
/* 非iBCS2扩展... */
	/* 位置22: 原始信号掩码 */
	put_fs_long(oldmask, frame+22);
	/* 位置23: 页错误地址 */
	put_fs_long(current->tss.cr2, frame+23);
/* 设置返回代码... */
	/* 位置24-26: 返回代码 */
	put_fs_long(0x0000b858, CODE(0));	/* popl %eax ; movl $,%eax */
	put_fs_long(0x80cd0000, CODE(4));	/* int $0x80 */
	put_fs_long(__NR_sigreturn, CODE(2));	/* sigreturn系统调用号 */
	/* 更新栈指针 */
	*fp = frame;
/* 清除宏定义 */
#undef __CODE
#undef CODE
}

/*
 * 注意：'init'是一个特殊的进程：它不会收到它不想处理的信号。
 * 因此即使误操作也无法用SIGKILL杀死init进程。
 *
 * do_signal - 信号处理核心函数
 * 注意：我们两次遍历信号：第一次检查内核可以处理的信号，
 * 然后一次性构建所有用户级信号处理的栈帧。
 * 
 * 参数:
 * oldmask - 原始信号掩码
 * regs - 当前寄存器状态
 * 
 * 返回值: 1表示已设置信号处理程序，0表示没有信号处理
 */
asmlinkage int do_signal(unsigned long oldmask, struct pt_regs * regs)
{
	unsigned long mask = ~current->blocked;	/* 未阻塞的信号掩码 */
	unsigned long handler_signal = 0;	/* 需要处理的信号掩码 */
	unsigned long *frame = NULL;		/* 信号帧指针 */
	unsigned long eip = 0;			/* 指令指针 */
	unsigned long signr;			/* 信号编号 */
	struct sigaction * sa;		/* 信号动作结构体指针 */

	/* 遍历所有未阻塞的信号 */
	while ((signr = current->signal & mask)) {
		/* 使用汇编指令找到最低位的1并清除它 */
		__asm__("bsf %2,%1\n\t"	/* 位扫描向前，找到最低位的1 */
			"btrl %1,%0"		/* 位测试并复位，清除该位 */
			:"=m" (current->signal),"=r" (signr)
			:"1" (signr));
		/* 获取信号对应的处理动作 */
		sa = current->sigaction + signr;
		/* 调整信号编号为1-based */
		signr++;
		/* 处理被跟踪进程的信号 */
		if ((current->flags & PF_PTRACED) && signr != SIGKILL) {
			/* 设置退出代码并停止进程 */
			current->exit_code = signr;
			current->state = TASK_STOPPED;
			/* 通知父进程 */
			notify_parent(current);
			/* 调度其他进程运行 */
			schedule();
			/* 检查父进程是否发送了新信号 */
			if (!(signr = current->exit_code))
				continue;		/* 没有新信号，继续处理下一个 */
			/* 清除退出代码 */
			current->exit_code = 0;
			/* SIGSTOP特殊处理 */
			if (signr == SIGSTOP)
				continue;		/* 忽略SIGSTOP */
			/* 检查新信号是否被阻塞 */
			if (_S(signr) & current->blocked) {
				/* 重新设置信号位，稍后处理 */
				current->signal |= _S(signr);
				continue;		/* 继续处理下一个信号 */
			}
			/* 更新信号动作指针 */
			sa = current->sigaction + signr - 1;
		}
		/* 处理忽略信号 */
		if (sa->sa_handler == SIG_IGN) {
			/* SIGCHLD特殊处理 */
			if (signr != SIGCHLD)
				continue;		/* 忽略非SIGCHLD信号 */
			/* 检查SIGCHLD：它是特殊的 */
			while (sys_waitpid(-1,NULL,WNOHANG) > 0)
				/* nothing */;	/* 回收僵尸进程 */
			continue;		/* 继续处理下一个信号 */
		}
		/* 处理默认信号动作 */
		if (sa->sa_handler == SIG_DFL) {
			/* init进程特殊处理 */
			if (current->pid == 1)
				continue;		/* init进程不会因信号而终止 */
			/* 根据信号类型执行默认动作 */
			switch (signr) {
			/* 忽略的信号 */
			case SIGCONT: case SIGCHLD: case SIGWINCH:
				continue;		/* 忽略这些信号 */

			/* 停止信号 */
			case SIGSTOP: case SIGTSTP: case SIGTTIN: case SIGTTOU:
				/* 被跟踪的进程不停止 */
				if (current->flags & PF_PTRACED)
					continue;		/* 继续执行 */
				/* 停止进程 */
				current->state = TASK_STOPPED;
				current->exit_code = signr;
				/* 通知父进程(除非设置了SA_NOCLDSTOP) */
				if (!(current->p_pptr->sigaction[SIGCHLD-1].sa_flags & 
						SA_NOCLDSTOP))
					notify_parent(current);
				/* 调度其他进程运行 */
				schedule();
				continue;		/* 继续处理下一个信号 */

			/* 产生core文件的信号 */
			case SIGQUIT: case SIGILL: case SIGTRAP:
			case SIGIOT: case SIGFPE: case SIGSEGV:
				/* 尝试生成core文件 */
				if (core_dump(signr,regs))
					signr |= 0x80;	/* 设置core标志 */
				/* fall through */	/* 继续执行下面的代码 */
			/* 终止信号 */
			default:
				/* 重新设置信号位 */
				current->signal |= _S(signr & 0x7f);
				/* 终止进程 */
				do_exit(signr);
			}
		}
		/*
		 * 好的，我们将调用一个处理程序
		 */
		/* 处理系统调用重启 */
		if (regs->orig_eax >= 0) {
			/* 如果系统调用被信号中断且不能重启 */
			if (regs->eax == -ERESTARTNOHAND ||
			   (regs->eax == -ERESTARTSYS && !(sa->sa_flags & SA_RESTART)))
				/* 设置返回值为EINTR */
				regs->eax = -EINTR;
		}
		/* 标记需要处理的信号 */
		handler_signal |= 1 << (signr-1);
		/* 从掩码中移除被当前处理程序阻塞的信号 */
		mask &= ~sa->sa_mask;
	}
	/* 处理系统调用重启(如果没有处理程序被调用) */
	if (regs->orig_eax >= 0 &&
	    (regs->eax == -ERESTARTNOHAND ||
	     regs->eax == -ERESTARTSYS ||
	     regs->eax == -ERESTARTNOINTR)) {
		/* 恢复原始系统调用号 */
		regs->eax = regs->orig_eax;
		/* 调整指令指针，重新执行系统调用指令 */
		regs->eip -= 2;
	}
	/* 如果没有处理程序将被调用，返回0 */
	if (!handler_signal)		/* no handler will be called - return 0 */
		return 0;
	/* 保存当前指令指针和栈指针 */
	eip = regs->eip;
	frame = (unsigned long *) regs->esp;
	/* 重置信号编号和信号动作指针 */
	signr = 1;
	sa = current->sigaction;
	/* 第二次遍历：构建所有信号处理程序的栈帧 */
	for (mask = 1 ; mask ; sa++,signr++,mask += mask) {
		/* 检查是否超出需要处理的信号 */
		if (mask > handler_signal)
			break;		/* 超出范围，退出循环 */
		/* 检查当前信号是否需要处理 */
		if (!(mask & handler_signal))
			continue;		/* 不需要处理，继续下一个 */
		/* 设置信号帧 */
		setup_frame(sa,&frame,eip,regs,signr,oldmask);
		/* 设置下一条指令为信号处理程序入口 */
		eip = (unsigned long) sa->sa_handler;
		/* 如果是一次性处理程序，重置为NULL */
		if (sa->sa_flags & SA_ONESHOT)
			sa->sa_handler = NULL;
/* 强制以监督模式预加载信号处理程序页面以减少竞争 */
		__asm__("testb $0,%%fs:%0": :"m" (*(char *) eip));
		/* 设置用户模式段寄存器 */
		regs->cs = USER_CS; regs->ss = USER_DS;
		regs->ds = USER_DS; regs->es = USER_DS;
		regs->gs = USER_DS; regs->fs = USER_DS;
		/* 更新进程的信号掩码 */
		current->blocked |= sa->sa_mask;
		/* 更新原始信号掩码 */
		oldmask |= sa->sa_mask;
	}
	/* 设置新的栈指针 */
	regs->esp = (unsigned long) frame;
	/* 设置新的指令指针 */
	regs->eip = eip;		/* "返回"到第一个处理程序 */
	/* 清除陷阱编号和错误码 */
	current->tss.trap_no = current->tss.error_code = 0;
	/* 返回1，表示已设置信号处理程序 */
	return 1;
}