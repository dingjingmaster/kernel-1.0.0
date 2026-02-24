/* ptrace.c - 进程跟踪系统调用实现 */
/* By Ross Biro 1/23/92 */
/* edited by Linus Torvalds */

#include <linux/head.h>
#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/mm.h>
#include <linux/errno.h>
#include <linux/ptrace.h>
#include <linux/user.h>

#include <asm/segment.h>
#include <asm/system.h>
#include <linux/debugreg.h>

/*
 * 注意：尚未捕获子进程死亡时发送的信号。
 * 这个功能在exit.c或signal.c中实现。
 */

/* 确定用户可以访问的标志位 */
/* 1 = access 0 = no access */
#define FLAG_MASK 0x00044dd5

/* 设置陷阱标志 */
#define TRAP_FLAG 0x100

/*
 * 从栈顶减去的数字，用于查找本地帧。
 */
#define MAGICNUMBER 68

/* 将PID转换为任务结构体 */
static inline struct task_struct * get_task(int pid)
{
	int i;

	/* 遍历任务数组，查找匹配的PID */
	for (i = 1; i < NR_TASKS; i++) {
		if (task[i] != NULL && (task[i]->pid == pid))
			return task[i];
	}
	return NULL;	/* 未找到 */
}

/*
 * 从进程的特权栈中获取一个字
 * 偏移量是相对于TSS中存储的基址的距离
 * 此例程假设所有特权栈都在我们的数据空间中。
 */
   
static inline int get_stack_long(struct task_struct *task, int offset)
{
	unsigned char *stack;

	/* 获取栈指针 */
	stack = (unsigned char *)task->tss.esp0;
	/* 加上偏移量 */
	stack += offset;
	/* 返回栈中的值 */
	return (*((int *)stack));
}

/*
 * this routine will put a word on the processes priviledged stack. 
 * the offset is how far from the base addr as stored in the TSS.  
 * this routine assumes that all the priviledged stacks are in our
 * data space.
 */
static inline int put_stack_long(struct task_struct *task, int offset,
	unsigned long data)
{
	unsigned char * stack;

	stack = (unsigned char *) task->tss.esp0;
	stack += offset;
	*(unsigned long *) stack = data;
	return 0;
}

/*
 * This routine gets a long from any process space by following the page
 * tables. NOTE! You should check that the long isn't on a page boundary,
 * and that it is in the task area before calling this: this routine does
 * no checking.
 *
 * NOTE2! This uses "tsk->tss.cr3" even though we know it's currently always
 * zero. This routine shouldn't have to change when we make a better mm.
 */
static unsigned long get_long(struct task_struct * tsk,
	unsigned long addr)
{
	unsigned long page;

repeat:
	page = *PAGE_DIR_OFFSET(tsk->tss.cr3,addr);
	if (page & PAGE_PRESENT) {
		page &= PAGE_MASK;
		page += PAGE_PTR(addr);
		page = *((unsigned long *) page);
	}
	if (!(page & PAGE_PRESENT)) {
		do_no_page(0,addr,tsk,0);
		goto repeat;
	}
/* this is a hack for non-kernel-mapped video buffers and similar */
	if (page >= high_memory)
		return 0;
	page &= PAGE_MASK;
	page += addr & ~PAGE_MASK;
	return *(unsigned long *) page;
}

/*
 * This routine puts a long into any process space by following the page
 * tables. NOTE! You should check that the long isn't on a page boundary,
 * and that it is in the task area before calling this: this routine does
 * no checking.
 *
 * Now keeps R/W state of page so that a text page stays readonly
 * even if a debugger scribbles breakpoints into it.  -M.U-
 */
static void put_long(struct task_struct * tsk, unsigned long addr,
	unsigned long data)
{
	unsigned long page, pte = 0;
	int readonly = 0;

repeat:
	page = *PAGE_DIR_OFFSET(tsk->tss.cr3,addr);
	if (page & PAGE_PRESENT) {
		page &= PAGE_MASK;
		page += PAGE_PTR(addr);
		pte = page;
		page = *((unsigned long *) page);
	}
	if (!(page & PAGE_PRESENT)) {
		do_no_page(0 /* PAGE_RW */ ,addr,tsk,0);
		goto repeat;
	}
	if (!(page & PAGE_RW)) {
		if(!(page & PAGE_COW))
			readonly = 1;
		do_wp_page(PAGE_RW | PAGE_PRESENT,addr,tsk,0);
		goto repeat;
	}
/* this is a hack for non-kernel-mapped video buffers and similar */
	if (page >= high_memory)
		return;
/* we're bypassing pagetables, so we have to set the dirty bit ourselves */
	*(unsigned long *) pte |= (PAGE_DIRTY|PAGE_COW);
	page &= PAGE_MASK;
	page += addr & ~PAGE_MASK;
	*(unsigned long *) page = data;
	if(readonly) {
		*(unsigned long *) pte &=~ (PAGE_RW|PAGE_COW);
		invalidate();
	} 
}

/*
 * This routine checks the page boundaries, and that the offset is
 * within the task area. It then calls get_long() to read a long.
 */
static int read_long(struct task_struct * tsk, unsigned long addr,
	unsigned long * result)
{
	unsigned long low,high;

	if (addr > TASK_SIZE-sizeof(long))
		return -EIO;
	if ((addr & ~PAGE_MASK) > PAGE_SIZE-sizeof(long)) {
		low = get_long(tsk,addr & ~(sizeof(long)-1));
		high = get_long(tsk,(addr+sizeof(long)) & ~(sizeof(long)-1));
		switch (addr & (sizeof(long)-1)) {
			case 1:
				low >>= 8;
				low |= high << 24;
				break;
			case 2:
				low >>= 16;
				low |= high << 16;
				break;
			case 3:
				low >>= 24;
				low |= high << 8;
				break;
		}
		*result = low;
	} else
		*result = get_long(tsk,addr);
	return 0;
}

/*
 * This routine checks the page boundaries, and that the offset is
 * within the task area. It then calls put_long() to write a long.
 */
static int write_long(struct task_struct * tsk, unsigned long addr,
	unsigned long data)
{
	unsigned long low,high;

	if (addr > TASK_SIZE-sizeof(long))
		return -EIO;
	if ((addr & ~PAGE_MASK) > PAGE_SIZE-sizeof(long)) {
		low = get_long(tsk,addr & ~(sizeof(long)-1));
		high = get_long(tsk,(addr+sizeof(long)) & ~(sizeof(long)-1));
		switch (addr & (sizeof(long)-1)) {
			case 0: /* shouldn't happen, but safety first */
				low = data;
				break;
			case 1:
				low &= 0x000000ff;
				low |= data << 8;
				high &= ~0xff;
				high |= data >> 24;
				break;
			case 2:
				low &= 0x0000ffff;
				low |= data << 16;
				high &= ~0xffff;
				high |= data >> 16;
				break;
			case 3:
				low &= 0x00ffffff;
				low |= data << 24;
				high &= ~0xffffff;
				high |= data >> 8;
				break;
		}
		put_long(tsk,addr & ~(sizeof(long)-1),low);
		put_long(tsk,(addr+sizeof(long)) & ~(sizeof(long)-1),high);
	} else
		put_long(tsk,addr,data);
	return 0;
}

/*
 * sys_ptrace - 进程跟踪系统调用
 * 实现对其他进程的跟踪和调试功能，包括读取/修改内存、寄存器和控制执行
 * 这是调试器(如gdb)与内核交互的核心接口
 * 
 * 参数:
 * request - 请求类型(跟踪、附加、读取、写入等)
 * pid - 目标进程ID
 * addr - 地址(内存地址或寄存器偏移)
 * data - 数据(用于写入操作或信号)
 * 
 * 返回值: 成功返回0或读取的数据，失败返回错误码
 */
asmlinkage int sys_ptrace(long request, long pid, long addr, long data)
{
	struct task_struct *child;	/* 被跟踪的子进程 */
	struct user * dummy;		/* 用于地址计算的虚拟结构体 */
	int i;				/* 循环计数器 */

	dummy = NULL;			/* 初始化虚拟结构体指针 */

	/* 处理TRACEME请求：当前进程请求被跟踪 */
	if (request == PTRACE_TRACEME) {
		/* 检查当前进程是否已经被跟踪 */
		if (current->flags & PF_PTRACED)
			return -EPERM;		/* 已经被跟踪 */
		/* 设置进程标志，表示可被跟踪 */
		current->flags |= PF_PTRACED;
		return 0;			/* 成功返回 */
	}
	/* 不允许跟踪init进程(PID=1) */
	if (pid == 1)		/* 不允许干扰init进程 */
		return -EPERM;		/* 权限不足 */
	/* 根据PID获取目标进程 */
	if (!(child = get_task(pid)))
		return -ESRCH;		/* 进程不存在 */
	/* 处理ATTACH请求：附加到指定进程进行跟踪 */
	if (request == PTRACE_ATTACH) {
		/* 不允许跟踪自己 */
		if (child == current)
			return -EPERM;		/* 不能跟踪自己 */
		/* 检查权限：必须具有相同UID/GID或超级用户权限 */
		if ((!child->dumpable || (current->uid != child->euid) ||
		    (current->gid != child->egid)) && !suser())
			return -EPERM;		/* 权限不足 */
		/* 同一进程不能被多次附加 */
		if (child->flags & PF_PTRACED)
			return -EPERM;		/* 已经被跟踪 */
		/* 设置进程跟踪标志 */
		child->flags |= PF_PTRACED;
		/* 如果当前进程不是父进程，需要重新建立父子关系 */
		if (child->p_pptr != current) {
			/* 从原父进程的子进程列表中移除 */
			REMOVE_LINKS(child);
			/* 设置新的父进程 */
			child->p_pptr = current;
			/* 添加到新父进程的子进程列表 */
			SET_LINKS(child);
		}
		/* 向目标进程发送停止信号 */
		send_sig(SIGSTOP, child, 1);
		return 0;			/* 成功返回 */
	}
	/* 检查目标进程是否已被跟踪 */
	if (!(child->flags & PF_PTRACED))
		return -ESRCH;		/* 进程未被跟踪 */
	/* 检查目标进程状态(除KILL请求外，必须处于停止状态) */
	if (child->state != TASK_STOPPED) {
		if (request != PTRACE_KILL)
			return -ESRCH;		/* 进程未停止 */
	}
	/* 检查当前进程是否是目标进程的跟踪者 */
	if (child->p_pptr != current)
		return -ESRCH;		/* 不是跟踪者 */

	/* 根据请求类型执行相应操作 */
	switch (request) {
	/* 当指令空间和数据空间分离时，这些需要修复 */
		case PTRACE_PEEKTEXT: /* 读取指定地址的指令字 */ 
		case PTRACE_PEEKDATA: { /* 读取指定地址的数据字 */
			unsigned long tmp;	/* 临时存储读取的数据 */
			int res;			/* 操作结果 */

			/* 从目标进程内存中读取一个长字 */
			res = read_long(child, addr, &tmp);
			if (res < 0)
				return res;		/* 读取失败 */
			/* 验证用户空间缓冲区的可写性 */
			res = verify_area(VERIFY_WRITE, (void *) data, sizeof(long));
			if (!res)
				/* 将读取的数据写入用户空间 */
				put_fs_long(tmp,(unsigned long *) data);
			return res;			/* 返回操作结果 */
		}

	/* 读取USER区域中指定地址的字 */
		case PTRACE_PEEKUSR: {
			unsigned long tmp;	/* 临时存储读取的数据 */
			int res;		/* 操作结果 */

			/* 检查地址对齐和范围 */
			if ((addr & 3) || addr < 0 || 
			    addr > sizeof(struct user) - 3)
				return -EIO;		/* 无效地址 */

			/* 验证用户空间缓冲区的可写性 */
			res = verify_area(VERIFY_WRITE, (void *) data, sizeof(long));
			if (res)
				return res;		/* 缓冲区无效 */
			tmp = 0;  /* 默认返回值 */
			/* 处理寄存器读取 */
			if(addr < 17*sizeof(long)) {
			  addr = addr >> 2; /* 临时转换：地址转换为寄存器索引 */

			  /* 从目标进程的内核栈中读取寄存器值 */
			  tmp = get_stack_long(child, sizeof(long)*addr - MAGICNUMBER);
			  /* 段寄存器只返回低16位 */
			  if (addr == DS || addr == ES ||
			      addr == FS || addr == GS ||
			      addr == CS || addr == SS)
			    tmp &= 0xffff;
			};
			/* 处理调试寄存器读取 */
			if(addr >= (long) &dummy->u_debugreg[0] &&
			   addr <= (long) &dummy->u_debugreg[7]){
				/* 计算调试寄存器索引 */
				addr -= (long) &dummy->u_debugreg[0];
				addr = addr >> 2;
				/* 读取调试寄存器值 */
				tmp = child->debugreg[addr];
			};
			/* 将读取的数据写入用户空间 */
			put_fs_long(tmp,(unsigned long *) data);
			return 0;			/* 成功返回 */
		}

      /* 当指令空间和数据空间分离时，这些需要修复 */
		case PTRACE_POKETEXT: /* 写入指定地址的指令字 */
		case PTRACE_POKEDATA: { /* 写入指定地址的数据字 */
			/* 调用write_long函数写入目标进程内存 */
			return write_long(child,addr,data);
		}

		case PTRACE_POKEUSR: { /* 写入USER区域中指定地址的字 */
			/* 检查地址对齐和范围 */
			if ((addr & 3) || addr < 0 || 
			    addr > sizeof(struct user) - 3)
				return -EIO;		/* 无效地址 */

			/* 将地址转换为寄存器索引(临时转换) */
			addr = addr >> 2;

			/* 不允许修改原始系统调用号 */
			if (addr == ORIG_EAX)
				return -EIO;		/* 不允许修改 */
			/* 处理段寄存器 */
			if (addr == DS || addr == ES ||
			    addr == FS || addr == GS ||
			    addr == CS || addr == SS) {
			     	/* 段寄存器只保留低16位 */
			     	data &= 0xffff;
			     	/* 检查段选择子的有效性 */
			     	if (data && (data & 3) != 3)
					return -EIO;	/* 无效段选择子 */
			}
			/* 处理标志寄存器 */
			if (addr == EFL) {   /* 标志寄存器 */
				/* 只允许修改用户可访问的标志位 */
				data &= FLAG_MASK;
				/* 保留其他标志位不变 */
				data |= get_stack_long(child, EFL*sizeof(long)-MAGICNUMBER)  & ~FLAG_MASK;
			}
		  /* 不允许用户为内核地址空间设置调试寄存器 */
		  if(addr < 17){			/* 处理普通寄存器 */
			  /* 将数据写入目标进程的内核栈 */
			  if (put_stack_long(child, sizeof(long)*addr-MAGICNUMBER, data))
				return -EIO;		/* 写入失败 */
			return 0;			/* 成功返回 */
			};

		  /* 这里需要非常小心。我们隐式地想要修改task_struct的一部分，
		     并且必须有选择地允许用户修改哪些部分。 */

		  /* 将索引转换回地址 */
		  addr = addr << 2;
		  /* 处理调试寄存器 */
		  if(addr >= (long) &dummy->u_debugreg[0] &&
		     addr <= (long) &dummy->u_debugreg[7]){

			  /* 不允许修改DR4和DR5(保留给Intel处理器) */
			  if(addr == (long) &dummy->u_debugreg[4]) return -EIO;
			  if(addr == (long) &dummy->u_debugreg[5]) return -EIO;
			  /* 不允许设置内核地址空间的断点 */
			  if(addr < (long) &dummy->u_debugreg[4] &&
			     ((unsigned long) data) >= 0xbffffffd) return -EIO;
		  
			  /* 处理DR7(调试控制寄存器) */
			  if(addr == (long) &dummy->u_debugreg[7]) {
				  /* 清除保留位 */
				  data &= ~DR_CONTROL_RESERVED;
				  /* 检查断点类型的有效性 */
				  for(i=0; i<4; i++)
					  if ((0x5f54 >> ((data >> (16 + 4*i)) & 0xf)) & 1)
						  return -EIO;	/* 无效断点类型 */
			  };

			  /* 计算调试寄存器索引 */
			  addr -= (long) &dummy->u_debugreg;
			  addr = addr >> 2;
			  /* 设置调试寄存器值 */
			  child->debugreg[addr] = data;
			  return 0;			/* 成功返回 */
		  };
		  /* 无效地址 */
		  return -EIO;

		case PTRACE_SYSCALL: /* 继续执行并在下一个系统调用(或返回)时停止 */
		case PTRACE_CONT: { /* 在信号后重新启动 */
			long tmp;			/* 临时变量 */

			/* 检查信号编号的有效性 */
			if ((unsigned long) data > NSIG)
				return -EIO;		/* 无效信号 */
			/* 设置系统调用跟踪标志 */
			if (request == PTRACE_SYSCALL)
				child->flags |= PF_TRACESYS;	/* 启用系统调用跟踪 */
			else
				child->flags &= ~PF_TRACESYS;	/* 禁用系统调用跟踪 */
			/* 设置退出代码(信号) */
			child->exit_code = data;
			/* 设置进程状态为运行中 */
			child->state = TASK_RUNNING;
			/* 确保单步标志位被清除 */
			tmp = get_stack_long(child, sizeof(long)*EFL-MAGICNUMBER) & ~TRAP_FLAG;
			put_stack_long(child, sizeof(long)*EFL-MAGICNUMBER,tmp);
			return 0;			/* 成功返回 */
		}

/*
 * 使子进程退出。最好的方法是向它发送SIGKILL信号。
 * 也许应该在状态中设置它想要退出。
 */
		case PTRACE_KILL: {		/* 终止被跟踪的进程 */
			long tmp;			/* 临时变量 */

			/* 设置进程状态为运行中 */
			child->state = TASK_RUNNING;
			/* 设置退出代码为SIGKILL */
			child->exit_code = SIGKILL;
			/* 确保单步标志位被清除 */
			tmp = get_stack_long(child, sizeof(long)*EFL-MAGICNUMBER) & ~TRAP_FLAG;
			put_stack_long(child, sizeof(long)*EFL-MAGICNUMBER,tmp);
			return 0;			/* 成功返回 */
		}

		case PTRACE_SINGLESTEP: {  /* 设置陷阱标志，实现单步执行 */
			long tmp;			/* 临时变量 */

			/* 检查信号编号的有效性 */
			if ((unsigned long) data > NSIG)
				return -EIO;		/* 无效信号 */
			/* 禁用系统调用跟踪 */
			child->flags &= ~PF_TRACESYS;
			/* 设置陷阱标志位(启用单步执行) */
			tmp = get_stack_long(child, sizeof(long)*EFL-MAGICNUMBER) | TRAP_FLAG;
			put_stack_long(child, sizeof(long)*EFL-MAGICNUMBER,tmp);
			/* 设置进程状态为运行中 */
			child->state = TASK_RUNNING;
			/* 设置退出代码(信号) */
			child->exit_code = data;
			/* 给它一个运行的机会 */
			return 0;			/* 成功返回 */
		}

		case PTRACE_DETACH: { /* 分离已附加的进程 */
			long tmp;			/* 临时变量 */

			/* 检查信号编号的有效性 */
			if ((unsigned long) data > NSIG)
				return -EIO;		/* 无效信号 */
			/* 清除跟踪标志 */
			child->flags &= ~(PF_PTRACED|PF_TRACESYS);
			/* 设置进程状态为运行中 */
			child->state = TASK_RUNNING;
			/* 设置退出代码(信号) */
			child->exit_code = data;
			/* 从当前父进程的子进程列表中移除 */
			REMOVE_LINKS(child);
			/* 恢复原始父进程 */
			child->p_pptr = child->p_opptr;
			/* 添加到原始父进程的子进程列表 */
			SET_LINKS(child);
			/* 确保单步标志位被清除 */
			tmp = get_stack_long(child, sizeof(long)*EFL-MAGICNUMBER) & ~TRAP_FLAG;
			put_stack_long(child, sizeof(long)*EFL-MAGICNUMBER,tmp);
			return 0;			/* 成功返回 */
		}

		/* 无效的请求类型 */
		default:
			return -EIO;		/* 无效请求 */
	}
}

/*
 * syscall_trace - 系统调用跟踪处理函数
 * 在系统调用入口和出口处被调用，用于实现系统调用跟踪
 * 当进程被设置为系统调用跟踪模式时，此函数会暂停进程执行
 * 并通知父进程(调试器)，允许检查系统调用的参数和返回值
 * 
 * 此函数在系统调用处理的关键位置被调用，实现strace等工具的核心功能
 */
asmlinkage void syscall_trace(void)
{
	/* 检查当前进程是否同时设置了PF_PTRACED和PF_TRACESYS标志 */
	if ((current->flags & (PF_PTRACED|PF_TRACESYS))
			!= (PF_PTRACED|PF_TRACESYS))
		return;			/* 不是被跟踪的系统调用，直接返回 */
	/* 设置退出代码为SIGTRAP，表示因系统调用跟踪而停止 */
	current->exit_code = SIGTRAP;
	/* 设置进程状态为停止，等待父进程(调试器)处理 */
	current->state = TASK_STOPPED;
	/* 通知父进程(调试器)当前进程已停止 */
	notify_parent(current);
	/* 调度器选择其他进程运行，让父进程有机会处理 */
	schedule();
	/*
	 * 这与继续执行一个信号不完全相同，但对于正常使用已经足够。
	 * strace只在停止信号不是SIGTRAP时才继续执行一个信号。 -brl
	 */
	/* 如果有退出代码(信号)，将其添加到进程的信号掩码中 */
	if (current->exit_code)
		current->signal |= (1 << (current->exit_code - 1));
	/* 清除退出代码 */
	current->exit_code = 0;
}