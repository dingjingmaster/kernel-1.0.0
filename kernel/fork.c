/*
 *  linux/kernel/fork.c
 *
 *  Copyright (C) 1991, 1992  Linus Torvalds
 */

/*
 *  'fork.c' contains the help-routines for the 'fork' system call
 * (see also system_call.s).
 * Fork is rather simple, once you get the hang of it, but the memory
 * management can be a bitch. See 'mm/mm.c': 'copy_page_tables()'
 */

#include <linux/errno.h>
#include <linux/sched.h>
#include <linux/kernel.h>
#include <linux/mm.h>
#include <linux/stddef.h>
#include <linux/unistd.h>
#include <linux/segment.h>
#include <linux/ptrace.h>
#include <linux/malloc.h>
#include <linux/ldt.h>

#include <asm/segment.h>
#include <asm/system.h>

asmlinkage void ret_from_sys_call(void) __asm__("ret_from_sys_call");

/* These should maybe be in <linux/tasks.h> */

#define MAX_TASKS_PER_USER (NR_TASKS/2)
#define MIN_TASKS_LEFT_FOR_ROOT 4

extern int shm_fork(struct task_struct *, struct task_struct *);
long last_pid=0;

static int find_empty_process(void)
{
	int free_task;
	int i, tasks_free;
	int this_user_tasks;

repeat:
	if ((++last_pid) & 0xffff8000)
		last_pid=1;
	this_user_tasks = 0;
	tasks_free = 0;
	free_task = -EAGAIN;
	i = NR_TASKS;
	while (--i > 0) {
		if (!task[i]) {
			free_task = i;
			tasks_free++;
			continue;
		}
		if (task[i]->uid == current->uid)
			this_user_tasks++;
		if (task[i]->pid == last_pid || task[i]->pgrp == last_pid ||
		    task[i]->session == last_pid)
			goto repeat;
	}
	if (tasks_free <= MIN_TASKS_LEFT_FOR_ROOT ||
	    this_user_tasks > MAX_TASKS_PER_USER)
		if (current->uid)
			return -EAGAIN;
	return free_task;
}

static struct file * copy_fd(struct file * old_file)
{
	struct file * new_file = get_empty_filp();
	int error;

	if (new_file) {
		memcpy(new_file,old_file,sizeof(struct file));
		new_file->f_count = 1;
		if (new_file->f_inode)
			new_file->f_inode->i_count++;
		if (new_file->f_op && new_file->f_op->open) {
			error = new_file->f_op->open(new_file->f_inode,new_file);
			if (error) {
				iput(new_file->f_inode);
				new_file->f_count = 0;
				new_file = NULL;
			}
		}
	}
	return new_file;
}

int dup_mmap(struct task_struct * tsk)
{
	struct vm_area_struct * mpnt, **p, *tmp;

	tsk->mmap = NULL;
	tsk->stk_vma = NULL;
	p = &tsk->mmap;
	for (mpnt = current->mmap ; mpnt ; mpnt = mpnt->vm_next) {
		tmp = (struct vm_area_struct *) kmalloc(sizeof(struct vm_area_struct), GFP_KERNEL);
		if (!tmp)
			return -ENOMEM;
		*tmp = *mpnt;
		tmp->vm_task = tsk;
		tmp->vm_next = NULL;
		if (tmp->vm_inode)
			tmp->vm_inode->i_count++;
		*p = tmp;
		p = &tmp->vm_next;
		if (current->stk_vma == mpnt)
			tsk->stk_vma = tmp;
	}
	return 0;
}

#define IS_CLONE (regs.orig_eax == __NR_clone)
#define copy_vm(p) ((clone_flags & COPYVM)?copy_page_tables(p):clone_page_tables(p))

/*
 *  Ok, this is the main fork-routine. It copies the system process
 * information (task[nr]) and sets up the necessary registers. It
 * also copies the data segment in its entirety.
 */
/*
 * sys_fork - fork系统调用实现
 * 
 * 创建一个与当前进程几乎完全相同的子进程
 * 
 * 参数:
 *   regs - 父进程的寄存器状态，用于设置子进程的初始状态
 * 
 * 返回值:
 *   父进程中: 子进程的PID(>0)
 *   子进程中: 0
 *   错误: -EAGAIN
 */
asmlinkage int sys_fork(struct pt_regs regs)
{
	struct pt_regs * childregs;	/* 子进程的寄存器状态指针 */
	struct task_struct *p;		/* 新任务结构体指针 */
	int i,nr;				/* 循环计数器和任务槽位号 */
	struct file *f;			/* 文件结构体指针 */
	unsigned long clone_flags = COPYVM | SIGCHLD;	/* 克隆标志，默认复制内存和发送SIGCHLD信号 */

	/* 为新任务结构体分配一个页面 */
	if(!(p = (struct task_struct*)__get_free_page(GFP_KERNEL)))
		goto bad_fork;	/* 分配失败，跳转到错误处理 */
	/* 在任务数组中找到一个空槽位 */
	nr = find_empty_process();
	if (nr < 0)
		goto bad_fork_free;	/* 没有空槽位，释放已分配的页面并跳转到错误处理 */
	/* 将新任务结构体放入任务数组 */
	task[nr] = p;
	/* 复制父进程的任务结构体到子进程 */
	*p = *current;
	/* 初始化子进程特有的字段 */
	p->did_exec = 0;			/* 子进程尚未执行exec */
	p->kernel_stack_page = 0;		/* 内核栈页面，稍后分配 */
	p->state = TASK_UNINTERRUPTIBLE;	/* 设置为不可中断状态，防止调度 */
	p->flags &= ~(PF_PTRACED|PF_TRACESYS);	/* 清除跟踪标志 */
	p->pid = last_pid;			/* 设置进程ID */
	p->swappable = 1;			/* 可被换出 */
	/* 设置父进程指针 */
	p->p_pptr = p->p_opptr = current;	/* 父进程和原始父进程都是当前进程 */
	p->p_cptr = NULL;			/* 子进程列表为空 */
	SET_LINKS(p);			/* 将子进程添加到进程链表中 */
	p->signal = 0;			/* 清除信号 */
	/* 清除定时器 */
	p->it_real_value = p->it_virt_value = p->it_prof_value = 0;
	p->it_real_incr = p->it_virt_incr = p->it_prof_incr = 0;
	p->leader = 0;			/* 进程领导权不继承 */
	/* 清除时间统计 */
	p->utime = p->stime = 0;		/* 用户态和内核态时间 */
	p->cutime = p->cstime = 0;		/* 子进程的用户态和内核态时间 */
	p->min_flt = p->maj_flt = 0;		/* 次要和主要页面错误 */
	p->cmin_flt = p->cmaj_flt = 0;		/* 子进程的次要和主要页面错误 */
	p->start_time = jiffies;		/* 设置进程开始时间 */
/*
 * 设置新的TSS(任务状态段)和内核栈
 */
	/* 为子进程分配内核栈页面 */
	if (!(p->kernel_stack_page = __get_free_page(GFP_KERNEL)))
		goto bad_fork_cleanup;	/* 分配失败，跳转到清理代码 */
	/* 设置TSS的段寄存器 */
	p->tss.es = KERNEL_DS;		/* ES段 */
	p->tss.cs = KERNEL_CS;		/* CS段 */
	p->tss.ss = KERNEL_DS;		/* SS段 */
	p->tss.ds = KERNEL_DS;		/* DS段 */
	p->tss.fs = USER_DS;		/* FS段 */
	p->tss.gs = KERNEL_DS;		/* GS段 */
	p->tss.ss0 = KERNEL_DS;		/* 内核态栈段 */
	p->tss.esp0 = p->kernel_stack_page + PAGE_SIZE;	/* 内核态栈指针 */
	p->tss.tr = _TSS(nr);		/* TSS描述符 */
	/* 设置子进程的寄存器状态 */
	childregs = ((struct pt_regs *) (p->kernel_stack_page + PAGE_SIZE)) - 1;
	p->tss.esp = (unsigned long) childregs;	/* 栈指针 */
	p->tss.eip = (unsigned long) ret_from_sys_call;	/* 指令指针 */
	*childregs = regs;			/* 复制父进程的寄存器状态 */
	childregs->eax = 0;			/* 子进程返回0 */
	p->tss.back_link = 0;		/* 反向链接 */
	p->tss.eflags = regs.eflags & 0xffffcfff;	/* IOPL总是0 */
	/* 处理clone系统调用的特殊情况 */
	if (IS_CLONE) {
		if (regs.ebx)
			childregs->esp = regs.ebx;	/* 设置子进程的栈指针 */
		clone_flags = regs.ecx;		/* 获取克隆标志 */
		if (childregs->esp == regs.esp)
			clone_flags |= COPYVM;	/* 如果栈指针相同，复制内存 */
	}
	p->exit_signal = clone_flags & CSIGNAL;	/* 设置退出信号 */
	p->tss.ldt = _LDT(nr);		/* LDT描述符 */
	/* 如果父进程有LDT，复制它 */
	if (p->ldt) {
		p->ldt = (struct desc_struct*) vmalloc(LDT_ENTRIES*LDT_ENTRY_SIZE);
		if (p->ldt != NULL)
			memcpy(p->ldt, current->ldt, LDT_ENTRIES*LDT_ENTRY_SIZE);
	}
	/* 设置IO位图 */
	p->tss.bitmap = offsetof(struct tss_struct,io_bitmap);
	for (i = 0; i < IO_BITMAP_SIZE+1 ; i++) /* IO位图实际大小是SIZE+1 */
		p->tss.io_bitmap[i] = ~0;	/* 设置所有IO端口为禁止访问 */
	/* 如果父进程使用了数学协处理器，保存其状态 */
	if (last_task_used_math == current)
		__asm__("clts ; fnsave %0 ; frstor %0":"=m" (p->tss.i387));
	/* 初始化信号量和共享内存 */
	p->semun = NULL; p->shm = NULL;
	/* 复制内存空间和共享内存 */
	if (copy_vm(p) || shm_fork(current, p))
		goto bad_fork_cleanup;	/* 复制失败，跳转到清理代码 */
	/* 处理文件描述符 */
	if (clone_flags & COPYFD) {
		/* 复制文件描述符 */
		for (i=0; i<NR_OPEN;i++)
			if ((f = p->filp[i]) != NULL)
				p->filp[i] = copy_fd(f);
	} else {
		/* 只增加文件引用计数 */
		for (i=0; i<NR_OPEN;i++)
			if ((f = p->filp[i]) != NULL)
				f->f_count++;
	}
	/* 增加当前目录、根目录和可执行文件的引用计数 */
	if (current->pwd)
		current->pwd->i_count++;
	if (current->root)
		current->root->i_count++;
	if (current->executable)
		current->executable->i_count++;
	/* 复制内存映射区域 */
	dup_mmap(p);
	/* 设置GDT中的TSS描述符 */
	set_tss_desc(gdt+(nr<<1)+FIRST_TSS_ENTRY,&(p->tss));
	/* 设置GDT中的LDT描述符 */
	if (p->ldt)
		set_ldt_desc(gdt+(nr<<1)+FIRST_LDT_ENTRY,p->ldt, 512);
	else
		set_ldt_desc(gdt+(nr<<1)+FIRST_LDT_ENTRY,&default_ldt, 1);

	/* 设置子进程的时间片为父进程的一半 */
	p->counter = current->counter >> 1;
	/* 设置子进程为可运行状态，这必须是最后一步 */
	p->state = TASK_RUNNING;	/* 最后设置状态，以防万一 */
	/* 返回子进程的PID */
	return p->pid;

/* 错误处理代码 */
bad_fork_cleanup:
	task[nr] = NULL;		/* 清除任务数组中的引用 */
	REMOVE_LINKS(p);		/* 从进程链表中移除 */
	free_page(p->kernel_stack_page);	/* 释放内核栈页面 */
bad_fork_free:
	free_page((long) p);		/* 释放任务结构体 */
bad_fork:
	return -EAGAIN;		/* 返回错误码 */
}