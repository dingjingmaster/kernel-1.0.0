/*
 *  linux/kernel/exit.c
 *
 *  Copyright (C) 1991, 1992  Linus Torvalds
 */

#define DEBUG_PROC_TREE

#include <linux/wait.h>
#include <linux/errno.h>
#include <linux/signal.h>
#include <linux/sched.h>
#include <linux/kernel.h>
#include <linux/resource.h>
#include <linux/mm.h>
#include <linux/tty.h>
#include <linux/malloc.h>

#include <asm/segment.h>
extern void shm_exit (void);
extern void sem_exit (void);

int getrusage(struct task_struct *, int, struct rusage *);

/*
 * 生成信号并设置到目标进程的信号位图中
 * 
 * 参数:
 *   sig - 要生成的信号编号
 *   p   - 目标进程的任务结构体指针
 * 
 * 返回值:
 *   1 - 成功生成信号
 *   0 - 信号被忽略或无需处理
 * 
 * 此函数执行以下操作:
 * 1. 计算信号对应的位掩码
 * 2. 获取进程的信号处理动作
 * 3. 特殊情况处理（被跟踪进程）
 * 4. 检查信号是否被忽略
 * 5. 检查默认忽略的信号
 * 6. 设置信号位图
 */
static int generate(unsigned long sig, struct task_struct * p)
{
	/* 计算信号对应的位掩码，信号编号从1开始，所以需要减1 */
	unsigned long mask = 1 << (sig-1);
	/* 获取进程的信号处理动作结构，信号编号从1开始，所以需要减1 */
	struct sigaction * sa = sig + p->sigaction - 1;

	/* 特殊处理：被跟踪的进程总是接收信号（用于调试器跟踪） */
	if (p->flags & PF_PTRACED) {
		/* 设置信号位图中对应的位 */
		p->signal |= mask;
		return 1;
	}
	/* 检查信号是否被忽略（SIGCHLD是特殊情况，不能被忽略） */
	if (sa->sa_handler == SIG_IGN && sig != SIGCHLD)
		return 0;
	/* 检查默认忽略的信号（SIGCONT已经处理过了） */
	if ((sa->sa_handler == SIG_DFL) &&
	    (sig == SIGCONT || sig == SIGCHLD || sig == SIGWINCH))
		return 0;
	/* 设置信号位图中对应的位，表示进程有待处理的信号 */
	p->signal |= mask;
	return 1;
}

/*
 * 向指定进程发送信号
 * 
 * 参数:
 *   sig - 要发送的信号编号
 *   p   - 目标进程的任务结构体指针
 *   priv- 权限标志，非0表示忽略权限检查
 * 
 * 返回值:
 *   0 - 成功
 *   -EINVAL - 无效参数（进程指针为空或信号编号超出范围）
 *   -EPERM - 权限不足
 * 
 * 此函数执行以下操作:
 * 1. 参数有效性检查
 * 2. 权限检查
 * 3. 特殊信号处理（SIGKILL和SIGCONT）
 * 4. 停止信号处理（SIGSTOP等）
 * 5. 生成并发送信号
 */
int send_sig(unsigned long sig,struct task_struct * p,int priv)
{
	/* 检查参数有效性：进程指针不能为空，信号编号不能超过32 */
	if (!p || sig > 32)
		return -EINVAL;
	/* 权限检查：非特权用户只能向同UID进程发送信号，或向同一会话发送SIGCONT */
	if (!priv && ((sig != SIGCONT) || (current->session != p->session)) &&
	    (current->euid != p->euid) && (current->uid != p->uid) && !suser())
		return -EPERM;
	/* 信号编号为0，不执行任何操作 */
	if (!sig)
		return 0;
	/* 处理SIGKILL和SIGCONT信号的特殊情况 */
	if ((sig == SIGKILL) || (sig == SIGCONT)) {
		/* 如果目标进程处于停止状态，恢复为运行状态 */
		if (p->state == TASK_STOPPED)
			p->state = TASK_RUNNING;
		/* 清除退出代码 */
		p->exit_code = 0;
		/* 清除所有停止信号（SIGSTOP, SIGTSTP, SIGTTIN, SIGTTOU） */
		p->signal &= ~( (1<<(SIGSTOP-1)) | (1<<(SIGTSTP-1)) |
				(1<<(SIGTTIN-1)) | (1<<(SIGTTOU-1)) );
	}
	/* 处理停止信号（SIGSTOP到SIGTTOU）的情况 */
	/* 注意：此处理依赖于SIGSTOP, SIGTSTP, SIGTTIN, SIGTTOU的顺序 */
	if ((sig >= SIGSTOP) && (sig <= SIGTTOU)) 
		/* 清除SIGCONT信号，因为停止信号和继续信号互斥 */
		p->signal &= ~(1<<(SIGCONT-1));
	/* 实际生成并发送信号 */
	generate(sig,p);
	return 0;
}

/*
 * 通知父进程子进程状态改变
 * 
 * 参数:
 *   tsk - 状态发生改变的子进程任务结构体指针
 * 
 * 此函数执行以下操作:
 * 1. 如果父进程是init进程(task[1])，确保退出信号为SIGCHLD
 * 2. 向父进程发送子进程退出信号
 * 3. 唤醒等待子进程状态改变的父进程
 */
void notify_parent(struct task_struct * tsk)
{
	/* 检查父进程是否为init进程(task[1]) */
	if (tsk->p_pptr == task[1])
		/* 如果是init进程，确保退出信号为SIGCHLD */
		tsk->exit_signal = SIGCHLD;
	/* 向父进程发送子进程退出信号 */
	send_sig(tsk->exit_signal, tsk->p_pptr, 1);
	/* 唤醒等待子进程状态改变的父进程 */
	wake_up_interruptible(&tsk->p_pptr->wait_chldexit);
}

/*
 * 释放任务结构体及其相关资源
 * 
 * 参数:
 *   p - 要释放的任务结构体指针
 * 
 * 此函数执行以下操作:
 * 1. 从任务数组中移除任务
 * 2. 从进程链表和兄弟链表中移除任务
 * 3. 释放任务的内核栈页面
 * 4. 释放任务结构体本身占用的页面
 */
void release(struct task_struct * p)
{
	int i;	/* 循环计数器 */

	/* 检查指针是否有效 */
	if (!p)
		return;
	/* 防止任务释放自身 */
	if (p == current) {
		printk("task releasing itself\n");
		return;
	}
	/* 在任务数组中查找要释放的任务 */
	for (i=1 ; i<NR_TASKS ; i++)
		if (task[i] == p) {
			/* 从任务数组中移除任务 */
			task[i] = NULL;
			/* 从进程链表和兄弟链表中移除任务 */
			REMOVE_LINKS(p);
			/* 释放任务的内核栈页面 */
			free_page(p->kernel_stack_page);
			/* 释放任务结构体本身占用的页面 */
			free_page((long) p);
			return;
		}
	/* 如果找不到任务，触发内核恐慌 */
	panic("trying to release non-existent task");
}

#ifdef DEBUG_PROC_TREE
/*
 * Check to see if a task_struct pointer is present in the task[] array
 * Return 0 if found, and 1 if not found.
 */
/*
 * 检查任务结构体指针是否存在于任务数组中
 * 
 * 参数:
 *   p - 要检查的任务结构体指针
 * 
 * 返回值:
 *   0 - 指针有效（存在于task[]数组中或为空指针）
 *   1 - 指针无效（不存在于task[]数组中）
 */
int bad_task_ptr(struct task_struct *p)
{
	int 	i;	/* 循环计数器 */

	/* 如果指针为空，认为是有效的 */
	if (!p)
		return 0;
	/* 遍历任务数组，查找匹配的任务结构体指针 */
	for (i=0 ; i<NR_TASKS ; i++)
		if (task[i] == p)	/* 找到匹配的指针 */
			return 0;	/* 指针有效，存在于任务数组中 */
	/* 未找到匹配的指针，返回1表示指针无效 */
	return 1;
}
	
/*
 * This routine scans the pid tree and make sure the rep invarient still
 * holds.  Used for debugging only, since it's very slow....
 *
 * It looks a lot scarier than it really is.... we're doing nothing more
 * than verifying the doubly-linked list found in p_ysptr and p_osptr, 
 * and checking it corresponds with the process tree defined by p_cptr and 
 * p_pptr;
 */
/*
 * 审核进程树结构的完整性
 * 
 * 此函数遍历系统中的所有任务，检查进程树结构的完整性，包括：
 * 1. 验证所有任务指针的有效性
 * 2. 检查父子关系、兄弟关系的一致性
 * 3. 确保没有自引用指针
 * 4. 验证双向链表结构的正确性
 * 
 * 此函数仅在DEBUG_PROC_TREE宏定义时使用，用于调试目的
 */
void audit_ptree(void)
{
	int	i;	/* 循环计数器 */

	/* 遍历任务数组中的所有任务（从1开始，0是空闲任务） */
	for (i=1 ; i<NR_TASKS ; i++) {
		/* 跳过空任务槽位 */
		if (!task[i])
			continue;
		
		/* 检查父进程指针的有效性 */
		if (bad_task_ptr(task[i]->p_pptr))
			printk("Warning, pid %d's parent link is bad\n",
				task[i]->pid);
		/* 检查子进程指针的有效性 */
		if (bad_task_ptr(task[i]->p_cptr))
			printk("Warning, pid %d's child link is bad\n",
				task[i]->pid);
		/* 检查年轻兄弟指针(ysptr)的有效性 */
		if (bad_task_ptr(task[i]->p_ysptr))
			printk("Warning, pid %d's ys link is bad\n",
				task[i]->pid);
		/* 检查年长兄弟指针(osptr)的有效性 */
		if (bad_task_ptr(task[i]->p_osptr))
			printk("Warning, pid %d's os link is bad\n",
				task[i]->pid);
		
		/* 检查是否存在自引用指针 */
		if (task[i]->p_pptr == task[i])
			printk("Warning, pid %d parent link points to self\n",
				task[i]->pid);
		if (task[i]->p_cptr == task[i])
			printk("Warning, pid %d child link points to self\n",
				task[i]->pid);
		if (task[i]->p_ysptr == task[i])
			printk("Warning, pid %d ys link points to self\n",
				task[i]->pid);
		if (task[i]->p_osptr == task[i])
			printk("Warning, pid %d os link points to self\n",
				task[i]->pid);
		
		/* 检查年长兄弟关系的正确性 */
		if (task[i]->p_osptr) {
			/* 兄弟进程应该有相同的父进程 */
			if (task[i]->p_pptr != task[i]->p_osptr->p_pptr)
				printk(
			"Warning, pid %d older sibling %d parent is %d\n",
					task[i]->pid, task[i]->p_osptr->pid,
					task[i]->p_osptr->p_pptr->pid);
			/* 年长兄弟的ysptr应该指向当前进程 */
			if (task[i]->p_osptr->p_ysptr != task[i])
				printk(
		"Warning, pid %d older sibling %d has mismatched ys link\n",
					task[i]->pid, task[i]->p_osptr->pid);
		}
		
		/* 检查年轻兄弟关系的正确性 */
		if (task[i]->p_ysptr) {
			/* 兄弟进程应该有相同的父进程 */
			if (task[i]->p_pptr != task[i]->p_ysptr->p_pptr)
				printk(
			"Warning, pid %d younger sibling %d parent is %d\n",
					task[i]->pid, task[i]->p_osptr->pid,
					task[i]->p_osptr->p_pptr->pid);
			/* 年轻兄弟的osptr应该指向当前进程 */
			if (task[i]->p_ysptr->p_osptr != task[i])
				printk(
		"Warning, pid %d younger sibling %d has mismatched os link\n",
					task[i]->pid, task[i]->p_ysptr->pid);
		}
		
		/* 检查子进程关系的正确性 */
		if (task[i]->p_cptr) {
			/* 子进程的父进程应该指向当前进程 */
			if (task[i]->p_cptr->p_pptr != task[i])
				printk(
		"Warning, pid %d youngest child %d has mismatched parent link\n",
					task[i]->pid, task[i]->p_cptr->pid);
			/* 最年轻的子进程不应该有年轻兄弟指针 */
			if (task[i]->p_cptr->p_ysptr)
				printk(
		"Warning, pid %d youngest child %d has non-NULL ys link\n",
					task[i]->pid, task[i]->p_cptr->pid);
		}
	}
}
#endif /* DEBUG_PROC_TREE */

/*
 * session_of_pgrp - 获取进程组对应的会话ID
 * 查找指定进程组所属的会话，如果找不到则回退到进程ID
 * 
 * 此函数不仅检查进程组，如果找不到满意的进程组，
 * 还会回退到进程ID。我不知道 - 没有这个gdb无法正确工作...
 * 
 * 参数:
 * pgrp - 进程组ID或进程ID
 * 
 * 返回值: 成功返回会话ID，失败返回-1
 */
int session_of_pgrp(int pgrp)
{
	struct task_struct *p;	/* 任务结构体指针 */
	int fallback;			/* 回退值 */

	/* 初始化回退值为-1(表示未找到) */
	fallback = -1;
	/* 遍历所有任务，查找匹配的进程 */
	for_each_task(p) {
 		/* 跳过没有会话的进程(session <= 0) */
 		if (p->session <= 0)
 			continue;		/* 继续下一个任务 */
		/* 优先检查进程组是否匹配 */
		if (p->pgrp == pgrp) {
			/* 找到匹配的进程组，立即返回其会话ID */
			return p->session;
		}
		/* 如果进程组不匹配，检查进程ID是否匹配 */
		if (p->pid == pgrp) {
			/* 记录回退值(使用该进程的会话ID) */
			fallback = p->session;
		}
	}
	/* 返回找到的会话ID或回退值 */
	return fallback;
}

/*
 * kill_pg - 向进程组发送信号
 * 向指定进程组中的所有进程发送信号
 * 这就是终端控制字符(^C, ^Z等)所使用的功能
 * 
 * 参数:
 * pgrp - 目标进程组ID
 * sig - 要发送的信号编号
 * priv - 权限级别(0=普通用户,1=超级用户)
 * 
 * 返回值: 成功返回0，失败返回错误码
 *         -ESRCH: 进程组不存在
 *         -EINVAL: 无效参数
 */
int kill_pg(int pgrp, int sig, int priv)
{
	struct task_struct *p;	/* 任务结构体指针 */
	int err,retval = -ESRCH;	/* 错误码和返回值 */
	int found = 0;		/* 找到的进程计数器 */

	/* 检查参数有效性 */
	if (sig<0 || sig>32 || pgrp<=0)
		return -EINVAL;	/* 无效参数 */
	/* 遍历所有任务，查找属于指定进程组的进程 */
	for_each_task(p) {
		/* 检查进程是否属于目标进程组 */
		if (p->pgrp == pgrp) {
			/* 向进程发送信号 */
			if ((err = send_sig(sig,p,priv)) != 0)
				/* 记录错误(非0表示失败) */
				retval = err;
			else
				/* 成功发送，增加找到的进程计数 */
				found++;
		}
	}
	/* 如果找到至少一个进程，返回0；否则返回-ESRCH */
	return(found ? 0 : retval);
}

/*
 * 向指定会话的会话首进程发送信号
 * 
 * 此函数主要用于当终端连接丢失时，向终端的控制进程发送SIGHUP信号
 * 
 * 参数:
 *   sess - 目标会话ID
 *   sig  - 要发送的信号编号
 *   priv - 权限标志，非0表示忽略权限检查
 * 
 * 返回值:
 *   0 - 成功发送信号给至少一个会话首进程
 *   -EINVAL - 无效参数（信号编号超出范围或会话ID无效）
 *   -ESRCH - 没有找到匹配的会话首进程
 *   其他错误码 - 发送信号时遇到的错误
 */
int kill_sl(int sess, int sig, int priv)
{
	struct task_struct *p;	/* 任务结构体指针，用于遍历任务 */
	int err,retval = -ESRCH;	/* err: send_sig的返回值, retval: 函数返回值 */
	int found = 0;	/* 找到的匹配会话首进程数量 */

	/* 检查参数有效性：信号编号必须在0-32范围内，会话ID必须大于0 */
	if (sig<0 || sig>32 || sess<=0)
		return -EINVAL;
	/* 遍历系统中的所有任务 */
	for_each_task(p) {
		/* 检查任务是否属于指定会话且是会话首进程 */
		if (p->session == sess && p->leader) {
			/* 向会话首进程发送信号 */
			if ((err = send_sig(sig,p,priv)) != 0)
				/* 发送失败，保存错误码 */
				retval = err;
			else
				/* 发送成功，增加计数 */
				found++;
		}
	}
	/* 如果至少找到一个会话首进程并发送了信号，返回0；否则返回错误码 */
	return(found ? 0 : retval);
}

/*
 * 向指定进程ID的进程发送信号
 * 
 * 参数:
 *   pid  - 目标进程的进程ID
 *   sig  - 要发送的信号编号
 *   priv - 权限标志，非0表示忽略权限检查
 * 
 * 返回值:
 *   0 - 成功发送信号
 *   -EINVAL - 无效参数（信号编号超出范围）
 *   -ESRCH - 没有找到指定PID的进程
 *   其他错误码 - 发送信号时遇到的错误
 */
int kill_proc(int pid, int sig, int priv)
{
 	struct task_struct *p;	/* 任务结构体指针，用于遍历任务 */

	/* 检查信号编号的有效性：必须在0-32范围内 */
	if (sig<0 || sig>32)
		return -EINVAL;
	/* 遍历系统中的所有任务 */
	for_each_task(p) {
		/* 检查任务是否存在且PID匹配 */
		if (p && p->pid == pid)
			/* 找到目标进程，发送信号并返回结果 */
			return send_sig(sig,p,priv);
	}
	/* 没有找到指定PID的进程 */
	return(-ESRCH);
}

/*
 * sys_kill - 信号发送系统调用
 * 向指定进程或进程组发送信号
 * 
 * POSIX指定kill(-1,sig)是未指定的，但我们现有的实现
 * 可能是错误的。应该像BSD或SYSV那样实现。
 * 
 * 参数:
 * pid - 目标进程ID(正数)、进程组ID(负数)或0(当前进程组)
 * sig - 要发送的信号编号
 * 
 * 返回值: 成功返回0，失败返回错误码
 *         -ESRCH: 进程或进程组不存在
 *         -EPERM: 权限不足
 */
asmlinkage int sys_kill(int pid,int sig)
{
	int err, retval = 0, count = 0;	/* 错误码、返回值和计数器 */

	/* 如果pid为0，向当前进程组发送信号 */
	if (!pid)
		return(kill_pg(current->pgrp,sig,0));	/* 向进程组发送信号 */
	/* 如果pid为-1，向所有进程(除init和当前进程)发送信号 */
	if (pid == -1) {
		struct task_struct * p;	/* 任务结构体指针 */
		/* 遍历所有任务 */
		for_each_task(p) {
			/* 跳过init进程(pid=1)和当前进程 */
			if (p->pid > 1 && p != current) {
				/* 增加计数器 */
				++count;
				/* 向进程发送信号 */
				if ((err = send_sig(sig,p,0)) != -EPERM)
					/* 记录权限错误 */
					retval = err;
			}
		}
		/* 如果有进程被发送信号，返回最后一个错误 */
		return(count ? retval : -ESRCH);
	}
	/* 如果pid为负数，向指定进程组发送信号 */
	if (pid < 0) 
		return(kill_pg(-pid,sig,0));	/* 向进程组发送信号 */
	/* 正常情况：向指定进程发送信号 */
	return(kill_proc(pid,sig,0));	/* 向单个进程发送信号 */
}

/*
 * is_orphaned_pgrp - 检查进程组是否为孤儿进程组
 * 根据POSIX 2.2.2.52的定义确定进程组是否为"孤儿进程组"
 * 孤儿进程组不会受到终端生成的停止信号的影响
 * 新成为孤儿进程组的进程组将收到SIGHUP和SIGCONT信号
 * 
 * "我问你，你可曾知道成为孤儿是什么感觉？"
 * 
 * 参数:
 * pgrp - 要检查的进程组ID
 * 
 * 返回值: 1表示是孤儿进程组，0表示不是
 */
int is_orphaned_pgrp(int pgrp)
{
	struct task_struct *p;    /* 任务结构体指针，用于遍历任务 */

	/* 遍历系统中的所有任务 */
	for_each_task(p) {
		/* 跳过不符合条件的任务：
		 * 1. 不属于指定进程组的任务
		 * 2. 已处于僵尸状态的任务
		 * 3. 父进程是init进程(pid=1)的任务
		 */
		if ((p->pgrp != pgrp) || 
		    (p->state == TASK_ZOMBIE) ||
		    (p->p_pptr->pid == 1))
			continue;
		/* 检查是否存在父进程与我们在同一会话但不同进程组的情况
		 * 如果存在，说明进程组不是孤儿进程组 */
		if ((p->p_pptr->pgrp != pgrp) &&
		    (p->p_pptr->session == p->session))
			return 0;	/* 找到符合条件的父进程，不是孤儿进程组 */
	}
	/* 遍历完所有任务后没有找到符合条件的父进程，是孤儿进程组 */
	return(1);	/* (sighing) "Often!" - 原注释，表示这种情况经常发生 */
}

/*
 * has_stopped_jobs - 检查进程组中是否有已停止的作业
 * 遍历指定进程组中的所有进程，检查是否有进程处于TASK_STOPPED状态
 * 
 * 参数:
 * pgrp - 要检查的进程组ID
 * 
 * 返回值: 1表示有已停止的作业，0表示没有
 */
static int has_stopped_jobs(int pgrp)
{
	struct task_struct * p;    /* 任务结构体指针，用于遍历任务 */

	/* 遍历系统中的所有任务 */
	for_each_task(p) {
		/* 检查任务是否属于指定的进程组 */
		if (p->pgrp != pgrp)
			continue;	/* 不属于指定进程组，继续下一个任务 */
		/* 检查任务是否处于停止状态 */
		if (p->state == TASK_STOPPED)
			return(1);	/* 找到已停止的作业，返回1 */
	}
	/* 没有找到已停止的作业，返回0 */
	return(0);
}

/*
 * forget_original_parent - 忘记原始父进程
 * 将所有以指定进程为原始父进程的进程的原始父进程指针重定向
 * 通常用于进程退出时，将其子进程的原始父进程指向init进程
 * 
 * 参数:
 * father - 要被忘记的原始父进程指针
 */
static void forget_original_parent(struct task_struct * father)
{
	struct task_struct * p;    /* 任务结构体指针，用于遍历任务 */

	/* 遍历系统中的所有任务 */
	for_each_task(p) {
		/* 检查任务的原始父进程是否是要被忘记的父进程 */
		if (p->p_opptr == father)
			/* 将任务的原始父进程重定向 */
			if (task[1])
				/* 优先设置为init进程(task[1]) */
				p->p_opptr = task[1];
			else
				/* 如果init进程不存在，设置为空闲任务(task[0]) */
				p->p_opptr = task[0];
	}
}

/*
 * do_exit - 进程退出处理函数
 * 处理进程退出的所有必要操作，包括资源释放、子进程重定向、
 * 进程组孤儿检查和通知父进程等
 * 
 * 此函数执行以下主要操作：
 * 1. 释放信号量和共享内存资源
 * 2. 释放页表和文件描述符
 * 3. 重定向子进程的父进程关系
 * 4. 释放内存映射区域
 * 5. 释放LDT(局部描述符表)
 * 6. 检查孤儿进程组并发送适当信号
 * 7. 通知父进程子进程已退出
 * 8. 将进程状态设置为TASK_ZOMBIE
 * 
 * 参数:
 * code - 退出码，将被存储在exit_code字段中
 * 
 * 注意: 此函数永不返回(NORET_TYPE)
 */
NORET_TYPE void do_exit(long code)
{
	struct task_struct *p;    /* 任务结构体指针 */
	int i;                    /* 循环计数器 */

fake_volatile:              /* 用于避免gcc警告的标签，防止编译器报告"volatile函数不返回"的警告 */
	/* 释放信号量资源 */
	if (current->semun)
		sem_exit();
	/* 释放共享内存资源 */
	if (current->shm)
		shm_exit();
	/* 释放页表 */
	free_page_tables(current);
	/* 关闭所有打开的文件描述符 */
	for (i=0 ; i<NR_OPEN ; i++)
		if (current->filp[i])
			sys_close(i);
	/* 忘记原始父进程关系 */
	forget_original_parent(current);
	/* 释放当前工作目录inode */
	iput(current->pwd);
	current->pwd = NULL;
	/* 释放根目录inode */
	iput(current->root);
	current->root = NULL;
	/* 释放可执行文件inode */
	iput(current->executable);
	current->executable = NULL;
	/* 释放所有内存映射区域 */
	
	{
		struct vm_area_struct * mpnt, *mpnt1;
		mpnt = current->mmap;
		current->mmap = NULL;
		/* 遍历所有内存映射区域 */
		while (mpnt) {
			mpnt1 = mpnt->vm_next;
			/* 如果有关闭操作，调用它 */
			if (mpnt->vm_ops && mpnt->vm_ops->close)
				mpnt->vm_ops->close(mpnt);
			/* 释放内存映射区域结构 */
			kfree(mpnt);
			mpnt = mpnt1;
		}
	}

	/* 处理局部描述符表(LDT) */
	if (current->ldt) {
		/* 释放LDT内存 */
		vfree(current->ldt);
		current->ldt = NULL;
		/* 更新GDT中的LDT描述符 */
		for (i=1 ; i<NR_TASKS ; i++) {
			if (task[i] == current) {
				/* 设置默认LDT描述符 */
				set_ldt_desc(gdt+(i<<1)+FIRST_LDT_ENTRY, &default_ldt, 1);
				/* 加载LDT */
				load_ldt(i);
			}
		}
	}

	/* 设置进程状态为僵尸 */
	current->state = TASK_ZOMBIE;
	/* 保存退出码 */
	current->exit_code = code;
	/* 重置RSS(驻留集大小) */
	current->rss = 0;
	/* 
	 * 检查是否有进程组因为我们的退出而成为孤儿进程组
	 * 如果有已停止的作业，向它们发送SIGHUP和SIGCONT信号
	 * (POSIX 3.2.2.2)
	 *
	 * 情况i: 父进程与我们在不同的进程组中，且我们是唯一的
	 * 外部连接，所以我们的进程组即将成为孤儿进程组
 	 */
	if ((current->p_pptr->pgrp != current->pgrp) &&
	    (current->p_pptr->session == current->session) &&
	    is_orphaned_pgrp(current->pgrp) &&
	    has_stopped_jobs(current->pgrp)) {
		/* 向进程组发送SIGHUP信号 */
		kill_pg(current->pgrp,SIGHUP,1);
		/* 向进程组发送SIGCONT信号 */
		kill_pg(current->pgrp,SIGCONT,1);
	}
	/* 通知父进程我们已退出 */
	notify_parent(current);
	
	/*
	 * 这个循环做两件事：
	 * 
 	 * A. 让init进程继承所有子进程
	 * B. 检查是否有进程组因为我们的退出而成为孤儿进程组
	 *	如果有已停止的作业，向它们发送SIGHUP和SIGCONT信号
	 * (POSIX 3.2.2.2)
	 */
	while ((p = current->p_cptr) != NULL) {
		/* 从当前进程的子进程列表中取出一个子进程 */
		current->p_cptr = p->p_osptr;
		/* 清除子进程的年轻兄弟指针 */
		p->p_ysptr = NULL;
		/* 清除跟踪标志 */
		p->flags &= ~(PF_PTRACED|PF_TRACESYS);
		/* 设置子进程的新父进程 */
		if (task[1] && task[1] != current)
			p->p_pptr = task[1];	/* 优先设置为init进程 */
		else
			p->p_pptr = task[0];	/* 否则设置为空闲任务 */
		/* 将子进程添加到新父进程的子进程列表中 */
		p->p_osptr = p->p_pptr->p_cptr;
		p->p_osptr->p_ysptr = p;
		p->p_pptr->p_cptr = p;
		/* 如果子进程已经是僵尸状态，通知新父进程 */
		if (p->state == TASK_ZOMBIE)
			notify_parent(p);
		/*
		 * 进程组孤儿检查
		 * 情况ii: 子进程与我们在不同的进程组中，且它是唯一的
		 * 外部连接，所以子进程的进程组现在成为孤儿进程组
		 */
		if ((p->pgrp != current->pgrp) &&
		    (p->session == current->session) &&
		    is_orphaned_pgrp(p->pgrp) &&
		    has_stopped_jobs(p->pgrp)) {
			/* 向子进程的进程组发送SIGHUP信号 */
			kill_pg(p->pgrp,SIGHUP,1);
			/* 向子进程的进程组发送SIGCONT信号 */
			kill_pg(p->pgrp,SIGCONT,1);
		}
	}
	/* 如果当前进程是会话首进程，断开与控制终端的关联 */
	if (current->leader)
		disassociate_ctty(1);
	/* 如果当前进程是最后一个使用数学协处理器的进程，清除标记 */
	if (last_task_used_math == current)
		last_task_used_math = NULL;
#ifdef DEBUG_PROC_TREE
	/* 调试模式下审核进程树 */
	audit_ptree();
#endif
	/* 调度其他进程运行，由于当前进程状态为TASK_ZOMBIE，schedule()不会返回 */
	schedule();
/*
 * 为了消除"volatile函数不返回"的警告，我做了这个小循环
 * 让gcc认为do_exit确实是volatile的。实际上，在某些情况下
 * schedule()是volatile的：当current->state = ZOMBIE时，
 * schedule()永远不会返回。
 *
 * 实际上，自然的方式是将标签和goto放在一起，但我把
 * fake_volatile标签放在函数开始处，以防万一发生什么
 * 真的很糟糕的事情，schedule()返回了。这样我们可以再试一次。
 * 我不是偏执：只是所有人都想陷害我。
 */
	goto fake_volatile;
}

asmlinkage int sys_exit(int error_code)
{
	do_exit((error_code&0xff)<<8);
}

/*
 * sys_wait4 - 等待子进程状态改变系统调用
 * 等待指定子进程的状态改变(终止、停止等)，并收集子进程的资源使用信息
 * 这是waitpid和wait系统调用的底层实现
 * 
 * 参数:
 * pid - 要等待的子进程ID:
 *       >0: 等待指定PID的子进程
 *       =0: 等待与当前进程同进程组的任何子进程
 *       <-1: 等待进程组ID为-pid绝对值的任何子进程
 *       =-1: 等待任何子进程
 * stat_addr - 指向存储子进程状态信息的用户空间指针
 * options - 等待选项:
 *          WNOHANG: 非阻塞模式，如果没有子进程状态改变则立即返回
 *          WUNTRACED: 也等待已停止的子进程
 *          __WCLONE: 等待克隆进程(线程)
 * ru - 指向存储资源使用信息的用户空间指针(可为NULL)
 * 
 * 返回值: 成功返回子进程PID，失败返回错误码:
 *         -ECHILD: 没有符合条件的子进程
 *         -ERESTARTSYS: 被信号中断
 *         -EFAULT: stat_addr指向无效地址
 */
asmlinkage int sys_wait4(pid_t pid,unsigned long * stat_addr, int options, struct rusage * ru)
{
	int flag, retval;                       /* 标志和返回值 */
	struct wait_queue wait = { current, NULL }; /* 等待队列 */
	struct task_struct *p;                  /* 任务结构体指针 */

	/* 如果stat_addr不为空，验证用户空间地址是否可写 */
	if (stat_addr) {
		flag = verify_area(VERIFY_WRITE, stat_addr, 4);
		if (flag)
			return flag;
	}
	/* 将当前进程添加到子进程退出等待队列 */
	add_wait_queue(&current->wait_chldexit,&wait);
repeat:
	flag=0;	/* 重置标志，表示是否找到匹配的子进程 */
 	/* 遍历当前进程的所有子进程 */
 	for (p = current->p_cptr ; p ; p = p->p_osptr) {
		/* 根据pid参数筛选子进程 */
		if (pid>0) {
			/* 等待指定PID的子进程 */
			if (p->pid != pid)
				continue;
		} else if (!pid) {
			/* 等待与当前进程同进程组的任何子进程 */
			if (p->pgrp != current->pgrp)
				continue;
		} else if (pid != -1) {
			/* 等待进程组ID为-pid绝对值的任何子进程 */
			if (p->pgrp != -pid)
				continue;
		}
		/* 只有当设置了__WCLONE标志时才等待克隆进程(线程) */
		if ((p->exit_signal != SIGCHLD) ^ ((options & __WCLONE) != 0))
			continue;
		/* 设置标志，表示找到了匹配的子进程 */
		flag = 1;
		/* 根据子进程状态处理 */
		switch (p->state) {
			case TASK_STOPPED:
				/* 如果子进程没有退出代码，继续等待 */
				if (!p->exit_code)
					continue;
				/* 如果没有设置WUNTRACED且子进程未被跟踪，继续等待 */
				if (!(options & WUNTRACED) && !(p->flags & PF_PTRACED))
					continue;
				/* 将停止状态信息写入用户空间 */
				if (stat_addr)
					put_fs_long((p->exit_code << 8) | 0x7f,
						stat_addr);
				/* 清除子进程的退出代码 */
				p->exit_code = 0;
				/* 如果需要，获取子进程的资源使用信息 */
				if (ru != NULL)
					getrusage(p, RUSAGE_BOTH, ru);
				/* 返回子进程PID */
				retval = p->pid;
				goto end_wait4;
			case TASK_ZOMBIE:
				/* 累加子进程的用户态和内核态CPU时间到父进程 */
				current->cutime += p->utime + p->cutime;
				current->cstime += p->stime + p->cstime;
				/* 累加子进程的次要和主要页面错误计数 */
				current->cmin_flt += p->min_flt + p->cmin_flt;
				current->cmaj_flt += p->maj_flt + p->cmaj_flt;
				/* 如果需要，获取子进程的资源使用信息 */
				if (ru != NULL)
					getrusage(p, RUSAGE_BOTH, ru);
				/* 保存子进程PID用于返回 */
				flag = p->pid;
				/* 将退出状态写入用户空间 */
				if (stat_addr)
					put_fs_long(p->exit_code, stat_addr);
				/* 检查子进程的原始父进程是否与当前父进程不同 */
				if (p->p_opptr != p->p_pptr) {
					/* 从当前父进程中移除子进程 */
					REMOVE_LINKS(p);
					/* 将子进程的父进程设置为原始父进程 */
					p->p_pptr = p->p_opptr;
					/* 将子进程添加到原始父进程的子进程列表中 */
					SET_LINKS(p);
					/* 通知原始父进程 */
					notify_parent(p);
				} else
					/* 释放僵尸进程的资源 */
					release(p);
#ifdef DEBUG_PROC_TREE
				/* 调试模式下审核进程树 */
				audit_ptree();
#endif
				/* 返回子进程PID */
				retval = flag;
				goto end_wait4;
			default:
				/* 子进程状态不符合等待条件，继续检查下一个 */
				continue;
		}
	}
	/* 如果找到了匹配的子进程但状态不符合条件 */
	if (flag) {
		retval = 0;
		/* 如果设置了WNOHANG标志，不阻塞立即返回 */
		if (options & WNOHANG)
			goto end_wait4;
		/* 设置当前进程为可中断睡眠状态 */
		current->state=TASK_INTERRUPTIBLE;
		/* 调度其他进程运行 */
		schedule();
		/* 清除SIGCHLD信号 */
		current->signal &= ~(1<<(SIGCHLD-1));
		/* 如果被信号中断，返回-ERESTARTSYS */
		retval = -ERESTARTSYS;
		if (current->signal & ~current->blocked)
			goto end_wait4;
		/* 重新检查子进程状态 */
		goto repeat;
	}
	/* 没有找到符合条件的子进程 */
	retval = -ECHILD;
end_wait4:
	/* 从等待队列中移除当前进程 */
	remove_wait_queue(&current->wait_chldexit,&wait);
	return retval;
}

/*
 * sys_waitpid - 等待子进程状态改变系统调用(兼容性函数)
 * 此函数保持向后兼容性，实际的waitpid()应该通过libc.a调用sys_wait4()实现
 * 
 * 参数:
 * pid - 要等待的子进程ID(与sys_wait4相同)
 * stat_addr - 指向存储子进程状态信息的用户空间指针
 * options - 等待选项(与sys_wait4相同)
 * 
 * 返回值: 成功返回子进程PID，失败返回错误码(与sys_wait4相同)
 * 
 * 注意: 此函数是sys_wait4的简化版本，不收集资源使用信息
 */
asmlinkage int sys_waitpid(pid_t pid,unsigned long * stat_addr, int options)
{
	/* 直接调用sys_wait4，不收集资源使用信息 */
	return sys_wait4(pid, stat_addr, options, NULL);
}