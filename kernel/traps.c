/*
 *  linux/kernel/traps.c
 *
 *  Copyright (C) 1991, 1992  Linus Torvalds
 */

/*
 * 'Traps.c' handles hardware traps and faults after we have saved some
 * state in 'asm.s'. Currently mostly a debugging-aid, will be extended
 * to mainly kill the offending process (probably by giving it a signal,
 * but possibly by killing it outright if necessary).
 */
#include <linux/head.h>
#include <linux/sched.h>
#include <linux/kernel.h>
#include <linux/string.h>
#include <linux/errno.h>
#include <linux/segment.h>
#include <linux/ptrace.h>

#include <asm/system.h>
#include <asm/segment.h>
#include <asm/io.h>

static inline void console_verbose(void)
{
	extern int console_loglevel;
	console_loglevel = 15;
}

#define DO_ERROR(trapnr, signr, str, name, tsk) \
asmlinkage void do_##name(struct pt_regs * regs, long error_code) \
{ \
	tsk->tss.error_code = error_code; \
	tsk->tss.trap_no = trapnr; \
	if (signr == SIGTRAP && current->flags & PF_PTRACED) \
		current->blocked &= ~(1 << (SIGTRAP-1)); \
	send_sig(signr, tsk, 1); \
	die_if_kernel(str,regs,error_code); \
}

#define get_seg_byte(seg,addr) ({ \
register char __res; \
__asm__("push %%fs;mov %%ax,%%fs;movb %%fs:%2,%%al;pop %%fs" \
	:"=a" (__res):"0" (seg),"m" (*(addr))); \
__res;})

#define get_seg_long(seg,addr) ({ \
register unsigned long __res; \
__asm__("push %%fs;mov %%ax,%%fs;movl %%fs:%2,%%eax;pop %%fs" \
	:"=a" (__res):"0" (seg),"m" (*(addr))); \
__res;})

#define _fs() ({ \
register unsigned short __res; \
__asm__("mov %%fs,%%ax":"=a" (__res):); \
__res;})

void page_exception(void);

asmlinkage void divide_error(void);
asmlinkage void debug(void);
asmlinkage void nmi(void);
asmlinkage void int3(void);
asmlinkage void overflow(void);
asmlinkage void bounds(void);
asmlinkage void invalid_op(void);
asmlinkage void device_not_available(void);
asmlinkage void double_fault(void);
asmlinkage void coprocessor_segment_overrun(void);
asmlinkage void invalid_TSS(void);
asmlinkage void segment_not_present(void);
asmlinkage void stack_segment(void);
asmlinkage void general_protection(void);
asmlinkage void page_fault(void);
asmlinkage void coprocessor_error(void);
asmlinkage void reserved(void);
asmlinkage void alignment_check(void);

/*static*/ void die_if_kernel(char * str, struct pt_regs * regs, long err)
{
	int i;
	unsigned long esp;
	unsigned short ss;

	esp = (unsigned long) &regs->esp;
	ss = KERNEL_DS;
	if ((regs->eflags & VM_MASK) || (3 & regs->cs) == 3)
		return;
	if (regs->cs & 3) {
		esp = regs->esp;
		ss = regs->ss;
	}
	console_verbose();
	printk("%s: %04lx\n", str, err & 0xffff);
	printk("EIP:    %04x:%08lx\nEFLAGS: %08lx\n", 0xffff & regs->cs,regs->eip,regs->eflags);
	printk("eax: %08lx   ebx: %08lx   ecx: %08lx   edx: %08lx\n",
		regs->eax, regs->ebx, regs->ecx, regs->edx);
	printk("esi: %08lx   edi: %08lx   ebp: %08lx   esp: %08lx\n",
		regs->esi, regs->edi, regs->ebp, esp);
	printk("ds: %04x   es: %04x   fs: %04x   gs: %04x   ss: %04x\n",
		regs->ds, regs->es, regs->fs, regs->gs, ss);
	store_TR(i);
	printk("Pid: %d, process nr: %d (%s)\nStack: ", current->pid, 0xffff & i, current->comm);
	for(i=0;i<5;i++)
		printk("%08lx ", get_seg_long(ss,(i+(unsigned long *)esp)));
	printk("\nCode: ");
	for(i=0;i<20;i++)
		printk("%02x ",0xff & get_seg_byte(regs->cs,(i+(char *)regs->eip)));
	printk("\n");
	do_exit(SIGSEGV);
}

DO_ERROR( 0, SIGFPE,  "divide error", divide_error, current)
DO_ERROR( 3, SIGTRAP, "int3", int3, current)
DO_ERROR( 4, SIGSEGV, "overflow", overflow, current)
DO_ERROR( 5, SIGSEGV, "bounds", bounds, current)
DO_ERROR( 6, SIGILL,  "invalid operand", invalid_op, current)
DO_ERROR( 7, SIGSEGV, "device not available", device_not_available, current)
DO_ERROR( 8, SIGSEGV, "double fault", double_fault, current)
DO_ERROR( 9, SIGFPE,  "coprocessor segment overrun", coprocessor_segment_overrun, last_task_used_math)
DO_ERROR(10, SIGSEGV, "invalid TSS", invalid_TSS, current)
DO_ERROR(11, SIGSEGV, "segment not present", segment_not_present, current)
DO_ERROR(12, SIGSEGV, "stack segment", stack_segment, current)
DO_ERROR(13, SIGSEGV, "general protection", general_protection, current)
DO_ERROR(15, SIGSEGV, "reserved", reserved, current)
DO_ERROR(17, SIGSEGV, "alignment check", alignment_check, current)

asmlinkage void do_nmi(struct pt_regs * regs, long error_code)
{
	printk("Uhhuh. NMI received. Dazed and confused, but trying to continue\n");
	printk("You probably have a hardware problem with your RAM chips\n");
}

asmlinkage void do_debug(struct pt_regs * regs, long error_code)
{
	if (current->flags & PF_PTRACED)
		current->blocked &= ~(1 << (SIGTRAP-1));
	send_sig(SIGTRAP, current, 1);
	current->tss.trap_no = 1;
	current->tss.error_code = error_code;
	if((regs->cs & 3) == 0) {
	  /* If this is a kernel mode trap, then reset db7 and allow us to continue */
	  __asm__("movl $0,%%edx\n\t" \
		  "movl %%edx,%%db7\n\t" \
		  : /* no output */ \
		  : /* no input */ :"dx");

	  return;
	};
	die_if_kernel("debug",regs,error_code);
}

/*
 * math_error - 数学协处理器错误处理函数
 * 被IRQ13(387)和异常16用于处理数学错误
 *
 * 注意：我们通过操作'TS'位来希望在异步IRQ13行为存在的情况下
 * 获得正确的行为
 */
void math_error(void)
{
	struct i387_hard_struct * env;	/* 协处理器环境结构体指针 */

	/* 清除任务切换标志(TS)，允许使用数学协处理器 */
	clts();
	/* 检查是否有任务使用了数学协处理器 */
	if (!last_task_used_math) {
		/* 没有任务使用协处理器，清除异常状态并返回 */
		__asm__("fnclex");	/* 清除协处理器异常状态 */
		return;			/* 直接返回 */
	}
	/* 获取使用协处理器的任务的协处理器环境指针 */
	env = &last_task_used_math->tss.i387.hard;
	/* 向使用协处理器的任务发送浮点异常信号 */
	send_sig(SIGFPE, last_task_used_math, 1);
	/* 设置陷阱编号为16(协处理器错误) */
	last_task_used_math->tss.trap_no = 16;
	/* 设置错误码为0 */
	last_task_used_math->tss.error_code = 0;
	/* 保存协处理器状态到任务结构体中 */
	__asm__ __volatile__("fnsave %0":"=m" (*env));
	/* 清除最后一个使用协处理器的任务指针 */
	last_task_used_math = NULL;
	/* 设置任务切换标志(TS)，禁止使用数学协处理器 */
	stts();
	/* 处理保存的协处理器状态，确保一致性 */
	/* 修复指令指针的低16位 */
	env->fcs = (env->swd & 0x0000ffff) | (env->fcs & 0xffff0000);
	/* 设置操作数指针 */
	env->fos = env->twd;
	/* 清除状态字中的某些位 */
	env->swd &= 0xffff3800;
	/* 设置标记字为全1(表示空寄存器) */
	env->twd = 0xffffffff;
}

asmlinkage void do_coprocessor_error(struct pt_regs * regs, long error_code)
{
	ignore_irq13 = 1;
	math_error();
}

/*
 * trap_init - 中断和陷阱门初始化函数
 * 设置IDT(中断描述符表)中的陷阱门和中断门，
 * 将硬件陷阱和异常与相应的处理程序关联起来
 * 
 * 此函数在系统启动时被调用，完成异常处理机制的初始化
 * 它为CPU可能产生的各种异常设置处理程序，确保系统能够
 * 正确响应和处理硬件异常和软件中断
 */
void trap_init(void)
{
	int i;		/* 循环计数器 */

	/* 设置除法错误陷阱门(向量0) */
	set_trap_gate(0,&divide_error);
	/* 设置调试陷阱门(向量1) */
	set_trap_gate(1,&debug);
	/* 设置不可屏蔽中断门(向量2) */
	set_trap_gate(2,&nmi);
	/* 设置断点陷阱门(向量3) - 可从所有特权级调用 */
	set_system_gate(3,&int3);	/* int3-5 can be called from all */
	/* 设置溢出陷阱门(向量4) - 可从所有特权级调用 */
	set_system_gate(4,&overflow);
	/* 设置边界检查陷阱门(向量5) - 可从所有特权级调用 */
	set_system_gate(5,&bounds);
	/* 设置无效操作码陷阱门(向量6) */
	set_trap_gate(6,&invalid_op);
	/* 设置设备不可用陷阱门(向量7) */
	set_trap_gate(7,&device_not_available);
	/* 设置双重故障陷阱门(向量8) */
	set_trap_gate(8,&double_fault);
	/* 设置协处理器段越界陷阱门(向量9) */
	set_trap_gate(9,&coprocessor_segment_overrun);
	/* 设置无效TSS陷阱门(向量10) */
	set_trap_gate(10,&invalid_TSS);
	/* 设置段不存在陷阱门(向量11) */
	set_trap_gate(11,&segment_not_present);
	/* 设置栈段故障陷阱门(向量12) */
	set_trap_gate(12,&stack_segment);
	/* 设置一般保护故障陷阱门(向量13) */
	set_trap_gate(13,&general_protection);
	/* 设置页故障陷阱门(向量14) */
	set_trap_gate(14,&page_fault);
	/* 设置保留陷阱门(向量15) */
	set_trap_gate(15,&reserved);
	/* 设置协处理器错误陷阱门(向量16) */
	set_trap_gate(16,&coprocessor_error);
	/* 设置对齐检查陷阱门(向量17) */
	set_trap_gate(17,&alignment_check);
	/* 为向量18-47设置保留陷阱门 */
	for (i=18;i<48;i++)
		set_trap_gate(i,&reserved);	/* 未使用的异常向量 */
}