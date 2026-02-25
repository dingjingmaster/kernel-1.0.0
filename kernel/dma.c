/* $Id: dma.c,v 1.5 1992/11/18 02:49:05 root Exp root $
 * linux/kernel/dma.c: A DMA channel allocator. Inspired by linux/kernel/irq.c.
 * Written by Hennus Bergman, 1992. 
 */

#include <linux/kernel.h>
#include <linux/errno.h>
#include <asm/dma.h>


/* A note on resource allocation:
 *
 * All drivers needing DMA channels, should allocate and release them
 * through the public routines `request_dma()' and `free_dma()'.
 *
 * In order to avoid problems, all processes should allocate resources in
 * the same sequence and release them in the reverse order.
 * 
 * So, when allocating DMAs and IRQs, first allocate the IRQ, then the DMA.
 * When releasing them, first release the DMA, then release the IRQ.
 * If you don't, you may cause allocation requests to fail unnecessarily.
 * This doesn't really matter now, but it will once we get real semaphores
 * in the kernel.
 */



/* Channel n is busy iff dma_chan_busy[n] != 0.
 * DMA0 is reserved for DRAM refresh, I think.
 * DMA4 is reserved for cascading (?).
 */
static volatile unsigned int dma_chan_busy[MAX_DMA_CHANNELS] = {
	1, 0, 0, 0, 1, 0, 0, 0
};



/* Atomically swap memory location [32 bits] with `newval'.
 * This avoid the cli()/sti() junk and related problems.
 * [And it's faster too :-)]
 * Maybe this should be in include/asm/mutex.h and be used for
 * implementing kernel-semaphores as well.
 */
/*
 * mutex_atomic_swap - 原子交换操作函数
 * 执行原子的读-修改-写操作，用于实现互斥锁
 * 
 * 此函数实现了一个基本的互斥机制，允许多个进程/驱动程序
 * 安全地共享资源，防止竞争条件
 * 
 * 参数:
 * p - 指向要修改的内存位置的指针
 * newval - 要写入的新值
 * 
 * 返回值: 内存位置的原始值
 */
static __inline__ unsigned int mutex_atomic_swap(volatile unsigned int * p, unsigned int newval)
{
	unsigned int semval = newval;	/* 临时变量，存储新值 */

	/* 
	 * XCHG指令的注意事项：
	 * 如果XCHG指令的一个操作数是内存引用，
	 * 它会使交换成为不可中断的RMW周期。
	 *
	 * 一个操作数必须在内存中，另一个在寄存器中，否则
	 * 交换可能不是原子的。
	 */

	/* 使用内联汇编执行原子交换操作 */
	asm __volatile__ ("xchgl %2, %0\n"			: /* 输出: semval   */ "=r" (semval)
			: /* 输入: newval, p */ "0" (semval), "m" (*p)
			); 	/* p是包含地址的变量 */
	/* 返回内存位置的原始值 */
	return semval;
} /* mutex_atomic_swap */



/*
 * request_dma - 请求DMA通道
 * 为设备驱动程序分配DMA通道，用于高速数据传输
 * 
 * DMA(Direct Memory Access)允许设备直接访问内存，
 * 无需CPU干预，提高系统性能，特别适用于块设备
 * 
 * 参数:
 * dmanr - DMA通道编号
 * 
 * 返回值: 成功返回0，失败返回错误码
 *         -EINVAL: 无效的通道号
 *         -EBUSY: 通道已被占用
 */
int request_dma(unsigned int dmanr)
{
	/* 检查DMA通道号是否有效 */
	if (dmanr >= MAX_DMA_CHANNELS)
		return -EINVAL;		/* 无效的通道号 */

	/* 尝试原子地获取DMA通道 */
	if (mutex_atomic_swap(&dma_chan_busy[dmanr], 1) != 0)
		return -EBUSY;		/* 通道已被占用 */
	else
		/* 原标志为0，现在包含1表示忙碌 */
		return 0;			/* 成功获取通道 */
} /* request_dma */


void free_dma(unsigned int dmanr)
{
	if (dmanr >= MAX_DMA_CHANNELS) {
		printk("Trying to free DMA%d\n", dmanr);
		return;
	}

	if (mutex_atomic_swap(&dma_chan_busy[dmanr], 0) == 0)
		printk("Trying to free free DMA%d\n", dmanr);
} /* free_dma */