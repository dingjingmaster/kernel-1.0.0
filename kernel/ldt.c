/*
 * linux/kernel/ldt.c
 *
 * Copyright (C) 1992 Krishna Balasubramanian and Linus Torvalds
 */

#include <linux/config.h>
#include <linux/errno.h>
#include <linux/sched.h>
#include <linux/string.h>
#include <asm/segment.h>
#include <asm/system.h>
#include <linux/ldt.h>

static int read_ldt(void * ptr, unsigned long bytecount)
{
	int error;
	void * address = current->ldt;
	unsigned long size;

	if (!ptr)
		return -EINVAL;
	size = LDT_ENTRIES*LDT_ENTRY_SIZE;
	if (!address) {
		address = &default_ldt;
		size = sizeof(default_ldt);
	}
	if (size > bytecount)
		size = bytecount;
	error = verify_area(VERIFY_WRITE, ptr, size);
	if (error)
		return error;
	memcpy_tofs(ptr, address, size);
	return size;
}

/*
 * write_ldt - 写入本地描述符表(LDT)条目
 * 允许进程修改自己的LDT条目，用于实现段级内存保护
 * LDT是x86架构特有的机制，用于提供额外的段描述符
 * 
 * 参数:
 * ptr - 指向LDT信息的用户空间指针
 * bytecount - 数据大小(必须等于sizeof(ldt_info))
 * 
 * 返回值: 成功返回0，失败返回错误码
 */
static int write_ldt(void * ptr, unsigned long bytecount)
{
	struct modify_ldt_ldt_s ldt_info;	/* LDT信息结构体 */
	unsigned long *lp;			/* LDT条目指针 */
	unsigned long base, limit;		/* 段基址和界限 */
	int error, i;			/* 错误码和循环计数器 */

	/* 检查数据大小是否正确 */
	if (bytecount != sizeof(ldt_info))
		return -EINVAL;		/* 无效参数 */
	/* 验证用户空间缓冲区的可读性 */
	error = verify_area(VERIFY_READ, ptr, sizeof(ldt_info));
	if (error)
		return error;		/* 缓冲区访问错误 */

	/* 从用户空间复制LDT信息 */
	memcpy_fromfs(&ldt_info, ptr, sizeof(ldt_info));

	/* 检查LDT条目类型和编号的有效性 */
	if (ldt_info.contents == 3 || ldt_info.entry_number >= LDT_ENTRIES)
		return -EINVAL;		/* 无效的LDT条目 */

	/* 计算段基址和界限 */
	limit = ldt_info.limit;
	base = ldt_info.base_addr;
	/* 如果界限以页为单位，转换为字节 */
	if (ldt_info.limit_in_pages)
		limit *= PAGE_SIZE;

	/* 计算段的结束地址 */
	limit += base;
	/* 检查段范围是否有效 */
	if (limit < base || limit >= 0xC0000000)
		return -EINVAL;		/* 无效的段范围 */

	/* 如果当前进程还没有LDT，需要分配一个 */
	if (!current->ldt) {
		/* 遍历任务数组，找到当前进程的位置 */
		for (i=1 ; i<NR_TASKS ; i++) {
			if (task[i] == current) {
				/* 为当前进程分配LDT空间 */
				if (!(current->ldt = (struct desc_struct*) vmalloc(LDT_ENTRIES*LDT_ENTRY_SIZE)))
					return -ENOMEM;	/* 内存不足 */
				/* 在GDT中设置LDT描述符 */
				set_ldt_desc(gdt+(i<<1)+FIRST_LDT_ENTRY, current->ldt, LDT_ENTRIES);
				/* 加载LDT */
				load_ldt(i);
			}
		}
	}
	
	/* 获取指定LDT条目的地址 */
	lp = (unsigned long *) &current->ldt[ldt_info.entry_number];
    /* 允许用户清除LDT条目 */
    if (ldt_info.base_addr == 0 && ldt_info.limit == 0) {
		/* 清除LDT条目(设置为空描述符) */
		*lp = 0;
		*(lp+1) = 0;
		return 0;		/* 成功返回 */
	}
	/* 构建LDT条目的低32位(基址低16位和界限低16位) */
	*lp = ((ldt_info.base_addr & 0x0000ffff) << 16) |
		  (ldt_info.limit & 0x0ffff);
	/* 构建LDT条目的高32位(基址高8位、界限高4位、类型等) */
	*(lp+1) = (ldt_info.base_addr & 0xff000000) |
		  ((ldt_info.base_addr & 0x00ff0000)>>16) |
		  (ldt_info.limit & 0xf0000) |
		  (ldt_info.contents << 10) |
		  ((ldt_info.read_exec_only ^ 1) << 9) |
		  (ldt_info.seg_32bit << 22) |
		  (ldt_info.limit_in_pages << 23) |
		  0xf000;		/* 高4位固定为0xf */
	return 0;		/* 成功返回 */
}

asmlinkage int sys_modify_ldt(int func, void *ptr, unsigned long bytecount)
{
	if (func == 0)
		return read_ldt(ptr, bytecount);
	if (func == 1)
		return write_ldt(ptr, bytecount);
	return -ENOSYS;
}