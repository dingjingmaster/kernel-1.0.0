/*
 *  linux/mm/memory.c
 *
 *  Copyright (C) 1991, 1992  Linus Torvalds
 */

/*
 * demand-loading started 01.12.91 - seems it is high on the list of
 * things wanted, and it should be easy to implement. - Linus
 */

/*
 * Ok, demand-loading was easy, shared pages a little bit tricker. Shared
 * pages started 02.12.91, seems to work. - Linus.
 *
 * Tested sharing by executing about 30 /bin/sh: under the old kernel it
 * would have taken more than the 6M I have free, but it worked well as
 * far as I could see.
 *
 * Also corrected some "invalidate()"s - I wasn't doing enough of them.
 */

/*
 * Real VM (paging to/from disk) started 18.12.91. Much more work and
 * thought has to go into this. Oh, well..
 * 19.12.91  -  works, somewhat. Sometimes I get faults, don't know why.
 *		Found it. Everything seems to work now.
 * 20.12.91  -  Ok, making the swap-device changeable like the root.
 */

#include <asm/system.h>
#include <linux/config.h>

#include <linux/signal.h>
#include <linux/sched.h>
#include <linux/head.h>
#include <linux/kernel.h>
#include <linux/errno.h>
#include <linux/string.h>
#include <linux/types.h>
#include <linux/ptrace.h>
#include <linux/mman.h>

unsigned long high_memory = 0;

extern unsigned long pg0[1024];		/* page table for 0-4MB for everybody */

extern void sound_mem_init(void);
extern void die_if_kernel(char *,struct pt_regs *,long);

int nr_swap_pages = 0;
int nr_free_pages = 0;
unsigned long free_page_list = 0;
/*
 * The secondary free_page_list is used for malloc() etc things that
 * may need pages during interrupts etc. Normal get_free_page() operations
 * don't touch it, so it stays as a kind of "panic-list", that can be
 * accessed when all other mm tricks have failed.
 */
int nr_secondary_pages = 0;
unsigned long secondary_page_list = 0;

#define copy_page(from,to) \
__asm__("cld ; rep ; movsl": :"S" (from),"D" (to),"c" (1024):"cx","di","si")

unsigned short * mem_map = NULL;

#define CODE_SPACE(addr,p) ((addr) < (p)->end_code)

/*
 * oom() 打印一条消息(让用户知道进程为什么死亡)，
 * 并向进程发送一个无法捕获的SIGKILL信号。
 */
void oom(struct task_struct * task)
{
	/* 向控制台打印内存不足信息 */
	printk("\nout of memory\n");
	/* 清除SIGKILL信号的处理函数，确保进程无法捕获该信号 */
	task->sigaction[SIGKILL-1].sa_handler = NULL;
	/* 从进程的信号屏蔽字中移除SIGKILL信号，确保信号不会被阻塞 */
	task->blocked &= ~(1<<(SIGKILL-1));
	/* 向指定进程发送SIGKILL信号，强制终止进程 */
	send_sig(SIGKILL,task,1);
}

static void free_one_table(unsigned long * page_dir)
{
	int j;
	unsigned long pg_table = *page_dir;
	unsigned long * page_table;

	if (!pg_table)
		return;
	*page_dir = 0;
	if (pg_table >= high_memory || !(pg_table & PAGE_PRESENT)) {
		printk("Bad page table: [%p]=%08lx\n",page_dir,pg_table);
		return;
	}
	if (mem_map[MAP_NR(pg_table)] & MAP_PAGE_RESERVED)
		return;
	page_table = (unsigned long *) (pg_table & PAGE_MASK);
	for (j = 0 ; j < PTRS_PER_PAGE ; j++,page_table++) {
		unsigned long pg = *page_table;
		
		if (!pg)
			continue;
		*page_table = 0;
		if (pg & PAGE_PRESENT)
			free_page(PAGE_MASK & pg);
		else
			swap_free(pg);
	}
	free_page(PAGE_MASK & pg_table);
}

/*
 * This function clears all user-level page tables of a process - this
 * is needed by execve(), so that old pages aren't in the way. Note that
 * unlike 'free_page_tables()', this function still leaves a valid
 * page-table-tree in memory: it just removes the user pages. The two
 * functions are similar, but there is a fundamental difference.
 */
void clear_page_tables(struct task_struct * tsk)
{
	int i;
	unsigned long pg_dir;
	unsigned long * page_dir;

	if (!tsk)
		return;
	if (tsk == task[0])
		panic("task[0] (swapper) doesn't support exec()\n");
	pg_dir = tsk->tss.cr3;
	page_dir = (unsigned long *) pg_dir;
	if (!page_dir || page_dir == swapper_pg_dir) {
		printk("Trying to clear kernel page-directory: not good\n");
		return;
	}
	if (mem_map[MAP_NR(pg_dir)] > 1) {
		unsigned long * new_pg;

		if (!(new_pg = (unsigned long*) get_free_page(GFP_KERNEL))) {
			oom(tsk);
			return;
		}
		for (i = 768 ; i < 1024 ; i++)
			new_pg[i] = page_dir[i];
		free_page(pg_dir);
		tsk->tss.cr3 = (unsigned long) new_pg;
		return;
	}
	for (i = 0 ; i < 768 ; i++,page_dir++)
		free_one_table(page_dir);
	invalidate();
	return;
}

/*
 * This function frees up all page tables of a process when it exits.
 */
void free_page_tables(struct task_struct * tsk)
{
	int i;
	unsigned long pg_dir;
	unsigned long * page_dir;

	if (!tsk)
		return;
	if (tsk == task[0]) {
		printk("task[0] (swapper) killed: unable to recover\n");
		panic("Trying to free up swapper memory space");
	}
	pg_dir = tsk->tss.cr3;
	if (!pg_dir || pg_dir == (unsigned long) swapper_pg_dir) {
		printk("Trying to free kernel page-directory: not good\n");
		return;
	}
	tsk->tss.cr3 = (unsigned long) swapper_pg_dir;
	if (tsk == current)
		__asm__ __volatile__("movl %0,%%cr3": :"a" (tsk->tss.cr3));
	if (mem_map[MAP_NR(pg_dir)] > 1) {
		free_page(pg_dir);
		return;
	}
	page_dir = (unsigned long *) pg_dir;
	for (i = 0 ; i < PTRS_PER_PAGE ; i++,page_dir++)
		free_one_table(page_dir);
	free_page(pg_dir);
	invalidate();
}

/*
 * clone_page_tables() clones the page table for a process - both
 * processes will have the exact same pages in memory. There are
 * probably races in the memory management with cloning, but we'll
 * see..
 */
int clone_page_tables(struct task_struct * tsk)
{
	unsigned long pg_dir;

	pg_dir = current->tss.cr3;
	mem_map[MAP_NR(pg_dir)]++;
	tsk->tss.cr3 = pg_dir;
	return 0;
}

/*
 * copy_page_tables() just copies the whole process memory range:
 * note the special handling of RESERVED (ie kernel) pages, which
 * means that they are always shared by all processes.
 */
int copy_page_tables(struct task_struct * tsk)
{
	int i;
	unsigned long old_pg_dir, *old_page_dir;
	unsigned long new_pg_dir, *new_page_dir;

	if (!(new_pg_dir = get_free_page(GFP_KERNEL)))
		return -ENOMEM;
	old_pg_dir = current->tss.cr3;
	tsk->tss.cr3 = new_pg_dir;
	old_page_dir = (unsigned long *) old_pg_dir;
	new_page_dir = (unsigned long *) new_pg_dir;
	for (i = 0 ; i < PTRS_PER_PAGE ; i++,old_page_dir++,new_page_dir++) {
		int j;
		unsigned long old_pg_table, *old_page_table;
		unsigned long new_pg_table, *new_page_table;

		old_pg_table = *old_page_dir;
		if (!old_pg_table)
			continue;
		if (old_pg_table >= high_memory || !(old_pg_table & PAGE_PRESENT)) {
			printk("copy_page_tables: bad page table: "
				"probable memory corruption");
			*old_page_dir = 0;
			continue;
		}
		if (mem_map[MAP_NR(old_pg_table)] & MAP_PAGE_RESERVED) {
			*new_page_dir = old_pg_table;
			continue;
		}
		if (!(new_pg_table = get_free_page(GFP_KERNEL))) {
			free_page_tables(tsk);
			return -ENOMEM;
		}
		old_page_table = (unsigned long *) (PAGE_MASK & old_pg_table);
		new_page_table = (unsigned long *) (PAGE_MASK & new_pg_table);
		for (j = 0 ; j < PTRS_PER_PAGE ; j++,old_page_table++,new_page_table++) {
			unsigned long pg;
			pg = *old_page_table;
			if (!pg)
				continue;
			if (!(pg & PAGE_PRESENT)) {
				*new_page_table = swap_duplicate(pg);
				continue;
			}
			if ((pg & (PAGE_RW | PAGE_COW)) == (PAGE_RW | PAGE_COW))
				pg &= ~PAGE_RW;
			*new_page_table = pg;
			if (mem_map[MAP_NR(pg)] & MAP_PAGE_RESERVED)
				continue;
			*old_page_table = pg;
			mem_map[MAP_NR(pg)]++;
		}
		*new_page_dir = new_pg_table | PAGE_TABLE;
	}
	invalidate();
	return 0;
}

/*
 * a more complete version of free_page_tables which performs with page
 * granularity.
 */
int unmap_page_range(unsigned long from, unsigned long size)
{
	unsigned long page, page_dir;
	unsigned long *page_table, *dir;
	unsigned long poff, pcnt, pc;

	if (from & ~PAGE_MASK) {
		printk("unmap_page_range called with wrong alignment\n");
		return -EINVAL;
	}
	size = (size + ~PAGE_MASK) >> PAGE_SHIFT;
	dir = PAGE_DIR_OFFSET(current->tss.cr3,from);
	poff = (from >> PAGE_SHIFT) & (PTRS_PER_PAGE-1);
	if ((pcnt = PTRS_PER_PAGE - poff) > size)
		pcnt = size;

	for ( ; size > 0; ++dir, size -= pcnt,
	     pcnt = (size > PTRS_PER_PAGE ? PTRS_PER_PAGE : size)) {
		if (!(page_dir = *dir))	{
			poff = 0;
			continue;
		}
		if (!(page_dir & PAGE_PRESENT)) {
			printk("unmap_page_range: bad page directory.");
			continue;
		}
		page_table = (unsigned long *)(PAGE_MASK & page_dir);
		if (poff) {
			page_table += poff;
			poff = 0;
		}
		for (pc = pcnt; pc--; page_table++) {
			if ((page = *page_table) != 0) {
				*page_table = 0;
				if (1 & page) {
					if (!(mem_map[MAP_NR(page)] & MAP_PAGE_RESERVED))
						if (current->rss > 0)
							--current->rss;
					free_page(PAGE_MASK & page);
				} else
					swap_free(page);
			}
		}
		if (pcnt == PTRS_PER_PAGE) {
			*dir = 0;
			free_page(PAGE_MASK & page_dir);
		}
	}
	invalidate();
	return 0;
}

int zeromap_page_range(unsigned long from, unsigned long size, int mask)
{
	unsigned long *page_table, *dir;
	unsigned long poff, pcnt;
	unsigned long page;

	if (mask) {
		if ((mask & (PAGE_MASK|PAGE_PRESENT)) != PAGE_PRESENT) {
			printk("zeromap_page_range: mask = %08x\n",mask);
			return -EINVAL;
		}
		mask |= ZERO_PAGE;
	}
	if (from & ~PAGE_MASK) {
		printk("zeromap_page_range: from = %08lx\n",from);
		return -EINVAL;
	}
	dir = PAGE_DIR_OFFSET(current->tss.cr3,from);
	size = (size + ~PAGE_MASK) >> PAGE_SHIFT;
	poff = (from >> PAGE_SHIFT) & (PTRS_PER_PAGE-1);
	if ((pcnt = PTRS_PER_PAGE - poff) > size)
		pcnt = size;

	while (size > 0) {
		if (!(PAGE_PRESENT & *dir)) {
				/* clear page needed here?  SRB. */
			if (!(page_table = (unsigned long*) get_free_page(GFP_KERNEL))) {
				invalidate();
				return -ENOMEM;
			}
			if (PAGE_PRESENT & *dir) {
				free_page((unsigned long) page_table);
				page_table = (unsigned long *)(PAGE_MASK & *dir++);
			} else
				*dir++ = ((unsigned long) page_table) | PAGE_TABLE;
		} else
			page_table = (unsigned long *)(PAGE_MASK & *dir++);
		page_table += poff;
		poff = 0;
		for (size -= pcnt; pcnt-- ;) {
			if ((page = *page_table) != 0) {
				*page_table = 0;
				if (page & PAGE_PRESENT) {
					if (!(mem_map[MAP_NR(page)] & MAP_PAGE_RESERVED))
						if (current->rss > 0)
							--current->rss;
					free_page(PAGE_MASK & page);
				} else
					swap_free(page);
			}
			*page_table++ = mask;
		}
		pcnt = (size > PTRS_PER_PAGE ? PTRS_PER_PAGE : size);
	}
	invalidate();
	return 0;
}

/*
 * maps a range of physical memory into the requested pages. the old
 * mappings are removed. any references to nonexistent pages results
 * in null mappings (currently treated as "copy-on-access")
 */
int remap_page_range(unsigned long from, unsigned long to, unsigned long size, int mask)
{
	unsigned long *page_table, *dir;
	unsigned long poff, pcnt;
	unsigned long page;

	if (mask) {
		if ((mask & (PAGE_MASK|PAGE_PRESENT)) != PAGE_PRESENT) {
			printk("remap_page_range: mask = %08x\n",mask);
			return -EINVAL;
		}
	}
	if ((from & ~PAGE_MASK) || (to & ~PAGE_MASK)) {
		printk("remap_page_range: from = %08lx, to=%08lx\n",from,to);
		return -EINVAL;
	}
	dir = PAGE_DIR_OFFSET(current->tss.cr3,from);
	size = (size + ~PAGE_MASK) >> PAGE_SHIFT;
	poff = (from >> PAGE_SHIFT) & (PTRS_PER_PAGE-1);
	if ((pcnt = PTRS_PER_PAGE - poff) > size)
		pcnt = size;

	while (size > 0) {
		if (!(PAGE_PRESENT & *dir)) {
			/* clearing page here, needed?  SRB. */
			if (!(page_table = (unsigned long*) get_free_page(GFP_KERNEL))) {
				invalidate();
				return -1;
			}
			*dir++ = ((unsigned long) page_table) | PAGE_TABLE;
		}
		else
			page_table = (unsigned long *)(PAGE_MASK & *dir++);
		if (poff) {
			page_table += poff;
			poff = 0;
		}

		for (size -= pcnt; pcnt-- ;) {
			if ((page = *page_table) != 0) {
				*page_table = 0;
				if (PAGE_PRESENT & page) {
					if (!(mem_map[MAP_NR(page)] & MAP_PAGE_RESERVED))
						if (current->rss > 0)
							--current->rss;
					free_page(PAGE_MASK & page);
				} else
					swap_free(page);
			}

			/*
			 * the first condition should return an invalid access
			 * when the page is referenced. current assumptions
			 * cause it to be treated as demand allocation in some
			 * cases.
			 */
			if (!mask)
				*page_table++ = 0;	/* not present */
			else if (to >= high_memory)
				*page_table++ = (to | mask);
			else if (!mem_map[MAP_NR(to)])
				*page_table++ = 0;	/* not present */
			else {
				*page_table++ = (to | mask);
				if (!(mem_map[MAP_NR(to)] & MAP_PAGE_RESERVED)) {
					++current->rss;
					mem_map[MAP_NR(to)]++;
				}
			}
			to += PAGE_SIZE;
		}
		pcnt = (size > PTRS_PER_PAGE ? PTRS_PER_PAGE : size);
	}
	invalidate();
	return 0;
}

/*
 * This function puts a page in memory at the wanted address.
 * It returns the physical address of the page gotten, 0 if
 * out of memory (either when trying to access page-table or
 * page.)
 */
unsigned long put_page(struct task_struct * tsk,unsigned long page,
	unsigned long address,int prot)
{
	unsigned long *page_table;

	if ((prot & (PAGE_MASK|PAGE_PRESENT)) != PAGE_PRESENT)
		printk("put_page: prot = %08x\n",prot);
	if (page >= high_memory) {
		printk("put_page: trying to put page %08lx at %08lx\n",page,address);
		return 0;
	}
	page_table = PAGE_DIR_OFFSET(tsk->tss.cr3,address);
	if ((*page_table) & PAGE_PRESENT)
		page_table = (unsigned long *) (PAGE_MASK & *page_table);
	else {
		printk("put_page: bad page directory entry\n");
		oom(tsk);
		*page_table = BAD_PAGETABLE | PAGE_TABLE;
		return 0;
	}
	page_table += (address >> PAGE_SHIFT) & (PTRS_PER_PAGE-1);
	if (*page_table) {
		printk("put_page: page already exists\n");
		*page_table = 0;
		invalidate();
	}
	*page_table = page | prot;
/* no need for invalidate */
	return page;
}

/*
 * 将脏页面映射到进程的地址空间
 * 前一个函数(put_page)在需要标记页面为脏时效果不佳：
 * exec.c需要这个功能，因为它之前已经修改了页面，
 * 我们需要脏状态正确(用于虚拟内存)。因此使用相同的例程，
 * 但这次同时标记它为脏。
 * 
 * 参数:
 * tsk - 目标进程
 * page - 要映射的物理页面地址
 * address - 要映射到的虚拟地址
 * 
 * 返回值: 映射的页面地址，失败返回0
 */
unsigned long put_dirty_page(struct task_struct * tsk, unsigned long page, unsigned long address)
{
	unsigned long tmp, *page_table;	/* 临时变量和页表指针 */

	/* 检查页面地址是否超出内存范围 */
	if (page >= high_memory)
		printk("put_dirty_page: trying to put page %08lx at %08lx\n",page,address);
	/* 检查页面的引用计数是否为1(应该只有当前进程使用) */
	if (mem_map[MAP_NR(page)] != 1)
		printk("mem_map disagrees with %08lx at %08lx\n",page,address);
	/* 获取页目录项地址 */
	page_table = PAGE_DIR_OFFSET(tsk->tss.cr3,address);
	/* 检查页目录项是否已存在有效页表 */
	if (PAGE_PRESENT & *page_table)
		/* 如果页表已存在，直接使用现有页表 */
		page_table = (unsigned long *) (PAGE_MASK & *page_table);
	else {
		/* 页表不存在，需要分配新页表 */
		if (!(tmp = get_free_page(GFP_KERNEL)))
			return 0;	/* 分配失败，返回0 */
		/* 再次检查页目录项(防止竞争条件) */
		if (PAGE_PRESENT & *page_table) {
			/* 其他进程已经创建了页表，释放刚分配的页面 */
			free_page(tmp);
			page_table = (unsigned long *) (PAGE_MASK & *page_table);
		} else {
			/* 设置页目录项，指向新分配的页表 */
			*page_table = tmp | PAGE_TABLE;
			page_table = (unsigned long *) tmp;
		}
	}
	/* 计算页表项在页表中的索引位置 */
	page_table += (address >> PAGE_SHIFT) & (PTRS_PER_PAGE-1);
	/* 检查页表项是否已被使用(防止覆盖已有映射) */
	if (*page_table) {
		printk("put_dirty_page: page already exists\n");
		*page_table = 0;
		invalidate();
	}
	/* 设置页表项：
	 * - 指向物理页面
	 * - PAGE_DIRTY: 标记页面为脏(已修改)
	 * - PAGE_PRIVATE: 标记页面为私有(写时复制)
	 */
	*page_table = page | (PAGE_DIRTY | PAGE_PRIVATE);
/* no need for invalidate */
	/* 不需要使TLB失效，因为这是新映射 */
	return page;
}

/*
 * 执行写时复制(COW)操作
 * 注意：我们必须小心处理竞争条件
 * 
 * Goto纯化主义者注意：这里使用goto的唯一原因是它会产生更好的汇编代码
 * "默认"路径根本不会看到任何跳转
 */
static void __do_wp_page(unsigned long error_code, unsigned long address,
	struct task_struct * tsk, unsigned long user_esp)
{
	unsigned long *pde, pte, old_page, prot;	/* 页目录项、页表项、旧页面、保护属性 */
	unsigned long new_page;			/* 新分配的页面 */

	/* 预先分配一个新页面，用于可能的复制操作 */
	new_page = __get_free_page(GFP_KERNEL);
	/* 获取页目录项地址 */
	pde = PAGE_DIR_OFFSET(tsk->tss.cr3,address);
	/* 获取页目录项内容 */
	pte = *pde;
	/* 检查页目录项是否存在 */
	if (!(pte & PAGE_PRESENT))
		goto end_wp_page;	/* 页目录项不存在，直接退出 */
	/* 检查页目录项是否为有效的页表且在内存范围内 */
	if ((pte & PAGE_TABLE) != PAGE_TABLE || pte >= high_memory)
		goto bad_wp_pagetable;	/* 无效的页表，跳转到错误处理 */
	/* 获取页表的物理地址 */
	pte &= PAGE_MASK;
	/* 计算页表项地址 */
	pte += PAGE_PTR(address);
	/* 获取页表项内容(旧页面的信息) */
	old_page = *(unsigned long *) pte;
	/* 检查页面是否存在 */
	if (!(old_page & PAGE_PRESENT))
		goto end_wp_page;	/* 页面不存在，直接退出 */
	/* 检查页面地址是否在有效内存范围内 */
	if (old_page >= high_memory)
		goto bad_wp_page;	/* 无效的页面地址，跳转到错误处理 */
	/* 检查页面是否已经是可写的 */
	if (old_page & PAGE_RW)
		goto end_wp_page;	/* 页面已可写，直接退出 */
	/* 增加次要缺页计数 */
	tsk->min_flt++;
	/* 计算新页面的保护属性：保留原有属性并添加写权限 */
	prot = (old_page & ~PAGE_MASK) | PAGE_RW;
	/* 获取旧页面的物理地址 */
	old_page &= PAGE_MASK;
	/* 检查页面是否被多个进程共享(引用计数不为1) */
	if (mem_map[MAP_NR(old_page)] != 1) {
		/* 如果成功分配了新页面 */
		if (new_page) {
			/* 如果旧页面是保留页，增加进程的常驻内存大小 */
			if (mem_map[MAP_NR(old_page)] & MAP_PAGE_RESERVED)
				++tsk->rss;
			/* 复制旧页面的内容到新页面 */
			copy_page(old_page,new_page);
			/* 更新页表项，指向新页面并设置保护属性 */
			*(unsigned long *) pte = new_page | prot;
			/* 释放旧页面 */
			free_page(old_page);
			/* 使TLB无效，确保页表更改生效 */
			invalidate();
			return;		/* 写时复制完成 */
		}
		/* 新页面分配失败 */
		free_page(old_page);	/* 释放旧页面 */
		oom(tsk);		/* 处理内存不足情况 */
		/* 设置页表项指向坏页面 */
		*(unsigned long *) pte = BAD_PAGE | prot;
		/* 使TLB无效 */
		invalidate();
		return;
	}
	/* 页面只有一个引用，直接设置为可写 */
	*(unsigned long *) pte |= PAGE_RW;
	/* 使TLB无效 */
	invalidate();
	/* 释放预分配的新页面(未使用) */
	if (new_page)
		free_page(new_page);
	return;
/* 处理无效页面错误 */
bad_wp_page:
	/* 打印错误信息 */
	printk("do_wp_page: bogus page at address %08lx (%08lx)\n",address,old_page);
	/* 设置页表项指向坏页面 */
	*(unsigned long *) pte = BAD_PAGE | PAGE_SHARED;
	/* 发送SIGKILL信号终止进程 */
	send_sig(SIGKILL, tsk, 1);
	goto end_wp_page;
/* 处理无效页表错误 */
bad_wp_pagetable:
	/* 打印错误信息 */
	printk("do_wp_page: bogus page-table at address %08lx (%08lx)\n",address,pte);
	/* 设置页目录项指向坏页表 */
	*pde = BAD_PAGETABLE | PAGE_TABLE;
	/* 发送SIGKILL信号终止进程 */
	send_sig(SIGKILL, tsk, 1);
/* 清理并退出 */
end_wp_page:
	/* 释放预分配的新页面(如果存在) */
	if (new_page)
		free_page(new_page);
	return;
}

/*
 * 处理写保护页面错误
 * 检查页表更改是否实际需要，只在必要时调用底层函数
 * 当进程尝试写入只读页面时，此函数决定是否允许写入
 * 根据页面属性和引用计数，可能直接设置写权限或执行写时复制(COW)
 */
void do_wp_page(unsigned long error_code, unsigned long address,
	struct task_struct * tsk, unsigned long user_esp)
{
	unsigned long page;		/* 页表项内容 */
	unsigned long * pg_table;	/* 指向页表项的指针 */

	/* 获取页目录项地址 */
	pg_table = PAGE_DIR_OFFSET(tsk->tss.cr3,address);
	/* 获取页目录项内容 */
	page = *pg_table;
	/* 如果页目录项为空，直接返回 */
	if (!page)
		return;
	/* 检查页目录项是否有效且在内存范围内 */
	if ((page & PAGE_PRESENT) && page < high_memory) {
		/* 计算页表项地址 */
		pg_table = (unsigned long *) ((page & PAGE_MASK) + PAGE_PTR(address));
		/* 获取页表项内容 */
		page = *pg_table;
		/* 如果页面不存在，直接返回 */
		if (!(page & PAGE_PRESENT))
			return;
		/* 如果页面已经是可写的，直接返回 */
		if (page & PAGE_RW)
			return;
		/* 如果页面不支持写时复制(非COW页面) */
		if (!(page & PAGE_COW)) {
			/* 如果是用户空间访问且是当前进程 */
			if (user_esp && tsk == current) {
				/* 设置错误信息 */
				current->tss.cr2 = address;		/* 错误地址 */
				current->tss.error_code = error_code;	/* 错误代码 */
				current->tss.trap_no = 14;		/* 陷阱号(页面错误) */
				/* 发送SIGSEGV信号终止进程 */
				send_sig(SIGSEGV, tsk, 1);
				return;
			}
		}
		/* 如果页面只有一个引用(只有当前进程在使用) */
		if (mem_map[MAP_NR(page)] == 1) {
			/* 直接设置页面为可写和脏页 */
			*pg_table |= PAGE_RW | PAGE_DIRTY;
			/* 使TLB无效，确保页表更改生效 */
			invalidate();
			return;
		}
		/* 页面被多个进程共享，需要执行写时复制 */
		__do_wp_page(error_code, address, tsk, user_esp);
		return;
	}
	/* 页目录项无效，打印错误信息 */
	printk("bad page directory entry %08lx\n",page);
	/* 清除无效的页目录项 */
	*pg_table = 0;
}

/*
 * __verify_write - 验证并确保指定内存区域可写
 * 此函数确保指定地址范围内的所有页面都可以写入
 * 如果页面是只读的或共享的，会触发写时复制(COW)机制
 * 主要用于系统调用中验证用户空间缓冲区的可写性
 * 
 * 参数:
 * start - 起始虚拟地址
 * size - 内存区域大小(字节)
 * 
 * 返回值: 0表示成功
 */
int __verify_write(unsigned long start, unsigned long size)
{
	/* 调整大小，使其包含起始地址所在的整个页面 */
	size--;	/* 减1，因为后续会加上起始偏移 */
	/* 加上起始地址在页面内的偏移量，确保覆盖整个起始页面 */
	size += start & ~PAGE_MASK;
	/* 将大小转换为页数(右移PAGE_SHIFT位，相当于除以PAGE_SIZE) */
	size >>= PAGE_SHIFT;
	/* 将起始地址对齐到页边界 */
	start &= PAGE_MASK;
	/* 遍历所有页面，确保每个页面都可写 */
	do {
		/* 调用do_wp_page确保当前页面可写
		 * 参数1: error_code=1(表示写访问)
		 * 参数2: 当前页面的地址
		 * 参数3: 当前进程
		 * 参数4: user_esp=0(内核调用，不需要用户栈指针)
		 */
		do_wp_page(1,start,current,0);
		/* 移动到下一页 */
		start += PAGE_SIZE;
	} while (size--);	/* 处理完所有页面 */
	return 0;	/* 返回成功 */
}

/*
 * 获取一个空页面并映射到指定地址
 * 为进程分配一个清零的页面，并将其映射到指定的虚拟地址
 * 主要用于处理BSS区域、堆扩展和栈扩展等场景
 */
static inline void get_empty_page(struct task_struct * tsk, unsigned long address)
{
	unsigned long tmp;	/* 新分配的页面地址 */

	/* 尝试分配一个空闲页面 */
	if (!(tmp = get_free_page(GFP_KERNEL))) {
		/* 分配失败，处理内存不足情况 */
		oom(tsk);		/* 尝试杀死一个进程释放内存 */
		tmp = BAD_PAGE;	/* 使用坏页面作为替代 */
	}
	/* 将页面映射到进程的地址空间
	 * PAGE_PRIVATE标志表示这是一个私有页面，不能与其他进程共享
	 * 当进程尝试写入此页面时，会触发写时复制(COW)机制
	 */
	if (!put_page(tsk,tmp,address,PAGE_PRIVATE))
		/* 如果映射失败，释放页面 */
		free_page(tmp);
}

/*
 * try_to_share() checks the page at address "address" in the task "p",
 * to see if it exists, and if it is clean. If so, share it with the current
 * task.
 *
 * NOTE! This assumes we have checked that p != current, and that they
 * share the same executable or library.
 *
 * We may want to fix this to allow page sharing for PIC pages at different
 * addresses so that ELF will really perform properly. As long as the vast
 * majority of sharable libraries load at fixed addresses this is not a
 * big concern. Any sharing of pages between the buffer cache and the
 * code space reduces the need for this as well.  - ERY
 */
/*
 * 尝试在两个进程之间共享一个页面
 * tsk: 目标进程(需要页面的进程)
 * p: 源进程(已拥有页面的进程)
 * address: 要共享的虚拟地址
 * error_code: 页面错误代码(包含访问权限信息)
 * newpage: 新页面地址(用于写时复制)
 */
static int try_to_share(unsigned long address, struct task_struct * tsk,
	struct task_struct * p, unsigned long error_code, unsigned long newpage)
{
	unsigned long from;			/* 源进程的页表项内容 */
	unsigned long to;			/* 目标进程的页表项内容 */
	unsigned long from_page;		/* 源进程的页表地址 */
	unsigned long to_page;		/* 目标进程的页表地址 */

	/* 计算源进程和目标进程的页目录项地址 */
	from_page = (unsigned long)PAGE_DIR_OFFSET(p->tss.cr3,address);
	to_page = (unsigned long)PAGE_DIR_OFFSET(tsk->tss.cr3,address);
/* 检查源进程的页目录是否存在 */
	from = *(unsigned long *) from_page;
	if (!(from & PAGE_PRESENT))
		return 0;	/* 源页目录不存在，无法共享 */
	/* 获取页表的物理地址 */
	from &= PAGE_MASK;
	/* 计算源进程的页表项地址 */
	from_page = from + PAGE_PTR(address);
	/* 获取源进程的页表项内容 */
	from = *(unsigned long *) from_page;
/* 检查源页面是否干净且存在 */
	if ((from & (PAGE_PRESENT | PAGE_DIRTY)) != PAGE_PRESENT)
		return 0;	/* 页面不存在或已被修改，不能共享 */
	/* 检查源页面地址是否在有效内存范围内 */
	if (from >= high_memory)
		return 0;
	/* 检查源页面是否为保留页 */
	if (mem_map[MAP_NR(from)] & MAP_PAGE_RESERVED)
		return 0;
/* 检查目标进程的页目录是否有效 */
	to = *(unsigned long *) to_page;
	if (!(to & PAGE_PRESENT))
		return 0;	/* 目标页目录不存在，无法共享 */
	/* 获取目标页表的物理地址 */
	to &= PAGE_MASK;
	/* 计算目标进程的页表项地址 */
	to_page = to + PAGE_PTR(address);
	/* 检查目标页表项是否为空 */
	if (*(unsigned long *) to_page)
		return 0;	/* 目标页表项已被使用，不能共享 */
/* 如果是读访问则共享页面，否则立即执行写时复制 */
	if (error_code & PAGE_RW) {
		/* 写访问：需要执行写时复制(COW) */
		if(!newpage)	/* 检查新页面是否存在。SRB. */
			return 0;	/* 没有新页面可用，无法执行COW */
		/* 复制源页面内容到新页面 */
		copy_page((from & PAGE_MASK),newpage);
		/* 设置目标页表项指向新页面，标记为私有 */
		to = newpage | PAGE_PRIVATE;
	} else {
		/* 读访问：可以直接共享页面 */
		/* 增加源页面的引用计数 */
		mem_map[MAP_NR(from)]++;
		/* 清除源页面的写权限，确保只读 */
		from &= ~PAGE_RW;
		/* 目标页表项指向源页面 */
		to = from;
		/* 如果新页面存在，释放它(因为不需要COW) */
		if(newpage)	/* 仅当新页面存在时。SRB. */
			free_page(newpage);
	}
	/* 更新源进程的页表项(可能修改了写权限) */
	*(unsigned long *) from_page = from;
	/* 更新目标进程的页表项 */
	*(unsigned long *) to_page = to;
	/* 使TLB无效，确保页表更改生效 */
	invalidate();
	return 1;	/* 共享成功 */
}

/*
 * share_page() 尝试找到一个可以与当前进程共享页面的进程，
 * 并将匹配页面的地址返回给当前进程的数据空间。
 *
 * 我们首先通过检查executable->i_count来判断是否可行。
 * 如果有其他任务共享这个inode，它应该大于1。
 */
int share_page(struct vm_area_struct * area, struct task_struct * tsk,
	struct inode * inode,
	unsigned long address, unsigned long error_code, unsigned long newpage)
{
	struct task_struct ** p;	/* 指向任务结构体指针的指针，用于遍历所有任务 */

	/* 检查页面共享的前提条件：
	 * 1. inode必须存在
	 * 2. inode的引用计数必须大于等于2(表示有其他进程在使用)
	 * 3. 虚拟内存区域必须有操作函数集
	 */
	if (!inode || inode->i_count < 2 || !area->vm_ops)
		return 0;	/* 不满足共享条件，返回失败 */
	/* 从最后一个任务开始向前遍历所有任务 */
	for (p = &LAST_TASK ; p > &FIRST_TASK ; --p) {
		/* 跳过空的任务槽位 */
		if (!*p)
			continue;
		/* 跳过当前任务本身 */
		if (tsk == *p)
			continue;
		/* 如果inode不是其他进程的可执行文件 */
		if (inode != (*p)->executable) {
			  /* 如果没有虚拟内存区域，继续下一个任务 */
			  if(!area) continue;
			/* 现在检查虚拟内存管理器中是否有可以共享页面的内容 */
			if(area){
			  struct vm_area_struct * mpnt;	/* 指向其他进程的虚拟内存区域 */
			  /* 遍历其他进程的所有虚拟内存区域 */
			  for (mpnt = (*p)->mmap; mpnt; mpnt = mpnt->vm_next) {
			    /* 检查虚拟内存区域是否匹配：
			     * 1. 操作函数集相同
			     * 2. inode编号相同
			     * 3. 设备号相同
			     */
			    if (mpnt->vm_ops == area->vm_ops &&
			       mpnt->vm_inode->i_ino == area->vm_inode->i_ino&&
			       mpnt->vm_inode->i_dev == area->vm_inode->i_dev){
			      /* 调用特定文件系统的共享检查函数 */
			      if (mpnt->vm_ops->share(mpnt, area, address))
				break;	/* 找到可共享的区域，跳出循环 */
			    };
			  };
			  /* 如果没有找到匹配的虚拟内存区域，继续下一个任务 */
			  if (!mpnt) continue;  /* Nope.  Nuthin here */
			};
		}
		/* 尝试在当前任务和其他任务之间共享页面 */
		if (try_to_share(address,tsk,*p,error_code,newpage))
			return 1;	/* 共享成功，返回1 */
	}
	return 0;	/* 遍历完所有任务都没有找到可共享的页面，返回失败 */
}

/*
 * 获取或创建一个空页表
 * 如果指定地址对应的页表不存在，则分配一个新页表并初始化
 * 返回页表的物理地址，如果失败则返回0
 */
static inline unsigned long get_empty_pgtable(struct task_struct * tsk,unsigned long address)
{
	unsigned long page;		/* 新分配的页表地址 */
	unsigned long *p;		/* 指向页目录项的指针 */

	/* 计算地址对应的页目录项地址 */
	p = PAGE_DIR_OFFSET(tsk->tss.cr3,address);
	/* 检查页目录项是否已存在且有效 */
	if (PAGE_PRESENT & *p)
		return *p;	/* 页表已存在，直接返回 */
	/* 检查页目录项是否有无效值 */
	if (*p) {
		/* 打印错误信息 */
		printk("get_empty_pgtable: bad page-directory entry \n");
		/* 清除无效的页目录项 */
		*p = 0;
	}
	/* 分配一个空闲页面作为页表 */
	page = get_free_page(GFP_KERNEL);
	/* 重新计算页目录项地址(可能在分配过程中被其他进程修改) */
	p = PAGE_DIR_OFFSET(tsk->tss.cr3,address);
	/* 再次检查页目录项是否已存在(防止竞争条件) */
	if (PAGE_PRESENT & *p) {
		/* 如果其他进程已经创建了页表，释放刚分配的页面 */
		free_page(page);
		return *p;	/* 返回已存在的页表 */
	}
	/* 再次检查页目录项是否有无效值 */
	if (*p) {
		/* 打印错误信息 */
		printk("get_empty_pgtable: bad page-directory entry \n");
		/* 清除无效的页目录项 */
		*p = 0;
	}
	/* 如果页面分配成功 */
	if (page) {
		/* 设置页目录项，指向新分配的页表，并标记为页表类型 */
		*p = page | PAGE_TABLE;
		return *p;	/* 返回页目录项的内容 */
	}
	/* 页面分配失败，处理内存不足情况 */
	oom(current);	/* 尝试杀死一个进程释放内存 */
	/* 设置页目录项指向坏页表 */
	*p = BAD_PAGETABLE | PAGE_TABLE;
	return 0;	/* 返回失败 */
}

/*
 * do_no_page - 处理缺页中断
 * 当进程访问一个尚未映射到物理内存的页面时调用
 * 负责分配新页面或从交换设备读入页面
 */
void do_no_page(unsigned long error_code, unsigned long address,
	struct task_struct *tsk, unsigned long user_esp)
{
	unsigned long tmp;			/* 临时变量，用于存储页表项 */
	unsigned long page;			/* 页表地址 */
	struct vm_area_struct * mpnt;		/* 指向虚拟内存区域的指针 */

	/* 获取或创建页表 */
	page = get_empty_pgtable(tsk,address);
	if (!page)
		return;	/* 页表创建失败，直接返回 */
	/* 获取页表的物理地址 */
	page &= PAGE_MASK;
	/* 计算页表项的地址 */
	page += PAGE_PTR(address);
	/* 获取页表项的内容 */
	tmp = *(unsigned long *) page;
	/* 如果页面已经存在，直接返回 */
	if (tmp & PAGE_PRESENT)
		return;
	/* 增加进程的常驻内存大小 */
	++tsk->rss;
	/* 如果页表项非空但不存在(表示页面被交换出去) */
	if (tmp) {
		/* 主要缺页：需要从交换设备读入 */
		++tsk->maj_flt;
		/* 从交换设备读入页面 */
		swap_in((unsigned long *) page);
		return;
	}
	/* 将地址对齐到页边界 */
	address &= 0xfffff000;
	/* 初始化临时变量 */
	tmp = 0;
	/* 遍历进程的虚拟内存区域，查找包含该地址的区域 */
	for (mpnt = tsk->mmap; mpnt != NULL; mpnt = mpnt->vm_next) {
		/* 如果地址小于当前区域的起始地址，说明不在任何区域中 */
		if (address < mpnt->vm_start)
			break;
		/* 如果地址大于等于当前区域的结束地址，继续下一个区域 */
		if (address >= mpnt->vm_end) {
			tmp = mpnt->vm_end;	/* 保存当前区域的结束地址 */
			continue;
		}
		/* 如果区域没有操作函数集或缺页处理函数 */
		if (!mpnt->vm_ops || !mpnt->vm_ops->nopage) {
			/* 次要缺页：分配一个空页面 */
			++tsk->min_flt;
			get_empty_page(tsk,address);
			return;
		}
		/* 调用特定文件系统的缺页处理函数 */
		mpnt->vm_ops->nopage(error_code, mpnt, address);
		return;
	}
	/* 如果不是当前进程，直接分配空页面 */
	if (tsk != current)
		goto ok_no_page;
	/* 如果地址在数据段和堆之间(BSS区域)，分配空页面 */
	if (address >= tsk->end_data && address < tsk->brk)
		goto ok_no_page;
	/* 检查是否为栈扩展：
	 * 1. 当前区域是栈区域
	 * 2. 地址更接近栈的起始位置
	 * 3. 栈大小未超过限制
	 */
	if (mpnt && mpnt == tsk->stk_vma &&
	    address - tmp > mpnt->vm_start - address &&
	    tsk->rlim[RLIMIT_STACK].rlim_cur > mpnt->vm_end - address) {
		/* 扩展栈区域 */
		mpnt->vm_start = address;
		goto ok_no_page;
	}
	/* 非法访问：设置错误信息 */
	tsk->tss.cr2 = address;		/* 设置错误地址 */
	current->tss.error_code = error_code;	/* 设置错误代码 */
	current->tss.trap_no = 14;		/* 设置陷阱号(14表示页面错误) */
	/* 发送SIGSEGV信号给进程 */
	send_sig(SIGSEGV,tsk,1);
	/* 如果是用户级访问，直接返回 */
	if (error_code & 4)	/* user level access? */
		return;
/* 合法的缺页：分配空页面 */
ok_no_page:
	/* 次要缺页：分配一个空页面 */
	++tsk->min_flt;
	/* 分配一个空页面并映射到指定地址 */
	get_empty_page(tsk,address);
}

/*
 * 页面错误处理函数
 * 此例程处理页面错误。它确定地址和问题类型，然后将其传递给适当的处理函数。
 * 页面错误是当进程访问无效内存地址或触发保护机制时由CPU产生的异常。
 */
asmlinkage void do_page_fault(struct pt_regs *regs, unsigned long error_code)
{
	unsigned long address;		/* 触发页面错误的虚拟地址 */
	unsigned long user_esp = 0;		/* 用户空间的栈指针 */
	unsigned int bit;			/* 用于视频内存位图的位索引 */

	/* 从CR2寄存器获取触发页面错误的地址 */
	__asm__("movl %%cr2,%0":"=r" (address));
	/* 检查是否为用户空间地址(TASK_SIZE是用户空间和内核空间的分界线) */
	if (address < TASK_SIZE) {
		/* 检查是否为用户模式访问(error_code的第3位为1表示用户模式) */
		if (error_code & 4) {	/* user mode access? */
			/* 检查是否处于虚拟8086模式(用于运行DOS程序) */
			if (regs->eflags & VM_MASK) {
				/* 计算视频内存位图的位索引(0xA0000是视频内存起始地址) */
				bit = (address - 0xA0000) >> PAGE_SHIFT;
				/* 如果位索引在有效范围内，设置对应的位 */
				if (bit < 32)
					current->screen_bitmap |= 1 << bit;
			} else 
				/* 保存用户空间的栈指针，用于后续处理 */
				user_esp = regs->esp;
		}
		/* 检查页面错误类型(error_code的第0位为1表示写保护错误) */
		if (error_code & 1)
			/* 写保护错误：调用写时复制处理函数 */
			do_wp_page(error_code, address, current, user_esp);
		else
			/* 页面不存在错误：调用缺页处理函数 */
			do_no_page(error_code, address, current, user_esp);
		return;
	}
	/* 转换为内核空间地址(减去TASK_SIZE) */
	address -= TASK_SIZE;
	/* 检查是否为WP位测试(在mem_init中进行的测试) */
	if (wp_works_ok < 0 && address == 0 && (error_code & PAGE_PRESENT)) {
		/* WP位工作正常，设置标志 */
		wp_works_ok = 1;
		/* 恢复第一页的共享属性 */
		pg0[0] = PAGE_SHARED;
		/* 打印成功消息 */
		printk("This processor honours the WP bit even when in supervisor mode. Good.\n");
		return;
	}
	/* 检查是否为内核空指针访问 */
	if (address < PAGE_SIZE) {
		/* 打印空指针访问错误信息 */
		printk("Unable to handle kernel NULL pointer dereference");
		/* 恢复第一页的共享属性 */
		pg0[0] = PAGE_SHARED;
	} else
		/* 打印一般内核页面错误信息 */
		printk("Unable to handle kernel paging request");
	/* 打印错误地址 */
	printk(" at address %08lx\n",address);
	/* 如果在内核模式下，打印详细错误信息并终止进程 */
	die_if_kernel("Oops", regs, error_code);
	/* 退出当前进程 */
	do_exit(SIGKILL);
}

/*
 * BAD_PAGE is the page that is used for page faults when linux
 * is out-of-memory. Older versions of linux just did a
 * do_exit(), but using this instead means there is less risk
 * for a process dying in kernel mode, possibly leaving a inode
 * unused etc..
 *
 * BAD_PAGETABLE is the accompanying page-table: it is initialized
 * to point to BAD_PAGE entries.
 *
 * ZERO_PAGE is a special page that is used for zero-initialized
 * data and COW.
 */
/*
 * __bad_pagetable - 初始化坏页表
 * 坏页表是BAD_PAGE的配套页表，它被初始化为指向BAD_PAGE条目。
 * 当系统内存不足或页表出现错误时，会使用BAD_PAGETABLE作为替代，
 * 这样可以防止系统崩溃，提供一种安全的错误处理机制。
 * 返回坏页表的物理地址。
 */
unsigned long __bad_pagetable(void)
{
	extern char empty_bad_page_table[PAGE_SIZE];	/* 外部声明的坏页表数组 */

	/* 使用内联汇编快速初始化页表：
	 * cld     - 清除方向标志，确保字符串操作正向进行
	 * rep     - 重复执行下一条指令，次数由cx寄存器决定
	 * stosl   - 将eax寄存器的值存储到es:di指向的位置，并递增di
	 * 
	 * 输入操作数：
	 * "a" (BAD_PAGE + PAGE_TABLE) - 将eax寄存器设置为BAD_PAGE|PAGE_TABLE
	 *                              (每个页表项都指向坏页，并标记为页表)
	 * "D" (empty_bad_page_table) - 将edi寄存器设置为坏页表的地址（目标地址）
	 * "c" (PTRS_PER_PAGE)       - 将ecx寄存器设置为页面包含的长字数（重复次数）
	 * 
	 * 修改的寄存器：
	 * "di","cx"                  - 告诉编译器di和cx寄存器被修改
	 */
	__asm__ __volatile__("cld ; rep ; stosl":
		:"a" (BAD_PAGE + PAGE_TABLE),
		 "D" ((long) empty_bad_page_table),
		 "c" (PTRS_PER_PAGE)
		:"di","cx");
	/* 返回坏页表的地址 */
	return (unsigned long) empty_bad_page_table;
}

/*
 * __bad_page - 初始化坏页
 * 坏页是Linux内核在内存不足时使用的特殊页面。
 * 当系统无法分配正常页面时，会使用BAD_PAGE作为替代，
 * 这样可以减少进程在内核模式下死亡的风险，避免留下未使用的inode等问题。
 * 返回坏页的物理地址。
 */
unsigned long __bad_page(void)
{
	extern char empty_bad_page[PAGE_SIZE];	/* 外部声明的坏页数组 */

	/* 使用内联汇编快速清零页面：
	 * cld     - 清除方向标志，确保字符串操作正向进行
	 * rep     - 重复执行下一条指令，次数由cx寄存器决定
	 * stosl   - 将eax寄存器的值存储到es:di指向的位置，并递增di
	 * 
	 * 输入操作数：
	 * "a" (0)          - 将eax寄存器设置为0（要存储的值）
	 * "D" (empty_bad_page) - 将edi寄存器设置为坏页的地址（目标地址）
	 * "c" (PTRS_PER_PAGE) - 将ecx寄存器设置为页面包含的长字数（重复次数）
	 * 
	 * 修改的寄存器：
	 * "di","cx"        - 告诉编译器di和cx寄存器被修改
	 */
	__asm__ __volatile__("cld ; rep ; stosl":
		:"a" (0),
		 "D" ((long) empty_bad_page),
		 "c" (PTRS_PER_PAGE)
		:"di","cx");
	/* 返回坏页的地址 */
	return (unsigned long) empty_bad_page;
}

/*
 * __zero_page - 初始化零页
 * 零页是一个全为0的页面，用于多种目的：
 * 1. 初始化新分配的页面
 * 2. 作为写时复制(COW)的参考页面
 * 3. 填充文件中的空洞部分
 * 返回零页的物理地址
 */
unsigned long __zero_page(void)
{
	extern char empty_zero_page[PAGE_SIZE];	/* 外部声明的零页数组 */

	/* 使用内联汇编快速清零页面：
	 * cld     - 清除方向标志，确保字符串操作正向进行
	 * rep     - 重复执行下一条指令，次数由cx寄存器决定
	 * stosl   - 将eax寄存器的值存储到es:di指向的位置，并递增di
	 * 
	 * 输入操作数：
	 * "a" (0)          - 将eax寄存器设置为0（要存储的值）
	 * "D" (empty_zero_page) - 将edi寄存器设置为零页的地址（目标地址）
	 * "c" (PTRS_PER_PAGE) - 将ecx寄存器设置为页面包含的长字数（重复次数）
	 * 
	 * 修改的寄存器：
	 * "di","cx"        - 告诉编译器di和cx寄存器被修改
	 */
	__asm__ __volatile__("cld ; rep ; stosl":
		:"a" (0),
		 "D" ((long) empty_zero_page),
		 "c" (PTRS_PER_PAGE)
		:"di","cx");
	/* 返回零页的地址 */
	return (unsigned long) empty_zero_page;
}

/*
 * show_mem - 显示系统内存使用情况
 * 打印内存统计信息，包括空闲页、保留页、共享页等
 * 通常用于调试和监控系统状态
 */
void show_mem(void)
{
	int i,free = 0,total = 0,reserved = 0;	/* 内存页统计计数器 */
	int shared = 0;	/* 共享页计数器 */

	/* 打印内存信息标题 */
	printk("Mem-info:\n");
	/* 打印空闲页大小(将页数转换为KB，通过左移PAGE_SHIFT-10位实现) */
	printk("Free pages:      %6dkB\n",nr_free_pages<<(PAGE_SHIFT-10));
	/* 打印二级页大小(可能用于交换或特殊用途) */
	printk("Secondary pages: %6dkB\n",nr_secondary_pages<<(PAGE_SHIFT-10));
	/* 打印空闲交换空间大小 */
	printk("Free swap:       %6dkB\n",nr_swap_pages<<(PAGE_SHIFT-10));
	/* 计算总页数(将高端内存地址右移PAGE_SHIFT位) */
	i = high_memory >> PAGE_SHIFT;
	/* 遍历所有内存页，统计各类页面数量 */
	while (i-- > 0) {
		total++;	/* 总页数递增 */
		/* 检查是否为保留页(如BIOS、视频内存等) */
		if (mem_map[i] & MAP_PAGE_RESERVED)
			reserved++;	/* 保留页计数递增 */
		/* 检查是否为空闲页(mem_map值为0表示完全空闲) */
		else if (!mem_map[i])
			free++;	/* 空闲页计数递增 */
		else
			/* 共享页计数(值减1是因为共享计数从1开始) */
			shared += mem_map[i]-1;
	}
	/* 打印各类页面的统计信息 */
	printk("%d pages of RAM\n",total);	/* 总页数 */
	printk("%d free pages\n",free);	/* 空闲页数 */
	printk("%d reserved pages\n",reserved);	/* 保留页数 */
	printk("%d pages shared\n",shared);	/* 共享页数 */
	/* 显示缓冲区使用情况 */
	show_buffers();
}

/*
 * paging_init() sets up the page tables - note that the first 4MB are
 * already mapped by head.S.
 *
 * This routines also unmaps the page at virtual kernel address 0, so
 * that we can trap those pesky NULL-reference errors in the kernel.
 */
unsigned long paging_init(unsigned long start_mem, unsigned long end_mem)
{
	unsigned long * pg_dir;		/* 指向页目录的指针 */
	unsigned long * pg_table;	/* 指向页表的指针 */
	unsigned long tmp;		/* 临时变量，用于存储页表项 */
	unsigned long address;		/* 当前映射的物理地址 */

/*
 * Physical page 0 is special; it's not touched by Linux since BIOS
 * and SMM (for laptops with [34]86/SL chips) may need it.  It is read
 * and write protected to detect null pointer references in the
 * kernel.
 */
#if 0
	memset((void *) 0, 0, PAGE_SIZE);
#endif
	/* 将起始内存地址对齐到页边界 */
	start_mem = PAGE_ALIGN(start_mem);
	/* 初始化地址为0，从物理内存起始位置开始映射 */
	address = 0;
	/* 指向内核页目录(swapper_pg_dir) */
	pg_dir = swapper_pg_dir;
	/* 循环映射所有物理内存到虚拟地址空间 */
	while (address < end_mem) {
		/* 获取页目录项，偏移768对应虚拟地址0xC0000000(3GB处) */
		tmp = *(pg_dir + 768);		/* at virtual addr 0xC0000000 */
		/* 如果页目录项为空，需要创建新的页表 */
		if (!tmp) {
			/* 设置页目录项，指向新的页表，并标记为页表类型 */
			tmp = start_mem | PAGE_TABLE;
			*(pg_dir + 768) = tmp;
			/* 为新页表分配一个页面的内存空间 */
			start_mem += PAGE_SIZE;
		}
		/* 同时将页目录项映射到0x00000000处，用于初始化 */
		*pg_dir = tmp;			/* also map it in at 0x0000000 for init */
		/* 移动到下一个页目录项 */
		pg_dir++;
		/* 获取页表的物理地址(清除低12位标志位) */
		pg_table = (unsigned long *) (tmp & PAGE_MASK);
		/* 填充页表项，每个页表包含PTRS_PER_PAGE个条目 */
		for (tmp = 0 ; tmp < PTRS_PER_PAGE ; tmp++,pg_table++) {
			/* 如果当前地址在有效内存范围内，创建页表项 */
			if (address < end_mem)
				/* 设置页表项，映射物理地址到虚拟地址，标记为共享页 */
				*pg_table = address | PAGE_SHARED;
			else
				/* 超出内存范围，页表项设为0(无效) */
				*pg_table = 0;
			/* 移动到下一个页大小的地址 */
			address += PAGE_SIZE;
		}
	}
	/* 使TLB(Translation Lookaside Buffer)无效，确保页表更改生效 */
	invalidate();
	/* 返回下一个可用的内存地址 */
	return start_mem;
}

/*
 * mem_init - 内存管理初始化函数
 * 
 * 此函数负责初始化系统的内存管理子系统，包括：
 * 1. 设置内存映射表
 * 2. 标记可用和保留的内存页
 * 3. 建立空闲页链表
 * 4. 统计各类内存页的数量
 * 5. 测试CPU的WP(写保护)位功能
 * 
 * 参数:
 *   start_low_mem - 低端内存起始地址(通常为0)
 *   start_mem    - 可用内存起始地址(内核之后的第一个可用地址)
 *   end_mem      - 物理内存结束地址
 */
void mem_init(unsigned long start_low_mem, unsigned long start_mem, unsigned long end_mem)
{
	int codepages = 0;		/* 内核代码页计数器，用于统计内核代码占用的页数 */
	int reservedpages = 0;	/* 保留页计数器，用于统计保留内存占用的页数 */
	int datapages = 0;		/* 数据页计数器，用于统计数据占用的页数 */
	unsigned long tmp;		/* 临时变量，用于地址计算和循环 */
	unsigned short * p;		/* 指向内存映射表的指针 */
	extern int etext;		/* 内核代码段结束地址的外部声明 */

	/* 禁用中断，防止内存初始化过程被打断 */
	cli();
	/* 将内存结束地址对齐到页边界(4KB对齐) */
	end_mem &= PAGE_MASK;
	/* 设置高端内存边界，用于内存管理 */
	high_memory = end_mem;
	/* 对start_mem进行16字节对齐(向上对齐)，确保内存映射表对齐 */
	start_mem += 0x0000000f;
	start_mem &= ~0x0000000f;
	/* 计算内存页总数(总内存大小除以页大小) */
	tmp = MAP_NR(end_mem);
	/* 初始化内存映射表，存储在start_mem之后的位置 */
	mem_map = (unsigned short *) start_mem;
	/* 指向内存映射表的末尾 */
	p = mem_map + tmp;
	/* 更新start_mem到内存映射表之后的位置，为其他数据结构预留空间 */
	start_mem = (unsigned long) p;
	/* 初始化所有内存页为保留状态(MAP_PAGE_RESERVED)，防止被意外使用 */
	while (p > mem_map)
		*--p = MAP_PAGE_RESERVED;
	/* 对低端内存和高端内存起始地址进行页对齐(4KB对齐) */
	start_low_mem = PAGE_ALIGN(start_low_mem);
	start_mem = PAGE_ALIGN(start_mem);
	/* 标记640KB以下的低端内存为可用(0xA0000 = 640KB) */
	while (start_low_mem < 0xA0000) {
		mem_map[MAP_NR(start_low_mem)] = 0;	/* 0表示页面可用 */
		start_low_mem += PAGE_SIZE;	/* 移动到下一页 */
	}
	/* 标记高端内存为可用 */
	while (start_mem < end_mem) {
		mem_map[MAP_NR(start_mem)] = 0;	/* 0表示页面可用 */
		start_mem += PAGE_SIZE;	/* 移动到下一页 */
	}
#ifdef CONFIG_SOUND
	/* 如果配置了声音支持，初始化声音内存 */
	sound_mem_init();
#endif
	/* 初始化空闲页链表，用于管理空闲物理页 */
	free_page_list = 0;	/* 初始为空链表 */
	/* 初始化空闲页计数器 */
	nr_free_pages = 0;	/* 初始为0 */
	/* 遍历所有内存页，建立空闲页链表并统计各类页面 */
	for (tmp = 0 ; tmp < end_mem ; tmp += PAGE_SIZE) {
		/* 如果页面已被标记(非0)，则不是空闲页 */
		if (mem_map[MAP_NR(tmp)]) {
			/* 统计640KB-1MB之间的保留页(通常用于视频内存等) */
			if (tmp >= 0xA0000 && tmp < 0x100000)
				reservedpages++;
			/* 统计内核代码页(在etext之前) */
			else if (tmp < (unsigned long) &etext)
				codepages++;
			/* 其余为数据页 */
			else
				datapages++;
			continue;		/* 跳过已使用的页面 */
		}
		/* 将当前空闲页添加到空闲页链表中 */
		*(unsigned long *) tmp = free_page_list;	/* 在页面起始位置存储下一个空闲页的地址 */
		free_page_list = tmp;		/* 更新空闲页链表头 */
		/* 增加空闲页计数 */
		nr_free_pages++;
	}
	/* 计算空闲内存总大小(字节)，左移PAGE_SHIFT相当于乘以PAGE_SIZE */
	tmp = nr_free_pages << PAGE_SHIFT;
	/* 打印内存使用情况统计信息 */
	printk("Memory: %luk/%luk available (%dk kernel code, %dk reserved, %dk data)\n",
		tmp >> 10,			/* 可用内存(KB) */
		end_mem >> 10,		/* 总内存(KB) */
		codepages << (PAGE_SHIFT-10),	/* 内核代码内存(KB) */
		reservedpages << (PAGE_SHIFT-10),	/* 保留内存(KB) */
		datapages << (PAGE_SHIFT-10));	/* 数据内存(KB) */
/* test if the WP bit is honoured in supervisor mode */
	/* 测试在超级用户模式下WP(写保护)位是否生效 */
	wp_works_ok = -1;	/* 初始化为未知状态 */
	/* 设置第一页为只读 */
	pg0[0] = PAGE_READONLY;
	/* 使TLB无效，确保页表更改生效 */
	invalidate();
	/* 尝试写入只读页面，如果WP位生效，会触发页面错误异常 */
	__asm__ __volatile__("movb 0,%%al ; movb %%al,0": : :"ax", "memory");
	/* 恢复第一页的原始设置 */
	pg0[0] = 0;
	/* 再次使TLB无效 */
	invalidate();
	/* 如果没有发生异常，说明WP位不工作 */
	if (wp_works_ok < 0)
		wp_works_ok = 0;
	return;
}

void si_meminfo(struct sysinfo *val)
{
	int i;		/* 循环计数器，用于遍历内存页 */

	/* 计算总页数(将高端内存地址右移PAGE_SHIFT位) */
	i = high_memory >> PAGE_SHIFT;
	/* 初始化sysinfo结构体中的内存统计字段 */
	val->totalram = 0;	/* 总内存(页数) */
	val->freeram = 0;	/* 空闲内存(页数) */
	val->sharedram = 0;	/* 共享内存(页数) */
	val->bufferram = buffermem;	/* 缓冲区内存(全局变量) */
	/* 遍历所有内存页，统计各类内存使用情况 */
	while (i-- > 0)  {
		/* 跳过保留页(如BIOS、视频内存等) */
		if (mem_map[i] & MAP_PAGE_RESERVED)
			continue;
		/* 统计非保留页(可用内存) */
		val->totalram++;
		/* 如果mem_map[i]为0，表示该页完全空闲 */
		if (!mem_map[i]) {
			/* 统计空闲页 */
			val->freeram++;
			continue;
		}
		/* 统计共享内存页(值大于0表示被共享，减1是因为共享计数从1开始) */
		val->sharedram += mem_map[i]-1;
	}
	/* 将页数转换为字节数(左移PAGE_SHIFT位，相当于乘以PAGE_SIZE) */
	val->totalram <<= PAGE_SHIFT;
	val->freeram <<= PAGE_SHIFT;
	val->sharedram <<= PAGE_SHIFT;
	return;
}


/* This handles a generic mmap of a disk file */
/* 处理磁盘文件的内存映射缺页中断 */
void file_mmap_nopage(int error_code, struct vm_area_struct * area, unsigned long address)
{
	struct inode * inode = area->vm_inode;	/* 获取文件inode */
	unsigned int block;			/* 文件块号 */
	unsigned long page;			/* 页面地址 */
	int nr[8];				/* 存储块号的数组(最多8个块) */
	int i, j;				/* 循环计数器 */
	int prot = area->vm_page_prot;		/* 页面保护属性 */

	/* 将地址对齐到页边界 */
	address &= PAGE_MASK;
	/* 计算文件中的块偏移量(地址-区域起始地址+区域偏移) */
	block = address - area->vm_start + area->vm_offset;
	/* 将字节偏移转换为块号(右移块大小的位数) */
	block >>= inode->i_sb->s_blocksize_bits;

	/* 获取一个空闲页面用于读取文件内容 */
	page = get_free_page(GFP_KERNEL);
	/* 尝试共享已存在的页面(如果其他进程已经映射了相同文件的相同位置) */
	if (share_page(area, area->vm_task, inode, address, error_code, page)) {
		/* 次要缺页(不需要从磁盘读取) */
		++area->vm_task->min_flt;
		return;
	}

	/* 主要缺页(需要从磁盘读取) */
	++area->vm_task->maj_flt;
	/* 如果获取空闲页面失败 */
	if (!page) {
		/* 内存不足，杀死当前进程 */
		oom(current);
		/* 使用错误页面标记 */
		put_page(area->vm_task, BAD_PAGE, address, PAGE_PRIVATE);
		return;
	}
	/* 计算页面中包含的所有文件块号(一个页面可能包含多个块) */
	for (i=0, j=0; i< PAGE_SIZE ; j++, block++, i += inode->i_sb->s_blocksize)
		nr[j] = bmap(inode,block);	/* 将文件块号转换为磁盘块号 */
	/* 如果是写访问，设置页面为可写和脏页 */
	if (error_code & PAGE_RW)
		prot |= PAGE_RW | PAGE_DIRTY;
	/* 从磁盘读取块数据到页面中 */
	page = bread_page(page, inode->i_dev, nr, inode->i_sb->s_blocksize, prot);

	/* 如果是只读页面，再次尝试共享 */
	if (!(prot & PAGE_RW)) {
		if (share_page(area, area->vm_task, inode, address, error_code, page))
			return;
	}
	/* 将页面映射到进程的地址空间 */
	if (put_page(area->vm_task,page,address,prot))
		return;
	/* 如果映射失败，释放页面并报告内存不足 */
	free_page(page);
	oom(current);
}

/*
 * file_mmap_free - 释放文件映射区域
 * 当进程解除文件内存映射或进程退出时调用
 * 主要负责释放与文件映射相关的inode资源
 */
void file_mmap_free(struct vm_area_struct * area)
{
	/* 检查虚拟内存区域是否关联了inode */
	if (area->vm_inode)
		/* 递减inode的引用计数，当计数为0时释放inode */
		iput(area->vm_inode);
#if 0
	/* 调试代码：打印释放的inode信息，当前被禁用 */
	if (area->vm_inode)
		/* 打印设备号、inode号和引用计数 */
		printk("Free inode %x:%d (%d)\n",area->vm_inode->i_dev, 
				 area->vm_inode->i_ino, area->vm_inode->i_count);
#endif
}

/*
 * 比较两个内存映射条目的内容，决定是否允许共享页面
 * 只有当两个虚拟内存区域完全匹配时，才能共享页面
 */
int file_mmap_share(struct vm_area_struct * area1, 
		    struct vm_area_struct * area2, 
		    unsigned long address)
{
	/* 检查两个区域是否映射同一个文件(inode必须相同) */
	if (area1->vm_inode != area2->vm_inode)
		return 0;	/* 不同文件，不能共享 */
	/* 检查两个区域的起始虚拟地址是否相同 */
	if (area1->vm_start != area2->vm_start)
		return 0;	/* 起始地址不同，不能共享 */
	/* 检查两个区域的结束虚拟地址是否相同 */
	if (area1->vm_end != area2->vm_end)
		return 0;	/* 结束地址不同，不能共享 */
	/* 检查两个区域的文件偏移量是否相同 */
	if (area1->vm_offset != area2->vm_offset)
		return 0;	/* 文件偏移不同，不能共享 */
	/* 检查两个区域的页面保护属性是否相同 */
	if (area1->vm_page_prot != area2->vm_page_prot)
		return 0;	/* 保护属性不同，不能共享 */
	/* 所有条件都满足，可以共享页面 */
	return 1;
}

struct vm_operations_struct file_mmap = {
	NULL,			/* open */
	file_mmap_free,		/* close */
	file_mmap_nopage,	/* nopage */
	NULL,			/* wppage */
	file_mmap_share,	/* share */
	NULL,			/* unmap */
};