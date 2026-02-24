#include <linux/errno.h>
#include <linux/kernel.h>
#include <asm/segment.h>
#include <linux/mm.h>		/* defines GFP_KERNEL */
#include <linux/string.h>
#include <linux/module.h>
#include <linux/sched.h>
#include <linux/malloc.h>

struct module *module_list = NULL;
int freeing_modules;		/* true if some modules are marked for deletion */

struct module *find_module( const char *name);
int get_mod_name( char *user_name, char *buf);
int free_modules( void);

/*
 * Allocate space for a module.
 */
/*
 * sys_create_module - 创建内核模块
 * 为新模块分配空间并初始化模块结构
 * 此函数只是创建模块空间，模块代码需要通过sys_init_module加载
 * 
 * 参数:
 * module_name - 模块名称(用户空间指针)
 * size - 模块所需空间大小(字节)
 * 
 * 返回值: 成功返回模块地址，失败返回错误码
 */
asmlinkage int
sys_create_module(char *module_name, unsigned long size)
{
	int npages;				/* 模块占用的页数 */
	void* addr;				/* 模块的虚拟地址 */
	int len;					/* 模块名称长度 */
	char name[MOD_MAX_NAME];	/* 临时存储模块名称 */
	char *savename;			/* 保存的模块名称 */
	struct module *mp;			/* 模块结构体指针 */
	int error;				/* 错误码 */

	/* 检查用户权限(只有超级用户可以创建模块) */
	if (!suser())
		return -EPERM;			/* 权限不足 */
	/* 检查参数有效性 */
	if (module_name == NULL || size == 0)
		return -EINVAL;			/* 无效参数 */
	/* 从用户空间获取模块名称并验证 */
	if ((error = get_mod_name(module_name, name)) != 0)
		return error;			/* 名称无效 */
	/* 检查模块是否已存在 */
	if (find_module(name) != NULL) {
		return -EEXIST;			/* 模块已存在 */
	}
	/* 计算模块名称长度(包括终止符) */
	len = strlen(name) + 1;
	/* 分配内存保存模块名称 */
	if ((savename = (char*) kmalloc(len, GFP_KERNEL)) == NULL)
		return -ENOMEM;			/* 内存不足 */
	/* 复制模块名称 */
	memcpy(savename, name, len);
	/* 分配模块结构体 */
	if ((mp = (struct module*) kmalloc(sizeof *mp, GFP_KERNEL)) == NULL) {
		kfree(savename);		/* 释放名称内存 */
		return -ENOMEM;			/* 内存不足 */
	}
	/* 计算模块需要的页数(向上取整，包括引用计数空间) */
	npages = (size + sizeof (int) + 4095) / 4096;
	/* 分配模块的虚拟内存空间 */
	if ((addr = vmalloc(npages * 4096)) == 0) {
		kfree_s(mp, sizeof *mp);		/* 释放模块结构体 */
		kfree(savename);		/* 释放名称内存 */
		return -ENOMEM;			/* 内存不足 */
	}
	/* 初始化模块结构体 */
	mp->name = savename;			/* 设置模块名称 */
	mp->size = npages;			/* 设置模块大小(页数) */
	mp->addr = addr;			/* 设置模块地址 */
	mp->state = MOD_UNINITIALIZED;	/* 设置模块状态为未初始化 */
	* (int *) addr = 0;		/* 设置引用计数为0 */
	mp->cleanup = NULL;		/* 清理函数为空 */
	mp->next = module_list;		/* 添加到模块链表 */
	module_list = mp;			/* 更新链表头 */
	/* 打印模块创建信息 */
	printk("module `%s' (%lu pages @ 0x%08lx) created\n",
		mp->name, (unsigned long) mp->size, (unsigned long) mp->addr);
	/* 返回模块地址 */
	return (int) addr;
}

/*
 * sys_init_module - 初始化内核模块
 * 将模块代码复制到已分配的模块空间，并调用模块的初始化函数
 * 完成模块的加载过程，使模块变为运行状态
 * 
 * 参数:
 * module_name - 模块名称(用户空间指针)
 * code - 模块代码(用户空间指针)
 * codesize - 模块代码大小(字节)
 * routines - 模块例程结构体(包含初始化和清理函数指针)
 * 
 * 返回值: 成功返回0，失败返回错误码
 */
asmlinkage int
sys_init_module(char *module_name, char *code, unsigned codesize,
		struct mod_routines *routines)
{
	struct module *mp;			/* 模块结构体指针 */
	char name[MOD_MAX_NAME];	/* 临时存储模块名称 */
	int error;				/* 错误码 */
	struct mod_routines rt;		/* 模块例程结构体 */

	/* 检查用户权限(只有超级用户可以初始化模块) */
	if (!suser())
		return -EPERM;			/* 权限不足 */
	/*
	 * 首先回收已删除模块但未释放的内存
	 * 这些内存应该由定时器在模块删除时释放 - Jon.
	 */
	free_modules();

	/* 从用户空间获取模块名称并验证 */
	if ((error = get_mod_name(module_name, name)) != 0)
		return error;			/* 名称无效 */
	/* 打印模块初始化信息 */
	printk( "initializing module `%s', %d (0x%x) bytes\n",
		name, codesize, codesize);
	/* 从用户空间复制模块例程结构体 */
	memcpy_fromfs(&rt, routines, sizeof rt);
	/* 查找已创建的模块 */
	if ((mp = find_module(name)) == NULL)
		return -ENOENT;			/* 模块不存在 */
	/* 检查模块代码大小是否超出预分配空间 */
	if ((codesize + sizeof (int) + 4095) / 4096 > mp->size)
		return -EINVAL;			/* 代码太大 */
	/* 将模块代码从用户空间复制到模块空间 */
	memcpy_fromfs((char *)mp->addr + sizeof (int), code, codesize);
	/* 清零模块空间的剩余部分 */
	memset((char *)mp->addr + sizeof (int) + codesize, 0,
		mp->size * 4096 - (codesize + sizeof (int)));
	/* 打印模块例程地址信息 */
	printk( "  init entry @ 0x%08lx, cleanup entry @ 0x%08lx\n",
		(unsigned long) rt.init, (unsigned long) rt.cleanup);
	/* 设置模块的清理函数 */
	mp->cleanup = rt.cleanup;
	/* 调用模块的初始化函数 */
	if ((*rt.init)() != 0)
		return -EBUSY;			/* 初始化失败 */
	/* 设置模块状态为运行中 */
	mp->state = MOD_RUNNING;
	return 0;			/* 成功返回 */
}

asmlinkage int
sys_delete_module(char *module_name)
{
	struct module *mp;
	char name[MOD_MAX_NAME];
	int error;

	if (!suser())
		return -EPERM;
	if (module_name != NULL) {
		if ((error = get_mod_name(module_name, name)) != 0)
			return error;
		if ((mp = find_module(name)) == NULL)
			return -ENOENT;
		if (mp->state == MOD_RUNNING)
			(*mp->cleanup)();
		mp->state = MOD_DELETED;
	}
	free_modules();
	return 0;
}

/*
 * sys_get_kernel_syms - 获取内核符号表
 * 将内核符号表复制到用户空间。如果参数为空，只返回表的大小。
 * 这个系统调用允许调试工具和模块系统获取内核符号信息
 * 
 * 参数:
 * table - 指向用户空间缓冲区的指针，用于存储符号表
 * 
 * 返回值: 成功返回符号表大小，失败返回错误码
 */
asmlinkage int
sys_get_kernel_syms(struct kernel_sym *table)
{
	/* 定义内核符号结构体(与用户空间结构匹配) */
	struct symbol {
		unsigned long addr;	/* 符号地址 */
		char *name;		/* 符号名称 */
	};
	/* 外部变量声明 */
	extern int symbol_table_size;		/* 符号表大小 */
	extern struct symbol symbol_table[];	/* 内核符号表 */
	int i;				/* 循环计数器 */
	struct symbol *from;			/* 源符号指针 */
	struct kernel_sym *to;			/* 目标符号指针 */
	struct kernel_sym sym;			/* 临时符号结构体 */

	/* 如果用户提供了缓冲区，复制符号表 */
	if (table != NULL) {
		/* 设置源和目标指针 */
		from = symbol_table;			/* 源：内核符号表 */
		to = table;			/* 目标：用户空间缓冲区 */
		/* 验证用户空间缓冲区的可写性 */
		i = verify_area(VERIFY_WRITE, to, symbol_table_size * sizeof *table);
		if (i)
			return i;			/* 缓冲区无效 */
		/* 遍历所有符号，复制到用户空间 */
		for (i = symbol_table_size ; --i >= 0 ; ) {
			/* 复制符号地址 */
			sym.value = from->addr;
			/* 复制符号名称(使用strncpy确保字符串安全) */
			strncpy(sym.name, from->name, sizeof sym.name);
			/* 将符号结构体复制到用户空间 */
			memcpy_tofs(to, &sym, sizeof sym);
			/* 移动到下一个符号 */
			from++, to++;
		}
	}
	/* 返回符号表大小 */
	return symbol_table_size;
}


/*
 * Copy the name of a module from user space.
 */
int
get_mod_name(char *user_name, char *buf)
{
	int i;

	i = 0;
	for (i = 0 ; (buf[i] = get_fs_byte(user_name + i)) != '\0' ; ) {
		if (++i >= MOD_MAX_NAME)
			return -E2BIG;
	}
	return 0;
}


/*
 * Look for a module by name, ignoring modules marked for deletion.
 */
struct module *
find_module( const char *name)
{
	struct module *mp;

	for (mp = module_list ; mp ; mp = mp->next) {
		if (mp->state == MOD_DELETED)
			continue;
		if (!strcmp(mp->name, name))
			break;
	}
	return mp;
}


/*
 * Try to free modules which have been marked for deletion.  Returns nonzero
 * if a module was actually freed.
 */
int
free_modules( void)
{
	struct module *mp;
	struct module **mpp;
	int did_deletion;

	did_deletion = 0;
	freeing_modules = 0;
	mpp = &module_list;
	while ((mp = *mpp) != NULL) {
		if (mp->state != MOD_DELETED) {
			mpp = &mp->next;
		} else if (GET_USE_COUNT(mp) != 0) {
			freeing_modules = 1;
			mpp = &mp->next;
		} else {	/* delete it */
			*mpp = mp->next;
			vfree(mp->addr);
			kfree(mp->name);
			kfree_s(mp, sizeof *mp);
			did_deletion = 1;
		}
	}
	return did_deletion;
}


/*
 * Called by the /proc file system to return a current list of modules.
 */
int get_module_list(char *buf)
{
	char *p;
	char *q;
	int i;
	struct module *mp;
	char size[32];

	p = buf;
	for (mp = module_list ; mp ; mp = mp->next) {
		if (p - buf > 4096 - 100)
			break;			/* avoid overflowing buffer */
		q = mp->name;
		i = 20;
		while (*q) {
			*p++ = *q++;
			i--;
		}
		sprintf(size, "%d", mp->size);
		i -= strlen(size);
		if (i <= 0)
			i = 1;
		while (--i >= 0)
			*p++ = ' ';
		q = size;
		while (*q)
			*p++ = *q++;
		if (mp->state == MOD_UNINITIALIZED)
			q = "  (uninitialized)";
		else if (mp->state == MOD_RUNNING)
			q = "";
		else if (mp->state == MOD_DELETED)
			q = "  (deleted)";
		else
			q = "  (bad state)";
		while (*q)
			*p++ = *q++;
		*p++ = '\n';
	}
	return p - buf;
}