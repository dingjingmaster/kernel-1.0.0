/*
 *  linux/fs/namei.c
 *
 *  Copyright (C) 1991, 1992  Linus Torvalds
 */

/*
 * Some corrections by tytso.
 */

#include <asm/segment.h>

#include <linux/errno.h>
#include <linux/sched.h>
#include <linux/kernel.h>
#include <linux/string.h>
#include <linux/fcntl.h>
#include <linux/stat.h>

#define ACC_MODE(x) ("\000\004\002\006"[(x)&O_ACCMODE])

/*
 * In order to reduce some races, while at the same time doing additional
 * checking and hopefully speeding things up, we copy filenames to the
 * kernel data space before using them..
 *
 * POSIX.1 2.4: an empty pathname is invalid (ENOENT).
 */
/*
 * getname() - 安全复制用户空间路径名到内核空间
 * 
 * 功能：从用户空间安全复制文件名/路径名到内核临时缓冲区
 * 
 * 设计目的：
 * 1. 地址空间验证：确保用户地址有效且可访问
 * 2. 长度限制：防止过长的路径名导致内核缓冲区溢出
 * 3. 内存管理：分配和释放临时内核缓冲区
 * 4. 安全复制：使用get_fs_byte安全访问用户空间数据
 * 
 * 参数：
 *   filename  - 用户空间的路径名字符串指针
 *   result    - 输出参数，返回内核空间的字符串指针
 * 
 * 返回值：
 *   0        - 成功，*result指向有效的内核字符串
 *   -EFAULT  - 用户地址无效或无法访问
 *   -ENOENT  - 空路径名（POSIX标准要求）
 *   -ENAMETOOLONG - 路径名超过PAGE_SIZE长度限制
 *   -ENOMEM  - 内核内存不足，无法分配临时缓冲区
 * 
 * 重要特性：
 * - 分配的内存需要调用者通过putname()释放
 * - 自动添加字符串终止符
 * - 支持的最大长度为PAGE_SIZE（通常为4KB）
 * - 严格的地址空间验证，防止用户空间恶意访问
 */
int getname(const char * filename, char **result)
{
	int error;
	unsigned long i, page;
	char * tmp, c;

	/* 第一步：地址空间验证
	 * 检查用户提供的指针是否有效：
	 * 1. 非空检查（!i）
	 * 2. 用户空间地址范围检查（i >= TASK_SIZE）
	 * TASK_SIZE通常为3GB，区分用户空间和内核空间 */
	i = (unsigned long) filename;
	if (!i || i >= TASK_SIZE)
		return -EFAULT;
	
	/* 计算从filename到用户空间末端的距离
	 * 用于后续的长度限制检查 */
	i = TASK_SIZE - i;
	error = -EFAULT;
	
	/* 第二步：路径长度限制
	 * 如果剩余空间大于PAGE_SIZE，限制复制长度为PAGE_SIZE
	 * 防止用户空间提供超长的恶意路径名 */
	if (i > PAGE_SIZE) {
		i = PAGE_SIZE;
		error = -ENAMETOOLONG;  /* 预设错误码，如果复制未完成将返回此错误 */
	}

	/* 第三步：验证第一个字符
	 * 检查路径名是否为空（POSIX.1标准要求空路径返回ENOENT）
	 * get_fs_byte安全地从用户空间读取一个字节 */
	c = get_fs_byte(filename++);
	if (!c)
		return -ENOENT;

	/* 第四步：分配内核临时缓冲区
	 * 分配一个物理页面作为临时缓冲区
	 * GFP_KERNEL标志表示可以睡眠等待内存 */
	if(!(page = __get_free_page(GFP_KERNEL)))
		return -ENOMEM;

	/* 第五步：设置返回指针和临时变量 */
	*result = tmp = (char *) page;

	/* 第六步：复制路径名字符串
	 * 逐字节从用户空间复制到内核缓冲区
	 * 直到遇到字符串终止符或达到长度限制 */
	while (--i) {
		*(tmp++) = c;           /* 复制当前字符 */
		c = get_fs_byte(filename++);  /* 读取下一个字符 */
		if (!c) {               /* 遇到字符串终止符 */
			*tmp = '\0';        /* 确保字符串正确终止 */
			return 0;           /* 成功返回 */
		}
	}

	/* 第七步：处理复制失败情况
	 * 如果循环结束仍未遇到终止符，说明路径名过长
	 * 释放分配的内存并返回相应的错误码 */
	free_page(page);
	return error;
}

void putname(char * name)
{
	free_page((unsigned long) name);
}

/*
 *	permission()
 *
 * is used to check for read/write/execute permissions on a file.
 * I don't know if we should look at just the euid or both euid and
 * uid, but that should be easily changed.
 */
int permission(struct inode * inode,int mask)
{
	int mode = inode->i_mode;

	if (inode->i_op && inode->i_op->permission)
		return inode->i_op->permission(inode, mask);
	else if (current->euid == inode->i_uid)
		mode >>= 6;
	else if (in_group_p(inode->i_gid))
		mode >>= 3;
	if (((mode & mask & 0007) == mask) || suser())
		return 1;
	return 0;
}

/*
 * lookup() looks up one part of a pathname, using the fs-dependent
 * routines (currently minix_lookup) for it. It also checks for
 * fathers (pseudo-roots, mount-points)
 */
/*
 * lookup() - 目录项查找函数
 * 
 * 功能：在指定目录中查找指定名称的文件或子目录
 * 
 * 参数说明：
 *   dir      - 要搜索的目录inode（引用计数已增加）
 *   name     - 要查找的文件名（在dir目录中）
 *   len      - 文件名长度
 *   result   - 输出参数，返回查找到的inode指针
 * 
 * 返回值：
 *   0      - 成功，result指向查找到的inode（引用计数已增加）
 *   -ENOENT - 目录不存在或".."跨越挂载点失败
 *   -ENOTDIR - dir不是目录或目录不支持查找操作
 *   -EACCES  - 没有目录执行权限
 * 
 * 特殊处理：
 * 1. ".."目录：处理父目录查找，包括挂载点跨越
 * 2. 空名称：返回目录本身（用于路径解析的边界情况）
 * 3. 挂载点：正确处理文件系统挂载边界
 * 
 * 引用计数管理：
 * - 输入时dir的引用计数已增加
 * - 输出时返回的inode引用计数已增加
 * - 函数内部会正确处理中间状态的引用计数
 * 
 * 调用链：
 * 这是VFS层通用的目录查找接口，被各种文件系统调用
 */
int lookup(struct inode * dir,const char * name, int len,
	struct inode ** result)
{
	struct super_block * sb;
	int perm;

	/* 初始化输出参数 */
	*result = NULL;

	/* 第一步：基本参数验证
	 * 确保目录inode有效 */
	if (!dir)
		return -ENOENT;

	/* 第二步：权限检查
	 * 在执行任何目录操作之前检查执行权限
	 * MAY_EXEC表示目录执行权限（进入目录的权限） */
	perm = permission(dir,MAY_EXEC);

	/* 第三步：特殊处理".."（父目录）查找
	 * 这是路径解析中最复杂的情况，需要处理挂载点跨越 */
	if (len==2 && name[0] == '.' && name[1] == '.') {
		/* 情况1：已经在根目录，".."仍然是根目录 */
		if (dir == current->root) {
			*result = dir;
			return 0;
		/* 情况2：当前目录是某个文件系统的挂载点
		 * 需要跨越到挂载该文件系统的目录 */
		} else if ((sb = dir->i_sb) && (dir == sb->s_mounted)) {
			sb = dir->i_sb;        /* 获取当前文件系统的超级块 */
			iput(dir);             /* 释放当前目录的引用 */
			dir = sb->s_covered;   /* 获取挂载点目录 */
			if (!dir)
				return -ENOENT;    /* 挂载点不存在（不应该发生） */
			dir->i_count++;        /* 增加新目录的引用计数 */
		}
	}

	/* 第四步：验证目录支持查找操作
	 * 确保目录有lookup操作函数 */
	if (!dir->i_op || !dir->i_op->lookup) {
		iput(dir);
		return -ENOTDIR;
	}

	/* 第五步：权限验证
	 * 如果没有执行权限，不能查找目录内容 */
 	if (!perm) {
		iput(dir);
		return -EACCES;
	}

	/* 第六步：处理空文件名的情况
	 * 这种情况通常发生在路径解析的边界条件
	 * 例如：路径以'/'结尾，或连续的'//' */
	if (!len) {
		*result = dir;         /* 返回目录本身 */
		return 0;
	}

	/* 第七步：调用具体文件系统的lookup方法
	 * 这是VFS的通用接口，具体实现由各个文件系统提供
	 * 返回的inode引用计数已增加 */
	return dir->i_op->lookup(dir,name,len,result);
}

int follow_link(struct inode * dir, struct inode * inode,
	int flag, int mode, struct inode ** res_inode)
{
	if (!dir || !inode) {
		iput(dir);
		iput(inode);
		*res_inode = NULL;
		return -ENOENT;
	}
	if (!inode->i_op || !inode->i_op->follow_link) {
		iput(dir);
		*res_inode = inode;
		return 0;
	}
	return inode->i_op->follow_link(dir,inode,flag,mode,res_inode);
}

/*
 *	dir_namei()
 *
 * dir_namei() returns the inode of the directory of the
 * specified name, and the name within that directory.
 */
/*
 * dir_namei() - 目录路径解析函数
 * 
 * 功能：从指定目录开始解析路径名，返回最终目录的inode和文件名部分
 * 
 * 参数说明：
 *   pathname - 完整路径名（内核空间字符串）
 *   namelen  - 输出参数，返回文件名部分的长度
 *   name     - 输出参数，返回文件名部分的起始指针
 *   base     - 输入/输出参数，起始目录inode（NULL表示当前目录）
 *   res_inode- 输出参数，返回最终目录的inode指针
 * 
 * 返回值：
 *   0      - 成功，res_inode指向最终目录，name指向文件名部分
 *   -ENOTDIR - 中间路径不是目录
 *   -ENOENT - 路径不存在
 *   -EACCES - 访问权限不足
 *   -ELOOP   - 符号链接循环
 * 
 * 解析算法：
 * 1. 确定起始目录（当前目录或根目录）
 * 2. 逐级解析路径中的每个目录分量
 * 3. 处理"."和".."特殊目录
 * 4. 跟踪符号链接（如果需要）
 * 5. 返回最终目录和剩余文件名
 * 
 * 引用计数管理：
 * - 成功时返回的目录inode引用计数已增加
 * - 调用者负责最终释放返回的inode
 * - 中间目录的引用计数会被正确释放
 * 
 * 典型调用：
 * _namei() -> dir_namei() -> lookup() 的调用链
 */
static int dir_namei(const char * pathname, int * namelen, const char ** name,
	struct inode * base, struct inode ** res_inode)
{
	char c;
	const char * thisname;
	int len,error;
	struct inode * inode;

	/* 初始化输出参数 */
	*res_inode = NULL;

	/* 第一步：确定起始目录
	 * 如果base为NULL，从当前工作目录开始解析
	 * 否则使用调用者提供的起始目录 */
	if (!base) {
		base = current->pwd;  /* 获取当前工作目录 */
		base->i_count++;      /* 增加引用计数 */
	}

	/* 第二步：处理绝对路径
	 * 如果路径以'/'开头，从根目录开始解析
	 * 这是POSIX路径解析的标准行为 */
	if ((c = *pathname) == '/') {
		iput(base);           /* 释放之前获取的目录引用 */
		base = current->root; /* 获取根目录 */
		pathname++;           /* 跳过开头的'/' */
		base->i_count++;      /* 增加根目录引用计数 */
	}

	/* 第三步：逐级解析路径中的目录分量
	 * 这个循环处理路径中的每个'/'分隔的分量 */
	while (1) {
		/* 记录当前分量的起始位置 */
		thisname = pathname;
		
		/* 计算当前分量的长度（直到遇到'/'或字符串结束） */
		for(len=0;(c = *(pathname++))&&(c != '/');len++)
			/* nothing */ ;
		
		/* 如果到达路径末尾（没有更多的'/'），结束循环 */
		if (!c)
			break;

		/* 第四步：查找并验证目录分量
		 * 此时thisname指向一个目录分量，len是其长度 */
		base->i_count++;      /* lookup会消耗base的引用，预先增加 */
		
		/* 在当前目录中查找指定名称的inode */
		error = lookup(base,thisname,len,&inode);
		if (error) {
			iput(base);       /* 释放base目录引用 */
			return error;     /* 返回查找错误 */
		}

		/* 第五步：符号链接跟踪
		 * 如果查找到的是符号链接，跟踪到实际目标
		 * 这对于目录遍历是必需的，确保解析正确的路径 */
		error = follow_link(base,inode,0,0,&base);
		if (error)
			return error;     /* 符号链接跟踪失败 */
		/* 注意：此时base可能指向新的inode（如果跟踪了链接） */
	}

	/* 第六步：验证最终目录的有效性
	 * 确保最终路径分量确实是一个目录
	 * 并且支持目录查找操作 */
	if (!base->i_op || !base->i_op->lookup) {
		iput(base);           /* 释放目录引用 */
		return -ENOTDIR;      /* 不是目录或不允许查找 */
	}

	/* 第七步：设置输出参数
	 * thisname指向路径中的最后一个分量（文件名部分）
	 * len是该分量的长度 */
	*name = thisname;
	*namelen = len;
	*res_inode = base;      /* 返回最终目录的inode */
	
	/* 注意：base的引用计数没有释放，调用者需要负责释放 */
	return 0;
}

/*
 * _namei() - 核心路径解析函数
 * 
 * 功能：从指定目录开始解析路径名，获取最终目标文件的inode
 * 
 * 参数说明：
 *   pathname    - 要解析的路径名（内核空间字符串）
 *   base        - 起始目录的inode（NULL表示从根目录开始）
 *   follow_links- 是否跟踪符号链接（1=跟踪，0=不跟踪）
 *   res_inode   - 输出参数，返回解析得到的inode指针
 * 
 * 返回值：
 *   0      - 成功，res_inode指向有效的inode结构
 *   负值   - 错误码（-ENOENT, -EACCES, -ELOOP等）
 * 
 * 解析过程：
 * 1. 路径分解：将完整路径分解为目录部分和文件名部分
 * 2. 目录解析：逐级解析路径中的每个目录分量
 * 3. 文件查找：在最终目录中查找目标文件
 * 4. 符号链接：根据follow_links决定是否跟踪符号链接
 * 
 * 引用计数管理：
 * - 成功时返回的inode已增加引用计数
 * - 中间目录的引用计数会被正确释放
 * - 起始目录base的引用计数由调用者管理
 * 
 * 典型调用链：
 * namei() -> getname() -> _namei() -> dir_namei() -> lookup()
 */
static int _namei(const char * pathname, struct inode * base,
	int follow_links, struct inode ** res_inode)
{
	const char * basename;
	int namelen,error;
	struct inode * inode;

	/* 初始化输出参数 */
	*res_inode = NULL;

	/* 第一步：路径分解和目录解析
	 * dir_namei函数负责：
	 * 1. 解析路径中的目录部分（除最后一个分量外的所有路径）
	 * 2. 逐级跟踪每个目录分量
	 * 3. 返回最终目录的inode和文件名部分
	 * 4. 处理"."和".."特殊目录
	 * 5. 验证每个目录的访问权限
	 * 
	 * 参数说明：
	 * pathname - 完整路径名
	 * namelen  - 输出文件名长度
	 * basename - 输出文件名指针（指向路径中最后一个分量的起始）
	 * base     - 输入起始目录，输出最终目录inode
	 * base     - 作为输入和输出参数使用 */
	error = dir_namei(pathname,&namelen,&basename,base,&base);
	if (error)
		return error;

	/* 第二步：增加最终目录的引用计数
	 * lookup函数会消耗base的引用，所以需要预先增加
	 * 这是VFS层引用计数管理的约定 */
	base->i_count++;	/* lookup uses up base */

	/* 第三步：在最终目录中查找目标文件
	 * lookup函数负责：
	 * 1. 在base目录中查找basename文件
	 * 2. 验证文件名长度和格式
	 * 3. 检查目录访问权限
	 * 4. 返回目标文件的inode（引用计数已增加）
	 * 5. 处理各种错误情况（不存在、权限不足等） */
	error = lookup(base,basename,namelen,&inode);
	if (error) {
		iput(base);  /* 释放base目录的引用 */
		return error;
	}

	/* 第四步：符号链接处理
	 * 根据follow_links参数决定是否跟踪符号链接：
	 * follow_links=1：递归跟踪符号链接，直到获得实际文件
	 * follow_links=0：直接返回符号链接本身的inode */
	if (follow_links) {
		/* 跟踪符号链接
		 * follow_link函数负责：
		 * 1. 检查inode是否为符号链接
		 * 2. 读取链接目标路径
		 * 3. 递归解析链接目标
		 * 4. 处理循环链接检测
		 * 5. 返回最终目标文件的inode */
		error = follow_link(base,inode,0,0,&inode);
		if (error)
			return error;  /* 注意：此时inode可能已被释放 */
	} else {
		/* 不跟踪符号链接，释放base目录的引用
		 * 此时inode是符号链接本身的inode */
		iput(base);
	}

	/* 第五步：返回结果
	 * 成功时inode的引用计数已正确设置
	 * 调用者负责最终释放返回的inode */
	*res_inode = inode;
	return 0;
}

int lnamei(const char * pathname, struct inode ** res_inode)
{
	int error;
	char * tmp;

	error = getname(pathname,&tmp);
	if (!error) {
		error = _namei(tmp,NULL,0,res_inode);
		putname(tmp);
	}
	return error;
}

/*
 *	namei() - 路径名到inode转换函数
 *
 * 功能：将用户空间提供的路径名转换为对应的内核inode结构
 * 
 * 这是VFS层最常用的路径解析入口，被大量系统调用使用：
 * - 文件属性查询（stat, chmod, chown等）
 * - 目录操作（rmdir, mkdir等）
 * - 文件系统挂载（mount）
 * - 简单文件操作（unlink, rename等）
 * 
 * 注意：open, link等复杂操作使用专门的解析函数
 * 
 * 参数：
 *   pathname    - 用户空间的路径名字符串
 *   res_inode   - 输出参数，返回解析得到的inode指针
 * 
 * 返回值：
 *   0      - 成功，res_inode指向有效的inode结构
 *   -ENOENT - 路径不存在
 *   -EFAULT - 用户地址空间访问错误
 *   -ENOMEM - 内核内存不足
 *   -ELOOP   - 符号链接循环
 *   -ENAMETOOLONG - 路径名过长
 * 
 * 实现特点：
 * 1. 自动处理符号链接跟踪（follow_links=1）
 * 2. 从根目录开始解析（base=NULL）
 * 3. 完整的错误处理和内存管理
 */
int namei(const char * pathname, struct inode ** res_inode)
{
	int error;
	char * tmp;

	/* 第一步：从用户空间复制路径名到内核空间
	 * getname函数负责：
	 * - 验证用户地址空间有效性
	 * - 分配内核缓冲区
	 * - 复制字符串并添加终止符
	 * - 处理路径长度限制 */
	error = getname(pathname,&tmp);
	if (!error) {
		/* 第二步：执行实际的路径解析
		 * _namei函数负责：
		 * - 从根目录开始逐级解析路径分量
		 * - 处理".."和"."特殊目录
		 * - 跟踪符号链接（follow_links=1）
		 * - 权限检查和访问控制
		 * - 返回最终目标文件的inode */
		error = _namei(tmp,NULL,1,res_inode);
		
		/* 第三步：释放临时缓冲区
		 * 无论_namei成功与否，都需要释放getname分配的内存 */
		putname(tmp);
	}
	
	/* 返回解析结果：
	 * 成功时res_inode指向目标文件的inode，error=0
	 * 失败时res_inode为NULL，error为负的错误码 */
	return error;
}

/*
 *	open_namei()
 *
 * namei for open - this is in fact almost the whole open-routine.
 *
 * Note that the low bits of "flag" aren't the same as in the open
 * system call - they are 00 - no permissions needed
 *			  01 - read permission needed
 *			  10 - write permission needed
 *			  11 - read/write permissions needed
 * which is a lot more logical, and also allows the "no perm" needed
 * for symlinks (where the permissions are checked later).
 */
int open_namei(const char * pathname, int flag, int mode,
	struct inode ** res_inode, struct inode * base)
{
	const char * basename;
	int namelen,error;
	struct inode * dir, *inode;
	struct task_struct ** p;

	mode &= S_IALLUGO & ~current->umask;
	mode |= S_IFREG;
	error = dir_namei(pathname,&namelen,&basename,base,&dir);
	if (error)
		return error;
	if (!namelen) {			/* special case: '/usr/' etc */
		if (flag & 2) {
			iput(dir);
			return -EISDIR;
		}
		/* thanks to Paul Pluzhnikov for noticing this was missing.. */
		if (!permission(dir,ACC_MODE(flag))) {
			iput(dir);
			return -EACCES;
		}
		*res_inode=dir;
		return 0;
	}
	dir->i_count++;		/* lookup eats the dir */
	if (flag & O_CREAT) {
		down(&dir->i_sem);
		error = lookup(dir,basename,namelen,&inode);
		if (!error) {
			if (flag & O_EXCL) {
				iput(inode);
				error = -EEXIST;
			}
		} else if (!permission(dir,MAY_WRITE | MAY_EXEC))
			error = -EACCES;
		else if (!dir->i_op || !dir->i_op->create)
			error = -EACCES;
		else if (IS_RDONLY(dir))
			error = -EROFS;
		else {
			dir->i_count++;		/* create eats the dir */
			error = dir->i_op->create(dir,basename,namelen,mode,res_inode);
			up(&dir->i_sem);
			iput(dir);
			return error;
		}
		up(&dir->i_sem);
	} else
		error = lookup(dir,basename,namelen,&inode);
	if (error) {
		iput(dir);
		return error;
	}
	error = follow_link(dir,inode,flag,mode,&inode);
	if (error)
		return error;
	if (S_ISDIR(inode->i_mode) && (flag & 2)) {
		iput(inode);
		return -EISDIR;
	}
	if (!permission(inode,ACC_MODE(flag))) {
		iput(inode);
		return -EACCES;
	}
	if (S_ISBLK(inode->i_mode) || S_ISCHR(inode->i_mode)) {
		if (IS_NODEV(inode)) {
			iput(inode);
			return -EACCES;
		}
	} else {
		if (IS_RDONLY(inode) && (flag & 2)) {
			iput(inode);
			return -EROFS;
		}
	}
 	if ((inode->i_count > 1) && (flag & 2)) {
 		for (p = &LAST_TASK ; p > &FIRST_TASK ; --p) {
		        struct vm_area_struct * mpnt;
 			if (!*p)
 				continue;
 			if (inode == (*p)->executable) {
 				iput(inode);
 				return -ETXTBSY;
 			}
			for(mpnt = (*p)->mmap; mpnt; mpnt = mpnt->vm_next) {
				if (mpnt->vm_page_prot & PAGE_RW)
					continue;
				if (inode == mpnt->vm_inode) {
					iput(inode);
					return -ETXTBSY;
				}
			}
 		}
 	}
	if (flag & O_TRUNC) {
	      inode->i_size = 0;
	      if (inode->i_op && inode->i_op->truncate)
	           inode->i_op->truncate(inode);
	      if ((error = notify_change(NOTIFY_SIZE, inode))) {
		   iput(inode);
		   return error;
	      }
	      inode->i_dirt = 1;
	}
	*res_inode = inode;
	return 0;
}

int do_mknod(const char * filename, int mode, dev_t dev)
{
	const char * basename;
	int namelen, error;
	struct inode * dir;

	mode &= ~current->umask;
	error = dir_namei(filename,&namelen,&basename, NULL, &dir);
	if (error)
		return error;
	if (!namelen) {
		iput(dir);
		return -ENOENT;
	}
	if (IS_RDONLY(dir)) {
		iput(dir);
		return -EROFS;
	}
	if (!permission(dir,MAY_WRITE | MAY_EXEC)) {
		iput(dir);
		return -EACCES;
	}
	if (!dir->i_op || !dir->i_op->mknod) {
		iput(dir);
		return -EPERM;
	}
	down(&dir->i_sem);
	error = dir->i_op->mknod(dir,basename,namelen,mode,dev);
	up(&dir->i_sem);
	return error;
}

asmlinkage int sys_mknod(const char * filename, int mode, dev_t dev)
{
	int error;
	char * tmp;

	if (S_ISDIR(mode) || (!S_ISFIFO(mode) && !suser()))
		return -EPERM;
	switch (mode & S_IFMT) {
	case 0:
		mode |= S_IFREG;
		break;
	case S_IFREG: case S_IFCHR: case S_IFBLK: case S_IFIFO:
		break;
	default:
		return -EINVAL;
	}
	error = getname(filename,&tmp);
	if (!error) {
		error = do_mknod(tmp,mode,dev);
		putname(tmp);
	}
	return error;
}

static int do_mkdir(const char * pathname, int mode)
{
	const char * basename;
	int namelen, error;
	struct inode * dir;

	error = dir_namei(pathname,&namelen,&basename,NULL,&dir);
	if (error)
		return error;
	if (!namelen) {
		iput(dir);
		return -ENOENT;
	}
	if (IS_RDONLY(dir)) {
		iput(dir);
		return -EROFS;
	}
	if (!permission(dir,MAY_WRITE | MAY_EXEC)) {
		iput(dir);
		return -EACCES;
	}
	if (!dir->i_op || !dir->i_op->mkdir) {
		iput(dir);
		return -EPERM;
	}
	down(&dir->i_sem);
	error = dir->i_op->mkdir(dir,basename,namelen,mode);
	up(&dir->i_sem);
	return error;
}

asmlinkage int sys_mkdir(const char * pathname, int mode)
{
	int error;
	char * tmp;

	error = getname(pathname,&tmp);
	if (!error) {
		error = do_mkdir(tmp,mode);
		putname(tmp);
	}
	return error;
}

static int do_rmdir(const char * name)
{
	const char * basename;
	int namelen, error;
	struct inode * dir;

	error = dir_namei(name,&namelen,&basename,NULL,&dir);
	if (error)
		return error;
	if (!namelen) {
		iput(dir);
		return -ENOENT;
	}
	if (IS_RDONLY(dir)) {
		iput(dir);
		return -EROFS;
	}
	if (!permission(dir,MAY_WRITE | MAY_EXEC)) {
		iput(dir);
		return -EACCES;
	}
	if (!dir->i_op || !dir->i_op->rmdir) {
		iput(dir);
		return -EPERM;
	}
	return dir->i_op->rmdir(dir,basename,namelen);
}

asmlinkage int sys_rmdir(const char * pathname)
{
	int error;
	char * tmp;

	error = getname(pathname,&tmp);
	if (!error) {
		error = do_rmdir(tmp);
		putname(tmp);
	}
	return error;
}

static int do_unlink(const char * name)
{
	const char * basename;
	int namelen, error;
	struct inode * dir;

	error = dir_namei(name,&namelen,&basename,NULL,&dir);
	if (error)
		return error;
	if (!namelen) {
		iput(dir);
		return -EPERM;
	}
	if (IS_RDONLY(dir)) {
		iput(dir);
		return -EROFS;
	}
	if (!permission(dir,MAY_WRITE | MAY_EXEC)) {
		iput(dir);
		return -EACCES;
	}
	if (!dir->i_op || !dir->i_op->unlink) {
		iput(dir);
		return -EPERM;
	}
	return dir->i_op->unlink(dir,basename,namelen);
}

asmlinkage int sys_unlink(const char * pathname)
{
	int error;
	char * tmp;

	error = getname(pathname,&tmp);
	if (!error) {
		error = do_unlink(tmp);
		putname(tmp);
	}
	return error;
}

static int do_symlink(const char * oldname, const char * newname)
{
	struct inode * dir;
	const char * basename;
	int namelen, error;

	error = dir_namei(newname,&namelen,&basename,NULL,&dir);
	if (error)
		return error;
	if (!namelen) {
		iput(dir);
		return -ENOENT;
	}
	if (IS_RDONLY(dir)) {
		iput(dir);
		return -EROFS;
	}
	if (!permission(dir,MAY_WRITE | MAY_EXEC)) {
		iput(dir);
		return -EACCES;
	}
	if (!dir->i_op || !dir->i_op->symlink) {
		iput(dir);
		return -EPERM;
	}
	down(&dir->i_sem);
	error = dir->i_op->symlink(dir,basename,namelen,oldname);
	up(&dir->i_sem);
	return error;
}

asmlinkage int sys_symlink(const char * oldname, const char * newname)
{
	int error;
	char * from, * to;

	error = getname(oldname,&from);
	if (!error) {
		error = getname(newname,&to);
		if (!error) {
			error = do_symlink(from,to);
			putname(to);
		}
		putname(from);
	}
	return error;
}

static int do_link(struct inode * oldinode, const char * newname)
{
	struct inode * dir;
	const char * basename;
	int namelen, error;

	error = dir_namei(newname,&namelen,&basename,NULL,&dir);
	if (error) {
		iput(oldinode);
		return error;
	}
	if (!namelen) {
		iput(oldinode);
		iput(dir);
		return -EPERM;
	}
	if (IS_RDONLY(dir)) {
		iput(oldinode);
		iput(dir);
		return -EROFS;
	}
	if (dir->i_dev != oldinode->i_dev) {
		iput(dir);
		iput(oldinode);
		return -EXDEV;
	}
	if (!permission(dir,MAY_WRITE | MAY_EXEC)) {
		iput(dir);
		iput(oldinode);
		return -EACCES;
	}
	if (!dir->i_op || !dir->i_op->link) {
		iput(dir);
		iput(oldinode);
		return -EPERM;
	}
	down(&dir->i_sem);
	error = dir->i_op->link(oldinode, dir, basename, namelen);
	up(&dir->i_sem);
	return error;
}

asmlinkage int sys_link(const char * oldname, const char * newname)
{
	int error;
	char * to;
	struct inode * oldinode;

	error = namei(oldname, &oldinode);
	if (error)
		return error;
	error = getname(newname,&to);
	if (error) {
		iput(oldinode);
		return error;
	}
	error = do_link(oldinode,to);
	putname(to);
	return error;
}

static int do_rename(const char * oldname, const char * newname)
{
	struct inode * old_dir, * new_dir;
	const char * old_base, * new_base;
	int old_len, new_len, error;

	error = dir_namei(oldname,&old_len,&old_base,NULL,&old_dir);
	if (error)
		return error;
	if (!permission(old_dir,MAY_WRITE | MAY_EXEC)) {
		iput(old_dir);
		return -EACCES;
	}
	if (!old_len || (old_base[0] == '.' &&
	    (old_len == 1 || (old_base[1] == '.' &&
	     old_len == 2)))) {
		iput(old_dir);
		return -EPERM;
	}
	error = dir_namei(newname,&new_len,&new_base,NULL,&new_dir);
	if (error) {
		iput(old_dir);
		return error;
	}
	if (!permission(new_dir,MAY_WRITE | MAY_EXEC)) {
		iput(old_dir);
		iput(new_dir);
		return -EACCES;
	}
	if (!new_len || (new_base[0] == '.' &&
	    (new_len == 1 || (new_base[1] == '.' &&
	     new_len == 2)))) {
		iput(old_dir);
		iput(new_dir);
		return -EPERM;
	}
	if (new_dir->i_dev != old_dir->i_dev) {
		iput(old_dir);
		iput(new_dir);
		return -EXDEV;
	}
	if (IS_RDONLY(new_dir) || IS_RDONLY(old_dir)) {
		iput(old_dir);
		iput(new_dir);
		return -EROFS;
	}
	if (!old_dir->i_op || !old_dir->i_op->rename) {
		iput(old_dir);
		iput(new_dir);
		return -EPERM;
	}
	down(&new_dir->i_sem);
	error = old_dir->i_op->rename(old_dir, old_base, old_len, 
		new_dir, new_base, new_len);
	up(&new_dir->i_sem);
	return error;
}

asmlinkage int sys_rename(const char * oldname, const char * newname)
{
	int error;
	char * from, * to;

	error = getname(oldname,&from);
	if (!error) {
		error = getname(newname,&to);
		if (!error) {
			error = do_rename(from,to);
			putname(to);
		}
		putname(from);
	}
	return error;
}