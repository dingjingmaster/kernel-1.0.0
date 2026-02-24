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

/*
 * putname() - 释放getname分配的路径名缓冲区
 * 
 * 功能：释放由getname()函数分配的内核页面，用于路径名字符串
 * 
 * 参数：
 *   name - 指向getname()返回的内核空间字符串指针
 * 
 * 使用场景：
 * 这个函数与getname()成对使用，形成完整的路径名处理生命周期：
 * getname() -> 使用路径名 -> putname() 
 * 
 * 典型调用链：
 * namei() -> getname() -> _namei() -> putname()
 * 
 * 内存管理：
 * - getname()分配一个物理页面（PAGE_SIZE，通常4KB）
 * - putname()释放该页面
 * - 必须确保成对调用，避免内存泄漏
 * 
 * 安全特性：
 * - 接受NULL指针（虽然不应该发生）
 * - 使用free_page安全释放内核内存
 * - 参数类型转换为unsigned long符合free_page接口要求
 * 
 * 注意：
 * 这是内核中最简单的内存释放函数之一，但其重要性在于：
 * 1. 确保路径名处理不会内存泄漏
 * 2. 与getname形成对称的内存管理接口
 * 3. 为路径解析提供可靠的内存管理基础
 */
void putname(char * name)
{
	/* 释放getname()分配的物理页面
	 * 参数需要转换为unsigned long类型以符合free_page接口 */
	free_page((unsigned long) name);
}

/*
 *	permission() - 文件权限检查函数
 * 
 * 功能：检查当前进程对指定inode的读/写/执行权限
 * 
 * 参数说明：
 *   inode - 要检查权限的文件或目录的inode
 *   mask  - 请求的权限掩码（MAY_READ, MAY_WRITE, MAY_EXEC）
 * 
 * 返回值：
 *   1 - 有权限，允许访问
 *   0 - 无权限，拒绝访问
 * 
 * 权限检查算法（标准Unix权限模型）：
 * 1. 超级用户（uid=0）总是拥有所有权限
 * 2. 文件所有者：检查用户权限位（mode的高3位）
 * 3. 同组用户：检查组权限位（mode的中3位）
 * 4. 其他用户：检查其他权限位（mode的低3位）
 * 
 * 特殊情况：
 * - 文件系统可以实现自定义的permission方法
 * - 目录的"执行"权限表示"进入"权限
 * - 写权限检查可能受文件系统挂载选项影响（如只读挂载）
 * 
 * 权限位定义：
 * mode & 0700 - 文件所有者权限（读/写/执行）
 * mode & 0070 - 同组用户权限
 * mode & 0007 - 其他用户权限
 * 
 * 历史注释：
 * 原作者不确定是否应该只检查euid还是同时检查uid和euid
 * 这反映了早期Unix权限模型的设计考虑
 */
int permission(struct inode * inode,int mask)
{
	int mode = inode->i_mode;

	/* 第一步：检查文件系统是否实现了自定义权限检查
	 * 某些文件系统（如NFS）可能需要特殊的权限检查逻辑
	 * 如果实现了custom permission方法，优先使用它 */
	if (inode->i_op && inode->i_op->permission)
		return inode->i_op->permission(inode, mask);

	/* 第二步：文件所有者权限检查
	 * 如果当前进程的有效用户ID等于文件所有者ID
	 * 则使用文件所有者权限位（高3位） */
	else if (current->euid == inode->i_uid)
		mode >>= 6;  /* 右移6位，使用0700部分的权限位 */
	/* 第三步：同组用户权限检查
	 * 如果当前进程的有效用户ID不等于文件所有者ID
	 * 但进程属于文件的同组，则检查组权限位（中3位）
	 * 
	 * in_group_p()函数检查当前进程是否属于指定的组ID */
	else if (in_group_p(inode->i_gid))
		mode >>= 3;  /* 右移3位，使用0070部分的权限位 */

	/* 第四步：最终权限验证
	 * 此时mode包含相应的权限位（用户/组/其他）
	 * 
	 * 检查逻辑：
	 * (mode & mask & 0007) == mask
	 * - mode & 0007：提取低3位权限（用户/组/其他权限）
	 * - & mask：提取请求的权限位
	 * - == mask：验证是否有所请求的所有权限
	 * 
	 * suser()检查：超级用户（uid=0）总是拥有所有权限
	 * 这是Unix系统的传统权限模型 */
	if (((mode & mask & 0007) == mask) || suser())
		return 1;  /* 有权限，允许访问 */
	
	/* 第五步：权限拒绝
	 * 通过了用户、组、其他权限检查，且不是超级用户
	 * 返回0表示权限不足，拒绝访问 */
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

/*
 * lnamei() - 符号链接不跟踪版本的路径解析函数
 * 
 * 功能：将用户空间路径名转换为inode，但不跟踪符号链接
 * 
 * 与namei()的关键区别：
 * - namei():  follow_links=1，自动跟踪符号链接到最终目标
 * - lnamei(): follow_links=0，返回符号链接本身的inode
 * 
 * 参数说明：
 *   pathname    - 用户空间的路径名字符串
 *   res_inode   - 输出参数，返回解析得到的inode指针
 * 
 * 返回值：
 *   0      - 成功，res_inode指向路径对应的inode
 *   -ENOENT - 路径不存在
 *   -EFAULT - 用户地址空间访问错误
 *   -ENOMEM - 内核内存不足
 *   -ELOOP   - 符号链接循环（在路径解析过程中）
 * 
 * 使用场景：
 * 1. 读取符号链接本身的内容（readlink系统调用）
 * 2. 删除符号链接（unlink系统调用）
 * 3. 重命名符号链接（rename系统调用）
 * 4. 需要获取符号链接属性而不是目标文件属性的操作
 * 
 * 实现特点：
 * - 与namei()相同的错误处理和内存管理
 * - 唯一区别是follow_links参数设置为0
 * - 返回的inode可能是符号链接本身的inode
 * 
 * 典型调用链：
 * lnamei() -> getname() -> _namei(follow_links=0) -> dir_namei() -> lookup()
 * 
 * 注意：
 * 虽然函数名以"l"开头（可能让人联想到"link"），但实际上表示
 * "logical"或"literal"，即按字面意义解析路径而不跟踪链接
 */
int lnamei(const char * pathname, struct inode ** res_inode)
{
	int error;
	char * tmp;

	/* 第一步：从用户空间复制路径名到内核空间
	 * 与namei()使用相同的安全复制机制 */
	error = getname(pathname,&tmp);
	if (!error) {
		/* 第二步：执行路径解析，但不跟踪符号链接
		 * 关键参数：follow_links=0
		 * 这意味着：
		 * - 如果最终路径分量是符号链接，返回链接本身的inode
		 * - 如果中间路径有符号链接，仍会跟踪到目录（由dir_namei处理）
		 * - 适用于需要操作符号链接本身的系统调用 */
		error = _namei(tmp,NULL,0,res_inode);
		
		/* 第三步：释放临时缓冲区
		 * 无论_namei成功与否，都需要释放getname分配的内存 */
		putname(tmp);
	}
	
	/* 返回解析结果
	 * 成功时res_inode指向路径对应的inode（可能是符号链接本身）
	 * 失败时res_inode为NULL，error为负的错误码 */
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
/*
 * open_namei() - 文件打开/创建路径解析函数
 * 
 * 功能：解析文件路径并执行文件打开或创建操作所需的所有检查
 * 
 * 参数说明：
 *   pathname - 要打开/创建的文件路径
 *   flag     - 打开标志（O_RDONLY, O_WRONLY, O_RDWR, O_CREAT, O_EXCL, O_TRUNC等）
 *   mode     - 创建新文件时的权限模式（受umask影响）
 *   res_inode- 输出参数，返回打开文件的inode指针
 *   base     - 起始目录（NULL表示从当前目录开始）
 * 
 * 返回值：
 *   0      - 成功，res_inode指向有效的inode（引用计数已增加）
 *   -EISDIR - 试图以写模式打开目录
 *   -EACCES - 权限不足
 *   -EEXIST - O_CREAT|O_EXCL且文件已存在
 *   -EROFS  - 试图在只读文件系统上创建/写入
 *   -ETXTBSY- 试图写入正在执行的程序文件
 * 
 * 主要功能：
 * 1. 路径解析：解析完整路径，获取最终目录和文件名
 * 2. 文件创建：处理O_CREAT标志，创建新文件
 * 3. 权限检查：执行全面的权限验证
 * 4. 特殊文件：处理设备文件、目录等特殊文件
 * 5. 并发控制：防止写入正在执行的程序
 * 6. 截断处理：处理O_TRUNC标志
 * 
 * 与namei()的区别：
 * - namei(): 只进行路径解析
 * - open_namei(): 完整的文件打开准备，包括权限、类型、状态检查
 */
int open_namei(const char * pathname, int flag, int mode,
	struct inode ** res_inode, struct inode * base)
{
	const char * basename;
	int namelen,error;
	struct inode * dir, *inode;
	struct task_struct ** p;

	/* 第一步：处理文件创建模式
	 * 清除mode中不需要的位，只保留权限位（S_IALLUGO）
	 * 应用当前进程的umask掩码
	 * 设置普通文件标志（S_IFREG） */
	mode &= S_IALLUGO & ~current->umask;
	mode |= S_IFREG;

	/* 第二步：路径解析
	 * 解析完整路径，获取最终目录的inode和文件名部分
	 * 这个调用会消耗base的引用计数（如果提供） */
	error = dir_namei(pathname,&namelen,&basename,base,&dir);
	if (error)
		return error;

	/* 第三步：处理特殊情况 - 路径以目录结尾
	 * 例如："/usr/"或"/usr/bin/"等情况 */
	if (!namelen) {			/* special case: '/usr/' etc */
		/* 如果以写模式打开目录，返回错误 */
		if (flag & 2) {
			iput(dir);
			return -EISDIR;
		}
		/* 检查目录访问权限
		 * ACC_MODE将O_RDONLY/O_WRONLY/O_RDWR转换为MAY_READ/MAY_WRITE */
		if (!permission(dir,ACC_MODE(flag))) {
			iput(dir);
			return -EACCES;
		}
		/* 返回目录本身的inode */
		*res_inode=dir;
		return 0;
	}

	/* 第四步：增加目录引用计数
	 * 后续的lookup或create操作会消耗目录引用 */
	dir->i_count++;		/* lookup eats the dir */

	/* 第五步：处理文件创建（O_CREAT标志） */
	if (flag & O_CREAT) {
		/* 获取目录信号量，确保创建操作的原子性 */
		down(&dir->i_sem);
		
		/* 首先尝试查找文件是否已存在 */
		error = lookup(dir,basename,namelen,&inode);
		if (!error) {
			/* 文件已存在 */
			if (flag & O_EXCL) {
				/* O_EXCL标志要求文件必须不存在 */
				iput(inode);
				error = -EEXIST;
			}
		} else {
			/* 文件不存在，准备创建新文件 */
			/* 检查目录写入和执行权限 */
			if (!permission(dir,MAY_WRITE | MAY_EXEC))
				error = -EACCES;
			/* 检查目录是否支持创建操作 */
			else if (!dir->i_op || !dir->i_op->create)
				error = -EACCES;
			/* 检查文件系统是否只读 */
			else if (IS_RDONLY(dir))
				error = -EROFS;
			else {
				/* 所有检查通过，创建新文件 */
				dir->i_count++;/* create eats the dir */
				error = dir->i_op->create(dir,basename,namelen,mode,res_inode);
				up(&dir->i_sem);
				iput(dir);
				return error;
			}
		}
		up(&dir->i_sem);
	} else {
		/* 不创建文件，只进行查找 */
		error = lookup(dir,basename,namelen,&inode);
	}
	
	/* 第六步：处理查找错误 */
	if (error) {
		iput(dir);
		return error;
	}

	/* 第七步：跟踪符号链接 */
	error = follow_link(dir,inode,flag,mode,&inode);
	if (error)
		return error;

	/* 第八步：验证文件类型和打开模式的兼容性 */
	/* 不能以写模式打开目录 */
	if (S_ISDIR(inode->i_mode) && (flag & 2)) {
		iput(inode);
		return -EISDIR;
	}

	/* 第九步：文件权限检查 */
	if (!permission(inode,ACC_MODE(flag))) {
		iput(inode);
		return -EACCES;
	}

	/* 第十步：特殊文件处理 */
	/* 设备文件检查 */
	if (S_ISBLK(inode->i_mode) || S_ISCHR(inode->i_mode)) {
		/* 检查是否允许访问设备文件 */
		if (IS_NODEV(inode)) {
			iput(inode);
			return -EACCES;
		}
	} else {
		/* 普通文件和目录的只读文件系统检查 */
		if (IS_RDONLY(inode) && (flag & 2)) {
			iput(inode);
			return -EROFS;
		}
	}

	/* 第十一步：防止写入正在执行的程序
	 * 这是Unix系统的安全机制，防止程序自修改 */
 	if ((inode->i_count > 1) && (flag & 2)) {
 		/* 遍历所有进程，检查是否有进程正在执行此文件 */
 		for (p = &LAST_TASK ; p > &FIRST_TASK ; --p) {
	        struct vm_area_struct * mpnt;
 			if (!*p)
 				continue;
 			/* 检查进程的executable字段 */
 			if (inode == (*p)->executable) {
 				iput(inode);
 				return -ETXTBSY;
			}
			/* 检查进程的内存映射区域 */
			for(mpnt = (*p)->mmap; mpnt; mpnt = mpnt->vm_next) {
				/* 跳过可写映射 */
				if (mpnt->vm_page_prot & PAGE_RW)
					continue;
				/* 找到只读映射的inode匹配 */
				if (inode == mpnt->vm_inode) {
					iput(inode);
					return -ETXTBSY;
				}
			}
 		}
 	}

	/* 第十二步：文件截断处理（O_TRUNC标志） */
	if (flag & O_TRUNC) {
	      /* 清空文件大小 */
	      inode->i_size = 0;
	      /* 调用文件系统的truncate方法 */
	      if (inode->i_op && inode->i_op->truncate)
	           inode->i_op->truncate(inode);
	      /* 通知文件大小变更 */
	      if ((error = notify_change(NOTIFY_SIZE, inode))) {
		   iput(inode);
		   return error;
	      }
	      /* 标记inode为脏，需要写回磁盘 */
	      inode->i_dirt = 1;
	}

	/* 第十三步：返回结果 */
	*res_inode = inode;
	return 0;
}

/*
 * do_mknod() - 设备文件创建函数
 * 
 * 功能：在指定目录中创建设备文件（字符设备、块设备、FIFO等）
 * 
 * 参数说明：
 *   filename - 要创建的设备文件的完整路径
 *   mode     - 文件类型和权限（S_IFCHR, S_IFBLK, S_IFIFO等）
 *   dev      - 设备号（主设备号和次设备号）
 * 
 * 返回值：
 *   0      - 成功创建设备文件
 *   -ENOENT - 路径不存在或为空
 *   -EROFS  - 试图在只读文件系统上创建
 *   -EACCES - 目录权限不足
 *   -EPERM  - 不允许在此文件系统上创建设备文件
 * 
 * 支持的文件类型：
 * - S_IFCHR: 字符设备文件（如/dev/tty, /dev/null）
 * - S_IFBLK: 块设备文件（如/dev/hda, /dev/sda）
 * - S_IFIFO: FIFO（命名管道）
 * - S_IFREG: 普通文件（mknod通常不用于创建普通文件）
 * - S_IFDIR: 目录（mknod通常不用于创建目录）
 * 
 * 典型调用：
 * mknod系统调用 -> do_mknod() -> dir_namei() -> 文件系统mknod方法
 * 
 * 安全考虑：
 * - 只有超级用户可以创建设备文件（通常由sys_mknod检查）
 * - 设备号范围验证（通常由文件系统检查）
 * - 目录权限检查（需要写和执行权限）
 */
int do_mknod(const char * filename, int mode, dev_t dev)
{
	const char * basename;
	int namelen, error;
	struct inode * dir;

	/* 第一步：处理文件创建模式
	 * 应用当前进程的umask掩码，清除不允许的权限位
	 * 这确保新创建的文件不会有过宽的权限 */
	mode &= ~current->umask;

	/* 第二步：路径解析
	 * 解析完整路径，获取最终目录的inode和文件名部分
	 * NULL表示从当前工作目录开始解析 */
	error = dir_namei(filename,&namelen,&basename, NULL, &dir);
	if (error)
		return error;

	/* 第三步：验证文件名有效性
	 * 检查文件名是否为空（如路径以'/'结尾） */
	if (!namelen) {
		iput(dir);
		return -ENOENT;
	}

	/* 第四步：文件系统只读检查
	 * 防止在只读文件系统上创建设备文件 */
	if (IS_RDONLY(dir)) {
		iput(dir);
		return -EROFS;
	}

	/* 第五步：目录权限检查
	 * 创建设备文件需要目录的写和执行权限
	 * MAY_WRITE: 在目录中创建文件的权限
	 * MAY_EXEC: 搜索目录的权限 */
	if (!permission(dir,MAY_WRITE | MAY_EXEC)) {
		iput(dir);
		return -EACCES;
	}

	/* 第六步：文件系统能力检查
	 * 确保文件系统支持mknod操作
	 * 某些文件系统（如NFS）可能不支持创建设备文件 */
	if (!dir->i_op || !dir->i_op->mknod) {
		iput(dir);
		return -EPERM;
	}

	/* 第七步：执行设备文件创建
	 * 使用信号量保护目录操作，确保创建的原子性 */
	down(&dir->i_sem);
	
	/* 调用具体文件系统的mknod方法
	 * 文件系统负责：
	 * 1. 验证设备号的有效性
	 * 2. 创建新的inode结构
	 * 3. 设置文件类型和权限
	 * 4. 关联设备号到inode
	 * 5. 将inode链接到目录结构 */
	error = dir->i_op->mknod(dir,basename,namelen,mode,dev);
	
	/* 释放目录信号量 */
	up(&dir->i_sem);
	
	/* 返回创建结果
	 * 成功时设备文件已添加到文件系统
	 * 失败时error为负的错误码 */
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