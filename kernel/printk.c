/*
 *  linux/kernel/printk.c
 *
 *  Copyright (C) 1991, 1992  Linus Torvalds
 *
 * Modified to make sys_syslog() more flexible: added commands to
 * return the last 4k of kernel messages, regardless of whether
 * they've been read or not.  Added option to suppress kernel printk's
 * to the console.  Added hook for sending the console messages
 * elsewhere, in preparation for a serial line console (someday).
 * Ted Ts'o, 2/11/93.
 */

#include <stdarg.h>

#include <asm/segment.h>
#include <asm/system.h>

#include <linux/errno.h>
#include <linux/sched.h>
#include <linux/kernel.h>

#define LOG_BUF_LEN	4096

static char buf[1024];

extern int vsprintf(char * buf, const char * fmt, va_list args);
extern void console_print(const char *);

#define DEFAULT_MESSAGE_LOGLEVEL 7 /* KERN_DEBUG */
#define DEFAULT_CONSOLE_LOGLEVEL 7 /* anything more serious than KERN_DEBUG */

unsigned long log_size = 0;
struct wait_queue * log_wait = NULL;
int console_loglevel = DEFAULT_CONSOLE_LOGLEVEL;

static void (*console_print_proc)(const char *) = 0;
static char log_buf[LOG_BUF_LEN];
static unsigned long log_start = 0;
static unsigned long logged_chars = 0;

/*
 * sys_syslog - 系统日志操作
 * 实现对内核日志缓冲区的各种操作，包括读取、清除和控制台输出
 * 支持环形缓冲区机制，允许用户空间程序访问内核消息
 * 
 * sys_syslog命令说明:
 *	0 -- 关闭日志(当前为空操作)
 *	1 -- 打开日志(当前为空操作)
 *	2 -- 从日志读取(顺序读取)
 *	3 -- 读取环形缓冲区中最近的4k消息
 *	4 -- 读取并清除环形缓冲区中最近的4k消息
 *	5 -- 清除环形缓冲区
 *	6 -- 禁用printk输出到控制台
 *	7 -- 启用printk输出到控制台
 *	8 -- 设置输出到控制台的消息级别
 * 
 * 参数:
 * type - 操作类型
 * buf - 用户空间缓冲区指针(用于读取操作)
 * len - 缓冲区长度
 * 
 * 返回值: 成功返回读取的字节数或0，失败返回错误码
 */
asmlinkage int
sys_syslog(int type, char * buf, int len)
{
	unsigned long i, j, count;	/* 循环计数器 */
	int do_clear = 0;		/* 是否清除缓冲区标志 */
	char c;				/* 临时字符变量 */
	int error;			/* 错误码 */

	/* 检查权限(类型3允许所有用户，其他需要超级用户) */
	if ((type != 3) && !suser())
		return -EPERM;			/* 权限不足 */
	/* 根据操作类型执行相应操作 */
	switch (type) {
		case 0:	/* 关闭日志 */
			return 0;			/* 空操作 */
		case 1:	/* 打开日志 */
			return 0;			/* 空操作 */
		case 2:	/* 从日志顺序读取 */
			/* 检查参数有效性 */
			if (!buf || len < 0)
				return -EINVAL;		/* 无效参数 */
			if (!len)
				return 0;			/* 无数据请求 */
			/* 验证用户空间缓冲区的可写性 */
			error = verify_area(VERIFY_WRITE,buf,len);
			if (error)
				return error;			/* 缓冲区无效 */
			/* 关中断，准备访问共享数据 */
			cli();
			/* 等待日志数据可用 */
			while (!log_size) {
				/* 检查是否有待处理信号 */
				if (current->signal & ~current->blocked) {
					sti();			/* 开中断 */
					return -ERESTARTSYS;	/* 系统调用重启 */
				}
				/* 在日志等待队列上可中断睡眠 */
				interruptible_sleep_on(&log_wait);
			}
			/* 从环形缓冲区读取数据 */
			i = 0;
			while (log_size && i < len) {
				/* 获取当前字符 */
				c = *((char *) log_buf+log_start);
				/* 更新环形缓冲区指针 */
				log_start++;
				log_size--;
				log_start &= LOG_BUF_LEN-1;	/* 环形缓冲区 */
				/* 开中断，写入用户空间 */
				sti();
				put_fs_byte(c,buf);
				buf++;
				i++;
				/* 关中断，准备下一次读取 */
				cli();
			}
			sti();			/* 开中断 */
			return i;			/* 返回读取的字节数 */
		case 4:	/* 读取并清除最近的内核消息 */
			do_clear = 1; 			/* 设置清除标志 */
			/* FALL THRU */		/* 继续执行case 3的代码 */
		case 3:	/* 读取环形缓冲区中最近的4k消息 */
			/* 检查参数有效性 */
			if (!buf || len < 0)
				return -EINVAL;		/* 无效参数 */
			if (!len)
				return 0;			/* 无数据请求 */
			/* 验证用户空间缓冲区的可写性 */
			error = verify_area(VERIFY_WRITE,buf,len);
			if (error)
				return error;			/* 缓冲区无效 */
			/* 计算实际读取的字节数 */
			count = len;
			if (count > LOG_BUF_LEN)
				count = LOG_BUF_LEN;		/* 限制最大读取量 */
			if (count > logged_chars)
				count = logged_chars;	/* 不超过已记录的字符数 */
			/* 计算读取起始位置 */
			j = log_start + log_size - count;
			/* 从环形缓冲区读取数据 */
			for (i = 0; i < count; i++) {
				/* 获取当前字符 */
				c = *((char *) log_buf+(j++ & (LOG_BUF_LEN-1)));
				/* 写入用户空间 */
				put_fs_byte(c, buf++);
			}
			/* 如果需要清除缓冲区 */
			if (do_clear)
				logged_chars = 0;		/* 重置计数器 */
			return i;			/* 返回读取的字节数 */
		case 5:	/* 清除环形缓冲区 */
			logged_chars = 0;		/* 重置计数器 */
			return 0;			/* 成功返回 */
		case 6:	/* 禁用printk输出到控制台 */
			console_loglevel = 1; /* 只显示panic消息 */
			return 0;			/* 成功返回 */
		case 7:	/* 启用printk输出到控制台 */
			console_loglevel = DEFAULT_CONSOLE_LOGLEVEL;
			return 0;			/* 成功返回 */
		case 8:	/* 设置输出到控制台的消息级别 */
			/* 检查参数有效性 */
			if (len < 0 || len > 8)
				return -EINVAL;		/* 无效参数 */
			console_loglevel = len;	/* 设置新的日志级别 */
			return 0;			/* 成功返回 */
	}
	/* 无效的操作类型 */
	return -EINVAL;
}


asmlinkage int printk(const char *fmt, ...)
{
	va_list args;
	int i;
	char *msg, *p, *buf_end;
	static char msg_level = -1;
	long flags;

	save_flags(flags);
	cli();
	va_start(args, fmt);
	i = vsprintf(buf + 3, fmt, args); /* hopefully i < sizeof(buf)-4 */
	buf_end = buf + 3 + i;
	va_end(args);
	for (p = buf + 3; p < buf_end; p++) {
		msg = p;
		if (msg_level < 0) {
			if (
				p[0] != '<' ||
				p[1] < '0' || 
				p[1] > '7' ||
				p[2] != '>'
			) {
				p -= 3;
				p[0] = '<';
				p[1] = DEFAULT_MESSAGE_LOGLEVEL - 1 + '0';
				p[2] = '>';
			} else
				msg += 3;
			msg_level = p[1] - '0';
		}
		for (; p < buf_end; p++) {
			log_buf[(log_start+log_size) & (LOG_BUF_LEN-1)] = *p;
			if (log_size < LOG_BUF_LEN)
				log_size++;
			else
				log_start++;
			logged_chars++;
			if (*p == '\n')
				break;
		}
		if (msg_level < console_loglevel && console_print_proc) {
			char tmp = p[1];
			p[1] = '\0';
			(*console_print_proc)(msg);
			p[1] = tmp;
		}
		if (*p == '\n')
			msg_level = -1;
	}
	restore_flags(flags);
	wake_up_interruptible(&log_wait);
	return i;
}

/*
 * The console driver calls this routine during kernel initialization
 * to register the console printing procedure with printk() and to
 * print any messages that were printed by the kernel before the
 * console driver was initialized.
 */
void register_console(void (*proc)(const char *))
{
	int	i,j;
	int	p = log_start;
	char	buf[16];
	char	msg_level = -1;
	char	*q;

	console_print_proc = proc;

	for (i=0,j=0; i < log_size; i++) {
		buf[j++] = log_buf[p];
		p++; p &= LOG_BUF_LEN-1;
		if (buf[j-1] != '\n' && i < log_size - 1 && j < sizeof(buf)-1)
			continue;
		buf[j] = 0;
		q = buf;
		if (msg_level < 0) {
			msg_level = buf[1] - '0';
			q = buf + 3;
		}
		if (msg_level < console_loglevel)
			(*proc)(q);
		if (buf[j-1] == '\n')
			msg_level = -1;
		j = 0;
	}
}