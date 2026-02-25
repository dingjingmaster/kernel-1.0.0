/*
 *  linux/zBoot/xtract.c
 *
 *  Copyright (C) 1993  Hannu Savolainen
 *
 *	Extracts the system image and writes it to the stdout.
 *	based on tools/build.c by Linus Torvalds
 */

#include <stdio.h>	/* fprintf */
#include <string.h>
#include <stdlib.h>	/* contains exit */
#include <sys/types.h>	/* unistd.h needs this */
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <unistd.h>	/* contains read/write */
#include <fcntl.h>
#include <a.out.h>
#include <linux/config.h>

#define GCC_HEADER 1024

#define STRINGIFY(x) #x

void die(char * str)
{
	fprintf(stderr,"%s\n",str);
	exit(1);
}

void usage(void)
{
	die("Usage: xtract system [ | gzip | piggyback > piggy.s]");
}

/*
 * main - 系统镜像提取工具主函数
 * 
 * 此程序从系统镜像文件中提取系统镜像并写入标准输出
 * 基于Linus Torvalds的tools/build.c
 * 
 * 参数:
 *   argc - 参数个数
 *   argv - 参数数组
 *         argv[1]: 系统镜像文件路径
 * 
 * 返回值: 成功返回0，失败调用die()退出
 */
int main(int argc, char ** argv)
{
	int i,c,id, sz;		/* 循环计数器、字符计数器、文件描述符、大小 */
	char buf[1024];		/* 缓冲区 */
	char major_root, minor_root;	/* 根设备的主次设备号（未使用） */
	struct stat sb;		/* 文件状态结构（未使用） */

	struct exec *ex = (struct exec *)buf;	/* 执行文件头结构指针 */

	/* 检查参数个数 */
	if (argc  != 2)
		usage();	/* 参数不正确，显示用法并退出 */
	
	/* 打开系统镜像文件 */
	if ((id=open(argv[1],O_RDONLY,0))<0)
		die("Unable to open 'system'");	/* 无法打开系统镜像文件 */
	/* 读取GCC文件头 */
	if (read(id,buf,GCC_HEADER) != GCC_HEADER)
		die("Unable to read header of 'system'");	/* 无法读取系统镜像文件头 */
	/* 验证GCC文件头魔数 */
	if (N_MAGIC(*ex) != ZMAGIC)
		die("Non-GCC header of 'system'");	/* 非GCC文件头 */

	/* 计算系统镜像大小 */
	sz = N_SYMOFF(*ex) - GCC_HEADER + 4;	/* +4以获得与tools/build相同的结果 */

	/* 显示系统镜像大小 */
	fprintf(stderr, "System size is %d\n", sz);

	/* 读取并写入系统镜像内容 */
	while (sz)
	{
		int l, n;	/* 读取长度和实际读取字节数 */

		l = sz;	/* 剩余大小 */
		if (l > sizeof(buf)) l = sizeof(buf);	/* 限制读取大小 */

		/* 读取数据 */
		if ((n=read(id, buf, l)) !=l)
		{
			if (n == -1) 
			   perror(argv[1]);	/* 显示错误信息 */
			else
			   fprintf(stderr, "Unexpected EOF\n");	/* 意外的文件结束 */

			die("Can't read system");	/* 无法读取系统镜像 */
		}

		/* 写入数据到标准输出 */
		write(1, buf, l);
		sz -= l;	/* 减少剩余大小 */
	}

	close(id);	/* 关闭文件 */
	return(0);	/* 成功返回 */
}