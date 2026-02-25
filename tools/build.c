/*
 *  linux/tools/build.c
 *
 *  Copyright (C) 1991, 1992  Linus Torvalds
 */

/*
 * This file builds a disk-image from three different files:
 *
 * - bootsect: max 510 bytes of 8086 machine code, loads the rest
 * - setup: max 4 sectors of 8086 machine code, sets up system parm
 * - system: 80386 code for actual system
 *
 * It does some checking that all files are of the correct type, and
 * just writes the result to stdout, removing headers and padding to
 * the right amount. It also writes some system data to stderr.
 */

/*
 * Changes by tytso to allow root device specification
 */

#include <stdio.h>	/* fprintf */
#include <string.h>
#include <stdlib.h>	/* contains exit */
#include <sys/types.h>	/* unistd.h needs this */
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <unistd.h>	/* contains read/write */
#include <fcntl.h>
#include <linux/config.h>
#include <linux/a.out.h>

#define MINIX_HEADER 32
#define GCC_HEADER 1024

#define SYS_SIZE DEF_SYSSIZE

#define DEFAULT_MAJOR_ROOT 0
#define DEFAULT_MINOR_ROOT 0

/* max nr of sectors of setup: don't change unless you also change
 * bootsect etc */
#define SETUP_SECTS 4

#define STRINGIFY(x) #x

typedef union {
	long l;
	short s[2];
	char b[4];
} conv;

long intel_long(long l)
{
	conv t;

	t.b[0] = l & 0xff; l >>= 8;
	t.b[1] = l & 0xff; l >>= 8;
	t.b[2] = l & 0xff; l >>= 8;
	t.b[3] = l & 0xff; l >>= 8;
	return t.l;
}

short intel_short(short l)
{
	conv t;

	t.b[0] = l & 0xff; l >>= 8;
	t.b[1] = l & 0xff; l >>= 8;
	return t.s[0];
}

void die(char * str)
{
	fprintf(stderr,"%s\n",str);
	exit(1);
}

void usage(void)
{
	die("Usage: build bootsect setup system [rootdev] [> image]");
}

/*
 * main - 构建Linux内核镜像的主函数
 * 
 * 此程序将三个不同的文件构建成一个磁盘镜像：
 * - bootsect: 最多510字节的8086机器代码，用于加载其余部分
 * - setup: 最多4个扇区的8086机器代码，用于设置系统参数
 * - system: 实际系统的80386代码
 * 
 * 参数:
 *   argc - 参数个数
 *   argv - 参数数组
 *         argv[1]: bootsect文件路径
 *         argv[2]: setup文件路径
 *         argv[3]: system文件路径
 *         argv[4]: 根设备(可选)
 * 
 * 返回值: 成功返回0，失败调用die()退出
 */
int main(int argc, char ** argv)
{
	int i,c,id, sz;			/* 循环计数器、字符计数器、文件描述符、大小 */
	unsigned long sys_size;		/* 系统大小 */
	char buf[1024];			/* 缓冲区 */
	struct exec *ex = (struct exec *)buf;	/* 执行文件头结构指针 */
	char major_root, minor_root;		/* 根设备的主次设备号 */
	struct stat sb;			/* 文件状态结构 */

	/* 检查参数个数 */
	if ((argc < 4) || (argc > 5))
		usage();	/* 参数不正确，显示用法并退出 */
	/* 处理可选的根设备参数 */
	if (argc > 4) {
		if (!strcmp(argv[4], "CURRENT")) {
			/* 使用当前根设备 */
			if (stat("/", &sb)) {
				perror("/");
				die("Couldn't stat /");
			}
			major_root = major(sb.st_dev);	/* 获取主设备号 */
			minor_root = minor(sb.st_dev);	/* 获取次设备号 */
		} else if (strcmp(argv[4], "FLOPPY")) {
			/* 使用指定的根设备 */
			if (stat(argv[4], &sb)) {
				perror(argv[4]);
				die("Couldn't stat root device.");
			}
			major_root = major(sb.st_rdev);	/* 获取主设备号 */
			minor_root = minor(sb.st_rdev);	/* 获取次设备号 */
		} else {
			/* 使用软盘 */
			major_root = 0;
			minor_root = 0;
		}
	} else {
		/* 使用默认根设备 */
		major_root = DEFAULT_MAJOR_ROOT;
		minor_root = DEFAULT_MINOR_ROOT;
	}
	fprintf(stderr, "Root device is (%d, %d)\n", major_root, minor_root);
	/* 清空缓冲区 */
	for (i=0;i<sizeof buf; i++) buf[i]=0;
	
	/* 处理bootsect文件 */
	if ((id=open(argv[1],O_RDONLY,0))<0)
		die("Unable to open 'boot'");	/* 无法打开bootsect文件 */
	if (read(id,buf,MINIX_HEADER) != MINIX_HEADER)
		die("Unable to read header of 'boot'");	/* 无法读取bootsect文件头 */
	/* 验证Minix文件头 */
	if (((long *) buf)[0]!=intel_long(0x04100301))
		die("Non-Minix header of 'boot'");
	if (((long *) buf)[1]!=intel_long(MINIX_HEADER))
		die("Non-Minix header of 'boot'");
	if (((long *) buf)[3] != 0)
		die("Illegal data segment in 'boot'");	/* 非法数据段 */
	if (((long *) buf)[4] != 0)
		die("Illegal bss in 'boot'");	/* 非法bss段 */
	if (((long *) buf)[5] != 0)
		die("Non-Minix header of 'boot'");
	if (((long *) buf)[7] != 0)
		die("Illegal symbol table in 'boot'");	/* 非法符号表 */
	/* 读取bootsect内容 */
	i=read(id,buf,sizeof buf);
	fprintf(stderr,"Boot sector %d bytes.\n",i);
	if (i != 512)
		die("Boot block must be exactly 512 bytes");	/* 引导块必须是512字节 */
	/* 检查引导标志 */
	if ((*(unsigned short *)(buf+510)) != (unsigned short)intel_short(0xAA55))
		die("Boot block hasn't got boot flag (0xAA55)");	/* 缺少引导标志 */
	/* 在引导扇区中设置根设备信息 */
	buf[508] = (char) minor_root;	/* 次设备号 */
	buf[509] = (char) major_root;	/* 主设备号 */	
	/* 写入引导扇区到标准输出 */
	i=write(1,buf,512);
	if (i!=512)
		die("Write call failed");	/* 写入失败 */
	close (id);	/* 关闭bootsect文件 */
	
	/* 处理setup文件 */
	if ((id=open(argv[2],O_RDONLY,0))<0)
		die("Unable to open 'setup'");	/* 无法打开setup文件 */
	if (read(id,buf,MINIX_HEADER) != MINIX_HEADER)
		die("Unable to read header of 'setup'");	/* 无法读取setup文件头 */
	/* 验证Minix文件头 */
	if (((long *) buf)[0]!=intel_long(0x04100301))
		die("Non-Minix header of 'setup'");
	if (((long *) buf)[1]!=intel_long(MINIX_HEADER))
		die("Non-Minix header of 'setup'");
	if (((long *) buf)[3] != 0)
		die("Illegal data segment in 'setup'");	/* 非法数据段 */
	if (((long *) buf)[4] != 0)
		die("Illegal bss in 'setup'");	/* 非法bss段 */
	if (((long *) buf)[5] != 0)
		die("Non-Minix header of 'setup'");
	if (((long *) buf)[7] != 0)
		die("Illegal symbol table in 'setup'");	/* 非法符号表 */
	/* 读取并写入setup内容 */
	for (i=0 ; (c=read(id,buf,sizeof buf))>0 ; i+=c )
		if (write(1,buf,c)!=c)
			die("Write call failed");	/* 写入失败 */
	if (c != 0)
		die("read-error on 'setup'");	/* 读取错误 */
	close (id);	/* 关闭setup文件 */
	/* 检查setup大小 */
	if (i > SETUP_SECTS*512)
		die("Setup exceeds " STRINGIFY(SETUP_SECTS)
			" sectors - rewrite build/boot/setup");	/* setup太大 */
	fprintf(stderr,"Setup is %d bytes.\n",i);
	/* 填充setup到指定大小 */
	for (c=0 ; c<sizeof(buf) ; c++)
		buf[c] = '\0';	/* 清空缓冲区 */
	while (i<SETUP_SECTS*512) {
		c = SETUP_SECTS*512-i;	/* 计算需要填充的字节数 */
		if (c > sizeof(buf))
			c = sizeof(buf);	/* 限制填充大小 */
		if (write(1,buf,c) != c)
			die("Write call failed");	/* 写入失败 */
		i += c;
	}
	
	/* 处理system文件 */
	if ((id=open(argv[3],O_RDONLY,0))<0)
		die("Unable to open 'system'");	/* 无法打开system文件 */
	if (read(id,buf,GCC_HEADER) != GCC_HEADER)
		die("Unable to read header of 'system'");	/* 无法读取system文件头 */
	if (N_MAGIC(*ex) != ZMAGIC)
		die("Non-GCC header of 'system'");	/* 非GCC文件头 */
	/* 显示系统大小信息 */
	fprintf(stderr,"System is %d kB (%d kB code, %d kB data and %d kB bss)\n",
		(ex->a_text+ex->a_data+ex->a_bss)/1024,	/* 总大小 */
		ex->a_text /1024,		/* 代码段大小 */
		ex->a_data /1024,		/* 数据段大小 */
		ex->a_bss  /1024);		/* BSS段大小 */
	/* 计算系统大小 */
	sz = N_SYMOFF(*ex) - GCC_HEADER + 4;	/* 计算实际大小 */
	sys_size = (sz + 15) / 16;		/* 转换为16字节为单位 */
	if (sys_size > SYS_SIZE)
		die("System is too big");	/* 系统太大 */
	/* 读取并写入system内容 */
	while (sz > 0) {
		int l, n;

		l = sz;		/* 剩余大小 */
		if (l > sizeof(buf))
			l = sizeof(buf);	/* 限制读取大小 */
		if ((n=read(id, buf, l)) != l) {	/* 读取数据 */
			if (n == -1) 
				perror(argv[1]);	/* 显示错误信息 */
			else
				fprintf(stderr, "Unexpected EOF\n");	/* 意外的文件结束 */
			die("Can't read 'system'");
		}
		if (write(1, buf, l) != l)
			die("Write failed");	/* 写入失败 */
		sz -= l;	/* 减少剩余大小 */
	}
	close(id);	/* 关闭system文件 */
	/* 在偏移500处写入系统大小 */
	if (lseek(1,500,0) == 500) {	/* 定位到偏移500处 */
		buf[0] = (sys_size & 0xff);	/* 低字节 */
		buf[1] = ((sys_size >> 8) & 0xff);	/* 高字节 */
		if (write(1, buf, 2) != 2)
			die("Write failed");	/* 写入失败 */
	}
	return(0);	/* 成功返回 */
}