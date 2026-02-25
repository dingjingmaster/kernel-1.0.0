/*
 *	linux/zBoot/piggyback.c
 *
 *	(C) 1993 Hannu Savolainen
 */

/*
 *	This program reads the compressed system image from stdin and
 *	encapsulates it into an object file written to the stdout.
 */

#include <stdio.h>
#include <unistd.h>
#include <a.out.h>

/*
 * main - 压缩内核镜像封装程序主函数
 * 
 * 此程序从标准输入读取压缩的系统镜像，并将其封装成一个目标文件写入标准输出
 * 
 * 参数:
 *   argc - 参数个数
 *   argv - 参数数组
 * 
 * 返回值: 成功返回0，失败返回-1
 */
int main(int argc, char *argv[])
{
	int c, n=0, len=0;		/* 字符计数器、读取字节数、总长度 */
	char tmp_buf[512*1024];		/* 临时缓冲区，最大512KB */
	
	/* 目标文件头结构，魔数为0x00640107 */
	struct exec obj = {0x00640107};	/* object header */
	/* 符号名字符串表，包含两个符号名：_input_data和_input_len */
	char string_names[] = {"_input_data\0_input_len\0"};

	/* 符号表结构，定义两个符号：_input_data和_input_len */
	struct nlist var_names[2] = /* Symbol table */
		{	
			{	/* _input_data	*/	/* 压缩数据符号 */
				(char *)4, 7, 0, 0, 0	/* 字符串表偏移、类型、其他等 */
			},
			{	/* _input_len */		/* 数据长度符号 */
				(char *)16, 7, 0, 0, 0	/* 字符串表偏移、类型、其他等 */
			}
		};


	len = 0;	/* 初始化长度 */
	/* 从标准输入读取压缩的系统镜像到缓冲区 */
	while ((n = read(0, &tmp_buf[len], sizeof(tmp_buf)-len+1)) > 0)
	      len += n;	/* 累加读取的字节数 */

	/* 检查读取错误 */
	if (n==-1)
	{
		perror("stdin");	/* 显示错误信息 */
		exit(-1);	/* 退出程序 */
	}

	/* 检查输入大小是否超过缓冲区 */
	if (len >= sizeof(tmp_buf))
	{
		fprintf(stderr, "%s: Input too large\n", argv[0]);
		exit(-1);	/* 输入太大，退出程序 */
	}

	/* 显示压缩后的大小 */
	fprintf(stderr, "Compressed size %d.\n", len);

/*
 *	输出目标文件头
 */
	obj.a_data = len + sizeof(long);	/* 设置数据段大小（压缩数据+长度） */
	obj.a_syms = sizeof(var_names);	/* 设置符号表大小 */
	write(1, (char *)&obj, sizeof(obj));	/* 写入目标文件头 */

/*
 *	输出数据段（压缩的系统镜像和长度）
 */
	write(1, tmp_buf, len);			/* 写入压缩的系统镜像 */
	write(1, (char *)&len, sizeof(len));	/* 写入压缩镜像的长度 */

/*
 *	输出符号表
 */
	var_names[1].n_value = len;		/* 设置_input_len符号的值为压缩镜像长度 */
	write(1, (char *)&var_names, sizeof(var_names));	/* 写入符号表 */

/*
 *	输出字符串表
 */
	len = sizeof(string_names) + sizeof(len);	/* 计算字符串表大小（包括长度字段） */
	write(1, (char *)&len, sizeof(len));	/* 写入字符串表长度 */
	write(1, string_names, sizeof(string_names));	/* 写入字符串表内容 */

	exit(0);	/* 成功退出 */

}