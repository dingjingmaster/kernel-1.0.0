## 目录项查找

目录项查找函数：fs/namei.c --> lookup()

```c
int lookup(struct inode * dir,
            const char * name,
            int len,
            struct inode ** result);
```
1. 权限检查，调用 permission() 函数检查目录执行权限（MAY_EXEC）
2. 处理特殊的 `..` (父目录查找)，同时处理根目录、跨越挂载文件系统目录的情况
3. 验证目录支持查找操作
4. 确保目录 inode 有 i_op 以及 i_op->lookup 函数指针
5. 处理空文件名情况（路径以'/'结尾，或连续的'//'）
6. 调用具体文件系统的 lookup 函数（i_op->lookup），进行目录项查找


## 路径解析

路径解析函数：fs/namei.c --> namei()

```c
int namei(const char * pathname, struct inode ** res_inode);
```
1. 从用户空间复制路径名到内核空间（getname函数）
    - 验证用户地址空间有效性
    - 分配内核缓存区
    - 复制路径名到内核缓存区
    - 处理路径长度限制
2. 执行实际的路径解析（_namei函数）
    - 从根开始逐级解析路径分量
    - 处理 . 和 .. 特殊目录
    - 跟踪符号链接
    - 权限检查和访问控制
    - 返回最终的目标文件 inode
3. 返回结果

> dir_namei() 逐级处理路径分量，然后传给 lookup() 函数，获取各个分量的 inode 结构体

## 文件系统挂载

挂载调用入口：fs/super.c --> sys_mount()

### sys_mount 函数
```c
asmlinkage int sys_mount(
                        char * dev_name,
                        char * dir_name,
                        char * type,
                        unsigned long new_flags,
                        void * data)
```
1. 把用户传入的 文件系统 类型复制到内核空间
2. 根据用户空间传入的文件系统类型字符串，获取到对应的 struct file_system_type 结构体
3. 如果文件系统类型结构体中 requires_dev 字段为 true，说明该文件系统类型需要块设备，调用 namei() 函数解析用户空间传入的设备名字符串，获取到对应的 inode 结构体
4. 如果获取到的 inode 结构体不是块设备类型，释放 inode 结构体并返回错误，否则调用 get_blkfops() 函数获取到对应的 struct file_operations 结构体
5. 调用 块设备 文件操作函数指针 -- open 函数打开块设备
6. 复制用户空间传入的挂载参数
7. 调用 do_mount 函数挂载文件系统， 如果挂载成功，返回 0，否则返回错误码并调用块设备的 release 函数指针，关闭块设备
8. 挂载成功后，调用 iput() 函数释放 inode 结构体

### do_mount 函数
```c
static int do_mount(dev_t dev, const char * dir, char * type, int flags, void * data);
```
1. 调用 namei() 函数解析用户空间传入的挂载点路径字符串，获取到对应的 inode 结构体
2. 验证挂载点的有效性：
   - i_count == 1: 确保挂载点只有当前引用(未被打开)
   - i_mount == 0: 确保挂载点未被挂载其他文件系统
3. 验证挂载点类型：确保挂载点是目录而不是其他类型
4. 调用 fs_may_mount() 函数检查设备是否可以被挂载
5. 调用 read_super() 函数读取并初始化文件系统超级块
    - 调用具体文件系统类型结构体中的 read_super() 函数
    - 验证文件系统完整性
    - 初始化超级块结构
6. 建立挂载关系：
    - 将挂载点 inode 记录到超级块的 s_covered 字段
    - 将超级块的根 inode 记录到挂载点的 i_mount 字段

