/*
 * linux/ipc/msg.c
 * Copyright (C) 1992 Krishna Balasubramanian 
 */

#include <linux/errno.h>
#include <linux/sched.h>
#include <linux/msg.h>
#include <linux/stat.h>
#include <linux/malloc.h>

#include <asm/segment.h>

extern int ipcperms (struct ipc_perm *ipcp, short msgflg);

static void freeque (int id);
static int newque (key_t key, int msgflg);
static int findkey (key_t key);

static struct msqid_ds *msgque[MSGMNI];
static int msgbytes = 0;
static int msghdrs = 0;
static unsigned short msg_seq = 0;
static int used_queues = 0;
static int max_msqid = 0;
static struct wait_queue *msg_lock = NULL;

/*
 * msg_init - 初始化消息队列系统
 * 在系统启动时调用，用于初始化消息队列相关的全局变量和数据结构
 * 为后续的消息队列操作准备初始状态
 */
void msg_init (void)
{
	int id;		/* 循环计数器，用于遍历消息队列数组 */
	
	/* 初始化消息队列数组：将所有消息队列槽位标记为未使用 */
	for (id=0; id < MSGMNI; id++) 
		msgque[id] = (struct msqid_ds *) IPC_UNUSED;
	/* 初始化全局统计变量：
	 * msgbytes: 所有消息队列中的总字节数
	 * msghdrs: 所有消息队列中的消息头数
	 * msg_seq: 消息序列号(用于生成唯一的消息队列ID)
	 * max_msqid: 当前使用的最大消息队列ID
	 * used_queues: 当前使用的消息队列数量
	 */
	msgbytes = msghdrs = msg_seq = max_msqid = used_queues = 0;
	/* 初始化消息队列锁为NULL(表示无进程等待) */
	msg_lock = NULL;
	return;
}

/*
 * sys_msgsnd - 消息发送系统调用
 * 将消息发送到指定的消息队列
 * 
 * 参数:
 * msqid - 消息队列标识符
 * msgp - 指向消息缓冲区的指针
 * msgsz - 消息大小(字节)
 * msgflg - 发送标志位
 * 
 * 返回值: 成功返回发送的字节数，失败返回错误码
 */
int sys_msgsnd (int msqid, struct msgbuf *msgp, int msgsz, int msgflg)
{
	int id, err;				/* 队列索引和错误码 */
	struct msqid_ds *msq;			/* 消息队列结构体指针 */
	struct ipc_perm *ipcp;			/* IPC权限结构体指针 */
	struct msg *msgh;			/* 消息头结构体指针 */
	long mtype;				/* 消息类型 */
	
	/* 参数验证：检查消息大小和队列ID的有效性 */
	if (msgsz > MSGMAX || msgsz < 0 || msqid < 0)
		return -EINVAL;			/* 无效参数 */
	/* 检查消息缓冲区指针是否有效 */
	if (!msgp) 
		return -EFAULT;			/* 错误地址 */
	/* 验证用户空间缓冲区的可读性 */
	err = verify_area (VERIFY_READ, msgp->mtext, msgsz);
	if (err) 
		return err;			/* 缓冲区访问错误 */
	/* 从用户空间获取消息类型 */
	if ((mtype = get_fs_long (&msgp->mtype)) < 1)
		return -EINVAL;			/* 无效的消息类型 */
	/* 计算消息队列在数组中的索引 */
	id = msqid % MSGMNI;
	/* 获取消息队列结构体 */
	msq = msgque [id];
	/* 检查消息队列是否存在 */
	if (msq == IPC_UNUSED || msq == IPC_NOID)
		return -EINVAL;			/* 无效的消息队列 */
	/* 获取IPC权限结构体 */
	ipcp = &msq->msg_perm; 

/* 重新检查队列状态(可能在被阻塞期间发生变化) */
slept:
	/* 检查序列号是否匹配(防止使用已删除的队列) */
	if (ipcp->seq != (msqid / MSGMNI)) 
		return -EIDRM;			/* 消息队列已被删除 */
	/* 检查写权限 */
	if (ipcperms(ipcp, S_IWUGO)) 
		return -EACCES;			/* 权限不足 */
	
	/* 检查队列是否有足够的空间 */
	if (msgsz + msq->msg_cbytes > msq->msg_qbytes) { 
		/* no space in queue */
		/* 如果设置了非阻塞标志，立即返回 */
		if (msgflg & IPC_NOWAIT)
			return -EAGAIN;		/* 队列已满，非阻塞模式 */
		/* 检查是否有待处理的信号 */
		if (current->signal & ~current->blocked)
			return -EINTR;		/* 被信号中断 */
		/* 在写等待队列上可中断睡眠 */
		interruptible_sleep_on (&msq->wwait);
		/* 唤醒后重新检查队列状态 */
		goto slept;
	}
	
	/* 分配消息头和文本空间 */ 
	msgh = (struct msg *) kmalloc (sizeof(*msgh) + msgsz, GFP_USER);
	if (!msgh)
		return -ENOMEM;			/* 内存不足 */
	/* 设置消息文本的存储位置(紧跟在消息头之后) */
	msgh->msg_spot = (char *) (msgh + 1);
	/* 从用户空间复制消息文本到内核空间 */
	memcpy_fromfs (msgh->msg_spot, msgp->mtext, msgsz); 
	
	/* 再次检查队列状态(防止竞争条件) */
	if (msgque[id] == IPC_UNUSED || msgque[id] == IPC_NOID
		|| ipcp->seq != msqid / MSGMNI) {
		/* 队列已被删除，释放已分配的内存 */
		kfree_s (msgh, sizeof(*msgh) + msgsz);
		return -EIDRM;			/* 消息队列已被删除 */
	}

	/* 将消息添加到队列尾部 */
	msgh->msg_next = NULL;			/* 新消息是队列的最后一个 */
	if (!msq->msg_first)
		/* 队列为空，新消息是第一个也是最后一个 */
		msq->msg_first = msq->msg_last = msgh;
	else {
		/* 队列不为空，将新消息添加到尾部 */
		msq->msg_last->msg_next = msgh;
		msq->msg_last = msgh;
	}
	/* 更新消息和队列的统计信息 */
	msgh->msg_ts = msgsz;			/* 设置消息大小 */
	msgh->msg_type = mtype;			/* 设置消息类型 */
	msq->msg_cbytes += msgsz;		/* 增加队列当前字节数 */
	msgbytes  += msgsz;			/* 增加全局字节数统计 */
	msghdrs++;				/* 增加全局消息头数统计 */
	msq->msg_qnum++;			/* 增加队列消息数量 */
	msq->msg_lspid = current->pid;		/* 设置最后发送进程ID */
	msq->msg_stime = CURRENT_TIME;		/* 设置最后发送时间 */
	/* 如果有进程在等待读取，唤醒它们 */
	if (msq->rwait)
		wake_up (&msq->rwait);
	/* 返回发送的字节数 */
	return msgsz;
}

int sys_msgrcv (int msqid, struct msgbuf *msgp, int msgsz, long msgtyp, 
		int msgflg)
{
	struct msqid_ds *msq;
	struct ipc_perm *ipcp;
	struct msg *tmsg, *leastp = NULL;
	struct msg *nmsg = NULL;
	int id, err;

	if (msqid < 0 || msgsz < 0)
		return -EINVAL;
	if (!msgp || !msgp->mtext)
	    return -EFAULT;
	err = verify_area (VERIFY_WRITE, msgp->mtext, msgsz);
	if (err)
		return err;

	id = msqid % MSGMNI;
	msq = msgque [id];
	if (msq == IPC_NOID || msq == IPC_UNUSED)
		return -EINVAL;
	ipcp = &msq->msg_perm; 

	/* 
	 *  find message of correct type.
	 *  msgtyp = 0 => get first.
	 *  msgtyp > 0 => get first message of matching type.
	 *  msgtyp < 0 => get message with least type must be < abs(msgtype).  
	 */
	while (!nmsg) {
		if(ipcp->seq != msqid / MSGMNI)
			return -EIDRM;
		if (ipcperms (ipcp, S_IRUGO))
			return -EACCES;
		if (msgtyp == 0) 
			nmsg = msq->msg_first;
		else if (msgtyp > 0) {
			if (msgflg & MSG_EXCEPT) { 
				for (tmsg = msq->msg_first; tmsg; 
				     tmsg = tmsg->msg_next)
					if (tmsg->msg_type != msgtyp)
						break;
				nmsg = tmsg;
			} else {
				for (tmsg = msq->msg_first; tmsg; 
				     tmsg = tmsg->msg_next)
					if (tmsg->msg_type == msgtyp)
						break;
				nmsg = tmsg;
			}
		} else {
			for (leastp = tmsg = msq->msg_first; tmsg; 
			     tmsg = tmsg->msg_next) 
				if (tmsg->msg_type < leastp->msg_type) 
					leastp = tmsg;
			if (leastp && leastp->msg_type <= - msgtyp)
				nmsg = leastp;
		}
		
		if (nmsg) { /* done finding a message */
			if ((msgsz < nmsg->msg_ts) && !(msgflg & MSG_NOERROR))
				return -E2BIG;
			msgsz = (msgsz > nmsg->msg_ts)? nmsg->msg_ts : msgsz;
			if (nmsg ==  msq->msg_first)
				msq->msg_first = nmsg->msg_next;
			else {
				for (tmsg= msq->msg_first; tmsg; 
				     tmsg = tmsg->msg_next)
					if (tmsg->msg_next == nmsg) 
						break;
				tmsg->msg_next = nmsg->msg_next;
				if (nmsg == msq->msg_last)
					msq->msg_last = tmsg;
			}
			if (!(--msq->msg_qnum))
				msq->msg_last = msq->msg_first = NULL;
			
			msq->msg_rtime = CURRENT_TIME;
			msq->msg_lrpid = current->pid;
			msgbytes -= nmsg->msg_ts; 
			msghdrs--; 
			msq->msg_cbytes -= nmsg->msg_ts;
			if (msq->wwait)
				wake_up (&msq->wwait);
			put_fs_long (nmsg->msg_type, &msgp->mtype);
			memcpy_tofs (msgp->mtext, nmsg->msg_spot, msgsz);
			kfree_s (nmsg, sizeof(*nmsg) + msgsz); 
			return msgsz;
		} else {  /* did not find a message */
			if (msgflg & IPC_NOWAIT)
				return -ENOMSG;
			if (current->signal & ~current->blocked)
				return -EINTR; 
			interruptible_sleep_on (&msq->rwait);
		}
	} /* end while */
	return -1;
}


static int findkey (key_t key)
{
	int id;
	struct msqid_ds *msq;
	
	for (id=0; id <= max_msqid; id++) {
		while ((msq = msgque[id]) == IPC_NOID) 
			interruptible_sleep_on (&msg_lock);
		if (msq == IPC_UNUSED)
			continue;
		if (key == msq->msg_perm.key)
			return id;
	}
	return -1;
}

static int newque (key_t key, int msgflg)
{
	int id;
	struct msqid_ds *msq;
	struct ipc_perm *ipcp;

	for (id=0; id < MSGMNI; id++) 
		if (msgque[id] == IPC_UNUSED) {
			msgque[id] = (struct msqid_ds *) IPC_NOID;
			goto found;
		}
	return -ENOSPC;

found:
	msq = (struct msqid_ds *) kmalloc (sizeof (*msq), GFP_KERNEL);
	if (!msq) {
		msgque[id] = (struct msqid_ds *) IPC_UNUSED;
		if (msg_lock)
			wake_up (&msg_lock);
		return -ENOMEM;
	}
	ipcp = &msq->msg_perm;
	ipcp->mode = (msgflg & S_IRWXUGO);
	ipcp->key = key;
	ipcp->cuid = ipcp->uid = current->euid;
	ipcp->gid = ipcp->cgid = current->egid;
	ipcp->seq = msg_seq;
	msq->msg_first = msq->msg_last = NULL;
	msq->rwait = msq->wwait = NULL;
	msq->msg_cbytes = msq->msg_qnum = 0;
	msq->msg_lspid = msq->msg_lrpid = 0;
	msq->msg_stime = msq->msg_rtime = 0;
	msq->msg_qbytes = MSGMNB;
	msq->msg_ctime = CURRENT_TIME;
	if (id > max_msqid)
		max_msqid = id;
	msgque[id] = msq;
	used_queues++;
	if (msg_lock)
		wake_up (&msg_lock);
	return (int) msg_seq * MSGMNI + id;
}

int sys_msgget (key_t key, int msgflg)
{
	int id;
	struct msqid_ds *msq;
	
	if (key == IPC_PRIVATE) 
		return newque(key, msgflg);
	if ((id = findkey (key)) == -1) { /* key not used */
		if (!(msgflg & IPC_CREAT))
			return -ENOENT;
		return newque(key, msgflg);
	}
	if (msgflg & IPC_CREAT && msgflg & IPC_EXCL)
		return -EEXIST;
	msq = msgque[id];
	if (msq == IPC_UNUSED || msq == IPC_NOID)
		return -EIDRM;
	if (ipcperms(&msq->msg_perm, msgflg))
		return -EACCES;
	return msq->msg_perm.seq * MSGMNI +id;
} 

static void freeque (int id)
{
	struct msqid_ds *msq = msgque[id];
	struct msg *msgp, *msgh;

	msq->msg_perm.seq++;
	msg_seq++;
	msgbytes -= msq->msg_cbytes;
	if (id == max_msqid)
		while (max_msqid && (msgque[--max_msqid] == IPC_UNUSED));
	msgque[id] = (struct msqid_ds *) IPC_UNUSED;
	used_queues--;
	while (msq->rwait || msq->wwait) {
		if (msq->rwait)
			wake_up (&msq->rwait); 
		if (msq->wwait)
			wake_up (&msq->wwait);
		schedule(); 
	}
	for (msgp = msq->msg_first; msgp; msgp = msgh ) {
		msgh = msgp->msg_next;
		msghdrs--;
		kfree_s (msgp, sizeof(*msgp) + msgp->msg_ts);
	}
	kfree_s (msq, sizeof (*msq));
}

int sys_msgctl (int msqid, int cmd, struct msqid_ds *buf)
{
	int id, err;
	struct msqid_ds *msq, tbuf;
	struct ipc_perm *ipcp;
	
	if (msqid < 0 || cmd < 0)
		return -EINVAL;
	switch (cmd) {
	case IPC_INFO: 
	case MSG_INFO: 
		if (!buf)
			return -EFAULT;
	{ 
		struct msginfo msginfo;
		msginfo.msgmni = MSGMNI;
		msginfo.msgmax = MSGMAX;
		msginfo.msgmnb = MSGMNB;
		msginfo.msgmap = MSGMAP;
		msginfo.msgpool = MSGPOOL;
		msginfo.msgtql = MSGTQL;
		msginfo.msgssz = MSGSSZ;
		msginfo.msgseg = MSGSEG;
		if (cmd == MSG_INFO) {
			msginfo.msgpool = used_queues;
			msginfo.msgmap = msghdrs;
			msginfo.msgtql = msgbytes;
		}
		err = verify_area (VERIFY_WRITE, buf, sizeof (struct msginfo));
		if (err)
			return err;
		memcpy_tofs (buf, &msginfo, sizeof(struct msginfo));
		return max_msqid;
	}
	case MSG_STAT:
		if (!buf)
			return -EFAULT;
		err = verify_area (VERIFY_WRITE, buf, sizeof (*msq));
		if (err)
			return err;
		if (msqid > max_msqid)
			return -EINVAL;
		msq = msgque[msqid];
		if (msq == IPC_UNUSED || msq == IPC_NOID)
			return -EINVAL;
		if (ipcperms (&msq->msg_perm, S_IRUGO))
			return -EACCES;
		id = msqid + msq->msg_perm.seq * MSGMNI; 
		memcpy_tofs (buf, msq, sizeof(*msq));
		return id;
	case IPC_SET:
		if (!buf)
			return -EFAULT;
		memcpy_fromfs (&tbuf, buf, sizeof (*buf));
		break;
	case IPC_STAT:
		if (!buf)
			return -EFAULT;
		err = verify_area (VERIFY_WRITE, buf, sizeof(*msq));
		if (err)
			return err;
		break;
	}

	id = msqid % MSGMNI;
	msq = msgque [id];
	if (msq == IPC_UNUSED || msq == IPC_NOID)
		return -EINVAL;
	ipcp = &msq->msg_perm;
	if (ipcp->seq != msqid / MSGMNI)
		return -EIDRM;

	switch (cmd) {
	case IPC_STAT:
		if (ipcperms (ipcp, S_IRUGO))
			return -EACCES;
		memcpy_tofs (buf, msq, sizeof (*msq));
		return 0;
		break;
	case IPC_RMID: case IPC_SET:
		if (!suser() && current->euid != ipcp->cuid && 
		    current->euid != ipcp->uid)
			return -EPERM;
		if (cmd == IPC_RMID) {
			freeque (id); 
			return 0;
		}
		if (tbuf.msg_qbytes > MSGMNB && !suser())
			return -EPERM;
		msq->msg_qbytes = tbuf.msg_qbytes;
		ipcp->uid = tbuf.msg_perm.uid;
		ipcp->gid =  tbuf.msg_perm.gid;
		ipcp->mode = (ipcp->mode & ~S_IRWXUGO) | 
			(S_IRWXUGO & tbuf.msg_perm.mode);
		msq->msg_ctime = CURRENT_TIME;
		break;
	default:
		return -EINVAL;
		break;
	}
	return 0;
}