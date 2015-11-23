
#include "module.h"


unsigned long tpe_alert_wtime = 0;
unsigned long tpe_alert_fyet = 0;

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 19)
#define get_inode(file) file->f_dentry->d_inode;
#define get_parent_inode(file) file->f_dentry->d_parent->d_inode;
#else
#define get_inode(file) file->f_path.dentry->d_inode;
#define get_parent_inode(file) file->f_path.dentry->d_parent->d_inode;
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 19)

char *exe_from_mm(struct mm_struct *mm, char *buf, int len) {

    struct vm_area_struct *vma;
    char *p = NULL;

    if (!mm)
        return (char *)-EFAULT;

    down_read(&mm->mmap_sem);

    vma = mm->mmap;

    while (vma) {
        if ((vma->vm_flags & VM_EXECUTABLE) && vma->vm_file)
            break;
        vma = vma->vm_next;
    }

    if (vma && vma->vm_file)
        p = tpe_d_path(vma->vm_file, buf, len);

    up_read(&mm->mmap_sem);

    return p;
}
#else

// determine the executed file from the task file struct
#define exe_from_mm(mm, buf, len) tpe_d_path(mm->exe_file, buf, len)

#endif



#if 0
static char snd_msg[MAX_FILE_LEN];
static int pid = 0;
static int nl_send_msg(char* method, char *cmd)       // execve process
{
    struct nlmsghdr *nlh;
    struct sk_buff *skb_out;
    int msg_size, res, cpid;

    cpid = task_pid_nr(current);
    if(cpid == pid)
    {        // pid= acl-daemon(netlink) ?
        acl_result = 1;       //success
        return 1;
    }
    sprintf(snd_msg, "%s|%s", method, cmd);

    acl_result = 0;

    msg_size = strlen(snd_msg);
    skb_out = nlmsg_new(msg_size, 0);
    if(!skb_out)
    {
        printk(KERN_ERR "Failed to allocate new skb\n");
        return -1;
    }
    nlh = nlmsg_put(skb_out, 0, 0, NLMSG_DONE, msg_size, 0);

    NETLINK_CB(skb_out).dst_group = 0; /* not in mcast group */

    strncpy(nlmsg_data(nlh), snd_msg, msg_size);
    res = nlmsg_unicast(nl_sk, skb_out, pid);
    //        printk("res=%d\n", res);
    if(res < 0)
        return -1;
    else
        return 1;
}
#endif

// lookup pathnames and log that an exec was denied
int log_denied_exec(const struct file *file, const char *method, const char *reason)
{
    char filename[MAX_FILE_LEN], *f;
    char pfilename[MAX_FILE_LEN], *pf;
    struct task_struct *parent, *task;
    int c = 0;

    if(!tpe_log)
        goto nolog;

    // rate-limit the tpe logging
    if(!tpe_alert_wtime || jiffies - tpe_alert_wtime > tpe_log_floodtime * HZ)
    {
        tpe_alert_wtime = jiffies;
        tpe_alert_fyet = 0;
    }
    else if((jiffies - tpe_alert_wtime < tpe_log_floodtime * HZ) && (tpe_alert_fyet < tpe_log_floodburst))
    {
        tpe_alert_fyet++;
    }
    else if(tpe_alert_fyet == tpe_log_floodburst)
    {
        tpe_alert_wtime = jiffies;
        tpe_alert_fyet++;
        printk(PKPRE "more alerts, logging disabled for %d seconds\n", tpe_log_floodtime);
        goto nolog;
    }
    else goto nolog;

	if(parent && parent->mm)
	{
		parent = get_task_parent(current);

		f = tpe_d_path(file, filename, MAX_FILE_LEN);

		pf = exe_from_mm(parent->mm, pfilename, MAX_FILE_LEN);

		printk(PKPRE "%s untrusted %s of %s (uid:%d) by %s (uid:%d), parents: ",
			(tpe_softmode ? "Would deny" : "Denied"),
			method,
			(!IS_ERR(f) ? f : "<d_path failed>"),
			__kuid_val(get_task_uid(current)),
			(!IS_ERR(pf) ? pf : "<d_path failed>"),
			__kuid_val(get_task_uid(parent))
		);
	}
	else goto nolog;
    // recursively walk the task's parent until we reach init
    // start from this task's grandparent, since this task and parent have already been printed
    task = get_task_parent(parent);

walk:

    if(task && task->mm)
    {
        c++;

        if(tpe_log_max && c > tpe_log_max)
        {
            printk("tpe log_max %d reached", tpe_log_max);
            goto walk_out;
        }

        parent = get_task_parent(task);

        f = exe_from_mm(task->mm, filename, MAX_FILE_LEN);

        printk("%s (uid:%d)", (!IS_ERR(f) ? f : "<d_path failed>"), __kuid_val(get_task_uid(task)));

        if(parent && task->pid != 1)
        {
            printk(", ");
            task = parent;
            goto walk;
        }
    }

    // if we get here on the first pass, there are no additional parents
    if(c == 0)
    {
        printk("(none)");
    }

walk_out:
    printk(". Deny reason: %s\n", reason);

nolog:

    if(tpe_softmode)
        return 0;

    // if not a root process and kill is enabled, kill it
    if(tpe_kill && __kuid_val(get_task_uid(current)))
    {
        (void)send_sig_info(SIGKILL, NULL, current);
        // only kill the parent if it isn't root; it _shouldn't_ ever be, but you never know!
        if(__kuid_val(get_task_uid(get_task_parent(current))))
            (void)send_sig_info(SIGKILL, NULL, get_task_parent(current));
    }

    return -EACCES;
}


#define INODE_IS_WRITABLE(inode) ((inode->i_mode & S_IWOTH) || (tpe_group_writable && inode->i_mode & S_IWGRP))
#define INODE_IS_TRUSTED(inode) \
	(__kuid_val(inode->i_uid) == 0 || \
	(tpe_admin_gid && __kgid_val(inode->i_gid) == tpe_admin_gid) || \
	(__kuid_val(inode->i_uid) == uid && !tpe_trusted_invert && tpe_trusted_gid && in_group_p(KGIDT_INIT(tpe_trusted_gid))))

void send_notification(char *text)
{
    struct sockaddr_in to_addr;
    struct msghdr msg;
    struct iovec iov;
    mm_segment_t oldfs;
    int len = 0;

    if(out_socket->sk == NULL)
    {
        printk(KERN_ERR "%s: socket skbuff is null\n", __func__);
        return;
    }

    iov.iov_base = text;
    len = strlen(text);
    iov.iov_len = len;

    memset(&to_addr, 0, sizeof(to_addr));
    to_addr.sin_family = AF_INET;
    to_addr.sin_addr.s_addr = in_aton("127.0.0.1");
    to_addr.sin_port = htons(MY_OUT_PORT);

    msg.msg_flags = 0;
    msg.msg_name = &to_addr;
    msg.msg_namelen = sizeof(struct sockaddr_in);
    msg.msg_control = NULL;
    msg.msg_controllen = 0;
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;
    msg.msg_control = NULL;

    oldfs = get_fs();
    set_fs(KERNEL_DS);
    sock_sendmsg(out_socket, &msg, len);
    set_fs(oldfs);

    acl_result = -2;
    log_verbose("send msg:%s", text);
}


int lac_allow_exec(const struct file *file, const char *method)
{

    struct inode *inode;
    uid_t uid;
    
    if(tpe_dmz_gid && in_group_p(KGIDT_INIT(tpe_dmz_gid)))
        return log_denied_exec(file, method, "uid in dmz_gid");

    uid = __kuid_val(get_task_uid(current));

    inode = get_parent_inode(file);

    int res;
    char filename[MAX_FILE_LEN];
    //char pfilename[MAX_FILE_LEN];
    char* exec_name;
    //char* parent_exec_name;
    struct task_struct *parent;
    
    int random_key, random;
    char key_plus_exec_name[MAX_FILE_LEN+4];

    //parent = get_task_parent(current);
    exec_name = tpe_d_path(file, filename, MAX_FILE_LEN);

    //if(parent->mm != NULL)
    //    nf->arg = exe_from_mm(parent->mm, pfilename, MAX_FILE_LEN);

    if(strcmp(method, "exec") == 0)
    {
        log_verbose("method:%s exec_name:%s ", method, exec_name);

        if(strcmp(exec_name, "/usr/sbin/sysctl") == 0
           || strcmp(exec_name, "/usr/bin/bash") == 0
           || strcmp(exec_name, "/usr/bin/kmod") == 0
                || strcmp(exec_name, "/usr/bin/sudo") == 0)
            return 0;


        
        while(true)
        {
            get_random_bytes(&random, sizeof(random));
            random_key = random%100;
            if(random_key > 0)
            {
                break;
            }
        }
        
        
        
        sprintf(key_plus_exec_name, "%d %s", random_key, exec_name);
        printk(PKPRE "execName = %s\n", exec_name);
        printk(PKPRE "random key = %d \n", random_key);
        printk(PKPRE "key_plus_exec_name = %s\n", key_plus_exec_name);
        
//        send_notification(key_plus_exec_name);
       
//        memset(key_plus_exec_name, 0x00, MAX_FILE_LEN+4);
//        printk(PKPRE "key memset %s\n", key_plus_exec_name);
        

//        printk(PKPRE "tpe_kill = %d\n",tpe_kill);
//        //msleep(1000);
//        mdelay(1000);
//        printk(PKPRE "tpe_kill = %d\n",tpe_kill);
//        if(tpe_kill == random_key*10 + 1)
//        {
            
//            return log_denied_exec(file, method, "not allowed command");l
//        }
//        else if(tpe_kill == random_key*10)
//        {
//            return 0;
//        }
//        else
//        {
//            return log_denied_exec(file, method, "Invalid command");
//        }
        

    }


#if 0
    // if user is not trusted, enforce the trusted path
    if(!UID_IS_TRUSTED(uid))
    {

        if(!INODE_IS_TRUSTED(inode))
            return log_denied_exec(file, method, "directory uid not trusted");

        if(INODE_IS_WRITABLE(inode))
            return log_denied_exec(file, method, "directory is writable");

        if(tpe_check_file)
        {

            inode = get_inode(file);

            if(!INODE_IS_TRUSTED(inode))
                return log_denied_exec(file, method, "file uid not trusted");

            if(INODE_IS_WRITABLE(inode))
                return log_denied_exec(file, method, "file is writable");

        }

        if(strlen(tpe_hardcoded_path))
        {
            char filename[MAX_FILE_LEN];
            char path[TPE_HARDCODED_PATH_LEN];
            char *f, *p, *c;
            int i, error = 1;

            p = path;
            strncpy(p, tpe_hardcoded_path, TPE_HARDCODED_PATH_LEN);

            f = tpe_d_path(file, filename, MAX_FILE_LEN);

            while((c = strsep(&p, ":")))
            {
                i = (int)strlen(c);
                if(!strncmp(c, f, i) && !strstr(&f[i + 1], "/"))
                {
                    error = 0;
                    break;
                }
            }

            if(error)
                return log_denied_exec(file, method, "outside of hardcoded_path");

        }

    }
#endif
    return 0;
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 19)
int lac_allow(const char *name, const char *method) {

    struct file *file;
    int ret;

    printk(PKPRE "lac_allow()\n");

    file = open_exec(name);

    if (IS_ERR(file))
        return PTR_ERR(file);

    ret = lac_allow_exec(file, method);
    printk(PKPRE "lac_allow() ret:$d\n", ret); 

    fput(file);

    return ret;
}
#endif

