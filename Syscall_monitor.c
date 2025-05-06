#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/kprobes.h>
#include <linux/fs.h>
#include <linux/sched.h>
#include <linux/uaccess.h>
#include <linux/proc_fs.h>
#include <linux/miscdevice.h>
#include <linux/string.h>
#include <linux/file.h>
#include <linux/fdtable.h>
#include <linux/path.h>
#include <linux/dcache.h>
#include <linux/slab.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Kernel Developer");
MODULE_DESCRIPTION("System Call Monitor using Kprobes");
MODULE_VERSION("1.0");

#define MODE_OFF  0
#define MODE_LOG  1
#define MODE_BLOCK 2

//IOCTL commands 
#define SYSCALL_MON_MAGIC 'k'
#define IOCTL_SET_MODE     _IOW(SYSCALL_MON_MAGIC, 1, int)
#define IOCTL_SET_BLOCK    _IOW(SYSCALL_MON_MAGIC, 2, struct block_config)

// which syscall to block 
#define BLOCK_OPEN  1
#define BLOCK_READ  2
#define BLOCK_WRITE 3

struct block_config {
    pid_t pid;           
    int syscall_type;    
};


static int current_mode = MODE_OFF;
static struct block_config block_settings = {0, 0};

// thee Log file 
static struct file *log_file = NULL;
#define LOG_FILENAME "/tmp/syscall_monitor.log"


static struct kprobe kp_open, kp_read, kp_write;

// writing to the logg file
static void write_log(const char *fmt, ...)
{
    va_list args;
    char buf[256];
    int len;
    
    if (current_mode != MODE_LOG || !log_file)
        return;
    
    va_start(args, fmt);
    len = vsnprintf(buf, sizeof(buf), fmt, args);
    va_end(args);
    
    if (len > 0) {
        kernel_write(log_file, buf, len, &log_file->f_pos);
    }
}

// Open syscall pre-handler 
static int handler_pre_open(struct kprobe *p, struct pt_regs *regs)
{
    const char __user *filename = (const char __user *)regs->di;
    char fname[256] = {0};
    
    // Skip if module is off 
    if (current_mode == MODE_OFF)
        return 0;
    
    
    if (current_mode == MODE_BLOCK && 
        block_settings.syscall_type == BLOCK_OPEN &&
        block_settings.pid == current->pid) {
        pr_info("Blocked open syscall for process %d\n", current->pid);
        return -EPERM; // we return this error to block the syscall
    }
    
    //Log the syscall 
    if (current_mode == MODE_LOG) {
        if (strncpy_from_user(fname, filename, sizeof(fname) - 1) > 0) {
            write_log("[%d] Process '%s' called open('%s')\n", 
                   current->pid, current->comm, fname);
        } else {
            write_log("[%d] Process '%s' called open(invalid_path)\n", 
                   current->pid, current->comm);
        }
    }
    
    return 0;
}

// Read syscall pre-handler 
static int handler_pre_read(struct kprobe *p, struct pt_regs *regs)
{
    int fd = regs->di;
    size_t count = regs->dx;
    
    
    if (current_mode == MODE_OFF)
        return 0;
    
    if (current_mode == MODE_BLOCK && 
        block_settings.syscall_type == BLOCK_READ &&
        block_settings.pid == current->pid) {
        pr_info("Blocked read syscall for process %d\n", current->pid);
        return -EPERM; 
    }
    
    /* Log the syscall */
    if (current_mode == MODE_LOG) {
        write_log("[%d] Process '%s' called read(fd=%d, count=%zu)\n", 
               current->pid, current->comm, fd, count);
    }
    
    return 0;
}

// Write syscall pre-handler 
static int handler_pre_write(struct kprobe *p, struct pt_regs *regs)
{
    int fd = regs->di;
    size_t count = regs->dx;
    
    if (current_mode == MODE_OFF)
        return 0;
    
    if (current_mode == MODE_BLOCK && 
        block_settings.syscall_type == BLOCK_WRITE &&
        block_settings.pid == current->pid) {
        pr_info("Blocked write syscall for process %d\n", current->pid);
        return -EPERM; 
    }
    
    if (current_mode == MODE_LOG) {
        write_log("[%d] Process '%s' called write(fd=%d, count=%zu)\n", 
               current->pid, current->comm, fd, count);
    }
    
    return 0;
}

// IOCTL handler
static long device_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
    switch (cmd) {
        case IOCTL_SET_MODE:
        {
            int new_mode;
            if (copy_from_user(&new_mode, (int *)arg, sizeof(int)))
                return -EFAULT;
            
            if (new_mode < MODE_OFF || new_mode > MODE_BLOCK)
                return -EINVAL;
            
            current_mode = new_mode;
            pr_info("Syscall monitor mode changed to %d\n", new_mode);
            return 0;
        }
        
        case IOCTL_SET_BLOCK:
        {
            struct block_config config;
            
            if (copy_from_user(&config, (struct block_config *)arg, sizeof(struct block_config)))
                return -EFAULT;
            
            if (config.syscall_type < BLOCK_OPEN || config.syscall_type > BLOCK_WRITE)
                return -EINVAL;
            
            block_settings = config;
            pr_info("Block settings updated: PID=%d, Syscall=%d\n", 
                   config.pid, config.syscall_type);
            return 0;
        }
        
        default:
            return -ENOTTY;
    }
}

/* File operations for our device */
static const struct file_operations device_fops = {
    .owner = THIS_MODULE,
    .unlocked_ioctl = device_ioctl,
};

/* Device for IOCTL interface */
static struct miscdevice syscall_monitor_device = {
    .minor = MISC_DYNAMIC_MINOR,
    .name = "syscall_monitor",
    .fops = &device_fops,
};

/* Initialize the module */
static int __init syscall_monitor_init(void)
{
    int ret;
    
    // Create log file 
    log_file = filp_open(LOG_FILENAME, O_WRONLY | O_CREAT | O_APPEND, 0644);
    if (IS_ERR(log_file)) {
        pr_err("Failed to open log file\n");
        log_file = NULL;
        return PTR_ERR(log_file);
    }
    
    // Register device for ioctl 
    ret = misc_register(&syscall_monitor_device);
    if (ret) {
        pr_err("Failed to register misc device\n");
        filp_close(log_file, NULL);
        return ret;
    }
    
    // Register kprobe for open syscall 
    kp_open.symbol_name = "do_sys_open";
    kp_open.pre_handler = handler_pre_open;
    ret = register_kprobe(&kp_open);
    if (ret < 0) {
        pr_err("Failed to register kprobe for open syscall\n");
        goto fail_open;
    }
    
    // Register kprobe for read syscall 
    kp_read.symbol_name = "ksys_read";
    kp_read.pre_handler = handler_pre_read;
    ret = register_kprobe(&kp_read);
    if (ret < 0) {
        pr_err("Failed to register kprobe for read syscall\n");
        goto fail_read;
    }
    
    // Register kprobe for write syscall 
    kp_write.symbol_name = "ksys_write";
    kp_write.pre_handler = handler_pre_write;
    ret = register_kprobe(&kp_write);
    if (ret < 0) {
        pr_err("Failed to register kprobe for write syscall\n");
        goto fail_write;
    }
    
    pr_info("Syscall Monitor: Module loaded successfully\n");
    return 0;
    
fail_write:
    unregister_kprobe(&kp_read);
fail_read:
    unregister_kprobe(&kp_open);
fail_open:
    misc_deregister(&syscall_monitor_device);
    filp_close(log_file, NULL);
    return ret;
}

/* Cleanup the module */
static void __exit syscall_monitor_exit(void)
{
    unregister_kprobe(&kp_open);
    unregister_kprobe(&kp_read);
    unregister_kprobe(&kp_write);
    misc_deregister(&syscall_monitor_device);
    
    if (log_file)
        filp_close(log_file, NULL);
    
    pr_info("Syscall Monitor: Module unloaded\n");
}

module_init(syscall_monitor_init);
module_exit(syscall_monitor_exit);
