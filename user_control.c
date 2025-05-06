#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <string.h>

#define MODE_OFF  0
#define MODE_LOG  1
#define MODE_BLOCK 2

#define BLOCK_OPEN  1
#define BLOCK_READ  2
#define BLOCK_WRITE 3

#define SYSCALL_MON_MAGIC 'k'
#define IOCTL_SET_MODE     _IOW(SYSCALL_MON_MAGIC, 1, int)
#define IOCTL_SET_BLOCK    _IOW(SYSCALL_MON_MAGIC, 2, struct block_config)

struct block_config {
    pid_t pid;           
    int syscall_type;    
};

void print_usage(const char *progname) {
    printf("Usage:\n");
    printf("  %s mode [off|log|block]\n", progname);
    printf("  %s block <pid> <syscall>\n", progname);
    printf("\nWhere:\n");
    printf("  mode: Set the operation mode\n");
    printf("  block: Configure which process and syscall to block\n");
    printf("  <pid>: Process ID to block\n");
    printf("  <syscall>: System call to block (open, read, or write)\n");
}

int main(int argc, char *argv[]) {
    int fd;
    
    // Open the device 
    fd = open("/dev/syscall_monitor", O_RDWR);
    if (fd < 0) {
        perror("Failed to open device");
        return 1;
    }
    
    if (argc < 2) {
        print_usage(argv[0]);
        close(fd);
        return 1;
    }
    
    //  'mode' command 
    if (strcmp(argv[1], "mode") == 0) {
        int mode;
        
        if (argc < 3) {
            print_usage(argv[0]);
            close(fd);
            return 1;
        }
        
        if (strcmp(argv[2], "off") == 0) {
            mode = MODE_OFF;
        } else if (strcmp(argv[2], "log") == 0) {
            mode = MODE_LOG;
        } else if (strcmp(argv[2], "block") == 0) {
            mode = MODE_BLOCK;
        } else {
            printf("Invalid mode: %s\n", argv[2]);
            print_usage(argv[0]);
            close(fd);
            return 1;
        }
        
        if (ioctl(fd, IOCTL_SET_MODE, &mode) < 0) {
            perror("IOCTL failed");
            close(fd);
            return 1;
        }
        
        printf("Mode set to %s\n", argv[2]);
    }
    //'block' command 
    else if (strcmp(argv[1], "block") == 0) {
        struct block_config config;
        
        if (argc < 4) {
            print_usage(argv[0]);
            close(fd);
            return 1;
        }
        
        // Get PID 
        config.pid = atoi(argv[2]);
        if (config.pid <= 0) {
            printf("Invalid PID: %s\n", argv[2]);
            close(fd);
            return 1;
        }
        
        //Get syscall type 
        if (strcmp(argv[3], "open") == 0) {
            config.syscall_type = BLOCK_OPEN;
        } else if (strcmp(argv[3], "read") == 0) {
            config.syscall_type = BLOCK_READ;
        } else if (strcmp(argv[3], "write") == 0) {
            config.syscall_type = BLOCK_WRITE;
        } else {
            printf("Invalid syscall: %s\n", argv[3]);
            print_usage(argv[0]);
            close(fd);
            return 1;
        }
        
        if (ioctl(fd, IOCTL_SET_BLOCK, &config) < 0) {
            perror("IOCTL failed");
            close(fd);
            return 1;
        }
        
        printf("Blocking %s syscall for PID %d\n", argv[3], config.pid);
    }
    else {
        print_usage(argv[0]);
        close(fd);
        return 1;
    }
    
    close(fd);
    return 0;
}
