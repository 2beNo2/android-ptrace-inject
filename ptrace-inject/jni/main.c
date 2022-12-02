
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dlfcn.h>
#include <sys/mman.h>
#include <unistd.h>
#include <sys/types.h>

#include "proc_tool.h"
#include "inject.h"


int main(int argc, char* argv[])
{
    pid_t pid = 0;
    char* so_name = NULL;
    char cmd[256] = {0};
    if(argc < 3){
        printf("[-] missing command line arguments.\n");
        return 0;
    }

    pid = atoi(argv[1]);
    so_name = argv[2];
    printf("[+] start inject [%s] to [pid:%d] process\n", so_name, pid);

#if defined(__aarch64__)
    system("su -c setenforce 0");
    system("mount -o rw,remount /");
    system("mount -o rw,remount /system");
    snprintf(cmd, sizeof(cmd), "cp %s /system/lib64/libtest.so", so_name);
    system(cmd);
    system("chmod 777 /system/lib64/libtest.so");
    system("chcon u:object_r:system_file:s0 /system/lib64/libtest.so");

    if(start_inject(pid, so_name) < 0){
        printf("[-] inject failed\n");
    }else{
        printf("[+] inject ok\n");
    }

#else
    if(start_inject(pid, so_name) < 0){
        printf("[-] inject failed\n");
    }else{
        printf("[+] inject ok\n");
    }
#endif
    fflush(stdout);
    return 0;
}
