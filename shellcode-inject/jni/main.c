
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
    fflush(stdout);

    if(start_inject(pid, so_name) < 0){
        printf("[-] inject failed\n");
    }else{
        printf("[+] inject ok\n");
    }
    return 0;
}
