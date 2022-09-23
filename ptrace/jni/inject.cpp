
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dlfcn.h>
#include <sys/mman.h>
#include <unistd.h>
#include <sys/types.h>

#include "ptrace_utils.h"


/**
 * inject
 */
static int Inject(pid_t pid, const char *so_path){
    void* mmap_addr = NULL;
    void* mmap_result = NULL;
    void* dlopen_addr = NULL;
    void* handle = NULL;
    void* dlerror_addr = NULL;
    long dlerror_data = 0;
    pt_regs old_regs = {0};
    pt_regs new_regs = {0};
    char errbuf[100] = {0};

    //attach target process
    if(AttachProcess(pid) < 0){
        return -1;
    }
    printf("[+] PTRACE_ATTACH OK\n");

    if(GetRegs(pid, &old_regs) < 0){
        return -1;
    }
    new_regs = old_regs;

    // get target process mmap addr
    mmap_addr = GetRemoteFunAddr(pid, "libc.so", (void*)mmap);
    if(mmap_addr == NULL){
        printf("[-] getRemoteFunAddr mmap failed\n");
        return -1;
    }
    printf("[+] mmap_addr = %p\n", mmap_addr);
    mmap_result = (void*)CallRemoteFun(pid, mmap_addr, &new_regs, 6,
                                 NULL,
                                 0x1000,
                                 PROT_EXEC | PROT_READ | PROT_WRITE,
                                 MAP_PRIVATE  | MAP_ANONYMOUS,
                                 0,
                                 0);
    if(mmap_result == NULL){
        printf("[-] get mmap result failed\n");
        return -1;
    }
    printf("[+] mmap_result=%p\n", mmap_result);


    //write inject_so path
    if(RemoteWriteString(pid, mmap_result, so_path) < 0){
        printf("[-] write inject so path failed\n");
        return -1;
    }
    printf("[+] write inject_so path OK\n");

    /**
     * get dlopen addr
     *  ANDROID 10.0  /libdl.so --> dlopen
     * */
    dlopen_addr = GetRemoteFunAddr(pid, "/libdl.so", (void*)dlopen);
    if(dlopen_addr == NULL){
        printf("[-] getRemoteFunAddr dlopen failed\n");
        return -1;
    }
    printf("[+] dlopen_addr=%p\n", dlopen_addr);
    handle = (void*)CallRemoteFun(pid, dlopen_addr, &new_regs, 2, mmap_result, RTLD_NOW);
    if(handle == 0){
        //if dlopen failed, get dlerror
        dlerror_addr = GetRemoteFunAddr(pid, "/libdl.so", (void*)dlerror);
        if(dlerror_addr == NULL){
            printf("[-] getRemoteFunAddr dlerror failed\n");
            return -1;
        }
        printf("[-] dlerror_addr=%p\n", dlerror_addr);

        dlerror_data = CallRemoteFun(pid, dlerror_addr, &new_regs, 0);
        if(dlerror_data  == 0){
            printf("[-] getRemoteFunResult dlerror failed\n");
            return -1;
        }
        printf("[-] dlerror_data=%lx\n", dlerror_data);

        RemoteReadData(pid, (void*)dlerror_data, (void*)errbuf, 100);
        printf("[-] dlerror = %s\n", errbuf);
        
    }else{
        printf("[+] dlopen handle=%p\n", handle);
    }
    

EXIT:
    if(DetachProcess(pid, &old_regs) < 0){
        return -1;
    }
    return 0;
}



int main(int argc, char* argv[]){
    pid_t pid = 0;
    char* so_name = NULL;
    if(argc < 3){
        printf("[-] missing command line arguments.\n");
        return 0;
    }

    pid = atoi(argv[1]);
    so_name = argv[2];
    printf("[+] start inject [%s] to [pid:%d] process\n", so_name, pid);

    system("su -c setenforce 0");

    if(Inject(pid, so_name) < 0){
        printf("[-] inject failed\n");
    } else{
        printf("[+] inject [%s] to [pid:%d] process ok!\n", so_name, pid);
    }
    return 0;
}
