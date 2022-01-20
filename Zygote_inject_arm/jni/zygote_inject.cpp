

#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/mman.h>
#include <dlfcn.h>
#include <string.h>
#include <asm/ptrace.h>
#include <linux/un.h>


/**
 * connect zygote.
 */
static int socketZygote(){
    int s, len;
    struct sockaddr_un un;

    printf("[+] sleep 2s...\n");
    sleep(2);

    if((s = socket(AF_UNIX, SOCK_STREAM, 0)) == -1){
        printf("[-] socket failed\n");
        return -1;
    }
    un.sun_family = AF_UNIX;
    strcpy(un.sun_path, "/dev/socket/zygote");
    len = strlen(un.sun_path) + offsetof(sockaddr_un, sun_path);
    printf("[+] start connect zygote socket\n");

    if(connect(s, (struct sockaddr *) &un, len) == -1){
        printf("[-] connect failed\n");
        return -1;
    }
    printf("[+] close socket\n");
    close(s);
    return 0;
}

/**
 * get target process name.
 */
const char* getProcessName(pid_t pid) {
    static char buffer[255];
    FILE* f;
    char path[255];

    snprintf(path, sizeof(path), "/proc/%d/cmdline", pid);
    if((f = fopen(path, "r")) == NULL){
        return NULL;
    }

    if(fgets(buffer, sizeof(buffer), f) == NULL){
        return NULL;
    }

    fclose(f);
    return buffer;
}


/**
 * if zygote process.
 */
static int isZygote(pid_t pid){
    const char* name = getProcessName(pid);
    if(name == NULL){
        return -1;
    }
    return strcmp(name, "zygote");
}


/**
 * show register data.
 */
static void show_regs(pt_regs* regs) {
    for (int i = 0; i < 17; i++) {
        if (i == 13) {
            printf("SP=%08lX ", regs->uregs[i]);
            continue;
        }
        if (i == 14) {
            printf("LR=%08lX ", regs->uregs[i]);
            continue;
        }
        if (i == 15) {
            printf("PC=%08lX ", regs->uregs[i]);
            continue;
        }
        if (i == 16) {
            printf("CPSR=%08lX ", regs->uregs[i]);
            continue;
        }

        printf("R%d=%08lX ", i, regs->uregs[i]);
        if ((i + 1) % 8 == 0) {
            printf("\n");
        }
    }
    printf("\n");
}


/**
 * use PTRACE_ATTACH attach target process.
 */
static int ptraceAttach(pid_t pid){
    if (ptrace(PTRACE_ATTACH, pid, NULL, NULL) < 0) {
        perror("[-] PTRACE_ATTACH");
        return -1;
    }
    waitpid(pid, NULL, WUNTRACED);


    if(isZygote(pid) == 0){
        if(socketZygote() < 0){
            return -1;
        }
    }

    /**
     * use PTRACE_SYSCALL restart target process,
     * target process will stop at next syscall.
     */
    if (ptrace(PTRACE_SYSCALL, pid, NULL, 0) < 0){
        perror( "[-] PTRACE_SYSCALL");
        return -1;
    }
    waitpid( pid, NULL, WUNTRACED);

    return 0;
}


/**
 * use PTRACE_GETREGS get regs value.
 */
static int ptraceGetRegs(pid_t pid, pt_regs* regs){
    if (ptrace(PTRACE_GETREGS, pid, NULL, regs) < 0) {
        perror("[-] PTRACE_GETREGS");
        return -1;
    }
    return 0;
}


/**
 * use PTRACE_SETREGS set regs value.
 */
static int ptraceSetRegs(pid_t pid, pt_regs* regs){
    if (ptrace(PTRACE_SETREGS, pid, NULL, regs) < 0) {
        perror("[-] PTRACE_SETREGS");
        return -1;
    }
    return 0;
}


/**
 * use PTRACE_CONT restart target process.
 */
static int ptraceCont(pid_t pid){
    if (ptrace(PTRACE_CONT, pid, NULL, NULL) < 0) {
        perror("[-] PTRACE_CONT");
        return -1;
    }
    return 0;
}


/**
 * use PTRACE_DETACH detach target process.
 */
static int ptraceDetach(pid_t pid, pt_regs* regs){
    if(ptraceSetRegs(pid, regs) < 0){
        return -1;
    }

    if (ptrace(PTRACE_DETACH, pid, NULL, NULL) < 0) {
        perror("[-] PTRACE_DETACH");
        return -1;
    }
    return 0;
}


/**
 * get ModuleBase from /proc/pid/maps
 *  pid  = -1, get self
 *  pid != -1, get target process
 *  module_name --> module name
 */
static void* getModuleBase(pid_t pid, const char* module_name){
    char buf[260];
    if (pid == -1) {
        sprintf(buf, "/proc/self/maps");
    }
    else {
        sprintf(buf, "/proc/%d/maps", pid);
    }

    FILE *fp = fopen(buf, "r");
    if(fp == NULL){
        return  NULL;
    }

    void* address = NULL;
    while(!feof(fp)) {
        fgets(buf, sizeof(buf), fp);
        if (strstr(buf, module_name) != NULL) {
            sscanf(buf, "%p", &address);
            break;
        }
    }
    fclose(fp);
    return address;
}


/**
 * get target process fun addr
 *  pid --> target process pid
 *  module_name --> target module name
 *  local_addr --> local fun addr
 */
static void* getRemoteFunAddr(pid_t pid, const char* module_name, void* local_addr){
    void* local_module_base = getModuleBase(-1, module_name);
    if(local_module_base == NULL){
        printf("[-] get local_module_base failed\n");
        return NULL;
    }

    void* remote_module_base = getModuleBase(pid, module_name);
    if(remote_module_base == NULL){
        printf("[-] get remote_module_base failed\n");
        return NULL;
    }
    char* remote_addr = (char*)remote_module_base + ((char*)local_addr - (char*)local_module_base);
    return (void*)remote_addr;
}


/**
 * remote read data
 *  pid --> target process pid
 *  dst --> target process addr
 *  data --> buffer to save data
 *  size --> data size
 */
static int remoteReadData(pid_t pid, void* dst, void* data, int size){
    int count = size / 4;
    int over_count = size % 4;
    int *data_point = (int*)data;
    int *dst_point = (int*)dst;
    char buf[4] = {0};

    for (int i = 0; i < count; i++) {
        *data_point = ptrace(PTRACE_PEEKDATA, pid, (void*)(dst_point), NULL);
        data_point++;
        dst_point++;
    }

    if(over_count > 0){
        *buf = ptrace(PTRACE_PEEKDATA, pid, (void*)(dst_point), NULL);
        memcpy((void*)data_point, (const void*)buf, over_count);
    }
    return 0;
}


/**
 * remote write data
 *  pid --> target process pid
 *  dst --> target process addr
 *  data --> the write data
 *  size --> data size
 */
static int remoteWriteData(pid_t pid, void* dst, void* data, int size){
    int count = size / 4;
    int over_count = size % 4;
    int *dst_point = (int*)dst;
    int *src_point = (int*)data;
    char buf[4] = {0};

    for (int i = 0; i < count; i++) {

        if (ptrace(PTRACE_POKEDATA, pid, (void*)(dst_point), *src_point) < 0) {
            perror("[-] PTRACE_POKEDATA");
            return -1;
        }
        src_point++;
        dst_point++;
    }

    if(over_count > 0){
        *buf = ptrace(PTRACE_PEEKDATA, pid, (void*)(dst_point), NULL);
        for(int i = 0; i < over_count; i++){
            buf[i] = *((char*)src_point + i);
        }

        if (ptrace(PTRACE_POKEDATA, pid, (void*)(dst_point), *buf) < 0) {
            perror("[-] PTRACE_POKEDATA");
            return -1;
        }
    }
    return 0;
}


/**
 * remote write string
 */
static int remoteWriteString(pid_t pid, void* dst, const char *str)
{
    return remoteWriteData(pid, dst, (void*)str, strlen(str)+1);
}


/**
 * call target process fun
 *  pid --> target process pid
 *  remote_addr --> target process fun addr
 *  regs --> register
 *  param_num --> the param count
 *  ...
 */
static int callRemoteFun(pid_t pid, void* remote_addr, pt_regs* regs, int param_num, ...){
    pt_regs new_regs = *regs;
    new_regs.ARM_pc = (long)remote_addr & ~1;
    new_regs.ARM_lr = 0;
    va_list arglist;

    if ((long)remote_addr & 1) {
        new_regs.ARM_cpsr |=  0x20;   //thumb
    }
    else  {
        new_regs.ARM_cpsr &=  ~0x20;   //arm
    }

    va_start(arglist, param_num);
    if(param_num < 5){
        for(int i = 0; i < param_num; i++){
            new_regs.uregs[i] = va_arg(arglist, int);
        }
    }
    else{
        for(int i = 0; i < 4; i++){
            new_regs.uregs[i] = va_arg(arglist, int);
        }

        int stack_num = param_num - 4;
        new_regs.ARM_sp -= stack_num * 4;
        int n = 0;
        for(int i = 0; i < stack_num; i++){
            n = va_arg(arglist, int);
            if(remoteWriteData(pid, (void*)(new_regs.ARM_sp + i * 4), (void*)&n, 4) < 0){
                printf("[-] remoteWriteData failed\n");
                return -1;
            }
        }
    }
    va_end(arglist);

    if(ptraceSetRegs(pid, &new_regs) < 0){
        return -1;
    }

    if(ptraceGetRegs(pid, &new_regs) < 0){
        return -1;
    }
    puts("[+] new regs: ");
    show_regs(&new_regs);

    if(ptraceCont(pid) < 0){
        return -1;
    }
    return 0;
}


/**
 * get Remote Fun Result
 *  r0 save result
 */
static long getRemoteFunResult(pid_t pid){
    pt_regs regs;
    if (ptrace(PTRACE_GETREGS, pid, NULL, &regs) < 0) {
        perror("[-] PTRACE_GETREGS");
        return -1;
    }
    return regs.ARM_r0;
}


/**
 * inject
 */
static int injectRemoteProcess(pid_t pid){
    //attach target process
    if(ptraceAttach(pid) < 0){
        return -1;
    }
    printf("[+] PTRACE_ATTACH OK\n");

    //get regs for save environment
    pt_regs old_regs;
    if(ptraceGetRegs(pid, &old_regs) < 0){
        return -1;
    }

    puts("[+] old regs: ");
    show_regs(&old_regs);
    pt_regs new_regs = old_regs;

    // get target process mmap addr
    void* mmap_addr = getRemoteFunAddr(pid, "libc.so", (void*)mmap);
    if(mmap_addr == NULL){
        printf("[-] getRemoteFunAddr mmap failed\n");
        return -1;
    }
    printf("[+] mmap_addr = %p\n", mmap_addr);


    // callRemoteFun mmap
    if(callRemoteFun(pid, mmap_addr, &new_regs, 6,
                     NULL,
                     0x1000,
                     PROT_EXEC | PROT_READ | PROT_WRITE,
                     MAP_PRIVATE  | MAP_ANONYMOUS,
                     0,
                     0) < 0){
        printf("[-] callRemoteFun mmap failed\n");
        return -1;
    }

    waitpid(pid, NULL, WUNTRACED);


    //get mmap result
    void* mmap_result = (void*)getRemoteFunResult(pid);
    if(mmap_result == NULL){
        printf("[-] getRemoteFunAddr dlopen failed\n");
        return -1;
    }
    printf("[+] mmap_result=%p\n", mmap_result);

    //write inject_so path
    char path[100] = {"/data/local/tmp/libInject.so"};
    remoteWriteString(pid, mmap_result, path);

    //TEST
//    char path2[100] = {0};
//    remoteReadData(pid, mmap_result, path2, sizeof(path2));
//    printf("[+] path2=%s\n", path2);

    /**
     * get dlopen addr
     *  ANDROID 10.0  /libdl.so --> dlopen
     * */
    void* dlopen_addr = getRemoteFunAddr(pid, "/libdl.so", (void*)dlopen);
    if(dlopen_addr == NULL){
        printf("[-] getRemoteFunAddr dlopen failed\n");
        return -1;
    }
    printf("[+] dlopen_addr=%p\n", dlopen_addr);

    // callRemoteFun dlopen
    if(callRemoteFun(pid, dlopen_addr, &new_regs, 2,
                     mmap_result,
                     RTLD_NOW) < 0){
        printf("[-] callRemoteFun dlopen failed\n");
        return -1;
    }

    waitpid(pid, NULL, WUNTRACED);

    //get dlopen result
    void* handle = (void*)getRemoteFunResult(pid);
    printf("[+] dlopen handle=%p\n", handle);


    //detach
    if(ptraceDetach(pid, &old_regs) < 0){
        return -1;
    }

    return 0;
}



int main(int argc, char* argv[]){
    pid_t pid = 0;
    if(argc < 2){
        printf("[-] missing command line arguments.\n");
        return 0;
    }

    pid = atoi(argv[1]);
    printf("[+] start inject %d process\n", pid);

    system("su -c setenforce 0");
    if(injectRemoteProcess(pid) < 0){
        printf("[-] inject failed\n");
    } else{
        printf("[+] complete inject %d process\n", pid);
    }
    return 0;
}