#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/socket.h>
#include <unistd.h>
#include <sys/ptrace.h>
#include <linux/un.h>
#include <errno.h>
#include <sys/mman.h>
#include <dlfcn.h>
#include <elf.h>

#include "inject.h"
#include "proc_tool.h"
#include "log_marco.h"

/**
 * is zygote process.
 */
static int is_zygote(pid_t pid)
{
    char* name = proc_get_process_name(pid);
    if(name == NULL) return -1;
    return strcmp(name, ZYGOTE_NAME);
}


/**
 * connect zygote.
 */
static int socket_zygote()
{
    int s = -1, len = 0;
    struct sockaddr_un un;

    sleep(1);

    if((s = socket(AF_UNIX, SOCK_STREAM, 0)) == -1) return -1;

    un.sun_family = AF_UNIX;
    strcpy(un.sun_path, "/dev/socket/zygote");
    len = strlen(un.sun_path) + offsetof(struct sockaddr_un, sun_path);
    if(connect(s, (struct sockaddr *) &un, len) == -1){
        close(s);
        return -1;
    }
    close(s);
    return 0;
}


/**
 * use PTRACE_ATTACH attach target process.
 */
static int ptrace_attach_process(pid_t pid)
{
    if (ptrace(PTRACE_ATTACH, pid, NULL, NULL) < 0) return -1;
    waitpid(pid, NULL, WUNTRACED);

    if(is_zygote(pid) == 0){
        if(socket_zygote() < 0) 
            return -1;
    }

    /**
     * use PTRACE_SYSCALL restart target process,
     * target process will stop at next syscall.
     */
    if (ptrace(PTRACE_SYSCALL, pid, NULL, 0) < 0) return -1;
    waitpid(pid, NULL, WUNTRACED);
    return 0;
}



/**
 * use PTRACE_GETREGS get regs value.
 */
static int ptrace_get_regs(pid_t pid, struct pt_regs* regs)
{
#if defined(__aarch64__)
    unsigned int expected_size;
    struct iovec iov;
    iov.iov_base = regs;
    iov.iov_len = expected_size = sizeof(struct pt_regs);
    if(ptrace(PTRACE_GETREGS, pid, (void*)NT_PRSTATUS, &iov) < 0) return -1;
    if (iov.iov_len != expected_size) return -1;
    return 0;
#endif

    if(ptrace(PTRACE_GETREGS, pid, NULL, regs) < 0) return -1;
    return 0;
}


/**
 * use PTRACE_SETREGS set regs value.
 */
static int ptrace_set_regs(pid_t pid, struct pt_regs* regs)
{
#if defined(__aarch64__)
    struct iovec iov;
    iov.iov_base = regs;
    iov.iov_len = sizeof(struct pt_regs);
    if(ptrace(PTRACE_SETREGS, pid, (void*)NT_PRSTATUS, &iov) < 0) return -1;
    return 0;
#endif
    if(ptrace(PTRACE_SETREGS, pid, NULL, regs) < 0) return -1;
    return 0;
}


/**
 * use PTRACE_CONT restart target process.
 */
static int ptrace_cont_process(pid_t pid)
{
    if(ptrace(PTRACE_CONT, pid, NULL, NULL) < 0) return -1;
    return 0;
}


/**
 * use PTRACE_DETACH detach target process.
 */
static int ptrace_detach_process(pid_t pid, struct pt_regs* regs)
{
    if(ptrace_set_regs(pid, regs) < 0) return -1;
    if(ptrace(PTRACE_DETACH, pid, NULL, NULL) < 0) return -1;
    return 0;
}


/**
 * use PTRACE_PEEKDATA remote read data.
 *  pid:  target process pid
 *  src:  target process addr
 *  dst:  buffer to save data
 *  size: need read data size
 */
static void remote_read_data(pid_t pid, void* src, void* dst, int size)
{
    int count = size / 4;
    int over_count = size % 4;
    int *dst_ptr = (int*)dst;
    int *src_ptr = (int*)src;
    char buf[4] = {0};

    for (int i = 0; i < count; i++) {
        *dst_ptr = ptrace(PTRACE_PEEKDATA, pid, (void*)(src_ptr), NULL);
        //check
        dst_ptr++;
        src_ptr++;
    }

    if(over_count > 0){
        *buf = ptrace(PTRACE_PEEKDATA, pid, (void*)(src_ptr), NULL);
        //check
        memcpy((void*)dst_ptr, (const void*)buf, over_count);
    }
}


/**
 * use PTRACE_POKEDATA remote write data.
 *  pid:  target process pid
 *  src:  target process addr
 *  dst:  the write data
 *  size: the write data size
 */
static int remote_write_data(pid_t pid, void* dst, void* src, int size)
{
    int count = size / 4;
    int over_count = size % 4;
    int *dst_ptr = (int*)dst;
    int *src_ptr = (int*)src;
    char buf[4] = {0};

    for (int i = 0; i < count; i++) {
        if (ptrace(PTRACE_POKEDATA, pid, (void*)(dst_ptr), *src_ptr) < 0) 
            return -1;
        dst_ptr++;
        src_ptr++;
    }

    if(over_count > 0){
        *buf = ptrace(PTRACE_PEEKDATA, pid, (void*)(dst_ptr), NULL);
        for(int i = 0; i < over_count; i++){
            buf[i] = *((char*)src_ptr + i);
        }

        if (ptrace(PTRACE_POKEDATA, pid, (void*)(dst_ptr), *buf) < 0)
            return -1;
    }
    return 0;
}


/**
 * remote write string
 */
static int remote_write_string(pid_t pid, void* dst, const char *str)
{
    return remote_write_data(pid, dst, (void*)str, 256);
}


/**
 * call target process fun
 *  pid         -> target process pid
 *  fun_addr    -> target process fun addr
 *  regs        -> register
 *  param_num   -> the param count
 *  ...
 */
static long remote_call_fun(pid_t pid, void* fun_addr, struct pt_regs* regs, int param_num, ...)
{
    struct pt_regs new_regs = *regs;
    new_regs.ARM_pc = (long)fun_addr & ~1;
    new_regs.ARM_lr = 0;
    va_list arglist;

    if ((long)fun_addr & 1) {
        new_regs.ARM_cpsr |= 0x20;   //thumb 0010 0000
    }
    else  {
        new_regs.ARM_cpsr &= ~0x20;  //arm   0000 0000
    }

#if defined(__aarch64__)
    va_start(arglist, param_num);
    if(param_num < 9){
        for(int i = 0; i < param_num; i++){
            new_regs.uregs[i] = va_arg(arglist, int);
        }
    }
    else{
        for(int i = 0; i < 8; i++){
            new_regs.uregs[i] = va_arg(arglist, int);
        }

        int stack_num = param_num - 8;
        new_regs.ARM_sp -= stack_num * 8;
        int n = 0;
        for(int i = 0; i < stack_num; i++){
            n = va_arg(arglist, int);
            if(remote_write_data(pid, (void*)(new_regs.ARM_sp + i * 8), (void*)&n, 8) < 0)
                return -1;
        }
    }
    va_end(arglist);
#else
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
            if(remote_write_data(pid, (void*)(new_regs.ARM_sp + i * 4), (void*)&n, 4) < 0)
                return -1;
        }
    }
    va_end(arglist);
#endif

    if(ptrace_set_regs(pid, &new_regs) < 0) return -1;
    if(ptrace_cont_process(pid) < 0) return -1;
    waitpid( pid, NULL, WUNTRACED);
    if(ptrace_get_regs(pid, &new_regs) < 0)return -1;
    return new_regs.ARM_r0;
}


/**
 * inject
 */
int start_inject(pid_t pid, const char *so_path){
    void* mmap_addr = NULL;
    void* mmap_result = NULL;
    void* dlopen_addr = NULL;
    void* handle = NULL;
    void* dlerror_addr = NULL;
    long  dlerror_data = 0;
    struct pt_regs old_regs = {0};
    struct pt_regs new_regs = {0};
    char errbuf[MAX_LENGTH] = {0};

#define fatal(fmt, args...) do {LOGE(fmt, ##args); goto ERR_EXIT;} while(0)

    //attach target process
    if(ptrace_attach_process(pid) < 0) {
        LOGE("[-] PTRACE_ATTACH FAILED:[%s]", strerror(errno));
        return -1;
    }
    LOGD("[+] PTRACE_ATTACH OK");

    if(ptrace_get_regs(pid, &old_regs) < 0) {
        LOGE("[-] PTRACE_GETREGS FAILED:[%s]", strerror(errno));
        return -1;
    }
    LOGD("[+] PTRACE_GETREGS OK");
    new_regs = old_regs;

    // get target process mmap addr
    mmap_addr = proc_get_remote_fun_addr(pid, "libc.so", (void*)mmap);
    if(mmap_addr == NULL) 
        fatal("[-] GET_MMAP_FUN FAILED");
    LOGD("[+] MMAP_FUN = %p", mmap_addr);
    mmap_result = (void*)remote_call_fun(pid, mmap_addr, &new_regs, 6,
                                 NULL,
                                 0x1000,
                                 PROT_EXEC | PROT_READ | PROT_WRITE,
                                 MAP_PRIVATE  | MAP_ANONYMOUS,
                                 0,
                                 0);
    if(mmap_result == MAP_FAILED) 
        fatal("[-] REMOTE_CALL_MMAP FAILED:[%s]", strerror(errno));
    LOGD("[+] MMAP_RESULT = %p", mmap_result);

    //write inject_so path
    if(remote_write_string(pid, mmap_result, so_path) < 0) 
        fatal("[-] REMOTE_WRITE FAILED:[%s]", strerror(errno));
    LOGD("[+] REMOTE_WRITE OK");

    /**
     * get dlopen addr
     *  ANDROID 10.0  /libdl.so -> dlopen
     * */
    dlopen_addr = proc_get_remote_fun_addr(pid, "/libdl.so", (void*)dlopen);
    if(dlopen_addr == NULL) 
        fatal("[-] GET_DLOPEN_FUN FAILED");
    LOGD("[+] DLOPEN_FUN = %p", dlopen_addr);
    handle = (void*)remote_call_fun(pid, dlopen_addr, &new_regs, 2, mmap_result, RTLD_NOW);

    if(handle == NULL){
        //if dlopen failed, get dlerror
        dlerror_addr = proc_get_remote_fun_addr(pid, "/libdl.so", (void*)dlerror);
        if(dlerror_addr == NULL) 
            fatal("[-] GET_DLERROR_FUN FAILED");
        LOGD("[+] DLERROR_FUN = %p", dlerror_addr);

        dlerror_data = remote_call_fun(pid, dlerror_addr, &new_regs, 0);
        if(dlerror_data <= 0) 
            fatal("[-] REMOTE_CALL_DLERROR FAILED");
        remote_read_data(pid, (void*)dlerror_data, (void*)errbuf, MAX_LENGTH);
        LOGD("[+] DLERROR_RESULT = %s", errbuf);
        
    }else{
        LOGD("[+] DLOPEN_RESULT = %p", handle);
    }
    
#undef fatal    
    if(ptrace_detach_process(pid, &old_regs) < 0) return -1;
    return 0;

ERR_EXIT:
    if(ptrace_detach_process(pid, &old_regs) < 0) return -1;
    return -1;
}
