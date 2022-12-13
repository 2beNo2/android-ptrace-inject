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
#else
    if(ptrace(PTRACE_GETREGS, pid, NULL, regs) < 0) return -1;
    return 0;
#endif
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
#else
    if(ptrace(PTRACE_SETREGS, pid, NULL, regs) < 0) return -1;
    return 0;
#endif
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
            new_regs.uregs[i] = va_arg(arglist, long);
        }
    }
    else{
        for(int i = 0; i < 8; i++){
            new_regs.uregs[i] = va_arg(arglist, long);
        }

        int stack_num = param_num - 8;
        new_regs.ARM_sp -= stack_num * 8;
        int n = 0;
        for(int i = 0; i < stack_num; i++){
            n = va_arg(arglist, long);
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


unsigned int shell_code_arm[] = 
{
    0xe59f0040, //0   +0    ldr  r0, [pc, #64]   ; 48 <.text+0x48>
    0xe3a01000, //1   +4    mov  r1, #0  ; 0x0
    0xe1a0e00f, //2   +8    mov  lr, pc
    0xe59ff038, //3   +c    ldr  pc, [pc, #56]   ; 4c <.text+0x4c>
    0xe59fd02c, //4   +10   ldr  sp, [pc, #44]   ; 44 <.text+0x44>
    0xe59f0010, //5   +14   ldr  r0, [pc, #16]   ; 30 <.text+0x30>
    0xe59f1010, //6   +18   ldr  r1, [pc, #16]   ; 34 <.text+0x34>
    0xe59f2010, //7   +1c   ldr  r2, [pc, #16]   ; 38 <.text+0x38>
    0xe59f3010, //8   +20   ldr  r3, [pc, #16]   ; 3c <.text+0x3c>
    0xe59fe010, //9   +24   ldr  lr, [pc, #16]   ; 40 <.text+0x40>
    0xe59ff010, //10  +28   ldr  pc, [pc, #16]   ; 44 <.text+0x44>
    0xe1a00000, //11  +2c   nop                  r0
    0xe1a00000, //12  +30   nop                  r1 
    0xe1a00000, //13  +34   nop                  r2 
    0xe1a00000, //14  +38   nop                  r3 
    0xe1a00000, //15  +3c   nop                  lr 
    0xe1a00000, //16  +40   nop                  pc
    0xe1a00000, //17  +44   nop                  sp
    0xe1a00000, //18  +48   nop                  addr of libname
    0xe1a00000, //19  +4c   nop                  dlopenaddr
};


/**
 * inject
 */
int start_inject(pid_t pid, const char *so_path)
{
    void* dlopen_addr = NULL;
    void* mprotect_addr = NULL;
    void* sopath_addr = NULL;
    size_t inject_path_len = 0;
    struct pt_regs old_regs = {0};
    struct pt_regs new_regs = {0};


#define fatal(fmt, args...) do {printf(fmt, ##args); goto ERR_EXIT;} while(0)

    //attach target process
    if(ptrace_attach_process(pid) < 0) {
        printf("[-] PTRACE_ATTACH FAILED:[%s]\n", strerror(errno));
        return -1;
    }
    printf("[+] PTRACE_ATTACH OK\n");

    if(ptrace_get_regs(pid, &old_regs) < 0) {
        printf("[-] PTRACE_GETREGS FAILED:[%s]\n", strerror(errno));
        return -1;
    }
    printf("[+] PTRACE_GETREGS OK\n");
    new_regs = old_regs;

	printf("pc=%p lr=%p sp=%p fp=%p\n", old_regs.ARM_pc, old_regs.ARM_lr, old_regs.ARM_sp, old_regs.ARM_cpsr);
    /**
     * get dlopen addr
     *  ANDROID 10.0  /libdl.so -> dlopen
     * */
    dlopen_addr = proc_get_remote_fun_addr(pid, "/libdl.so", (void*)dlopen);
    if(dlopen_addr == NULL) 
        fatal("[-] GET_DLOPEN_FUN FAILED\n");
    printf("[+] DLOPEN_FUN = %p\n", dlopen_addr);
    
    //get mprotect addr
    mprotect_addr = proc_get_remote_fun_addr(pid, "/libc.so", (void*)mprotect);
    if(mprotect_addr == NULL) 
        fatal("[-] GET_MPROTECT_FUN FAILED\n");
    printf("[+] MPROTECT_FUN = %p\n", mprotect_addr);

	shell_code_arm[11] = new_regs.uregs[0];
	shell_code_arm[12] = new_regs.uregs[1];
	shell_code_arm[13] = new_regs.uregs[2];
	shell_code_arm[14] = new_regs.uregs[3];
	shell_code_arm[15] = new_regs.ARM_lr;
	shell_code_arm[16] = new_regs.ARM_pc;
	shell_code_arm[17] = new_regs.ARM_sp;
	shell_code_arm[19] = (size_t)dlopen_addr; // ldr fix T

    inject_path_len = strlen(so_path) + 1;
    inject_path_len = inject_path_len / 4 + (inject_path_len % 4 ? 1 : 0);
	sopath_addr = (void*)(new_regs.ARM_sp - (inject_path_len * 4) - sizeof(shell_code_arm));
	shell_code_arm[18] = (size_t)sopath_addr;	

    // printf("old_regs.ARM_lr=%p\n", old_regs.ARM_lr);
    // printf("old_regs.ARM_pc=%p\n", old_regs.ARM_pc);
    // printf("old_regs.ARM_sp=%p\n", old_regs.ARM_sp);
    // printf("old_regs.ARM_cpsr=%p\n", old_regs.ARM_cpsr);
    // for (size_t i = 0; i < sizeof(shell_code_arm) / sizeof(shell_code_arm[0]); i++)
    // {
    //    printf("pc=%p\n", shell_code_arm[i]);
    // }
    // printf("codeaddr=%p\n", (new_regs.ARM_sp - sizeof(shell_code_arm)));

    //write inject_so path
    if(remote_write_data(pid, sopath_addr, (void*)so_path, strlen(so_path) + 1) < 0) 
        fatal("[-] REMOTE_WRITE_PATH FAILED:[%s]\n", strerror(errno));
    printf("[+] REMOTE_WRITE_PATH OK\n");

	//write code to stack
    if(remote_write_data(pid, (void*)(new_regs.ARM_sp - sizeof(shell_code_arm)), (void*)shell_code_arm, sizeof(shell_code_arm)) < 0) 
        fatal("[-] REMOTE_WRITE_CODE FAILED:[%s]\n", strerror(errno));
    printf("[+] REMOTE_WRITE_CODE OK\n");

    // 调用mprotect返回-1，待处理
    new_regs.uregs[0] = (size_t)PAGE_START(new_regs.ARM_sp - sizeof(shell_code_arm));
    new_regs.uregs[1] = 0x1000;
    new_regs.uregs[2] = PROT_READ | PROT_WRITE | PROT_EXEC; 
    //new_regs.ARM_lr = (size_t)(new_regs.ARM_sp - sizeof(shell_code_arm)); // arm ? thumb ? 
    new_regs.ARM_lr = old_regs.ARM_pc;
    new_regs.ARM_pc = (size_t)mprotect_addr & ~1; // arm ? thumb ? 
    if ((size_t)mprotect_addr & 1) {
        new_regs.ARM_cpsr |= 0x20;   //thumb 0010 0000
    }
    else  {
        new_regs.ARM_cpsr &= ~0x20;  //arm   0000 0000
    }

    // printf("new_regs.ARM_1=%p\n", new_regs.uregs[0]);
    // printf("new_regs.ARM_2=%p\n", new_regs.uregs[1]);
    // printf("new_regs.ARM_3=%p\n", new_regs.uregs[2]);
    // printf("new_regs.ARM_lr=%p\n", new_regs.ARM_lr);
    // printf("new_regs.ARM_pc=%p\n", new_regs.ARM_pc);

#undef fatal    
    if(ptrace_detach_process(pid, &old_regs) < 0) return -1;
    return 0;

ERR_EXIT:
    if(ptrace_detach_process(pid, &old_regs) < 0) return -1;
    return -1;
}
