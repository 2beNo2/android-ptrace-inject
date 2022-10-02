
#ifndef PTRACE_UTILS_H
#define PTRACE_UTILS_H

#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/socket.h>
#include <unistd.h>
#include <sys/ptrace.h>
#include <asm/ptrace.h>
#include <linux/un.h>

#include "inject_utils.h"

#if defined(__LP64__)
#define PTRACE_GETREGS PTRACE_GETREGSET
#define PTRACE_SETREGS PTRACE_SETREGSET
#define pt_regs  user_pt_regs
#define uregs    regs
#define ARM_pc   pc
#define ARM_sp   sp
#define ARM_cpsr pstate
#define ARM_lr   regs[30]
#define ARM_r0   regs[0]
#endif

/**
 * is zygote process.
 */
static int isZygote(pid_t pid){
    const char* name = GetProcessName(pid);
    if(name == NULL){
        return -1;
    }
    return strcmp(name, "zygote");
}


/**
 * connect zygote.
 */
static int socketZygote(){
    int s = -1, len = 0;
    struct sockaddr_un un;

    sleep(2);

    if((s = socket(AF_UNIX, SOCK_STREAM, 0)) == -1){
        perror("[-] socket");
        return -1;
    }

    un.sun_family = AF_UNIX;
    strcpy(un.sun_path, "/dev/socket/zygote");
    len = strlen(un.sun_path) + offsetof(sockaddr_un, sun_path);
    if(connect(s, (struct sockaddr *) &un, len) == -1){
        perror("[-] connect");
        return -1;
    }
    close(s);
    return 0;
}


/**
 * use PTRACE_ATTACH attach target process.
 */
static int AttachProcess(pid_t pid){
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
static int GetRegs(pid_t pid, pt_regs* regs){
    if (ptrace(PTRACE_GETREGS, pid, NULL, regs) < 0) {
        perror("[-] PTRACE_GETREGS");
        return -1;
    }
    return 0;
}


/**
 * use PTRACE_SETREGS set regs value.
 */
static int SetRegs(pid_t pid, pt_regs* regs){
    if (ptrace(PTRACE_SETREGS, pid, NULL, regs) < 0) {
        perror("[-] PTRACE_SETREGS");
        return -1;
    }
    return 0;
}


/**
 * use PTRACE_CONT restart target process.
 */
static int ContProcess(pid_t pid){
    if (ptrace(PTRACE_CONT, pid, NULL, NULL) < 0) {
        perror("[-] PTRACE_CONT");
        return -1;
    }
    return 0;
}


/**
 * use PTRACE_DETACH detach target process.
 */
static int DetachProcess(pid_t pid, pt_regs* regs){
    if(SetRegs(pid, regs) < 0){
        return -1;
    }

    if (ptrace(PTRACE_DETACH, pid, NULL, NULL) < 0) {
        perror("[-] PTRACE_DETACH");
        return -1;
    }
    return 0;
}


/**
 * use PTRACE_PEEKDATA remote read data.
 *  pid:  target process pid
 *  dst:  target process addr
 *  data: buffer to save data
 *  size: data size
 */
static int RemoteReadData(pid_t pid, void* dst, void* data, int size){
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
 * use PTRACE_POKEDATA remote write data.
 *  pid:  target process pid
 *  dst:  target process addr
 *  data: the write data
 *  size: data size
 */
static int RemoteWriteData(pid_t pid, void* dst, void* data, int size){
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
        dst_point++;
        src_point++;
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
static int RemoteWriteString(pid_t pid, void* dst, const char *str)
{
    return RemoteWriteData(pid, dst, (void*)str, 256);
}


/**
 * call target process fun
 *  pid         -> target process pid
 *  fun_addr    -> target process fun addr
 *  regs        -> register
 *  param_num   -> the param count
 *  ...
 */
static long CallRemoteFun(pid_t pid, void* fun_addr, pt_regs* regs, int param_num, ...){
    pt_regs new_regs = *regs;
    new_regs.ARM_pc = (long)fun_addr & ~1;
    new_regs.ARM_lr = 0;
    va_list arglist;

    if ((long)fun_addr & 1) {
        new_regs.ARM_cpsr |=  0x20;   //thumb 0010 0000
    }
    else  {
        new_regs.ARM_cpsr &=  ~0x20;  //arm   0000 0000
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
            if(RemoteWriteData(pid, (void*)(new_regs.ARM_sp + i * 4), (void*)&n, 4) < 0){
                printf("[-] RemoteWriteData failed\n");
                return -1;
            }
        }
    }
    va_end(arglist);

    if(SetRegs(pid, &new_regs) < 0){
        return -1;
    }

    if(ContProcess(pid) < 0){
        return -1;
    }

    waitpid( pid, NULL, WUNTRACED);

    if (ptrace(PTRACE_GETREGS, pid, NULL, &new_regs) < 0) {
        perror("[-] PTRACE_GETREGS");
        return -1;
    }
    return new_regs.ARM_r0;
}

#endif //PTRACE_UTILS_H

