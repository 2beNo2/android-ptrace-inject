#ifndef INJECT_H
#define INJECT_H

#include <asm/ptrace.h>

#ifdef __cplusplus
extern "C" {
#endif

#if defined(__aarch64__)
#define ZYGOTE_NAME "zygote64"
#define PTRACE_GETREGS PTRACE_GETREGSET
#define PTRACE_SETREGS PTRACE_SETREGSET
#define pt_regs  user_pt_regs
#define uregs    regs
#define ARM_pc   pc
#define ARM_sp   sp
#define ARM_cpsr pstate
#define ARM_lr   regs[30]
#define ARM_r0   regs[0]
#else
#define ZYGOTE_NAME "zygote"
#endif

int start_inject(pid_t pid, const char *so_path);

#ifdef __cplusplus
}
#endif

#endif //INJECT_H