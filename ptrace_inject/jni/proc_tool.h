#ifndef PROC_TOOL_H
#define PROC_TOOL_H

#include <sys/types.h>

#ifndef MAX_LENGTH
#define MAX_LENGTH 1024
#endif //MAX_LENGTH

#ifdef __cplusplus
extern "C" {
#endif

char* proc_get_process_name(pid_t pid);
void* proc_get_module_base(pid_t pid, const char* module_name);
void* proc_get_remote_fun_addr(pid_t pid, const char* module_name, void* local_addr);

#ifdef __cplusplus
}
#endif

#endif //PROC_TOOL_H




