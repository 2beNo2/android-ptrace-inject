#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include "proc_tool.h"
#include "log_marco.h"

/**
 * get target process name.
 *  pid  = -1, get self
 *  pid != -1, get target process
 * return: process_name
 */
char* proc_get_process_name(pid_t pid)
{
    FILE* fp = NULL;
    char path[MAX_LENGTH] = {0};
    static char buffer[MAX_LENGTH] = {0};

#define fatal(fmt, args...) do {LOGE(fmt, ##args); goto ERR_EXIT;} while(0)

    if(0 > pid){
        snprintf(path, sizeof(path), "/proc/self/cmdline");
    }
    else{
        snprintf(path, sizeof(path), "/proc/%d/cmdline", pid);
    }

    fp = fopen(path, "r");
    if(NULL == fp) fatal("[-] fopen:[%s], errno:[%s]", path, strerror(errno));
    if(NULL == fgets(buffer, sizeof(buffer), fp)) fatal("[-] fgets errno:[%s]", strerror(errno));
        
#undef fatal
    fclose(fp);
    return buffer;

ERR_EXIT:
    if(NULL != fp) fclose(fp);
    return NULL;
}

/**
 * get moduleBase from /proc/pid/maps
 *  pid  = -1, get self
 *  pid != -1, get target process
 *  moduleName -> module name
 * return base_addr
 */
void* proc_get_module_base(pid_t pid, const char* module_name)
{
    FILE* fp = NULL;
    void* base_addr = NULL;
    char perm[5];
    char path[MAX_LENGTH] = {0};
    char buff[MAX_LENGTH] = {0};

#define fatal(fmt, args...) do {LOGE(fmt, ##args); goto ERR_EXIT;} while(0)

    if(NULL == module_name) return NULL;

    if(pid < 0){
        snprintf(path, sizeof(path), "/proc/self/maps");
    }
    else{
        snprintf(path, sizeof(path), "/proc/%d/maps", pid);
    }

    fp = fopen(path, "r");
    if(NULL == fp) fatal("[-] fopen:[%s], errno:[%s]", path, strerror(errno));
    while(fgets(buff, sizeof(buff), fp)){
        if(sscanf(buff, "%p-%*p %4s", &base_addr, perm) != 2) continue;
        if (perm[3] != 'p') continue;
        if (perm[0] == '-' && perm[1] == '-' && perm[2] == '-') continue;
#if defined(__aarch64__)
        if (NULL == strstr(buff, "lib64")) continue;
#endif
        if (NULL != strstr(buff, module_name)) {
            break;
        }
    }

#undef fatal
    fclose(fp);
    return base_addr;

ERR_EXIT:
    if(NULL != fp) fclose(fp);
    return NULL;    
}

/**
 * get target process fun addr
 *  pid:         target process pid
 *  module_name: target module name
 *  local_addr:  local fun addr
 * return remote_addr
 */
void* proc_get_remote_fun_addr(pid_t pid, const char* module_name, void* local_addr)
{
    void* local_module_base = NULL;
    void* remote_module_base = NULL;
    char* remote_addr = NULL;

#define fatal(fmt, args...) do {LOGE(fmt, ##args); goto ERR_EXIT;} while(0)

    local_module_base = proc_get_module_base(-1, module_name);
    if(NULL == local_module_base) fatal("[-] get local module base failed");
    remote_module_base = proc_get_module_base(pid, module_name);
    if(NULL == remote_module_base) fatal("[-] get remote module base failed");
    remote_addr = (char*)remote_module_base + ((char*)local_addr - (char*)local_module_base);

#undef fatal    
    return (void*)remote_addr;

ERR_EXIT:
    return NULL;    
}
