
#ifndef INJECT_UTILS_H
#define INJECT_UTILS_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>


#ifndef MAX_LENGTH
#define MAX_LENGTH 1024
#endif //MAX_LENGTH


/**
 * get target process name.
 *  pid  = -1, get self
 *  pid != -1, get target process
 *  processName -> the result
 */
char* GetProcessName(pid_t pid){
    FILE* fp = NULL;
    static char buffer[MAX_LENGTH] = {0};
    char path[MAX_LENGTH] = {0};

    if(pid < 0){
        snprintf(path, sizeof(path), "/proc/self/cmdline");
    }
    else{
        snprintf(path, sizeof(path), "/proc/%d/cmdline", pid);
    }

    fp = fopen(path, "r");
    if(fp == NULL){
        perror("[-] fopen");
        return NULL;
    }

    if(fgets(buffer, sizeof(buffer), fp) == NULL){
        perror("[-] fgets");
        fclose(fp);
        return NULL;
    }
    fclose(fp);
    return buffer;
}


/**
 * get moduleBase from /proc/pid/maps
 *  pid  = -1, get self
 *  pid != -1, get target process
 *  moduleName -> module name
 */
void* GetModuleBase(pid_t pid, const char* moduleName){
    FILE* fp = NULL;
    void* address = NULL;
    char path[MAX_LENGTH] = {0};
    char buffer[MAX_LENGTH] = {0};

    if(moduleName == NULL){
        return NULL;
    }

    if(pid < 0){
        snprintf(path, sizeof(path), "/proc/self/maps");
    }
    else{
        snprintf(path, sizeof(path), "/proc/%d/maps", pid);
    }

    fp = fopen(path, "r");
    if(fp == NULL){
        perror("[-] fopen");
        return  NULL;
    }

    while (fgets(buffer, sizeof(buffer), fp)){
        if (strstr(buffer, moduleName) != NULL) {
            sscanf(buffer, "%p", &address);
            break;
        }
    }
    fclose(fp);
    return address;
}


/**
 * get target process fun addr
 *  pid:         target process pid
 *  module_name: target module name
 *  local_addr:  local fun addr
 */
static void* GetRemoteFunAddr(pid_t pid, const char* module_name, void* local_addr){
    void* local_module_base = GetModuleBase(-1, module_name);
    if(local_module_base == NULL){
        printf("[-] get local_module_base failed\n");
        return NULL;
    }

    void* remote_module_base = GetModuleBase(pid, module_name);
    if(remote_module_base == NULL){
        printf("[-] get remote_module_base failed\n");
        return NULL;
    }
    char* remote_addr = (char*)remote_module_base + ((char*)local_addr - (char*)local_module_base);
    return (void*)remote_addr;
}


#endif //INJECT_UTILS_H




