#ifndef LOG_UTILS_H
#define LOG_UTILS_H

#include <android/log.h>

#define TAG "PTRACE_INJECT"
#define INJECT_DEBUG 1

#ifdef INJECT_DEBUG
#define LOGD(...) __android_log_print(ANDROID_LOG_DEBUG, TAG, __VA_ARGS__)
#else
#define LOGD(...)
#endif // INJECT_DEBUG
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO,  TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, TAG, __VA_ARGS__)
#define LOGW(...) __android_log_print(ANDROID_LOG_WARN,  TAG, __VA_ARGS__)

#ifndef PAGE_SIZE
#define PAGE_SIZE 4096
#endif

#define PAGE_START(addr)	(~(PAGE_SIZE - 1) & (addr))
#define PAGE_END(addr)      (PAGE_START(addr + sizeof(uintptr_t) - 1) + PAGE_SIZE)
#define PAGE_COVER(addr)    (PAGE_END(addr) - PAGE_START(addr))

#define SET_BIT0(addr)		(addr | 1)
#define CLEAR_BIT0(addr)	(addr & 0xFFFFFFFE)
#define TEST_BIT0(addr)		(addr & 1)

#endif //LOG_UTILS_H