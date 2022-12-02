LOCAL_PATH:= $(call my-dir)
include $(CLEAR_VARS)

LOCAL_MODULE := inject
LOCAL_SRC_FILES := main.c proc_tool.c inject.c
LOCAL_LDLIBS := -lc -llog
include $(BUILD_EXECUTABLE)


include $(CLEAR_VARS) 
LOCAL_MODULE := test
LOCAL_SRC_FILES := inject_so.c
include $(BUILD_SHARED_LIBRARY)