LOCAL_PATH:= $(call my-dir)
include $(CLEAR_VARS)

LOCAL_MODULE := inject
LOCAL_SRC_FILES := inject.cpp
LOCAL_LDLIBS := -lc -ldl

include $(BUILD_EXECUTABLE)