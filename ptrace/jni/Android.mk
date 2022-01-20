LOCAL_PATH:= $(call my-dir)
include $(CLEAR_VARS)

LOCAL_MODULE := inject
LOCAL_SRC_FILES := zygote_inject.cpp

LOCAL_LDLIBS := -lc -ldl

LOCAL_CPPFLAGS += -o2

include $(BUILD_EXECUTABLE)