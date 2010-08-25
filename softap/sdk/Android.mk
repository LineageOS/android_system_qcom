

LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)

LOCAL_C_INCLUDES :=

LOCAL_MODULE:= libqsap_sdk

LOCAL_SRC_FILES := qsap_api.c \
                   qsap.c

LOCAL_PRELINK_MODULE := false

LOCAL_SHARED_LIBRARIES := libnetutils libutils libbinder libcutils

include $(BUILD_SHARED_LIBRARY)

