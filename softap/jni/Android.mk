
LOCAL_PATH:= $(call my-dir)

include $(CLEAR_VARS)

LOCAL_PRELINK_MODULE := false

LOCAL_SRC_FILES := QWiFiSoftApCfg.c

LOCAL_MODULE := libQWiFiSoftApCfg

LOCAL_MODULE_TAGS := optional

LOCAL_C_INCLUDES := $(KERNEL_HEADERS) \
                    $(JNI_H_INCLUDE)

LOCAL_SHARED_LIBRARIES := libsysutils libcutils libnetutils libcrypto

include $(BUILD_SHARED_LIBRARY)

