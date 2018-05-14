
LOCAL_PATH:= $(call my-dir)

include $(CLEAR_VARS)

LOCAL_PRELINK_MODULE := false

LOCAL_SRC_FILES := QWiFiSoftApCfg.c

LOCAL_MODULE := libQWiFiSoftApCfg

LOCAL_MODULE_TAGS := optional

LOCAL_C_INCLUDES += NSTALLED_KERNEL_HEADERS/include \
                    $(JNI_H_INCLUDE)

LOCAL_ADDITIONAL_DEPENDENCIES := INSTALLED_KERNEL_HEADERS
LOCAL_SHARED_LIBRARIES := libsysutils libcutils libnetutils libcrypto liblog

include $(BUILD_SHARED_LIBRARY)
