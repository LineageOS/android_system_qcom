/*
 * Copyright (c) 2010, Code Aurora Forum. All rights reserved.

 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 *  * Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *  * Redistributions in binary form must reproduce the above
 *    copyright notice, this list of conditions and the following
 *    disclaimer in the documentation and/or other materials provided
 *    with the distribution.
 *  * Neither the name of Code Aurora Forum, Inc. nor the names of its
 *    contributors may be used to endorse or promote products derived
 *    from this software without specific prior written permission.

 * THIS SOFTWARE IS PROVIDED "AS IS" AND ANY EXPRESS OR IMPLIED
 * WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NON-INFRINGEMENT
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS
 * BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR
 * BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE
 * OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN
 * IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */


#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <ctype.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <linux/wireless.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/select.h>
#include <sys/types.h>
#include <unistd.h>

#include "qsap_api.h"
#include "qsap.h"

#define QCSAP_IOCTL_GET_CHANNEL       (SIOCIWFIRSTPRIV+9)
#define QCSAP_IOCTL_ASSOC_STA_MACADDR (SIOCIWFIRSTPRIV+10)
#define QCSAP_IOCTL_DISASSOC_STA      (SIOCIWFIRSTPRIV+11)

//#define LOG_TAG "QCSDK-"

#include "cutils/properties.h"
#include "cutils/log.h"


#define SKIP_BLANK_SPACE(x) {while(*x != '\0') { if((*x == ' ') || (*x == '\t')) x++; else break; }}

/** If this variable is enabled, the soft AP is reloaded, after the commit
  * command is received */
static volatile int gIniUpdated = 0;

/** Supported command requests.
  * WANRING: The enum eCMD_REQ in the file qsap_api.h should be
  * updated if Cmd_req[], us updated
  */
s8 *Cmd_req[eCMD_REQ_LAST] = {
    "get",
    "set"
};

/* 
 * WARNING: On updating the cmd_list, the enum esap_cmd in file 
 * qsap_api.h must be updates to reflect the changes 
 */
static s8 *cmd_list[eCMD_LAST] = {
    "ssid",
    "ignore_broadcast_ssid",
    "channel",
    "beacon_int",
    "dtim_period",
    "hw_mode",
    "auth_algs",
    "security_mode",
    "wep_key0",
    "wep_key1",
    "wep_key2",
    "wep_key3",
    "wep_default_key",
    "wpa_passphrase",
    "wpa_pairwise",
    "rsn_pairwise",
    "mac_address",
    "reset_ap",
    "macaddr_acl",
    "add_to_allow_list",
    "add_to_deny_list",
    "remove_from_allow_list",
    "remove_from_deny_list",
    "allow_list",
    "deny_list",
    "commit",
    "enable_softap",
    "disassoc_sta",
    "reset_to_default",
    "protection_flag",
    "data_rate",
    "sta_mac_list",
    "tx_power",
    "sdk_version",
    "wmm_enabled",

    /** Warning: Do not change the order of the WPS commands */    
    "wps_state",
    "config_methods",
    "uuid",
    "device_name",
    "manufacturer",
    "model_name",
    "model_number",
    "serial_number",
    "device_type",
    "os_version",
    "friendly_name",
    "manufacturer_url",
    "model_description",
    "model_url",
    "upc",
    /************ WPS commands end *********/

    "fragm_threshold",
    "rts_threshold",  
    "wpa_group_rekey",
    "country_code",
    "intra_bss_forward",
    "regulatory_domain",
};

static s8 *qsap_str[eSTR_LAST] = {
    "wpa",
    "accept_mac_file",
    "deny_mac_file",
    "gAPMacAddr",              /** AP MAC address */
    "gEnableApProt",           /** protection flag in ini file */
    "gFixedRate",              /** Fixed rate in ini */
    "gTxPowerCap",             /** Tx power in ini */
    "gFragmentationThreshold", /** Fragmentation threshold in ini */
    "RTSThreshold",            /** RTS threshold in ini */
    "gAPCntryCode",            /** Country code in ini */
    "gDisableIntraBssFwd",     /** Intra-bss forward in ini */
    "WmmIsEnabled",            /** WMM */
    "g11dSupportEnabled",      /** 802.11d support */
    "ieee80211n",
    "ctrl_interface",
    "interface",
    "eap_server"
};

/** Supported operating mode */
char *hw_mode[HW_MODE_UNKNOWN] = {
    "b", "g", "n", "g_only", "n_only"
};

/** configuration file path */
char *pconffile = CONFIG_FILE; 
char *fIni = INI_FILE;

/**
 * @brief
 *        For a give configuration parameter, read the configuration value from the file.
 * @param pfile [IN] configuration file path
 * @param pcmd [IN] pointer to the comand string
 * @param presp [OUT] buffer to store the configuration value
 * @param plen [IN-OUT] The length of the buffer is provided as input.
 *                      The length of the configuration parameter value, stored
 *                      in the 'presp', is provided as the output
 * @return void 
*/
static s32 qsap_read_cfg(s8 *pfile, s8 *pcmd, s8 *presp, u32 *plen, s8 *var)
{
    FILE *fcfg;
    s8    buf[MAX_CONF_LINE_LEN];
    u16   len;
    s8   *val;

    /** Open the configuration file */
    fcfg = fopen(pfile, "r");

    if(NULL == fcfg) {
        LOGE("%s : unable to open file \n", __func__);
        *plen = snprintf(presp, *plen, "%s", ERR_RES_UNAVAILABLE);
        return eERR_FILE_OPEN;
    }

    /** Read the line from the configuration file */
    len = strlen(pcmd);
    while(NULL != fgets(buf, MAX_CONF_LINE_LEN, fcfg)) {
        s8 *pline = buf;

        /** Skip the commented lines */
        if(buf[0] == '#') {
            continue;
        }
    
        /** Identify the configuration parameter in the configuration file */
        if(!strncmp(pline, pcmd, len) && (pline[len] == '=')) {
            buf[strlen(buf)-1] = '\0';
            if ( NULL != var ) {
                val = strchr(pline, '=');
                if(NULL == val)
                    break;
                *plen = snprintf(presp, *plen, "%s %s%s", SUCCESS, var, val);
            }
            else {
                *plen = snprintf(presp, *plen, "%s %s", SUCCESS, pline);
            }
            fclose(fcfg);
            return eSUCCESS;
        }
    }

    /** Configuration parameter is absent in the file */
    *plen = snprintf(presp, *plen, "%s", ERR_FEATURE_NOT_ENABLED);
    
    fclose(fcfg);

    return eERR_CONFIG_PARAM_MISSING;
}

/**
 * @brief
 *        Write the configuration parameter value into the configuration file.
 * @param pfile [IN] configuration file path.
 * @param pcmd [IN] command name
 * @param pVal [IN] configuration parameter to be written to the file.
 * @param presp [OUT] buffer to store the configuration value.
 * @param plen [IN-OUT] The length of the buffer is provided as input.
 *                      The length of the configuration parameter value, stored
 *                      in the 'presp', is provided as the output
 * @return void 
*/
static s32 qsap_write_cfg(s8 *pfile, s8 * pcmd, s8 *pVal, s8 *presp, u32 *plen, s32 inifile)
{
    FILE *fcfg, *ftmp;
    s8 buf[MAX_CONF_LINE_LEN+1];
    s16 len, result = FALSE;

    LOGD("cmd=%s, Val:%s, INI:%ld \n", pcmd, pVal, inifile);

    /** Open the configuration file */
    fcfg = fopen(pfile, "r");
    if(NULL == fcfg) {
        LOGE("%s : unable to open file \n", __func__);
        *plen = snprintf(presp, *plen, "%s", ERR_RES_UNAVAILABLE);
        return eERR_FILE_OPEN;
    }

    /** Open a temporary file */
    ftmp = fopen(TMP_FILE, "w");
    if(NULL == ftmp) {
        LOGE("%s : unable to open tmp file \n", __func__);
        *plen = snprintf(presp, *plen, "%s", ERR_RES_UNAVAILABLE);
        fclose(fcfg);
        return eERR_FILE_OPEN;
    }

    /** Read the values from the configuration file */
    len = strlen(pcmd);
    while(NULL != fgets(buf, MAX_CONF_LINE_LEN, fcfg)) {
        s8 *pline = buf;

        /** commented line */
        if(buf[0] == '#')
            pline++;
    
        /** Identify the configuration parameter to be updated */
        if((!strncmp(pline, pcmd, len)) && (result == FALSE)) {
            if(pline[len] == '=') {
                snprintf(buf, MAX_CONF_LINE_LEN, "%s=%s\n", pcmd, pVal);
                result = TRUE;
                LOGD("Updated:%s\n", buf);
            }
        }
        
        if(inifile && (!strncmp(pline, "END", 3)))
            break;

        fprintf(ftmp, "%s", buf);
    }

    if (result == FALSE) {
        /* Configuration line not found */
        /* Add the new line at the end of file */
        snprintf(buf, MAX_CONF_LINE_LEN, "%s=%s\n", pcmd, pVal);
        fprintf(ftmp, "%s", buf);
        LOGD("Adding a new line in %s file: [%s] \n", inifile ? "inifile" : "hostapd.conf", buf);
    }

    if(inifile) {
        gIniUpdated = 1;
        fprintf(ftmp, "END\n");
        while(NULL != fgets(buf, MAX_CONF_LINE_LEN, fcfg))
            fprintf(ftmp, "%s", buf);
    }

    fclose(fcfg);
    fclose(ftmp);

    /** Restore the updated configuration file */
    result = rename(TMP_FILE, pfile);

    *plen = snprintf(presp, *plen, "%s", (result == eERR_UNKNOWN) ? ERR_FEATURE_NOT_ENABLED : SUCCESS);

    /** Remove the temporary file. Dont care the return value */
    unlink(TMP_FILE);

    if(result == eERR_UNKNOWN)
        return eERR_FEATURE_NOT_ENABLED;

    return eSUCCESS;
}

/**
 * @brief Read the security mode set in the configuration
 * @param pfile [IN] configuration file path.
 * @param presp [OUT] buffer to store the security mode.
 * @param plen [IN-OUT] The length of the buffer is provided as input.
 *                      The length of the security mode value, stored
 *                      in the 'presp', is provided as the output
 * @return void 
*/
static sec_mode_t qsap_read_security_mode(s8 *pfile, s8 *presp, u32 *plen)
{
    sec_mode_t mode;
    u32 temp = *plen;

    /** Read the WEP default key */
    qsap_read_cfg(pfile, cmd_list[eCMD_DEFAULT_KEY], presp, plen, NULL);

    if ( !strcmp(presp, ERR_FEATURE_NOT_ENABLED) ) {
        *plen = temp;
        
        /* WEP, is not enabled */

        /** Read WPA security status */
        qsap_read_cfg(pfile, qsap_str[STR_WPA], presp, plen, NULL);
        if ( !strcmp(presp, ERR_FEATURE_NOT_ENABLED) ) {
            /** WPA is disabled, No security */
            mode = SEC_MODE_NONE;
        }
        else {
            /** WPA, WPA2 or WPA-WPA2 mixed security */
            s8 * ptmp = presp;
            while((*plen)-- && (*ptmp++ != '=') );
            mode =     *plen ? (
                    *ptmp == '1' ? SEC_MODE_WPA_PSK : 
                    *ptmp == '2' ? SEC_MODE_WPA2_PSK : 
                    *ptmp == '3' ? SEC_MODE_WPA_WPA2_PSK : SEC_MODE_INVALID ): SEC_MODE_INVALID;
        }
    }
    else {
        /** Verify if, WPA is disabled */
        *plen = temp;
        qsap_read_cfg(pfile, qsap_str[STR_WPA], presp, plen, NULL);
        if ( !strcmp(presp, ERR_FEATURE_NOT_ENABLED) ) {
            /** WPA is disabled, hence WEP is enabled */
            mode = SEC_MODE_WEP;
        }
        else {
            *plen = snprintf(presp, *plen, "%s", ERR_UNKNOWN);
            return SEC_MODE_INVALID;
        }
    }

    if(mode != SEC_MODE_INVALID) {
        *plen = snprintf(presp, temp,"%s %s=%d", SUCCESS, cmd_list[eCMD_SEC_MODE], mode);
    }
    else {
        *plen = snprintf(presp, temp,"%s", ERR_NOT_SUPPORTED);
    }

    return mode;
}

/**
 * @brief
 *         Enable or disable a configuration parameter in the configuration file.
 * @param pfile [IN] configuration file name
 * @param pcmd [IN] configuration parameter name
 * @param status [IN] status to be set. The valid values are 'ENABLE' or 'DISABLE'
 * @return On success, return 0
 *         On failure, return -1
*/
static s32 qsap_change_cfg(s8 *pfile, s8 *pcmd, u32 status)
{
    FILE *fcfg, *ftmp;
    s8 buf[MAX_CONF_LINE_LEN+1];
    u16 len;

    /** Open the configuartion file */
    fcfg = fopen(pfile, "r");
    if(NULL == fcfg) {
        LOGE("%s : unable to open file \n", __func__);
        return eERR_UNKNOWN;
    }

    /** Open a temporary file */
    ftmp = fopen(TMP_FILE, "w");
    if(NULL == ftmp) {
        LOGE("%s : unable to open tmp file \n", __func__);
        fclose(fcfg);
        return eERR_UNKNOWN;
    }

    /** Read the configuration parameters from the configuration file */
    len = strlen(pcmd);
    while(NULL != fgets(buf+1, MAX_CONF_LINE_LEN, fcfg)) {
        s8 *p = buf+1;

        /** Commented line */
        if(p[0] == '#')
            p++;

        /** Identify the configuration parameter */
        if(!strncmp(p, pcmd, len)) {
            if(p[len] == '=') {
                if(status == DISABLE) {
                    fprintf(ftmp, "#%s", p);
                }
                else {
                    fprintf(ftmp, "%s", p);
                }
                continue;
            }
        }
        fprintf(ftmp, "%s", buf+1);
    }

    fclose(fcfg);
    fclose(ftmp);

    /** Restore the new configuration file */
    if(eERR_UNKNOWN == rename(TMP_FILE, pfile)) {
        LOGE("unable to rename the file \n");
        return eERR_UNKNOWN;
    }

    /** Delete the temporary file */
    unlink(TMP_FILE);

    return 0;
}

/**
 * @brief
 *         Set the security mode in the configuration. The security mode
 *         can be :
 *                   1. No security
 *                   2. WEP
 *                   3. WPA
 *                   4. WPA2
 *                   5. WPA and WPA2 mixed mode
 * @param pfile [IN] configuration file name
 * @param sec_mode [IN] security mode to be set
 * @param presp [OUTPUT] presp The command output format :
 *                    On success,
 *                            success <cmd>=<value>
 *                    On failure,
 *                            failure <error message>
 * @param plen [IN-OUT] plen
 *                      [IN] The length of the buffer, presp
 *                      [OUT] The length of the response in the buffer, presp
 * @return void
*/
static void qsap_set_security_mode(s8 *pfile, u32 sec_mode, s8 *presp, u32 *plen)
{
    s16 wep, wpa;
    s8 sec[MAX_INT_STR];
    s32 rsn_status = DISABLE;
    s32 ret = eERR_UNKNOWN;

    /** Is valid security mode ? */
    if(sec_mode >= SEC_MODE_INVALID) {
        *plen = snprintf(presp, *plen, "%s", ERR_UNKNOWN);
        return;
    }

    /** No security */
    if(SEC_MODE_NONE == sec_mode) {
        wep = DISABLE;
        wpa = DISABLE;
    }
    /** WEP security */
    else if(SEC_MODE_WEP == sec_mode) {
        wep = ENABLE;
        wpa = DISABLE;
    }
    else {
        /** WPA, WPA2 and mixed-mode security */
        u16 wpa_val;
        u32 tmp = *plen;

        wep = DISABLE;
        wpa = ENABLE;
        
        if(sec_mode == SEC_MODE_WPA_PSK)
            wpa_val = WPA_IN_CONF_FILE;

        else if(sec_mode == SEC_MODE_WPA2_PSK) {
            wpa_val = WPA2_IN_CONF_FILE;
            rsn_status = ENABLE;
        }

        else if(sec_mode == SEC_MODE_WPA_WPA2_PSK) {
            wpa_val = WPA_WPA2_IN_CONF_FILE;
            rsn_status = ENABLE;
        }

        snprintf(sec, MAX_INT_STR, "%u", wpa_val);
        qsap_write_cfg(pfile, qsap_str[STR_WPA], sec, presp, plen, HOSTAPD_CONF_FILE);
        *plen = tmp;
    }

    /** The configuration parameters for the security to be set are enabled
      * and the configuration parameters for the other security types are
      * disabled in the configuration file
      */
    if(eERR_UNKNOWN == qsap_change_cfg(pfile, cmd_list[eCMD_DEFAULT_KEY], wep)) {
        LOGE("%s: wep_default_key error\n", __func__);
        goto end;
    }

    if(eERR_UNKNOWN == qsap_change_cfg(pfile, cmd_list[eCMD_WEP_KEY0], wep)) {
        LOGE("%s: CMD_WEP_KEY0 \n", __func__);
        goto end;
    }

    if(eERR_UNKNOWN == qsap_change_cfg(pfile, cmd_list[eCMD_WEP_KEY1], wep)) {
        LOGE("%s: CMD_WEP_KEY1 \n", __func__);
        goto end;
    }

    if(eERR_UNKNOWN == qsap_change_cfg(pfile, cmd_list[eCMD_WEP_KEY2], wep)) {
        LOGE("%s: CMD_WEP_KEY2 \n", __func__);
        goto end;
    }
    
    if(eERR_UNKNOWN == qsap_change_cfg(pfile, cmd_list[eCMD_WEP_KEY3], wep)) {
        LOGE("%s: CMD_WEP_KEY3 \n", __func__);
        goto end;
    }

    if(eERR_UNKNOWN == qsap_change_cfg(pfile, cmd_list[eCMD_PASSPHRASE], wpa)) {
        LOGE("%s: Passphrase error\n", __func__);
        goto end;
    }

    if((sec_mode != SEC_MODE_NONE) && (sec_mode != SEC_MODE_WEP)) {
        u32 state = !rsn_status;

        if(sec_mode == SEC_MODE_WPA_WPA2_PSK) state = ENABLE;

        if(eERR_UNKNOWN == qsap_change_cfg(pfile, cmd_list[eCMD_WPA_PAIRWISE], state)) {
            LOGE("%s: WPA Pairwise\n", __func__);
            goto end;
        }
    }

    if(eERR_UNKNOWN == qsap_change_cfg(pfile, cmd_list[eCMD_RSN_PAIRWISE], rsn_status)) {
        LOGE("%s: WPA2 Pairwise\n", __func__);
        goto end;
    }
        
    if(eERR_UNKNOWN == qsap_change_cfg(pfile, qsap_str[STR_WPA], wpa)) {
        LOGE("%s: WPA\n", __func__);
        goto end;
    }

    ret = eSUCCESS;

end:
    *plen = snprintf(presp, *plen, "%s", (ret == eSUCCESS) ? SUCCESS : ERR_UNKNOWN);
    
    return;
}

/**
 * @brief
 *         Get the file path having the allow or deny MAC address list
 * @param pcfgfile [IN] configuration file name
 * @param pcmd [IN] pcmd pointer to the command string
 * @param pfile [OUT] buffer to store the return value, containing the file name
 *                   or the error message.
 * @param plen [IN-OUT] size of the buffer 'pfile', is provided as input and
 *                      the length of the file name is returned as output
 * @return 
 *           On success, a pointer to the file name in the buffer 'pfile'.
 *           On failure, NULL is returned
*/
static s8 *qsap_get_allow_deny_file_name(s8 *pcfgfile, s8 *pcmd, s8 *pfile, u32 *plen)
{
    if(eSUCCESS == qsap_read_cfg(pcfgfile, pcmd, pfile, plen, NULL)) {
        pfile[*plen] = '\0';
        return strchr(pfile, '=') + 1;
    }

    return NULL;
}

/** Function to identify a valid MAC address */
static int isValid_MAC_address(char *pMac)
{
    int i, len;

    len = strlen(pMac);

    if(len < MAC_ADDR_LEN)
        return FALSE;

    for(i=0; i<MAC_ADDR_LEN; i++) {
        switch(i) {
            case 2: case 5: case 8: case 11: case 14:
                if(pMac[i] != ':')
                    return FALSE;
                break;
            default:
                if(isxdigit(pMac[i]) == 0)
                    return FALSE;
        }
    }

    return TRUE;
}

/**
 * @brief
 *        Add a given MAC address to the allow or deny MAC list file.
 *        A maximum of 15 MAC addresses are allowed in the list. If the input
 *        MAC addresses are more than the allowed number, then the allowed number
 *        of MAC addresses are updated to the MAC list file and the remaining
 *        MAC addresses are discarded
 *
 * @param pfile [IN] Path of the allow or deny MAC list file
 * @param pVal [IN] A string containing one or more MAC addresses. Multiple
 *                  MAC addresses are separated by a SPACE separator
 *                  Ex. "11:22:33:44:55:66 77:88:99:00:88:00"
 * @param presp [OUT] buffer to store the response
 * @param plen [IN-OUT] The length of the buffer 'presp' is provided as input.
 *                      The length of the response, stored in buffer 'presp' is
 *                      provided as output.
 * @return void 
*/
static void qsap_add_mac_to_file(s8 *pfile, s8 *pVal, s8 *presp, u32 *plen)
{
    s32 len;
    s16 num_macs = 0;
    s8 buf[32];
    s8 macbuf[32];
    FILE *fp;

    /** Create the file if it does not exists and open it for reading */
    fp = fopen(pfile, "a");
    if(NULL != fp) {
        fclose(fp);
        fp = fopen(pfile, "r+");
    }
    
    if(NULL == fp) {
        LOGE("%s : unable to open the file \n", __func__);
        *plen = snprintf(presp, *plen, "%s", ERR_RES_UNAVAILABLE);
        return;
    }
    
    /** count the MAC address in the MAC list file */    
    while(NULL != (fgets(buf, 32, fp))) {
        num_macs++;
    }
    
    /** Evaluate the allowed limit */
    if(num_macs >= MAX_ALLOWED_MAC) {
        LOGE("%s : File is full\n", __func__);
        *plen = snprintf(presp, *plen, "%s", ERR_UNKNOWN);
        fclose(fp);
        return;
    }

    /** Update all the input MAC addresses into the MAC list file */
    len = strlen(pVal);
    while(len > 0) {
        int i = 0;

        /** Get a MAC address from the input string */
        while((*pVal != ' ' ) && (*pVal != '\0')) {
            macbuf[i] = *pVal;
            i++;
            pVal++;
    
            if(i == MAC_ADDR_LEN)
                break;
        }
        macbuf[i] = '\0';
        pVal++;

        /** Is valid MAC address input ? */
        if(TRUE == isValid_MAC_address(macbuf)) {

            /** Append the MAC address to the file */
            fprintf(fp, "%s\n", macbuf);
            num_macs++;

            /** Evaluate with the allowed limit */
            if(num_macs == MAX_ALLOWED_MAC) {
                LOGE("MAC file is full now.... \n");
                break;
            }

        }
        len -= strlen(macbuf);
        if(*pVal != '\0')
            len--;
    }

    fclose(fp);
    
    *plen = snprintf(presp, *plen, "%s", SUCCESS);
    
    return;
}

/**
 * @brief
 *         Remove one or more MAC addresses from the allow or deny MAC list file.
 * @param pfile [IN] path of the allow or deny list file.
 * @param pVal [IN] a list of MAC addresses to be removed from the MAC list file.
 * @param presp [OUT] the buffer to store the response
 * @param plen [IN-OUT] The length of the 'presp' buffer is provided as input.
 *                      The lenght of the response, stored in 'presp', is
 *                      provided as output
 * @return void
*/
static void qsap_remove_from_file(s8 *pfile, s8 *pVal, s8 *presp, u32 *plen)
{
    FILE *fp;
    FILE *ftmp;
    s8 buf[MAX_CONF_LINE_LEN];
    int status;
    
    /** Open the allow or deny MAC list file */
    fp = fopen(pfile, "r+");

    if(NULL == fp) {
        LOGE("%s : unable to open the file \n", __func__);
        *plen = snprintf(presp, *plen, "%s", ERR_RES_UNAVAILABLE);
        return;
    }

    /** Open a temporary file */
    ftmp = fopen(TMP_FILE, "w");

    if(ftmp == NULL) {
        LOGE("%s : unable to open the file \n", __func__);
        *plen = snprintf(presp, *plen, "%s", ERR_RES_UNAVAILABLE);
        fclose(fp);
        return;
    }

    /** Read all the MAC addresses from the file */
    while(NULL != fgets(buf, MAX_CONF_LINE_LEN, fp)) {
        s8 *plist;
        s32 slen;
        int write_back = 1;
        
        plist = pVal;
        slen = strlen(pVal);

        /** Compare each MAC address in the file with all the 
          * input MAC addresses */
        write_back = 1;
        while(slen > 0) {

            if(0 == strncmp(buf, plist, MAC_ADDR_LEN)) {
                write_back = 0;
                break;
            }

            while((*plist != ' ') && (*plist != '\0')) {
                plist++;
                slen--;
            }

            while(((*plist == ' ') || (*plist == '\t')) && (*plist != '\0')) {
                plist++; slen--;
            }
        }

        /** Update the file */
        if(write_back) {    
            fprintf(ftmp, "%s", buf);
        }
    }

    fclose(fp);
    fclose(ftmp);

    /** Restore the configuration file */
    status = rename(TMP_FILE, pfile);
    
    snprintf(presp, *plen, "%s", (status == eERR_UNKNOWN) ? ERR_FEATURE_NOT_ENABLED : SUCCESS);

    unlink(TMP_FILE);
        
    return;
}

/**
 * @brief
 *         Identify the MAC list file and the type of updation on the file.
 *         The MAC list file can be : Allow file or Deny file.
 *         The type of operation is : Add to file or Delete from file
 *
 * @param file [IN] path of the allow or deny MAC list file.
 * @param cNum [IN] command number to 'type of file' and the 'type of updation'
 *                  to be done.
 * @param pVal [IN] A list of one or more MAC addresses. Multiple MAC addresses
 *                  are separated by a SPACE character
 * @param presp [OUT] Buffer to store the command response
 * @param plen [IN-OUT] The length of the 'presp' buffer is provided as input
 *                      The length of the response, stored in the 'presp' is provided
 *                      as the output
 * @return void
*/
static void qsap_update_mac_list(s8 *pfile, esap_cmd_t cNum, s8 *pVal, s8 *presp, u32 *plen)
{
    LOGD("%s : Updating file %s \n", __func__, pfile);

    switch(cNum) {
        case eCMD_ADD_TO_ALLOW:
        case eCMD_ADD_TO_DENY:
                qsap_add_mac_to_file(pfile, pVal, presp, plen);
                break;

        case eCMD_REMOVE_FROM_ALLOW:
        case eCMD_REMOVE_FROM_DENY:
                qsap_remove_from_file(pfile, pVal, presp, plen);
                break;

        default:
                *plen = snprintf(presp, *plen, "%s", ERR_UNKNOWN);
                return;
    }

    return;
}

/**
 * @brief  
 * @param fconfig [INPUT] configuration file name
 * @param cNum [INPUT] command number. The valid command numbers supported by
 *                     this function are :
 *                     eCMD_ALLOW_LIST - Get the MAC address list from the allow list
 *                     eCMD_DENY_LIST - Get the MAC address list from the deny list 
 * @param presp [OUTPUT] presp The command output format :
 *                    On success,
 *                            success <cmd>=<value>
 *                    On failure,
 *                            failure <error message>
 * @param plen [IN-OUT] plen
 *                      [IN] The length of the buffer, presp
 *                      [OUT] The length of the response in the buffer, presp
 * @return void
**/
static void qsap_get_mac_list(s8 *fconfile, esap_cmd_t cNum, s8 *presp, u32 *plen)
{
    s8 buf[MAX_CONF_LINE_LEN];
    FILE *fp;
    u32 len_remain;
    s8 *pfile, *pOut;
    esap_cmd_t sNum;
    int cnt = 0;

    /** Identify the allow or deny file */
    if(eCMD_ALLOW_LIST == cNum) {
        sNum = STR_ACCEPT_MAC_FILE;    
    }
    else if(eCMD_DENY_LIST == cNum) {
        sNum = STR_DENY_MAC_FILE;
    }
    else {
        *plen = snprintf(presp, *plen, "%s", ERR_UNKNOWN);
        return;
    }

    /** Get the MAC allow or MAC deny file path */    
    len_remain = MAX_CONF_LINE_LEN;
    if(NULL == (pfile = qsap_get_allow_deny_file_name(fconfile, qsap_str[sNum], buf, &len_remain))) {
        LOGE("%s:Unknown error\n", __func__);
        *plen = snprintf(presp, *plen, "%s", ERR_RES_UNAVAILABLE);
        return;
    }

    /** Open allow / deny file, and read the MAC addresses */    
    fp = fopen(pfile, "r");
    if(NULL == fp) {
        LOGE("%s: file open error\n",__func__);
        *plen = snprintf(presp, *plen, "%s", ERR_RES_UNAVAILABLE);
        return;
    }

    /* Keep the NULL at the end of the buffer */
    presp[*plen-1] = '\0';
    *plen -= snprintf(presp, *plen, "%s %s=", SUCCESS, cmd_list[cNum]);

    /* Reserving the space for last null character in case of over flow */
    (u32)(*plen)--;

    pOut = presp + strlen(presp);

    /** Read the MAC address from the MAC allow or deny file */
    while(NULL != (fgets(buf, MAX_CONF_LINE_LEN, fp))) {
        u32 len;

        /** Avoid the commented lines */    
        if(buf[0] == '#')
            continue;

        if(FALSE == isValid_MAC_address(buf))
            continue;

        buf[strlen(buf)-1] = '\0';

        if(*plen < strlen(buf)) {
            *pOut = '\0';
            break;
        }
        
        len = snprintf(pOut, *plen, "%s ", buf);
        cnt++;

        if (cnt >= MAX_ALLOWED_MAC) {
            break;
        }

        pOut += len;
        *plen -= len;
    }

    *plen = strlen(presp);

    fclose(fp);

    return;
}

static int qsap_read_mac_address(s8 *presp, u32 *plen)
{
    char *ptr;
    char  mac[MAC_ADDR_LEN];
    u32   len, i;
    int   nRet = eERR_INVALID_MAC_ADDR;

    len = *plen;

    if(eSUCCESS != qsap_read_cfg(fIni, qsap_str[STR_MAC_IN_INI], presp, plen, cmd_list[eCMD_MAC_ADDR])) {
        LOGE("%s :MAC addr read failure \n",__func__);
        goto end;
    }

    ptr = strchr(presp, '=');
    if(NULL == ptr)
        goto end;

    strncpy(mac, ptr+1, MAC_ADDR_LEN);
    *plen = snprintf(presp, len, "%s %s=", SUCCESS, cmd_list[eCMD_MAC_ADDR]);
    ptr = presp + strlen(presp);
        
    for(i=0; i<MAC_ADDR_LEN-5; i+=2) {
        u32 tlen;

        tlen = snprintf(ptr, len, "%c%c:", mac[i], mac[i+1]);
        *plen += tlen;
        ptr += tlen;
    }
    presp[*plen-1] = '\0';
    (*plen)--;

    ptr = strchr(presp, '=');
    if(NULL == ptr)
        goto end;

    ptr++;

    LOGD("MAC :%s \n", ptr);
    if(TRUE == isValid_MAC_address(ptr)) {
        nRet = eSUCCESS;
    }
    else {
        LOGE("Invalid MAC in conf file \n");
    }
end:
    return nRet;
}

static void qsap_read_wmm(s8 *presp, u32 *plen)
{
    s8 *ptr;
    u32 tlen = *plen;
    u32 status;

    if(eSUCCESS != qsap_read_cfg(fIni, qsap_str[STR_WMM_IN_INI], presp, &tlen, cmd_list[eCMD_WMM_STATE])) {    
        *plen = snprintf(presp, *plen, "%s", ERR_NOT_SUPPORTED);
        return;
    }

    ptr = strchr((s8 *)presp, '=');
    if(ptr == NULL) {
        *plen = snprintf(presp, *plen, "%s", ERR_UNKNOWN);
        return;
    }
    ptr++;

    status = atoi(ptr);

    if(status == WMM_ENABLED_IN_INI)
        status = ENABLE;
    else
        status = DISABLE;

    *plen = snprintf(presp, *plen, "%s %s=%ld", SUCCESS, cmd_list[eCMD_WMM_STATE], status);
    return;
}

static void qsap_read_wps_state(s8 *presp, u32 *plen)
{
    u32  tlen = *plen;
    s32  status = ENABLE;

    if(eSUCCESS != qsap_read_cfg(pconffile, cmd_list[eCMD_WPS_STATE], presp, &tlen, NULL)) {
        /** unable to read the wps configuration, WPS is disabled !*/
        LOGE("%s :Failed to read wps_state from cfg \n", __func__);
        status = DISABLE;
    }

    *plen = snprintf(presp, *plen, "%s %s=%lu", SUCCESS, cmd_list[eCMD_WPS_STATE], status);

    return;    
}

s8 *qsap_get_config_value(s8 *pfile, s8 *pcmd, s8 *pbuf, u32 *plen)
{
    s8 *ptr = NULL;

    if(eSUCCESS == qsap_read_cfg(pfile, pcmd, pbuf, (u32 *)plen, NULL)) {
        ptr = strchr(pbuf, '=');
        if(NULL != ptr){
            ptr++;
        }
        else {
            LOGE("Invalid entry, %s\n", pcmd);
        }
    }

    return ptr;
}

/**
 *    Get the channel being used in the soft AP.
 */
int qsap_get_operating_channel(s32 *pchan)
{
    int sock;
    struct iwreq wrq;
    s8 interface[MAX_CONF_LINE_LEN];
    u32 len = MAX_CONF_LINE_LEN;
    s8 *pif;
    int ret;

    if(NULL == (pif = qsap_get_config_value(pconffile, qsap_str[STR_INTERFACE], interface, &len))) {
        LOGE("%s :interface error \n", __func__);
        goto error;
    }

    interface[len] = '\0';

    sock = socket(AF_INET, SOCK_DGRAM, 0);
    if(sock < 0) {
        LOGE("%s :socket error \n", __func__);
        goto error;
    }

    *pchan = 0;

    strncpy(wrq.ifr_name, pif, sizeof(wrq.ifr_name));
    wrq.u.data.length = sizeof(s32);
    wrq.u.data.pointer = pchan;
    wrq.u.data.flags = 0;

    ret = ioctl(sock, QCSAP_IOCTL_GET_CHANNEL, &wrq);
    if(ret < 0) {
        LOGE("%s: ioctl failure \n",__func__);
        goto error;
    }

    LOGE("Recv len :%d \n", wrq.u.data.length);

    LOGE("Operating channel :%ld \n", *pchan);
    return eSUCCESS;

error:
    *pchan = 0;
    LOGE("%s: Failed to read channel \n", __func__);
    return eERR_CHAN_READ;
}

int qsap_read_channel(s8 *pfile, s8 *pcmd, s8 *presp, u32 *plen, s8 *pvar)
{
    s8   *pval;
    s32  chan;
    u32  len = *plen;

    if(eSUCCESS == qsap_read_cfg(pfile, pcmd, presp, plen, pvar)) {
        pval = strchr(presp, '=');
        
        if(NULL == pval) {
            LOGE("%s :CHAN absent \n", __func__);
            return eERR_CONFIG_PARAM_MISSING;
        }

        pval++;
        chan = atoi(pval);

        if(chan == AUTO_CHANNEL) {
            if(eSUCCESS == qsap_get_operating_channel(&chan)) {
                *plen = snprintf(presp, len, "%s %s=0,%lu", SUCCESS, pcmd, chan);
            }
            else {
                *plen = snprintf(presp, len, "%s", ERR_UNKNOWN);
            }
        }
    }
    return eSUCCESS;
}

static int qsap_mac_to_macstr(s8 *pmac, u32 slen, s8 *pmstr, u32 *plen)
{
    int len;
    int totlen = 0;

    while((slen > 0) && (*plen > 0)) {
        len = snprintf(pmstr, *plen, "%.2X:%.2X:%.2X:%.2X:%.2X:%.2X ", (int)pmac[0], (int)pmac[1], (int)pmac[2],
                            (int)pmac[3], (int)pmac[4], (int)pmac[5]);
        pmac += 6;
        slen -= 6;
        *plen -= len;
        pmstr += len;
        totlen += len;
    }

    if(totlen > 0) {
        *pmstr--;
        totlen--;
    }
    *pmstr = '\0';
    *plen = totlen;

    return 0;
}

#define MAX_STA_ALLOWED  8
void qsap_get_associated_sta_mac(s8 *presp, u32 *plen)
{
    int sock, ret;
    struct iwreq wrq;
    s8 interface[MAX_CONF_LINE_LEN];
    u32 len = MAX_CONF_LINE_LEN;
    s8 *pif;
    s8 *pbuf, *pout;
    u32 recvLen;
    u32 tlen;

    if(NULL == (pif = qsap_get_config_value(pconffile, qsap_str[STR_INTERFACE], interface, &len))) {
        LOGE("%s :interface error \n", __func__);
        goto error;
    }
    interface[len] = '\0';

    sock = socket(AF_INET, SOCK_DGRAM, 0);
    if(sock < 0) {
        LOGE("%s :socket failure \n", __func__);
        goto error;
    }

    pbuf = (s8 *)malloc((MAX_STA_ALLOWED * 6) + 8);
    if(NULL == pbuf) {
        LOGE("%s :No memory \n", __func__);
        goto error;
    }


#define SIZE_OF_MAC_INT   (6)
    strncpy(wrq.ifr_name, pif, sizeof(wrq.ifr_name));
    wrq.u.data.length = SIZE_OF_MAC_INT * 8 + 8; /** 8 supported MAC and 7 SPACE separators and a '\0' */
    wrq.u.data.pointer = (void *)pbuf;
    wrq.u.data.flags = 0;

    ret = ioctl(sock, QCSAP_IOCTL_ASSOC_STA_MACADDR, &wrq);
    if(ret < 0) {
        LOGE("%s :ioctl failure \n", __func__);
        free(pbuf);
        goto error;
    }

    recvLen = *(unsigned long int *)(wrq.u.data.pointer);

    len = snprintf(presp, *plen, "%s %s=", SUCCESS, cmd_list[eCMD_ASSOC_STA_MACS]);
    pout = presp + len;
    tlen = *plen - len;

    qsap_mac_to_macstr(pbuf+sizeof(unsigned long int), recvLen, pout, &tlen);

    *plen = len + tlen;
    
    free(pbuf);

    return;
error:
    *plen = snprintf(presp, *plen, "%s", ERR_UNKNOWN);

    return;
}
/**
 * @brief 
 *       Get the configuration information from the softAP configuration
 *       files 
 * @param cNum [INPUT] 
 * @param presp [OUTPUT] presp The command output format :
 *                    On success,
 *                            success <cmd>=<value>
 *                    On failure,
 *                            failure <error message>
 * @param plen [IN-OUT] plen
 *                      [IN] The length of the buffer, presp
 *                      [OUT] The length of the response in the buffer, presp
 * @return void
**/
static void qsap_get_from_config(esap_cmd_t cNum, s8 *presp, u32 *plen)    
{
    u32 len;
    int status;

    switch(cNum) {
        case eCMD_ENABLE_SOFTAP:
            status = is_softap_enabled();
            *plen = snprintf(presp, *plen, "%s %s=%d", SUCCESS, cmd_list[cNum], status);
            break;

        case eCMD_SSID:
        case eCMD_BSSID:
        case eCMD_BCN_INTERVAL:
        case eCMD_DTIM_PERIOD:
        case eCMD_HW_MODE:
        case eCMD_AUTH_ALGS:
        case eCMD_WEP_KEY0:
        case eCMD_WEP_KEY1:
        case eCMD_WEP_KEY2:
        case eCMD_WEP_KEY3:
        case eCMD_DEFAULT_KEY:
        case eCMD_PASSPHRASE:
        case eCMD_WPA_PAIRWISE:
        case eCMD_RSN_PAIRWISE:
        case eCMD_MAC_ACL:
        case eCMD_WPS_CONFIG_METHOD:
        case eCMD_GTK_TIMEOUT:
        case eCMD_UUID:
        case eCMD_DEVICE_NAME:
        case eCMD_MANUFACTURER:
        case eCMD_MODEL_NAME:
        case eCMD_MODEL_NUMBER:
        case eCMD_SERIAL_NUMBER:
        case eCMD_DEVICE_TYPE:
        case eCMD_OS_VERSION:
        case eCMD_FRIENDLY_NAME:
        case eCMD_MANUFACTURER_URL:
        case eCMD_MODEL_DESC:
        case eCMD_MODEL_URL:
        case eCMD_UPC:
                qsap_read_cfg(pconffile, cmd_list[cNum], presp, plen, NULL);
                break;

        case eCMD_CHAN:
                qsap_read_channel(pconffile, cmd_list[cNum], presp, plen, NULL);
                break;

        case eCMD_FRAG_THRESHOLD:
                qsap_read_cfg(fIni, qsap_str[STR_FRAG_THRESHOLD_IN_INI], presp, plen, cmd_list[eCMD_FRAG_THRESHOLD]);
                break;
                
        case eCMD_REGULATORY_DOMAIN:
                qsap_read_cfg(fIni, qsap_str[STR_802DOT11D_IN_INI], presp, plen, cmd_list[eCMD_REGULATORY_DOMAIN]);
                break;

        case eCMD_RTS_THRESHOLD:
                qsap_read_cfg(fIni, qsap_str[STR_RTS_THRESHOLD_IN_INI], presp, plen, cmd_list[eCMD_RTS_THRESHOLD]);
                break;

        case eCMD_ALLOW_LIST: /* fall through */
        case eCMD_DENY_LIST:
                qsap_get_mac_list(pconffile, cNum, presp, plen);
                break;
 
        case eCMD_SEC_MODE:
                qsap_read_security_mode(pconffile, presp, plen);
                break;

        case eCMD_MAC_ADDR:
                if(eSUCCESS != qsap_read_mac_address(presp, plen)) {
                    *plen = snprintf(presp, *plen, "%s", ERR_NOT_SUPPORTED);
                }
                break;

        case eCMD_WMM_STATE:
                qsap_read_wmm(presp, plen);
                break;

        case eCMD_WPS_STATE:
                qsap_read_wps_state(presp, plen);
                break;

        case eCMD_PROTECTION_FLAG:
                qsap_read_cfg(fIni, qsap_str[STR_PROT_FLAG_IN_INI], presp, plen, cmd_list[eCMD_PROTECTION_FLAG]);
                break;

        case eCMD_DATA_RATES:
                qsap_read_cfg(fIni, qsap_str[STR_DATA_RATE_IN_INI], presp, plen, cmd_list[eCMD_DATA_RATES]);
                break;

        case eCMD_ASSOC_STA_MACS:
                qsap_get_associated_sta_mac(presp, plen);
                break;

        case eCMD_TX_POWER:
                qsap_read_cfg(fIni, qsap_str[STR_TX_POWER_IN_INI], presp, plen, cmd_list[eCMD_TX_POWER]);
                break;

        case eCMD_SDK_VERSION:
                *plen = snprintf(presp, *plen, "%s", QSAP_SDK_VERSION);
                break;

        case eCMD_INTRA_BSS_FORWARD:
                qsap_read_cfg(fIni, qsap_str[STR_INTRA_BSS_FORWARD_IN_INI], presp, plen, cmd_list[eCMD_INTRA_BSS_FORWARD]);
                break;

        case eCMD_COUNTRY_CODE:
                qsap_read_cfg(fIni, qsap_str[STR_COUNTRY_CODE_IN_INI], presp, plen, cmd_list[eCMD_COUNTRY_CODE]);
                break;

        default:
            /** Error case */
            *plen = snprintf(presp, *plen, "%s", ERR_INVALID_ARG);
    }

    len = *plen-1;

    /** Remove the space or tabs in the end of response */
    while(len) {
        if((presp[len] == ' ') || (presp[len] == '\t'))
            len--;
        else
            break;
    }
    presp[len+1] = '\0';
    *plen = len+1;

    return;
}

/**
 * @brief 
 *        Identify the command number corresponding to the input user command.
 * @param cName [INPUT] command name
 * @return 
 *             On success,
 *                     command number in the range 0 to (eCMD_INVALID-1)
 *          On failure,
 *                  eCMD_INVALID
**/
static esap_cmd_t qsap_get_cmd_num(s8 *cName)
{
    s16 i, len;

    for(i=0; i<eCMD_LAST; i++)     {
        len = strlen(cmd_list[i]);
        if(!strncmp(cmd_list[i], cName, len)) {
            if((cName[len] == '=') || (cName[len] == '\0'))
                return i;
        }
    }
    return eCMD_INVALID;
}

/**
 * @brief
 *            Handle the user requests of the form,
 *                "get <cmd num> [<value1> ...]"
 *           These commands are used to retreive the soft AP
 *           configuration information
 *
 * @param pcmd [IN] pointer to the string, storing the command.
 * @param presp [OUT] pointer to the buffer, to store the command response.
 *                         The command output format :
 *                    On success,
 *                            success <cmd>=<value>
 *                    On failure,
 *                            failure <error message>
 * @param plen [IN-OUT]
 *                 [IN] : Maximum length of the reponse buffer
 *                [OUT]: Reponse length
 * @return 
 *         void
*/
static void qsap_handle_get_request(s8 *pcmd, s8 *presp, u32 *plen)
{
    esap_cmd_t cNum;

    pcmd += strlen("get");
    
    SKIP_BLANK_SPACE(pcmd);

    cNum = qsap_get_cmd_num(pcmd);

    if(cNum == eCMD_INVALID) {
        *plen = snprintf(presp, *plen, "%s", ERR_INVALID_PARAM);
        return;
    }
    
    qsap_get_from_config(cNum, presp, plen);

    return;        
}

static s16 is_valid_wep_key(s8 *pwep)
{
    int weplen;
    s16 ret = TRUE;

    /** The WEP key should be of length 5, 13 or 16 characters
      * or 10, 26, or 32 digits */
    weplen = strlen(pwep);
    switch(weplen) {
        case WEP_64_KEY_ASCII:
        case WEP_128_KEY_ASCII:
        case WEP_152_KEY_ASCII:
                while(weplen--) {
                    if(0 == isascii(pwep[weplen]))
                        return FALSE;
                }
                break;

        case WEP_64_KEY_HEX:
        case WEP_128_KEY_HEX:
        case WEP_152_KEY_HEX:
                while(weplen--) {
                    if(0 == isxdigit(pwep[weplen]))
                        return FALSE;
                }
                break;

        default:
            ret = FALSE;
    }
    return ret;
}

static s16 wifi_qsap_reset_to_default(void)
{
    FILE *fcfg, *ftmp;
    char buf[MAX_CONF_LINE_LEN];
    int status = eSUCCESS;

    fcfg = fopen(DEFAULT_CONFIG_FILE_PATH, "r");

    if(NULL == fcfg) {
        LOGE("%s : unable to open file \n", __func__);
        return eERR_FILE_OPEN;
    }

    ftmp = fopen(TMP_FILE, "w");
    if(NULL == ftmp) {
        LOGE("%s : unable to open file \n", __func__);
        fclose(fcfg);
        return eERR_FILE_OPEN;
    }
    
    while(NULL != fgets(buf, MAX_CONF_LINE_LEN, fcfg)) {
        fprintf(ftmp, "%s", buf);
    }

    fclose(fcfg);
    fclose(ftmp);

    if(eERR_UNKNOWN == rename(TMP_FILE, pconffile))
        status = eERR_CONF_FILE;

    /** Remove the temporary file. Dont care the return value */
    unlink(TMP_FILE);

    return status;
}

#define CTRL_IFACE_PATH_LEN   (128)
static int qsap_send_cmd_to_hostapd(s8 *pcmd)
{
    int sock;
    struct sockaddr_un cli;
    struct sockaddr_un ser;
    struct timeval timeout;
    int ret = eERR_SEND_TO_HOSTAPD;
    u32 len;
    fd_set read;
    s8 dst_path[CTRL_IFACE_PATH_LEN], *pcif, *pif;
    s8 interface[64];
    s8 *ptr;
    u32 retry_cnt = 3;

    len = CTRL_IFACE_PATH_LEN;

#define RESP_BUF_SIZE (80)
    ptr = malloc(RESP_BUF_SIZE);
    if(NULL == ptr) {
        LOGE("%s :No memory \n", __func__);
        return ret;
    }
    
    if(NULL == (pcif = qsap_get_config_value(pconffile, qsap_str[STR_CTRL_INTERFACE], dst_path, &len))) {
        LOGE("%s :ctrl_iface path error \n", __func__);
        goto error;
    }

    len = 64;

    if(NULL == (pif = qsap_get_config_value(pconffile, qsap_str[STR_INTERFACE], interface, &len))) {
        LOGE("%s :interface error \n", __func__);
        goto error;
    }

    if(CTRL_IFACE_PATH_LEN <= snprintf(ptr, CTRL_IFACE_PATH_LEN-1, "%s/%s", pcif, pif)) {
        LOGE("Iface path : error, %s \n", ptr);
        goto error;
    }

    LOGD("Connect to :%s\n", ptr);

    sock = socket(PF_UNIX, SOCK_DGRAM, 0);
    if(sock < 0) {
        LOGE("%s :Socket error \n", __func__);
        goto error;
    }

    cli.sun_family = AF_UNIX;
    snprintf(cli.sun_path, sizeof(cli.sun_path), SDK_CTRL_IF);

    ret = bind(sock, (struct sockaddr *)&cli, sizeof(cli));

    if(ret < 0) {
        LOGE("Bind Failure\n");
        goto close_ret;
    }
    
    ser.sun_family = AF_UNIX;
    snprintf(ser.sun_path, sizeof(ser.sun_path), "%s", ptr);
    LOGD("Connect to: %s,(%d)\n", ser.sun_path, sock);

    ret = connect(sock, (struct sockaddr *)&ser, sizeof(ser));
    if(ret < 0) {
        LOGE("Connect Failure...\n");
        goto close_ret;
    }
    
    ret = send(sock, pcmd, strlen(pcmd), 0);
    if(ret < 0) {
        LOGE("Unable to send cmd to hostapd \n");
        goto close_ret;
    }

    len = RESP_BUF_SIZE;
    
#define HOSTAPD_RECV_TIMEOUT    (2)
    while(1) {
        timeout.tv_sec = HOSTAPD_RECV_TIMEOUT;
        timeout.tv_usec = 0;
        
        FD_ZERO(&read);
        FD_SET(sock, &read);

        ret = select(sock+1, &read, NULL, NULL, &timeout);
        
        if(FD_ISSET(sock, &read)) {

            ret = recv(sock, ptr, len, 0);

            if(ret < 0) {
                LOGE("%s: recv() failed \n", __func__);
                goto close_ret;
            }

            if((ret > 0) && (ptr[0] == '<')) {
                ptr[ret] = 0;
                LOGE("Not the expected response...\n: %s", ptr);
                retry_cnt--;
                if(retry_cnt)
                    continue;
                break;
            }

            ptr[len] = '\0';
            if(!strncmp(ptr, "FAIL", 4)) {
                LOGE("Command failed in hostapd \n");
                goto close_ret;
            }
        }
        else {
            LOGE("%s: Select failed \n", __func__);
            goto close_ret;
        }    
    }

    ret = eSUCCESS;

close_ret:
    close(sock);

error:
    free(ptr);
    unlink(SDK_CTRL_IF);
    return ret;
}

static void qsap_update_wps_config(s8 *pVal, s8 *presp, u32 *plen)
{
    u32 tlen = *plen;
    s32 status;
    s8  pwps_state[8];
    s32 cmd, i;

    /* Enable/disable the following in hostapd.conf
     * 1. Change the security mode to WPA-WPA2 Mixed
     * 2. Update wps_state
     * 3. Update config_methods
     * 4. Update UPnP related variables
     */
    status = atoi(pVal);

    if(status == ENABLE) {
        snprintf(pwps_state, 8, "%d", WPS_STATE_ENABLE);
        cmd = SEC_MODE_WPA_WPA2_PSK;
    }
    else {
        snprintf(pwps_state, 8, "%d", WPS_STATE_DISABLE);
        cmd = SEC_MODE_NONE;
    }

    qsap_write_cfg(pconffile, cmd_list[eCMD_WPS_STATE], pwps_state, presp, &tlen, HOSTAPD_CONF_FILE);

    snprintf(pwps_state, 8, "%d", ENABLE);

    /** update the eap_server=1 */    
    qsap_write_cfg(pconffile, qsap_str[STR_EAP_SERVER], pwps_state, presp, plen, HOSTAPD_CONF_FILE);
    
    for(i=eCMD_UUID; i<=eCMD_UPC; i++) {
        if(eERR_UNKNOWN == qsap_change_cfg(pconffile, cmd_list[i], status)) {
            LOGE("%s: failed to set %s\n", __func__, cmd_list[i]);
            goto error;
        }
    }

    return;
error:
    *plen = snprintf(presp, *plen, "%s", ERR_UNKNOWN);

    return;
}

static void qsap_config_wps_method(s8 *pVal, s8 *presp, u32 *plen)
{
    s8 buf[64];
    s8 *ptr;
    int i;
    s32 value;

    /** INPUT : <0/1> <PIN> */
    /** PBC method : WPS_PBC */
    /** PIN method : WPS_PIN any <key> */
    ptr = pVal;
    i = 0;

    while((*ptr != '\0') && (*ptr != ' ')) {
        buf[i] = *ptr;
        ptr++;
        i++;
    }

    buf[i] = '\0';

    /** Identify the WPS method */
    value = atoi(buf);
    if(TRUE != IS_VALID_WPS_CONFIG(value)) {
        *plen = snprintf(presp, *plen, "%s", ERR_INVALID_PARAM);
        return;
    }

    SKIP_BLANK_SPACE(ptr);

    if( (value == WPS_CONFIG_PIN) && (*ptr == '\0') ){
        LOGE("%s :Invalid command \n", __func__);
        *plen = snprintf(presp, *plen, "%s", ERR_INVALID_PARAM);
        return;
    }

    if(value == WPS_CONFIG_PBC)
        snprintf(buf, 64, "WPS_PBC");
    else {
        if(strlen(ptr) < WPS_KEY_LEN) {
            LOGD("%s :Invalid WPS key length\n", __func__);
            *plen = snprintf(presp, *plen, "%s", ERR_INVALID_PARAM);
            return;
        }
        snprintf(buf, 64, "WPS_PIN any %s", ptr);
    }

    value = qsap_send_cmd_to_hostapd(buf);

    *plen = snprintf(presp, *plen, "%s", (value == eSUCCESS) ? SUCCESS: ERR_UNKNOWN);

    return;
}


s32 atoh(u8 *str)
{
    u32 val = 0;
    u32 pos = 0;
    s32 len = strlen((char *)str) - 1;

    while(len >= 0) {
        switch(str[len]) {

        case '0' ... '9':
                val += (str[len] - '0') << pos;
                break;

        case 'a' ... 'f':
                val += (str[len] - 'a' + 10) << pos;
                break;

        case 'A'... 'F':
                val += (str[len] - 'A' + 10) << pos;
                break;
        }
        len--;
        pos += 4;
    }

    return val;
}

int qsap_get_mac_in_bytes(char *psmac, char *pbmac)
{
    int val;
    u8 str[3];
    u32 i;

    str[2] = '\0';

    if(FALSE == isValid_MAC_address(psmac)) {
        return FALSE;
    }

    for(i=0; i<strlen(psmac); i++) {
        if(psmac[i] == ':')
            continue;

        str[0] = psmac[i];
        str[1] = psmac[i+1];
        val = atoh(str);
        *pbmac = val;
        pbmac++;
        i += 2;
    }
    *pbmac = 0;

    return TRUE;
}

void qsap_disassociate_sta(s8 *pVal, s8 *presp, u32 *plen)
{
    int sock, ret = eERR_UNKNOWN;
    struct iwreq wrq;
    s8 pbuf[MAX_CONF_LINE_LEN];
    u32 len = MAX_CONF_LINE_LEN;
    s8 *pif;

    if(NULL == (pif = qsap_get_config_value(pconffile, qsap_str[STR_INTERFACE], pbuf, &len))) {
        LOGE("%s :interface error \n", __func__);
        goto end;
    }

    pbuf[len] = '\0';

    sock = socket(AF_INET, SOCK_DGRAM, 0);
    if(sock < 0) {
        LOGE("%s: socket failure \n", __func__);
        goto end;
    }

    strncpy(wrq.ifr_name, pif, sizeof(wrq.ifr_name));
    
    if(TRUE != qsap_get_mac_in_bytes(pVal, pbuf)) {
        LOGE("%s: Invalid input \n", __func__);
        goto end;    
    }

    wrq.u.data.length = MAC_ADDR_LEN_INT;
    wrq.u.data.pointer = (void *)pbuf;
    wrq.u.data.flags = 0;

    ret = ioctl(sock, QCSAP_IOCTL_DISASSOC_STA, &wrq);
    if(ret < 0) {
        LOGE("%s: ioctl failure \n", __func__);
    }

end:
    *plen = snprintf(presp, *plen, "%s", (ret == eSUCCESS) ? SUCCESS : ERR_UNKNOWN);

    return;
}

static int qsap_set_channel(s32 channel, s8 *tbuf, u32 *tlen)
{
    u32 ulen;
    s8 *pcfgval;
    s8 schan[MAX_INT_STR+1];
    s8 *pcfg = pconffile; 

    ulen = *tlen;

    /** Read the current operating mode */
    if(NULL == (pcfgval = qsap_get_config_value(pconffile, cmd_list[eCMD_HW_MODE], tbuf, &ulen))) {
        return eERR_UNKNOWN;
    }

    /** If the operating mode is NOT 'B' and the channel to be set is 12, 13 or 14
      * then change the operating mode to 'N' mode */
    if(strcmp(hw_mode[HW_MODE_B], pcfgval) && (channel > 11)) {
        /** Change the operating mode to 'B' */
        ulen = *tlen;
        if(eSUCCESS != qsap_write_cfg(pcfg, cmd_list[eCMD_HW_MODE], hw_mode[HW_MODE_B], tbuf, &ulen, HOSTAPD_CONF_FILE)) {
            LOGE("%s :Unable to update the operating mode \n", __func__);
            return eERR_UNKNOWN;
        }

        ulen = *tlen;
        snprintf(schan, MAX_INT_STR, "%d", AUTO_DATA_RATE);
        if(eSUCCESS != qsap_write_cfg(fIni, qsap_str[STR_DATA_RATE_IN_INI], schan, tbuf, &ulen, HOSTAPD_CONF_FILE)) {
            LOGE("%s :Unable to set to auto data rate \n", __func__);
            return eERR_UNKNOWN;
        }
    }

    snprintf(schan, MAX_INT_STR, "%ld", channel);

    return qsap_write_cfg(pcfg, cmd_list[eCMD_CHAN], schan, tbuf, tlen, HOSTAPD_CONF_FILE);
}

static int qsap_set_operating_mode(s32 mode, s8 *pmode, s8 *tbuf, u32 *tlen)
{
    u32 ulen;
    s8 *pcfgval;
    s32 channel;
    s8 sconf[MAX_INT_STR+1];
    s8 *pcfg = pconffile;
    s32 rate_idx; 

    ulen = *tlen;

    /** Read the current operating channel */
    if(NULL == (pcfgval = qsap_get_config_value(pconffile, cmd_list[eCMD_CHAN], tbuf, &ulen))) {
        LOGE("%s :Read mode error \n", __func__);
        return eERR_UNKNOWN;
    }

    /** If the operating channel is 12, 13 or 14 and the mode to be set is not
        'B' mode, then change the channel to auto channel */
    channel = atoi(pcfgval);

    if((channel > BG_MAX_CHANNEL) && (mode != HW_MODE_B)) {
        /** change to AUTO channel */
        ulen = *tlen;
        snprintf(sconf, MAX_INT_STR, "%d", AUTO_CHANNEL);
        if(eSUCCESS != qsap_write_cfg(pcfg, cmd_list[eCMD_CHAN], sconf, tbuf, &ulen, HOSTAPD_CONF_FILE)) {
            LOGE("%s :Unable to update the channel \n", __func__);
            return eERR_UNKNOWN;
        }
    }

    ulen = *tlen;
    if(NULL == (pcfgval = qsap_get_config_value(fIni, qsap_str[STR_DATA_RATE_IN_INI], tbuf, &ulen))) {
        LOGE("%s :Read mode error \n", __func__);
        return eERR_UNKNOWN;
    }

    /** Update the data rate, depending on the mode to be set */
    rate_idx = atoi(pcfgval);
    if(((mode == HW_MODE_B) && (rate_idx > B_MODE_MAX_DATA_RATE_IDX)) ||
        (((mode == HW_MODE_G) || (mode == HW_MODE_G_ONLY)) && (rate_idx > G_ONLY_MODE_MAX_DATA_RATE_IDX))) {
        snprintf(sconf, MAX_INT_STR, "%d", AUTO_DATA_RATE);
        ulen = *tlen;
        qsap_write_cfg(fIni, qsap_str[STR_DATA_RATE_IN_INI], sconf, tbuf, &ulen, INI_CONF_FILE);
    }

    /** Update the operating mode */
    return qsap_write_cfg(pcfg, cmd_list[eCMD_HW_MODE], pmode, tbuf, tlen, HOSTAPD_CONF_FILE);
}

static int qsap_set_data_rate(s32 drate_idx, s8 *presp, u32 *plen)
{
    u32 ulen;
    s8 *pmode;
    s8 sconf[MAX_INT_STR+1];
    int ret = eERR_UNKNOWN;

    if(TRUE != IS_VALID_DATA_RATE_IDX(drate_idx)) {
        LOGE("%s :Invalid rate index \n", __func__);
        goto end;
    }

    ulen = *plen;
    /** Read the current operating mode */
    if(NULL == (pmode = qsap_get_config_value(pconffile, cmd_list[eCMD_HW_MODE], presp, &ulen))) {
        LOGE("%s :Unable to read mode \n", __func__);
        goto end;
    }

    /** Validate the rate index against the current operating mode */
    if(((!strcmp(pmode, hw_mode[HW_MODE_B])) && (drate_idx > B_MODE_MAX_DATA_RATE_IDX)) || 
        ((!strcmp(pmode, hw_mode[HW_MODE_G]) || (!strcmp(pmode, hw_mode[HW_MODE_G_ONLY]))) && 
        (drate_idx > G_ONLY_MODE_MAX_DATA_RATE_IDX))) {
        LOGE("%s :Invalid rate index \n", __func__);
        goto end;
    }
   
    snprintf(sconf, MAX_INT_STR, "%ld", drate_idx);

    /** Update the rate index in the configuration */
    return qsap_write_cfg(fIni, qsap_str[STR_DATA_RATE_IN_INI], sconf, presp, plen, INI_CONF_FILE);

end:
    *plen = snprintf(presp, *plen, "%s", ERR_UNKNOWN);

    return ret;
}

/**
 * @brief
 *     Handle the user requests of the form,
 *     "set <cmd num> <value1> ..."
 *     These commands are used to update the soft AP
 *     configuration information
 *
 * @param pcmd [IN]   pointer to the string, storing the command.
 * @param presp [OUT] pointer to the buffer, to store the command response.
 *                    The command output format :
 *                    On success,
 *                            success
 *                    On failure,
 *                            failure <error message>
 * @param plen [IN-OUT]
 *                 [IN]: Maximum length of the reponse buffer
 *                [OUT]: Reponse length
 * @return 
 *         void
*/
static void qsap_handle_set_request(s8 *pcmd, s8 *presp, u32 *plen)
{
    esap_cmd_t cNum;
    esap_str_t sNum = STR_DENY_MAC_FILE;
    s8 *pVal, *pfile;
    s8 filename[MAX_FILE_PATH_LEN];
    u32 ulen;
    s32 status;
    s32 value;
    s16 ini = HOSTAPD_CONF_FILE;
    s8 *pcfg = pconffile; 

    pcmd += strlen("set");
    
    SKIP_BLANK_SPACE(pcmd);

    cNum = qsap_get_cmd_num(pcmd);
    if(cNum == eCMD_INVALID) {
        *plen = snprintf(presp, *plen, "%s", ERR_INVALID_ARG);
        LOGE("Invalid command number :%d\n", cNum);
        return;
    }

    pVal = pcmd + strlen(cmd_list[cNum]);
    if( (cNum != eCMD_COMMIT) &&
        (cNum != eCMD_RESET_TO_DEFAULT) && 
        ((*pVal != '=') || (strlen(pVal) < 2)) ) {
        *plen = snprintf(presp, *plen, "%s", ERR_INVALID_ARG);
        return;
    }
    pVal++;

    if((cNum != eCMD_COMMIT) && (cNum != eCMD_RESET_TO_DEFAULT)) {
        LOGE("Cmd: %s Argument :%s \n", cmd_list[cNum], pVal);
    }

    switch(cNum) {
        case eCMD_ADD_TO_ALLOW:
        case eCMD_REMOVE_FROM_ALLOW:
            sNum = STR_ACCEPT_MAC_FILE;
            /* fall through */

        case eCMD_ADD_TO_DENY:
        case eCMD_REMOVE_FROM_DENY:
            ulen = MAX_FILE_PATH_LEN;
            if(NULL != (pfile = qsap_get_allow_deny_file_name(pconffile, qsap_str[sNum], filename, &ulen))) {
                qsap_update_mac_list(pfile, cNum, pVal, presp, plen);
            }
            else {
                *plen = snprintf(presp, *plen, "%s", ERR_RES_UNAVAILABLE); 
            }
            return;

        case eCMD_SEC_MODE:
            value = atoi(pVal);
            if(FALSE == IS_VALID_SEC_MODE(value))
                goto error;
            /** Write back the integer value. This is to avoid values like 01, 001, 0001
             * being written to the configuration
             */
            snprintf(pVal, sizeof(u32), "%ld", value);
            qsap_set_security_mode(pconffile, value, presp, plen);
            return;

        case eCMD_MAC_ACL:
            value = atoi(pVal);
            if(FALSE == IS_VALID_MAC_ACL(value))
                goto error;
                
            /** Write back the integer value. This is to avoid values like 01, 001, 0001
              * being written to the configuration
              */
            snprintf(pVal, sizeof(u32), "%ld", value);
                
            if(ACL_ALLOW_LIST == value) {
                value = ENABLE;
                status = DISABLE;
            }
            else {
                value = DISABLE;
                status = ENABLE;
            }

            if(eERR_UNKNOWN != qsap_change_cfg(pconffile, qsap_str[STR_ACCEPT_MAC_FILE], value)) {
                if(eERR_UNKNOWN != qsap_change_cfg(pconffile, qsap_str[STR_DENY_MAC_FILE], status))
                {
                    qsap_write_cfg(pconffile, cmd_list[cNum], pVal, presp, plen, HOSTAPD_CONF_FILE);
                }
                else {
                    goto error;    
                }
            }
            else {
                goto error;
            }
            return;

        case eCMD_COMMIT:
            if ( gIniUpdated ) {
                status = wifi_qsap_reload_softap();
                gIniUpdated = 0;
            }
            else {
                status = commit();
            }
            *plen = snprintf(presp, *plen, "%s", (status ==  eSUCCESS)? SUCCESS : ERR_UNKNOWN);
            return;

        case eCMD_ENABLE_SOFTAP:
            value = atoi(pVal);

            if(TRUE != IS_VALID_SOFTAP_ENABLE(value))
                goto error;

            if ( *pVal == '0' ) {
                status = wifi_qsap_stop_softap();
                if(status == eSUCCESS)
                    status = wifi_qsap_unload_driver();
            }
            else {
                status = wifi_qsap_load_driver();
                if(status == eSUCCESS)
                    status = wifi_qsap_start_softap();
            }
            *plen = snprintf(presp, *plen, "%s", (status==eSUCCESS) ? SUCCESS : "failure Could not enable softap");
            return;

        case eCMD_SSID:
            value = strlen(pVal);
            if(SSD_MAX_LEN < value)
                goto error;
            break;

        case eCMD_BSSID:
            value = atoi(pVal);
            if(FALSE == IS_VALID_BSSID(value))
                goto error;
            /** Write back the integer value. This is to avoid values like 01, 001, 0001
              * being written to the configuration
              */
            snprintf(pVal, MAX_INT_STR, "%ld", value);
            break;
        case eCMD_PASSPHRASE:
            value = strlen(pVal);
            if(FALSE == IS_VALID_PASSPHRASE_LEN(value))
                goto error;
            break;

        case eCMD_CHAN:
            value = atoi(pVal);
            if(FALSE == IS_VALID_CHANNEL(value))
                goto error;

            ulen = MAX_FILE_PATH_LEN;
            value = qsap_set_channel(value, filename, &ulen);

            *plen = snprintf(presp, *plen, "%s", (value == eSUCCESS) ? SUCCESS : ERR_UNKNOWN);
            return;

        case eCMD_BCN_INTERVAL:
            value = atoi(pVal);
            if(FALSE == IS_VALID_BEACON(value))
                goto error;
            /** Write back the integer value. This is to avoid values like 01, 001, 0001
              * being written to the configuration
              */
            snprintf(pVal, MAX_INT_STR, "%ld", value);
            break;

        case eCMD_DTIM_PERIOD:
            value = atoi(pVal);
            if(FALSE == IS_VALID_DTIM_PERIOD(value))
                goto error;
            /** Write back the integer value. This is to avoid values like 01, 001, 0001
              * being written to the configuration
              */
            snprintf(pVal, MAX_INT_STR, "%ld", value);
            break;

        case eCMD_HW_MODE:
            status = FALSE;
            for(value=HW_MODE_B; value<HW_MODE_UNKNOWN; value++) {
                if(!strcmp(pVal, hw_mode[value])) {
                    status = TRUE;
                    break;
                }
            }

            /** TODO: Modify the channel number based on the mode */
            if(status == FALSE)
                goto error;

            ulen = MAX_FILE_PATH_LEN;
            value = qsap_set_operating_mode(value, pVal, filename, &ulen);
            *plen = snprintf(presp, *plen, "%s", (value == eSUCCESS) ? SUCCESS : ERR_UNKNOWN);
            return;

        case eCMD_AUTH_ALGS:
            value = atoi(pVal);
            if((value != AHTH_ALG_OPEN) && (value != AUTH_ALG_SHARED) &&
                          (value != AUTH_ALG_OPEN_SHARED))
                goto error;
            /** Write back the integer value. This is to avoid values like 01, 001, 0001
              * being written to the configuration
              */
            snprintf(pVal, MAX_INT_STR, "%ld", value);
            break;

        case eCMD_DEFAULT_KEY:
            value = atoi(pVal);
            if(FALSE == IS_VALID_WEP_KEY_IDX(value))
                goto error;
             /** Write back the integer value. This is to avoid values like 01, 001, 0001
               * being written to the configuration
               */
            snprintf(pVal, MAX_INT_STR, "%ld", value);
            
            qsap_write_cfg(pcfg, cmd_list[cNum], pVal, presp, plen, ini);
        
            ulen = MAX_FILE_PATH_LEN;
            if(SEC_MODE_WEP != qsap_read_security_mode(pcfg, filename, &ulen)) {
                if(eERR_UNKNOWN == qsap_change_cfg(pcfg, cmd_list[cNum], 0)) {
                    LOGE("%s: CMD_WEP_KEY0 \n", __func__);
                    goto error;
                }
            }

            return;

        case eCMD_WPA_PAIRWISE:
        case eCMD_RSN_PAIRWISE:
            if(FALSE == IS_VALID_PAIRWISE(pVal))
                goto error;

            /** If the encryption type is TKIP, disable the 802.11 HT */
            value = 1;
            if(!strcmp(pVal, "TKIP")) {
                value = 0;
            }

            if(eERR_UNKNOWN == qsap_change_cfg(pconffile, qsap_str[STR_HT_80211N], value)) {
                LOGE("%s: unable to update 802.11 HT\n", __func__);
                goto error;
            }

            break;

        case eCMD_WEP_KEY0:
        case eCMD_WEP_KEY1:
        case eCMD_WEP_KEY2:
        case eCMD_WEP_KEY3:
            if(FALSE == is_valid_wep_key(pVal))
                goto error;
        
            qsap_write_cfg(pcfg, cmd_list[cNum], pVal, presp, plen, ini);

            /** if the security mode is not WEP, update the WEP features, and
                do NOT set the WEP security */
            ulen = MAX_FILE_PATH_LEN;
            if(SEC_MODE_WEP != qsap_read_security_mode(pcfg, filename, &ulen)) {
                if(eERR_UNKNOWN == qsap_change_cfg(pcfg, cmd_list[cNum], 0)) {
                    LOGE("%s: CMD_WEP_KEY0 \n", __func__);
                    goto error;
                }
            }

            return;

        case eCMD_RESET_AP:
            value = atoi(pVal);
            LOGE("Reset :%ld \n", value);
            if(SAP_RESET_BSS == value) {
                status = wifi_qsap_stop_softap();
                if(status == eSUCCESS)
                    wifi_qsap_start_softap();
            }
            else if(SAP_RESET_DRIVER_BSS == value){
                status = wifi_qsap_reload_softap();
            }
            else if(SAP_STOP_BSS == value) {
                status = wifi_qsap_stop_bss();
            }
            else if(SAP_STOP_DRIVER_BSS == value) {
                status = wifi_qsap_stop_softap();
                if(status == eSUCCESS)
                    status = wifi_qsap_unload_driver();
            }
            else {
                status = !eSUCCESS;
            }
            *plen = snprintf(presp, *plen, "%s", (status == eSUCCESS) ? SUCCESS : ERR_UNKNOWN);
            return;

        case eCMD_DISASSOC_STA:
            qsap_disassociate_sta(pVal, presp, plen);
            return;

        case eCMD_RESET_TO_DEFAULT:
            if(eSUCCESS == (status = wifi_qsap_reset_to_default()))
                status = commit();
            *plen = snprintf(presp, *plen, "%s", (status ==  eSUCCESS) ? SUCCESS : ERR_UNKNOWN);
            return;

        case eCMD_DATA_RATES:
            value = atoi(pVal);
            qsap_set_data_rate(value, presp, plen);
            return;

        case eCMD_UUID:
            value = strlen(pVal);
            if(TRUE != IS_VALID_UUID_LEN(value))
                goto error;
            break;
        case eCMD_DEVICE_NAME:
            value = strlen(pVal);
            if(TRUE != IS_VALID_DEVICENAME_LEN(value))
                goto error;
            break;
        case eCMD_MANUFACTURER:
            value = strlen(pVal);
            if(TRUE != IS_VALID_MANUFACTURER_LEN(value))
                goto error;
            break;

        case eCMD_MODEL_NAME:
            value = strlen(pVal);
            if(TRUE != IS_VALID_MODELNAME_LEN(value))
                goto error;
            break;

        case eCMD_MODEL_NUMBER:
            value = strlen(pVal);
            if(TRUE != IS_VALID_MODELNUM_LEN(value))
                goto error;
            break;

        case eCMD_SERIAL_NUMBER:
            value = strlen(pVal);
            if(TRUE != IS_VALID_SERIALNUM_LEN(value))
                goto error;
            break;

        case eCMD_DEVICE_TYPE:
            value = strlen(pVal);
            if(TRUE != IS_VALID_DEV_TYPE_LEN(value))
                goto error;
            break;

        case eCMD_OS_VERSION:
            value = strlen(pVal);
            if(TRUE != IS_VALID_OS_VERSION_LEN(value))
                goto error;
            break;

        case eCMD_FRIENDLY_NAME:
            value = strlen(pVal);
            if(TRUE != IS_VALID_FRIENDLY_NAME_LEN(value))
                goto error;
            break;

        case eCMD_MANUFACTURER_URL:
        case eCMD_MODEL_URL:
            value = strlen(pVal);
            if(TRUE != IS_VALID_URL_LEN(value))
                goto error;
            break;

        case eCMD_MODEL_DESC:
            value = strlen(pVal);
            if(TRUE != IS_VALID_MODEL_DESC_LEN(value))
                goto error;
            break;

        case eCMD_UPC:
            value = strlen(pVal);
            if(TRUE != IS_VALID_UPC_LEN(value))
                goto error;
            break;

        case eCMD_WMM_STATE:
            value = atoi(pVal);
            if(TRUE != IS_VALID_WMM_STATE(value))
                goto error;

            if(value == ENABLE)
                value = WMM_ENABLED_IN_INI;
            else
                value = WMM_DISABLED_IN_INI;
            snprintf(pVal, MAX_INT_STR, "%ld", value);
            cNum = STR_WMM_IN_INI;
            ini = INI_CONF_FILE; 
            break;

        case eCMD_WPS_STATE:
            value = atoi(pVal);
            if(TRUE != IS_VALID_WPS_STATE(value))
                goto error;
            /** Write back the integer value. This is to avoid values like 01, 001, 0001
              * being written to the configuration
              */
            snprintf(pVal, MAX_INT_STR, "%ld", value);
            qsap_update_wps_config(pVal, presp, plen);
            return;

        case eCMD_WPS_CONFIG_METHOD:
            qsap_config_wps_method(pVal, presp, plen);
            return;

        case eCMD_PROTECTION_FLAG:
            value = atoi(pVal);
            if(TRUE != IS_VALID_PROTECTION(value))
                goto error;
            snprintf(pVal, MAX_INT_STR, "%ld", value);
            cNum = STR_PROT_FLAG_IN_INI;
            ini = INI_CONF_FILE;
            break;

        case eCMD_FRAG_THRESHOLD:
            value = atoi(pVal);
            if(TRUE != IS_VALID_FRAG_THRESHOLD(value))
                goto error;
            snprintf(pVal, MAX_INT_STR, "%ld", value);
             
            cNum = STR_FRAG_THRESHOLD_IN_INI;
            ini = INI_CONF_FILE;
            break;

        case eCMD_REGULATORY_DOMAIN:
            value = atoi(pVal);

            if(TRUE != IS_VALID_802DOT11D_STATE(value))
                goto error;

            snprintf(pVal, MAX_INT_STR, "%ld", value);
            cNum = STR_802DOT11D_IN_INI;
            ini = INI_CONF_FILE;
            break;

        case eCMD_RTS_THRESHOLD:
            value = atoi(pVal);
            if(TRUE != IS_VALID_RTS_THRESHOLD(value))
                goto error;
            snprintf(pVal, MAX_INT_STR, "%ld", value);
            cNum = STR_RTS_THRESHOLD_IN_INI;
            ini = INI_CONF_FILE;
            break;

        case eCMD_GTK_TIMEOUT:
            value = atoi(pVal);
            if(TRUE != IS_VALID_GTK(value))
                goto error;

            break;

        case eCMD_TX_POWER:
            value = atoi(pVal);
            if(TRUE != IS_VALID_TX_POWER(value))
                goto error;
            snprintf(pVal, sizeof(u32), "%ld", value);
            cNum = STR_TX_POWER_IN_INI;
            ini = INI_CONF_FILE; 
            break;

        case eCMD_INTRA_BSS_FORWARD:
            value = atoi(pVal);
            if(TRUE != IS_VALID_INTRA_BSS_STATUS(value))
                goto error;

            snprintf(pVal, MAX_INT_STR, "%ld", value);
            cNum = STR_INTRA_BSS_FORWARD_IN_INI;
            ini = INI_CONF_FILE;
            break;    
        
        case eCMD_COUNTRY_CODE:
            cNum = STR_COUNTRY_CODE_IN_INI;
            ini = INI_CONF_FILE;
            break;

        default: ;
            /** Do not goto error, in default case */
    }

    if(ini == INI_CONF_FILE) {
        LOGD("WRITE TO INI FILE :%s\n", qsap_str[cNum]);
        qsap_write_cfg(fIni, qsap_str[cNum], pVal, presp, plen, ini);
    }
    else {
        qsap_write_cfg(pcfg, cmd_list[cNum], pVal, presp, plen, ini);
    }

    return;

error:
    *plen = snprintf(presp, *plen, "%s", ERR_INVALID_PARAM);
    return;
}

/**
 * @brief
 *      Initiate the command and return response
 * @param pcmd string containing the command request
 *     The format of the command is 
 *         get param=value
 *             or
 *         set param=value
 * @param presp buffer to store the command response
 * @param plen length of the respone buffer
 * @return 
 *         void
*/
void qsap_hostd_exec_cmd(s8 *pcmd, s8 *presp, u32 *plen)
{
    LOGD("CMD INPUT  [%s][%lu]\n", pcmd, *plen);
    /* Skip any blank spaces */
    SKIP_BLANK_SPACE(pcmd);

    if(!strncmp(pcmd, Cmd_req[eCMD_GET], strlen(Cmd_req[eCMD_GET])) && isblank(pcmd[strlen(Cmd_req[eCMD_GET])])) {
        qsap_handle_get_request(pcmd, presp, plen);
    }

    else if(!(strncmp(pcmd, Cmd_req[eCMD_SET], strlen(Cmd_req[eCMD_SET]))) && isblank(pcmd[strlen(Cmd_req[eCMD_SET])]) ) {
        qsap_handle_set_request(pcmd, presp, plen);
    }

    else {
        *plen = snprintf(presp, *plen, "%s", ERR_INVALIDREQ);
    }

    LOGD("CMD OUTPUT [%s]\nlen :%lu\n\n", presp, *plen);
    
    return;
}

/* netd and Froyo Native UI specific API */
#define DEFAULT_SSID         "SOFTAP_SSID"
#define DEFAULT_CHANNEL      4
#define DEFAULT_PASSPHRASE   "12345678"
#define DEFAULT_AUTH_ALG     1
#define RECV_BUF_LEN         128
#define CMD_BUF_LEN          80

/** Command input
    argv[4] = SSID,
    argv[5] = SEC,
    argv[6] = 12345,
    argv[7] = CHANNEL
    argv[8] = PREAMBLE,
    argv[9] = MAX_SCB,
*/
int qsapsetSoftap(int argc, char *argv[])
{
    char cmdbuf[CMD_BUF_LEN];
    char respbuf[RECV_BUF_LEN];
    unsigned long int rlen = RECV_BUF_LEN;
    int i;

    LOGD("%s, %s, %s, %d\n", __FUNCTION__, argv[0], argv[1], argc);

    for ( i=0; i<argc;i++) {
        LOGD("ARG: %d - %s\n", i+1, argv[i]);
    }

    /** set SSID */
    if(argc > 4) {
        snprintf(cmdbuf, CMD_BUF_LEN, "set ssid=%s",argv[4]);
    }
    else {
        snprintf(cmdbuf, CMD_BUF_LEN, "set ssid=%s_%d", DEFAULT_SSID, rand());
    }
    (void) qsap_hostd_exec_cmd(cmdbuf, respbuf, &rlen);

    if(strncmp("success", respbuf, rlen) != 0) {
        LOGE("Failed to set ssid\n");
        return eERR_UNKNOWN;
    }

    /** Security */
    rlen = RECV_BUF_LEN;
    if(argc > 5) {
        int sec = SEC_MODE_NONE;

        /**TODO : need to identify the SEC strings for "wep", "wpa", "wpa2" */
        if(!strcmp(argv[5], "open"))
            sec = SEC_MODE_NONE;

        else if(!strcmp(argv[5], "wep"))
            sec = SEC_MODE_WEP;

        else if(!strcmp(argv[5], "wpa-psk"))
            sec = SEC_MODE_WPA_PSK;

        else if(!strcmp(argv[5], "wpa2-psk"))
            sec = SEC_MODE_WPA2_PSK;

        snprintf(cmdbuf, CMD_BUF_LEN, "set security_mode=%d",sec);
    }
    else {
        snprintf(cmdbuf, CMD_BUF_LEN, "set security_mode=%d", DEFAULT_AUTH_ALG);
    }

    (void) qsap_hostd_exec_cmd(cmdbuf, respbuf, &rlen);

    if(strncmp("success", respbuf, rlen) != 0) {
        LOGE("Failed to set security mode\n");
        return -1;
    }

    /** Key -- passphrase */
    rlen = RECV_BUF_LEN;
    if(argc > 6) {
        snprintf(cmdbuf, CMD_BUF_LEN, "set wpa_passphrase=%s",argv[6]);
    }
    else {
        snprintf(cmdbuf, CMD_BUF_LEN, "set wpa_passphrase=%s", DEFAULT_PASSPHRASE);
    }

    (void) qsap_hostd_exec_cmd(cmdbuf, respbuf, &rlen);

    /** channel */
    rlen = RECV_BUF_LEN;
    if(argc > 7) {
        snprintf(cmdbuf, CMD_BUF_LEN, "set channel=%d", atoi(argv[7]));
    }
    else {
        snprintf(cmdbuf, CMD_BUF_LEN, "set channel=%d", DEFAULT_CHANNEL);
    }
    (void) qsap_hostd_exec_cmd(cmdbuf, respbuf, &rlen);

    if(strncmp("success", respbuf, rlen) != 0) {
        LOGE("Failed to set channel \n");
        return -1;
    }

    rlen = RECV_BUF_LEN;

    snprintf(cmdbuf, CMD_BUF_LEN, "set commit");

    (void) qsap_hostd_exec_cmd(cmdbuf, respbuf, &rlen);

    if(strncmp("success", respbuf, rlen) != 0) {
        LOGE("Failed to COMMIT \n");
        return -1;
    }

    return 0;
}
