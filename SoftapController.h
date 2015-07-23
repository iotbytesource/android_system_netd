/*
 * Copyright (C) 2008 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef _SOFTAP_CONTROLLER_H
#define _SOFTAP_CONTROLLER_H

#ifdef BOARD_HAVE_MTK_MT6620    // Begin of MT6620 settings
#define MTK_WIFI_HOTSPOT_SUPPORT 1
#endif  // End of MT6620 code

#include <linux/in.h>
#include <net/if.h>
#include <utils/List.h>

#define SOFTAP_MAX_BUFFER_SIZE	4096
#define AP_BSS_START_DELAY	200000
#define AP_BSS_STOP_DELAY	500000
#define AP_SET_CFG_DELAY	500000
#ifndef BOARD_HAVE_MTK_MT6620    // Begin of MT6620 settings
#define AP_DRIVER_START_DELAY   800000
#else
//MTK_WIFI_HOTSPOT_SUPPORT
#define SOFTAP_MAX_COMMAND_SIZE 4096
#define AP_DRIVER_START_DELAY   400000
#define AP_CONNECT_TO_SUPPLICANT_DELAY 300000
//MTK_WIFI_HOTSPOT_SUPPORT
#endif  // End of MT6620 code

class SoftapController {
#ifdef MTK_WIFI_HOTSPOT_SUPPORT
    bool mIsEnabled;

    int doCommand(const char *cmd, char *replybuf, int replybuflen);
    int doStringCommand(const char *cmd);
#else
    char mBuf[SOFTAP_MAX_BUFFER_SIZE];
    char mIface[IFNAMSIZ];
    pid_t mPid;
    int mSock;

    int addParam(int pos, const char *cmd, const char *arg);
    int setCommand(char *iface, const char *fname, unsigned buflen=0);
#endif

public:
    SoftapController();
    virtual ~SoftapController();

    int startDriver(char *iface);
    int stopDriver(char *iface);
    int startSoftap();
    int stopSoftap();
    bool isSoftapStarted();
    int setSoftap(int argc, char *argv[]);
    void generatePsk(char *ssid, char *passphrase, char *psk);
    int fwReloadSoftap(int argc, char *argv[]);
    int clientsSoftap(char **retbuf);
#ifdef BOARD_HAVE_MTK_MT6620    // Begin of MT6620 settings
    int setFlag();
    int getChannelList(int buf_len, char *buf_list);
#endif  // End of MT6620 code
};

#endif
