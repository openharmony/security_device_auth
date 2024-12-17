/*
 * Copyright (C) 2024 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "net_observer.h"

#include <pthread.h>
#include <unistd.h>

#include "account_task_manager.h"
#include "common_defs.h"
#include "device_auth.h"
#include "device_auth_defines.h"
#include "hc_log.h"
#include "net_conn_client.h"
#include "net_conn_constants.h"

using namespace OHOS;
using namespace OHOS::NetManagerStandard;

static sptr<INetConnCallback> g_netCallback = nullptr;

void NetObserver::StartObserver()
{
    LOGI("[NetObserver]: Start to register net connection callback.");
    if (isObserverStarted_) {
        LOGI("[NetObserver]: Observer already started.");
        return;
    }
    isObserverStarted_ = true;
    NetObserver *observer = static_cast<NetObserver *>(this);
    regThread_ = std::thread([observer]() {
        NetSpecifier netSpecifier;
        NetAllCapabilities netAllCapabilities;
        netAllCapabilities.netCaps_.insert(NetManagerStandard::NetCap::NET_CAPABILITY_INTERNET);
        netSpecifier.ident_ = "";
        netSpecifier.netCapabilities_ = netAllCapabilities;
        sptr<NetSpecifier> specifier = new NetSpecifier(netSpecifier);
        constexpr uint32_t RETRY_MAX_TIMES = 10;
        uint32_t retryCount = 0;
        do {
            if (!observer->IsObserverStarted()) {
                LOGW("[NetObserver]: observer stopped, can not register!");
                return;
            }
            int32_t ret = NetConnClient::GetInstance().RegisterNetConnCallback(specifier, observer, 0);
            if (ret == NetConnResultCode::NET_CONN_SUCCESS) {
                LOGI("[NetObserver]: Register net connection callback succeeded.");
                g_netCallback = observer;
                return;
            }
            retryCount++;
            LOGW("[NetObserver]: Register failed, errCode = %d, retry.", ret);
            sleep(1);
        } while (retryCount < RETRY_MAX_TIMES);
        LOGE("[NetObserver]: Register net connection callback failed!");
    });
}

int32_t NetObserver::NetCapabilitiesChange(sptr<NetHandle> &netHandle, const sptr<NetAllCapabilities> &netAllCap)
{
    LOGI("[NetObserver]: Net capabilities change.");
    if (netAllCap == nullptr) {
        return 0;
    }
    return HandleNetAllCap(*netAllCap);
}

int32_t NetObserver::NetLost(sptr<NetHandle> &netHandle)
{
    LOGI("[NetObserver]: Net lost!");
    return 0;
}

int32_t NetObserver::NetAvailable(sptr<NetHandle> &netHandle)
{
    LOGI("[NetObserver]: Net available.");
    return 0;
}

int32_t NetObserver::HandleNetAllCap(const NetAllCapabilities &netAllCap)
{
    if (netAllCap.netCaps_.count(NET_CAPABILITY_INTERNET) <= 0 ||
        netAllCap.netCaps_.count(NET_CAPABILITY_VALIDATED) <= 0) {
        for (auto netCap : netAllCap.netCaps_) {
            LOGI("[NetObserver]: No net, netCap is: %d", static_cast<int32_t>(netCap));
        }
        return 0;
    }
    LOGI("[NetObserver]: Net available.");
    int32_t res = ExecuteAccountAuthCmd(DEFAULT_OS_ACCOUNT, RELOAD_CRED_MGR, nullptr, nullptr);
    LOGI("[NetObserver]: Reload credential manager res: %d", res);
    return 0;
}

bool NetObserver::IsObserverStarted()
{
    return isObserverStarted_;
}

void NetObserver::StopObserver()
{
    LOGI("[NetObserver]: Start to unregister net connection callback.");
    if (!isObserverStarted_) {
        LOGI("[NetObserver]: Observer already stopped.");
        return;
    }
    isObserverStarted_ = false;
    if (regThread_.joinable()) {
        regThread_.join();
    }
    if (g_netCallback == nullptr) {
        LOGI("[NetObserver]: Net connection callback is null.");
        return;
    }
    int32_t ret = NetConnClient::GetInstance().UnregisterNetConnCallback(g_netCallback);
    if (ret == 0) {
        LOGI("[NetObserver]: unregister net connection callback succeeded.");
        g_netCallback = nullptr;
    }
}