/*
 * Copyright (C) 2024-2025 Huawei Device Co., Ltd.
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

#include "account_task_manager.h"
#include "common_defs.h"
#include "device_auth.h"
#include "device_auth_defines.h"
#include "hc_log.h"
#include "net_conn_client.h"
#include "net_conn_constants.h"
#include "unload_handler.h"

using namespace OHOS;
using namespace OHOS::NetManagerStandard;

void NetObserver::StartObserver()
{
    LOGI("[NetObserver]: Start to register net connection callback.");
    NetSpecifier netSpecifier;
    NetAllCapabilities netAllCapabilities;
    netAllCapabilities.netCaps_.insert(NetManagerStandard::NetCap::NET_CAPABILITY_INTERNET);
    netSpecifier.ident_ = "";
    netSpecifier.netCapabilities_ = netAllCapabilities;
    sptr<NetSpecifier> specifier = new NetSpecifier(netSpecifier);
    int32_t ret = NetConnClient::GetInstance().RegisterNetConnCallback(specifier, this, 0);
    if (ret == NetConnResultCode::NET_CONN_SUCCESS) {
        LOGI("[NetObserver]: Register net connection callback succeeded.");
        netConnCallback_ = this;
        return;
    }
    LOGE("[NetObserver]: Register net connection callback failed, errCode = %" LOG_PUB "d.", ret);
}

int32_t NetObserver::NetCapabilitiesChange(sptr<NetHandle> &netHandle, const sptr<NetAllCapabilities> &netAllCap)
{
    LOGI("[NetObserver]: Net capabilities change.");
    if (netAllCap == nullptr) {
        LOGE("[NetObserver]: netAllCap is null!");
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
            LOGI("[NetObserver]: No net, netCap is: %" LOG_PUB "d", static_cast<int32_t>(netCap));
        }
        return 0;
    }
    LOGI("[NetObserver]: Net available, reload credential manager.");
    DelayUnload();
    int32_t res = ExecuteAccountAuthCmd(DEFAULT_OS_ACCOUNT, RELOAD_CRED_MGR, nullptr, nullptr);
    LOGI("[NetObserver]: Reload credential manager res: %" LOG_PUB "d.", res);
    return 0;
}

void NetObserver::StopObserver()
{
    LOGI("[NetObserver]: Start to unregister net connection callback.");
    if (netConnCallback_ == nullptr) {
        LOGW("[NetObserver]: Net connection callback is null.");
        return;
    }
    int32_t ret = NetConnClient::GetInstance().UnregisterNetConnCallback(netConnCallback_);
    LOGI("[NetObserver]: unregister net connection callback res: %" LOG_PUB "d.", ret);
    netConnCallback_ = nullptr;
}