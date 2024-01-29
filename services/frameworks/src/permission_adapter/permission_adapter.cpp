/*
 * Copyright (C) 2022-2023 Huawei Device Co., Ltd.
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

#include "permission_adapter.h"

#include <string>
#include <unordered_map>
#include <vector>

#include "accesstoken_kit.h"
#include "ipc_sdk.h"
#include "ipc_skeleton.h"

#include "device_auth_defines.h"
#include "hc_log.h"

using namespace std;
using namespace OHOS;
using namespace OHOS::Security::AccessToken;

#define PROC_NAME_DEVICE_MANAGER "device_manager"
#define PROC_NAME_SOFT_BUS "softbus_server"
#define PROC_NAME_DEVICE_SECURITY_LEVEL "dslm_service"

static unordered_map<int32_t, vector<string>> g_apiAccessWhitelist = {
    { IPC_CALL_ID_PROCESS_CREDENTIAL, { PROC_NAME_DEVICE_MANAGER } },
    { IPC_CALL_ID_DA_AUTH_DEVICE, { PROC_NAME_DEVICE_MANAGER, PROC_NAME_SOFT_BUS } },
    { IPC_CALL_ID_DA_PROC_DATA, { PROC_NAME_DEVICE_MANAGER, PROC_NAME_SOFT_BUS } },
    { IPC_CALL_ID_DA_CANCEL_REQUEST, { PROC_NAME_DEVICE_MANAGER, PROC_NAME_SOFT_BUS } },
};

static unordered_map<int32_t, vector<string>> g_apiAccessConfig = {
    { IPC_CALL_ID_REG_CB, { PROC_NAME_DEVICE_MANAGER } },
    { IPC_CALL_ID_UNREG_CB, { PROC_NAME_DEVICE_MANAGER } },
    { IPC_CALL_ID_CREATE_GROUP, { PROC_NAME_DEVICE_MANAGER } },
    { IPC_CALL_ID_DEL_GROUP, { PROC_NAME_DEVICE_MANAGER } },
    { IPC_CALL_ID_ADD_GROUP_MEMBER, { PROC_NAME_DEVICE_MANAGER } },
    { IPC_CALL_ID_DEL_GROUP_MEMBER, { PROC_NAME_DEVICE_MANAGER } },
    { IPC_CALL_ID_GM_PROC_DATA, { PROC_NAME_DEVICE_MANAGER } },
    { IPC_CALL_ID_APPLY_REG_INFO, { PROC_NAME_DEVICE_MANAGER } },
    { IPC_CALL_ID_ADD_MULTI_GROUP_MEMBERS, { PROC_NAME_DEVICE_MANAGER } },
    { IPC_CALL_ID_DEL_MULTI_GROUP_MEMBERS, { PROC_NAME_DEVICE_MANAGER } },
    { IPC_CALL_GM_CANCEL_REQUEST, { PROC_NAME_DEVICE_MANAGER } },
    { IPC_CALL_ID_AUTH_DEVICE, { PROC_NAME_SOFT_BUS, PROC_NAME_DEVICE_MANAGER } },
    { IPC_CALL_ID_GA_PROC_DATA, { PROC_NAME_SOFT_BUS, PROC_NAME_DEVICE_MANAGER } },
    { IPC_CALL_GA_CANCEL_REQUEST, { PROC_NAME_SOFT_BUS, PROC_NAME_DEVICE_MANAGER } },
    { IPC_CALL_ID_GET_PK_INFO_LIST, { PROC_NAME_DEVICE_SECURITY_LEVEL } },
};

static bool IsProcessAllowAccess(const string &processName, int32_t methodId)
{
    if (g_apiAccessConfig.find(methodId) == g_apiAccessConfig.end()) {
        return true;
    }
    return find(g_apiAccessConfig[methodId].begin(), g_apiAccessConfig[methodId].end(), processName) !=
        g_apiAccessConfig[methodId].end();
}

static bool IsProcessInWhitelist(const string& processName, int32_t methodId)
{
    if (g_apiAccessWhitelist.find(methodId) == g_apiAccessWhitelist.end()) {
        return true;
    }
    bool ret = find(g_apiAccessWhitelist[methodId].begin(), g_apiAccessWhitelist[methodId].end(), processName) !=
                  g_apiAccessWhitelist[methodId].end();
    if (!ret) {
        LOGE("Access Denied: Process(%s) not in access whitlist", processName.c_str());
    }
    return ret;
}

int32_t CheckPermission(int32_t methodId)
{
    AccessTokenID tokenId = IPCSkeleton::GetCallingTokenID();
    ATokenTypeEnum tokenType = AccessTokenKit::GetTokenTypeFlag(tokenId);
    if (tokenType != TOKEN_NATIVE) {
        LOGE("Invalid token type: %d", tokenType);
        return HC_ERROR;
    }
    NativeTokenInfo findInfo;
    if (AccessTokenKit::GetNativeTokenInfo(tokenId, findInfo) != 0) {
        LOGE("GetNativeTokenInfo failed!");
        return HC_ERROR;
    }
    if ((findInfo.apl != APL_SYSTEM_CORE) && (findInfo.apl != APL_SYSTEM_BASIC)) {
        LOGE("Check permission(APL3=SYSTEM_CORE or APL2=SYSTEM_BASIC) failed! APL: %d", findInfo.apl);
        return HC_ERROR;
    }

    if (!IsProcessInWhitelist(findInfo.processName, methodId)) {
        LOGE("Check permission(Access Whitelist) failed!");
        return HC_ERROR;
    }

    if (!IsProcessAllowAccess(findInfo.processName, methodId)) {
        LOGE("Check permission(Interface Access List) failed!");
        return HC_ERROR;
    }
    return HC_SUCCESS;
}