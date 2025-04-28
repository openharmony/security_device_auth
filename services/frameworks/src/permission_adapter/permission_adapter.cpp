/*
 * Copyright (C) 2022-2025 Huawei Device Co., Ltd.
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
#include "ipc_sdk_defines.h"
#include "ipc_skeleton.h"

#include "device_auth_defines.h"
#include "hc_log.h"

using namespace std;
using namespace OHOS;
using namespace OHOS::Security::AccessToken;

#define PROC_NAME_DEVICE_MANAGER "device_manager"
#define PROC_NAME_SOFT_BUS "softbus_server"
#define PROC_NAME_DEVICE_SECURITY_LEVEL "dslm_service"
#define PROC_NAME_ISHARE "CollaborationFwk"
#define PROC_NAME_REMOTE_COMM "remote_communication"

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
    { IPC_CALL_ID_AUTH_DEVICE, { PROC_NAME_SOFT_BUS, PROC_NAME_DEVICE_MANAGER, PROC_NAME_ISHARE } },
    { IPC_CALL_ID_GA_PROC_DATA, { PROC_NAME_SOFT_BUS, PROC_NAME_DEVICE_MANAGER, PROC_NAME_ISHARE } },
    { IPC_CALL_GA_CANCEL_REQUEST, { PROC_NAME_SOFT_BUS, PROC_NAME_DEVICE_MANAGER, PROC_NAME_ISHARE } },
    { IPC_CALL_ID_GET_PK_INFO_LIST, { PROC_NAME_DEVICE_SECURITY_LEVEL } },
    { IPC_CALL_ID_AV_GET_CLIENT_SHARED_KEY, { PROC_NAME_REMOTE_COMM } },
    { IPC_CALL_ID_AV_GET_SERVER_SHARED_KEY, { PROC_NAME_REMOTE_COMM } },
};

static unordered_set<int32_t> g_credMgrApi = {
    IPC_CALL_ID_CM_ADD_CREDENTIAL,
    IPC_CALL_ID_CM_AGREE_CREDENTIAL,
    IPC_CALL_ID_CM_DEL_CRED_BY_PARAMS,
    IPC_CALL_ID_CM_BATCH_UPDATE_CREDENTIALS,
    IPC_CALL_ID_CM_REG_LISTENER,
    IPC_CALL_ID_CM_UNREG_LISTENER,
    IPC_CALL_ID_CM_EXPORT_CREDENTIAL,
    IPC_CALL_ID_CM_QUERY_CREDENTIAL_BY_PARAMS,
    IPC_CALL_ID_CM_QUERY_CREDENTIAL_BY_CRED_ID,
    IPC_CALL_ID_CM_DEL_CREDENTIAL,
    IPC_CALL_ID_CM_UPDATE_CRED_INFO,
};

static unordered_set<int32_t> g_credAuthApi = {
    IPC_CALL_ID_CA_AUTH_CREDENTIAL,
    IPC_CALL_ID_CA_PROCESS_CRED_DATA,
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
        LOGE("Access Denied: Process(%" LOG_PUB "s) not in access whitlist", processName.c_str());
    }
    return ret;
}

int32_t CheckInterfacePermission(const char *permission)
{
    AccessTokenID accessTokenId = IPCSkeleton::GetCallingTokenID();
    int result = AccessTokenKit::VerifyAccessToken(accessTokenId, permission);
    if (result != PERMISSION_GRANTED) {
        LOGE("The permission %" LOG_PUB "s is not granted!, res: %" LOG_PUB "d", permission, result);
        return HC_ERR_IPC_PERMISSION_DENIED;
    }
    return HC_SUCCESS;
}

static int32_t CheckCredMgrPermission(int32_t methodId)
{
    if (g_credMgrApi.count(methodId) == 0) {
        return HC_SUCCESS;
    }
    if (CheckInterfacePermission(CRED_PRIVILEGE_PERMISSION) == HC_SUCCESS ||
        CheckInterfacePermission(CRED_MGR_PERMISSION) == HC_SUCCESS) {
        return HC_SUCCESS;
    }
    LOGE("Do not have CRED MGR or CRED PRIVILEGE permission!");
    return HC_ERR_IPC_PERMISSION_DENIED;
}

static int32_t CheckCredAuthPermission(int32_t methodId)
{
    if (g_credAuthApi.count(methodId) == 0) {
        return HC_SUCCESS;
    }
    if (CheckInterfacePermission(CRED_PRIVILEGE_PERMISSION) == HC_SUCCESS ||
        CheckInterfacePermission(CRED_AUTH_PERMISSION) == HC_SUCCESS) {
        return HC_SUCCESS;
    }
    LOGE("Do not have CRED AUTH or CRED PRIVILEGE permission!");
    return HC_ERR_IPC_PERMISSION_DENIED;
}

static int32_t CheckACLPermission(int32_t methodId)
{
    if (CheckCredAuthPermission(methodId) != HC_SUCCESS) {
        return HC_ERR_IPC_PERMISSION_DENIED;
    }
    if (CheckCredMgrPermission(methodId) != HC_SUCCESS) {
        return HC_ERR_IPC_PERMISSION_DENIED;
    }
    return HC_SUCCESS;
}

static bool CheckTokenType(ATokenTypeEnum tokenType, int32_t methodId)
{
    if (tokenType == TOKEN_HAP && (g_credAuthApi.count(methodId) != 0 || g_credMgrApi.count(methodId) != 0)) {
        LOGI("IS interface not need check token type");
        return true;
    }
    if (tokenType == TOKEN_NATIVE) {
        return true;
    }
    LOGE("[AccessTokenKit][GetTokenTypeFlag]: Invalid token type: %" LOG_PUB "d", tokenType);
    return false;
}

static int32_t CheckNativeTokenInfo(AccessTokenID tokenId, int32_t methodId)
{
    NativeTokenInfo findInfo;
    if (AccessTokenKit::GetNativeTokenInfo(tokenId, findInfo) != 0) {
        LOGE("[AccessTokenKit][GetNativeTokenInfo]: failed!");
        return HC_ERR_IPC_PERMISSION_DENIED;
    }
    if ((findInfo.apl != APL_SYSTEM_CORE) && (findInfo.apl != APL_SYSTEM_BASIC)) {
        LOGE("Check permission(APL3=SYSTEM_CORE or APL2=SYSTEM_BASIC) failed! APL: %" LOG_PUB "d", findInfo.apl);
        return HC_ERR_IPC_PERMISSION_DENIED;
    }
    if (!IsProcessInWhitelist(findInfo.processName, methodId)) {
        LOGE("Check permission(Access Whitelist) failed!");
        return HC_ERR_IPC_PERMISSION_DENIED;
    }
    if (!IsProcessAllowAccess(findInfo.processName, methodId)) {
        LOGE("Check permission(Interface Access List) failed!");
        return HC_ERR_IPC_PERMISSION_DENIED;
    }
    return HC_SUCCESS;
}

int32_t CheckPermission(int32_t methodId)
{
    AccessTokenID tokenId = IPCSkeleton::GetCallingTokenID();
    ATokenTypeEnum tokenType = AccessTokenKit::GetTokenTypeFlag(tokenId);
    if (!CheckTokenType(tokenType, methodId)) {
        return HC_ERR_IPC_PERMISSION_DENIED;
    }
    if (tokenType == TOKEN_NATIVE && CheckNativeTokenInfo(tokenId, methodId) != HC_SUCCESS) {
        return HC_ERR_IPC_PERMISSION_DENIED;
    }
    if (CheckACLPermission(methodId) != HC_SUCCESS) {
        LOGE("Check ACL permission failed!");
        return HC_ERR_IPC_PERMISSION_DENIED;
    }
    return HC_SUCCESS;
}

int32_t GetCallingUid(void)
{
    return IPCSkeleton::GetCallingUid();
}
