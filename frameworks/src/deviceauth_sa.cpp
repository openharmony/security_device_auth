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

#include <ipc_skeleton.h>
#include <system_ability_definition.h>

#include "hc_log.h"
#include "device_auth.h"
#include "device_auth_defines.h"
#include "ipc_adapt.h"
#include "ipc_sdk_defines.h"
#include "common_defs.h"
#include "hc_thread.h"
#include "securec.h"
#include "hc_string_vector.h"
#include "hidump_adapter.h"
#include "string_ex.h"
#include "ipc_service_common.h"

#include "deviceauth_sa.h"

#ifdef DEV_AUTH_USE_JEMALLOC
#include "malloc.h"
#endif

namespace OHOS {

static const uint32_t RESTORE_CODE = 14701;
using IpcCallMap = struct {
    int32_t (*func)(const IpcDataInfo*, int32_t, uintptr_t);
    uint32_t id;
};

static IpcCallMap g_ipcCallMaps[] = {
    {IpcServiceGmRegCallback, IPC_CALL_ID_REG_CB},
    {IpcServiceGmUnRegCallback, IPC_CALL_ID_UNREG_CB},
    {IpcServiceGmRegDataChangeListener, IPC_CALL_ID_REG_LISTENER},
    {IpcServiceGmUnRegDataChangeListener, IPC_CALL_ID_UNREG_LISTENER},
    {IpcServiceGmCreateGroup, IPC_CALL_ID_CREATE_GROUP},
    {IpcServiceGmDelGroup, IPC_CALL_ID_DEL_GROUP},
    {IpcServiceGmAddMemberToGroup, IPC_CALL_ID_ADD_GROUP_MEMBER},
    {IpcServiceGmDelMemberFromGroup, IPC_CALL_ID_DEL_GROUP_MEMBER},
    {IpcServiceGmAddMultiMembersToGroup, IPC_CALL_ID_ADD_MULTI_GROUP_MEMBERS},
    {IpcServiceGmDelMultiMembersFromGroup, IPC_CALL_ID_DEL_MULTI_GROUP_MEMBERS},
    {IpcServiceGmProcessData, IPC_CALL_ID_GM_PROC_DATA},
    {IpcServiceGmApplyRegisterInfo, IPC_CALL_ID_APPLY_REG_INFO},
    {IpcServiceGmCheckAccessToGroup, IPC_CALL_ID_CHECK_ACCESS_TO_GROUP},
    {IpcServiceGmGetPkInfoList, IPC_CALL_ID_GET_PK_INFO_LIST},
    {IpcServiceGmGetGroupInfoById, IPC_CALL_ID_GET_GROUP_INFO},
    {IpcServiceGmGetGroupInfo, IPC_CALL_ID_SEARCH_GROUPS},
    {IpcServiceGmGetJoinedGroups, IPC_CALL_ID_GET_JOINED_GROUPS},
    {IpcServiceGmGetRelatedGroups, IPC_CALL_ID_GET_RELATED_GROUPS},
    {IpcServiceGmGetDeviceInfoById, IPC_CALL_ID_GET_DEV_INFO_BY_ID},
    {IpcServiceGmGetTrustedDevices, IPC_CALL_ID_GET_TRUST_DEVICES},
    {IpcServiceGmIsDeviceInGroup, IPC_CALL_ID_IS_DEV_IN_GROUP},
    {IpcServiceGmCancelRequest, IPC_CALL_GM_CANCEL_REQUEST},
    {IpcServiceGaProcessData, IPC_CALL_ID_GA_PROC_DATA},
    {IpcServiceGaAuthDevice, IPC_CALL_ID_AUTH_DEVICE},
    {IpcServiceGaCancelRequest, IPC_CALL_GA_CANCEL_REQUEST},
    {IpcServiceGaGetRealInfo, IPC_CALL_ID_GET_REAL_INFO},
    {IpcServiceGaGetPseudonymId, IPC_CALL_ID_GET_PSEUDONYM_ID},
    {IpcServiceDaProcessCredential, IPC_CALL_ID_PROCESS_CREDENTIAL},
    {IpcServiceDaAuthDevice, IPC_CALL_ID_DA_AUTH_DEVICE},
    {IpcServiceDaProcessData, IPC_CALL_ID_DA_PROC_DATA},
    {IpcServiceDaCancelRequest, IPC_CALL_ID_DA_CANCEL_REQUEST},
    {IpcServiceCmAddCredential, IPC_CALL_ID_CM_ADD_CREDENTIAL},
    {IpcServiceCmRegCredChangeListener, IPC_CALL_ID_CM_REG_LISTENER},
    {IpcServiceCmUnRegCredChangeListener, IPC_CALL_ID_CM_UNREG_LISTENER},
    {IpcServiceCmExportCredential, IPC_CALL_ID_CM_EXPORT_CREDENTIAL},
    {IpcServiceCmQueryCredentialByParams, IPC_CALL_ID_CM_QUERY_CREDENTIAL_BY_PARAMS},
    {IpcServiceCmQueryCredentialByCredId, IPC_CALL_ID_CM_QUERY_CREDENTIAL_BY_CRED_ID},
    {IpcServiceCmDeleteCredential, IPC_CALL_ID_CM_DEL_CREDENTIAL},
    {IpcServiceCmUpdateCredInfo, IPC_CALL_ID_CM_UPDATE_CRED_INFO},
    {IpcServiceCmAgreeCredential, IPC_CALL_ID_CM_AGREE_CREDENTIAL},
    {IpcServiceCmDelCredByParams, IPC_CALL_ID_CM_DEL_CRED_BY_PARAMS},
    {IpcServiceCmBatchUpdateCredentials, IPC_CALL_ID_CM_BATCH_UPDATE_CREDENTIALS},
    {IpcServiceCaAuthCredential, IPC_CALL_ID_CA_AUTH_CREDENTIAL},
    {IpcServiceCaProcessCredData, IPC_CALL_ID_CA_PROCESS_CRED_DATA},
    {IpcServiceAvGetClientSharedKey, IPC_CALL_ID_AV_GET_CLIENT_SHARED_KEY},
    {IpcServiceAvGetServerSharedKey, IPC_CALL_ID_AV_GET_SERVER_SHARED_KEY},
};

REGISTER_SYSTEM_ABILITY_BY_ID(DeviceAuthAbility, SA_ID_DEVAUTH_SERVICE, true);

std::mutex DeviceAuthAbility::g_instanceLock;
sptr<DeviceAuthAbility> DeviceAuthAbility::g_instance;

DeviceAuthAbility::DeviceAuthAbility(int saId, bool runOnCreate = true) : SystemAbility(saId, runOnCreate)
{
    LOGI("DeviceAuthAbility");
}

DeviceAuthAbility::~DeviceAuthAbility()
{
    LOGI("~DeviceAuthAbility");
}

__attribute__((no_sanitize("cfi"))) static uint32_t SaSetIpcCallMap(
    uintptr_t ipcInstance, IpcServiceCall method, int32_t methodId)
{
    if ((method == nullptr) || (methodId <= 0)) {
        return static_cast<uint32_t>(HC_ERR_INVALID_PARAMS);
    }

    DeviceAuthAbility *service = reinterpret_cast<DeviceAuthAbility *>(ipcInstance);
    return static_cast<uint32_t>(service->SetCallMap(method, methodId));
}

static int32_t SaAddMethodMap(uintptr_t ipcInstance)
{
    uint32_t ret = 0;
    for (uint32_t i = 0; i < sizeof(g_ipcCallMaps)/sizeof(g_ipcCallMaps[0]); i++) {
        ret &= SaSetIpcCallMap(ipcInstance, g_ipcCallMaps[i].func, g_ipcCallMaps[i].id);
    }
    return ret;
}

sptr<DeviceAuthAbility> DeviceAuthAbility::GetInstance()
{
    std::lock_guard<std::mutex> autoLock(g_instanceLock);
    if (g_instance == nullptr) {
        g_instance = new (std::nothrow) DeviceAuthAbility(SA_ID_DEVAUTH_SERVICE, true);
    }
    return g_instance;
}

void DeviceAuthAbility::DestroyInstance()
{
    std::lock_guard<std::mutex> autoLock(g_instanceLock);
    if (g_instance != nullptr) {
        delete g_instance;
        g_instance = nullptr;
    }
    LOGI("DeviceAuthAbility DestroyInstance done");
}

int32_t DeviceAuthAbility::Dump(int32_t fd, const std::vector<std::u16string> &args)
{
    std::vector<std::string> strArgs;
    for (auto arg : args) {
        strArgs.emplace_back(Str16ToStr8(arg));
    }
    uint32_t argc = strArgs.size();
    StringVector strArgVec = CreateStrVector();
    for (uint32_t i = 0; i < argc; i++) {
        HcString strArg = CreateString();
        if (!StringSetPointer(&strArg, strArgs[i].c_str())) {
            LOGE("Failed to set strArg!");
            DeleteString(&strArg);
            continue;
        }
        if (strArgVec.pushBackT(&strArgVec, strArg) == nullptr) {
            LOGE("Failed to push strArg to strArgVec!");
            DeleteString(&strArg);
        }
    }
    DEV_AUTH_DUMP(fd, &strArgVec);
    DestroyStrVector(&strArgVec);
    return 0;
}

void DeviceAuthAbility::OnStart()
{
    LOGI("DeviceAuthAbility starting ...");
    int32_t ret = InitDeviceAuthService();
    if (ret != HC_SUCCESS) {
        LOGE("DeviceAuthAbility InitDeviceAuthService failed, ret %" LOG_PUB "d", ret);
        return;
    }

    ret = MainRescInit();
    if (ret != HC_SUCCESS) {
        DestroyDeviceAuthService();
        LOGE("device auth service main, init work failed");
        return;
    }

    sptr<DeviceAuthAbility> serviceInstance = DeviceAuthAbility::GetInstance();
    if (serviceInstance == nullptr) {
        LOGE("DeviceAuthAbility GetInstance Failed");
        DeMainRescInit();
        DestroyDeviceAuthService();
        return;
    }

    uintptr_t serviceInstanceAddress = reinterpret_cast<uintptr_t>(serviceInstance.GetRefPtr());
    ret = SaAddMethodMap(serviceInstanceAddress);
    if (ret != HC_SUCCESS) {
        LOGW("DeviceAuthAbility SaAddMethodMap failed at least once.");
    }
    
    if (!Publish(serviceInstance)) {
        LOGE("DeviceAuthAbility Publish failed");
        DeviceAuthAbility::DestroyInstance();
        DeMainRescInit();
        DestroyDeviceAuthService();
        return;
    }
    LOGI("DeviceAuthAbility start success.");
}

static void DevAuthInitMemoryPolicy(void)
{
#ifdef DEV_AUTH_USE_JEMALLOC
    (void)mallopt(M_SET_THREAD_CACHE, M_THREAD_CACHE_DISABLE);
    (void)mallopt(M_DELAYED_FREE, M_DELAYED_FREE_DISABLE);
#endif
}

int32_t DeviceAuthAbility::OnRemoteRequest(uint32_t code, MessageParcel &data, MessageParcel &reply,
    MessageOption &option)
{
    DevAuthInitMemoryPolicy();
    std::u16string readToken = data.ReadInterfaceToken();

    bool isRestoreCall = ((code == RESTORE_CODE) && (readToken == std::u16string(u"OHOS.Updater.RestoreData")));
    if (readToken != GetDescriptor() && !isRestoreCall) {
        LOGE("DeviceAuthAbility [IPC][C->S]: The proxy interface token is invalid!");
        return -1;
    }
    if (isRestoreCall) {
        return HandleRestoreCall(data, reply);
    } else {
        return HandleDeviceAuthCall(code, data, reply, option);
    }
}

void DeviceAuthAbility::OnStop()
{
    LOGI("DeviceAuthAbility OnStop");
    DeviceAuthAbility::DestroyInstance();
    DeMainRescInit();
    DestroyDeviceAuthService();
}

} // namespace OHOS