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
#include "event_runner.h"

#include "deviceauth_sa.h"
#include "iservice_registry.h"
#include "dev_session_mgr.h"
#include "critical_handler.h"

#ifdef DEV_AUTH_USE_JEMALLOC
#include "malloc.h"
#endif

namespace OHOS {
namespace {
    const uint32_t RESTORE_CODE = 14701;
    const std::string DEVAUTH_UNLOAD_SA_HANDLER = "devauth_unload_sa_handler";
    const std::string DEVAUTH_UNLOAD_TASK_ID = "devauth_unload_task";
    const int32_t DEVAUTH_LIFE_TIME = 90000; // 90 * 1000
    const int32_t SA_REFUSE_TO_UNLOAD = -1;
}

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
    {IpcServiceLaStartLightAccountAuth, IPC_CALL_ID_LA_START_LIGHT_ACCOUNT_AUTH},
    {IpcServiceLaProcessLightAccountAuth, IPC_CALL_ID_LA_PROCESS_LIGHT_ACCOUNT_AUTH},
};

REGISTER_SYSTEM_ABILITY_BY_ID(DeviceAuthAbility, SA_ID_DEVAUTH_SERVICE, true);

DeviceAuthAbility::DeviceAuthAbility(int saId, bool runOnCreate) : SystemAbility(saId, runOnCreate)
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

bool DeviceAuthAbility::CreateUnloadHandler()
{
    std::lock_guard<std::recursive_mutex> lock(instanceMutex_);
    if (unloadHandler_ != nullptr) {
        return true;
    }
    auto unloadRunner = AppExecFwk::EventRunner::Create(DEVAUTH_UNLOAD_SA_HANDLER);
    if (unloadRunner == nullptr) {
        LOGE("Create unloadRunner failed.");
        return false;
    }
    unloadHandler_ = std::make_shared<AppExecFwk::EventHandler>(unloadRunner);
    if (unloadHandler_ == nullptr) {
        LOGE("Create unloadHandler failed.");
        return false;
    }
    return true;
}

void DeviceAuthAbility::DestroyUnloadHandler()
{
    std::lock_guard<std::recursive_mutex> lock(instanceMutex_);
    if (unloadHandler_ == nullptr) {
        LOGE("unloadHandler is nullptr.");
        return;
    }
    unloadHandler_->RemoveTask(DEVAUTH_UNLOAD_TASK_ID);
    unloadHandler_ = nullptr;
}

void DeviceAuthAbility::DelayUnload()
{
    if (!CreateUnloadHandler()) {
        LOGE("UnloadHandler is nullptr.");
        return;
    }
    auto utask = []() {
        LOGI("The Service starts unloading.");
        auto saMgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
        if (saMgr == nullptr) {
            LOGE("Get systemabilitymanager instance failed.");
            return;
        }
        int32_t ret = saMgr->UnloadSystemAbility(DEVICE_AUTH_SERVICE_ID);
        if (ret != ERR_OK) {
            LOGE("Unload system ability failed.");
            return;
        }
        LOGI("Service unloaded successfully.");
    };
    unloadHandler_->RemoveTask(DEVAUTH_UNLOAD_TASK_ID);
    unloadHandler_->PostTask(utask, DEVAUTH_UNLOAD_TASK_ID, DEVAUTH_LIFE_TIME);
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

    uintptr_t serviceInstanceAddress = reinterpret_cast<uintptr_t>(this);
    ret = SaAddMethodMap(serviceInstanceAddress);
    if (ret != HC_SUCCESS) {
        LOGW("DeviceAuthAbility SaAddMethodMap failed at least once.");
    }
    if (!Publish(this)) {
        LOGE("DeviceAuthAbility Publish failed");
        DeMainRescInit();
        DestroyDeviceAuthService();
        return;
    }
    AddSystemAbilityListener(MEMORY_MANAGER_SA_ID);
    DelayUnload();
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
    std::lock_guard<std::recursive_mutex> lock(instanceMutex_);
    DelayUnload();
    DevAuthInitMemoryPolicy();
    std::u16string readToken = data.ReadInterfaceToken();

    bool isRestoreCall = ((code == RESTORE_CODE) && (readToken == std::u16string(u"OHOS.Updater.RestoreData")));
    if (readToken != GetDescriptor() && !isRestoreCall) {
        LOGE("DeviceAuthAbility [IPC][C->S]: The proxy interface token is invalid!");
        return -1;
    }
    if (isUnloading_) {
        LOGW("sa is unloading, need to retry.");
        return HC_ERR_IPC_SA_IS_UNLOADING;
    }
    int32_t ret;
    IncreaseCriticalCnt(ADD_ONE);
    if (isRestoreCall) {
        ret = HandleRestoreCall(data, reply);
    } else {
        ret = HandleDeviceAuthCall(code, data, reply, option);
    }
    DecreaseCriticalCnt();
    return ret;
}

void DeviceAuthAbility::OnActive(const SystemAbilityOnDemandReason &activeReason)
{
    std::lock_guard<std::recursive_mutex> lock(instanceMutex_);
    LOGI("OnActive, activeReason name is %" LOG_PUB "s, isUnloading is %" LOG_PUB "s.",
        activeReason.GetName().c_str(), isUnloading_ ? "YES" : "NO");
    isUnloading_ = false;
}

int32_t DeviceAuthAbility::OnIdle(const SystemAbilityOnDemandReason &idleReason)
{
    std::lock_guard<std::recursive_mutex> lock(instanceMutex_);
    isUnloading_ = GetCriticalCnt() > 0 ? false : true;
    LOGI("OnIdle, idleReason name is %" LOG_PUB "s, isUnloading is %" LOG_PUB "s.",
        idleReason.GetName().c_str(), isUnloading_ ? "YES" : "NO");
    if (isUnloading_) {
        return HC_SUCCESS;
    }
    return SA_REFUSE_TO_UNLOAD;
}

void DeviceAuthAbility::OnStop()
{
    std::lock_guard<std::recursive_mutex> lock(instanceMutex_);
    LOGI("DeviceAuthAbility OnStop");
    DestroyUnloadHandler();
    RemoveTimeoutSession();
    DeMainRescInit();
    DestroyDeviceAuthService();
    NotifyProcessIsStop();
}

void DeviceAuthAbility::OnAddSystemAbility(int32_t systemAbilityId, const std::string &deviceId)
{
    LOGI("OnAddSystemAbility systemAbilityId: %" LOG_PUB "d add.", systemAbilityId);
    if (systemAbilityId == MEMORY_MANAGER_SA_ID) {
        NotifyProcessIsActive();
    }
}

void DeviceAuthAbility::OnRemoveSystemAbility(int32_t systemAbilityId, const std::string &deviceId)
{
    LOGI("OnRemoveSystemAbility systemAbilityId: %" LOG_PUB "d add.", systemAbilityId);
}

} // namespace OHOS