/*
 * Copyright (C) 2021-2023 Huawei Device Co., Ltd.
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

#include "ipc_service_lite.h"

#include "common_defs.h"
#include "device_auth_defines.h"
#include "device_auth.h"
#include "hc_condition.h"
#include "hc_log.h"
#include "ipc_adapt.h"
#include "ipc_sdk_defines.h"
#include "ipc_service_common.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    int32_t (*func)(const IpcDataInfo*, int32_t, uintptr_t);
    uint32_t id;
} IpcCallMap;

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
};

int32_t AddMethodMap(uintptr_t ipcInstance)
{
    uint32_t ret = 0;
    for (uint32_t i = 0; i < sizeof(g_ipcCallMaps)/sizeof(g_ipcCallMaps[0]); i++) {
        ret |= SetIpcCallMap(ipcInstance, g_ipcCallMaps[i].func, g_ipcCallMaps[i].id);
    }

    return ret;
}

#ifndef DEV_AUTH_FUZZ_TEST
int32_t main(int32_t argc, char const *argv[])
{
    int32_t ret;
    HcCondition cond;

    (void)argc;
    (void)argv;
    LOGI("device authentication service starting ...");
    ret = InitDeviceAuthService();
    if (ret != HC_SUCCESS) {
        LOGE("device auth service main, InitDeviceAuthService failed, ret %" LOG_PUB "d", ret);
        return 1;
    }

    ret = MainRescInit();
    if (ret != HC_SUCCESS) {
        DestroyDeviceAuthService();
        LOGE("device auth service main, init work failed");
        return 1;
    }

    uintptr_t serviceInstance = 0x0;
    ret = CreateServiceInstance(&serviceInstance);
    if (ret != HC_SUCCESS) {
        LOGE("Failed to create device auth service instance!");
        DeMainRescInit();
        DestroyDeviceAuthService();
        return 1;
    }
    (void)AddMethodMap(serviceInstance);
    ret = AddDevAuthServiceToManager(serviceInstance);
    if (ret != HC_SUCCESS) {
        DestroyServiceInstance(serviceInstance);
        DeMainRescInit();
        DestroyDeviceAuthService();
        LOGE("device auth service main, AddDevAuthServiceToManager failed, ret %" LOG_PUB "d", ret);
        return 1;
    }
    LOGI("device authentication service register to IPC manager done, service running...");
    (void)memset_s(&cond, sizeof(cond), 0, sizeof(cond));
    ret = InitHcCond(&cond, NULL);
    if (ret != HC_SUCCESS) {
        LOGE("device auth service main, init condition failed, ret %" LOG_PUB "d", ret);
        DestroyServiceInstance(serviceInstance);
        DeMainRescInit();
        DestroyDeviceAuthService();
        return 1;
    }
    cond.wait(&cond);
    DestroyHcCond(&cond);
    return 0;
}
#endif

#ifdef __cplusplus
}
#endif
