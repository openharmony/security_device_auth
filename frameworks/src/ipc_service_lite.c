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
#include "ipc_sdk.h"
#include "ipc_service_common.h"

#ifdef __cplusplus
extern "C" {
#endif

int32_t AddMethodMap(uintptr_t ipcInstance)
{
    uint32_t ret = 0;
    typedef struct {
        int32_t (*func)(const IpcDataInfo*, int32_t, uintptr_t);
        uint32_t id;
    } IpcCallMap;

    IpcCallMap ipcCallMaps[] = {
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
    };

    for (uint32_t i = 0; i < sizeof(ipcCallMaps)/sizeof(ipcCallMaps[0]); i++) {
        ret &= SetIpcCallMap(ipcInstance, ipcCallMaps[i].func, ipcCallMaps[i].id);
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
        LOGE("device auth service main, InitDeviceAuthService failed, ret %d", ret);
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
        LOGE("device auth service main, AddDevAuthServiceToManager failed, ret %d", ret);
        return 1;
    }
    LOGI("device authentication service register to IPC manager done, service running...");
    (void)memset_s(&cond, sizeof(cond), 0, sizeof(cond));
    InitHcCond(&cond, NULL);
    cond.wait(&cond);
    DestroyHcCond(&cond);
    return 0;
}
#endif

#ifdef __cplusplus
}
#endif
