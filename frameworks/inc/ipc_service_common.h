/*
 * Copyright (C) 2024-2024 Huawei Device Co., Ltd.
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

#ifndef IPC_SERVICE_COMMON_H
#define IPC_SERVICE_COMMON_H

#include "ipc_adapt.h"

#ifdef __cplusplus
extern "C" {
# endif


// Group Manager Interfaces
int32_t IpcServiceGmRegCallback(const IpcDataInfo *ipcParams, int32_t paramNum, uintptr_t outCache);
int32_t IpcServiceGmUnRegCallback(const IpcDataInfo *ipcParams, int32_t paramNum, uintptr_t outCache);
int32_t IpcServiceGmRegDataChangeListener(const IpcDataInfo *ipcParams, int32_t paramNum, uintptr_t outCache);
int32_t IpcServiceGmUnRegDataChangeListener(const IpcDataInfo *ipcParams, int32_t paramNum, uintptr_t outCache);
int32_t IpcServiceGmCreateGroup(const IpcDataInfo *ipcParams, int32_t paramNum, uintptr_t outCache);
int32_t IpcServiceGmDelGroup(const IpcDataInfo *ipcParams, int32_t paramNum, uintptr_t outCache);
int32_t IpcServiceGmAddMemberToGroup(const IpcDataInfo *ipcParams, int32_t paramNum, uintptr_t outCache);
int32_t IpcServiceGmDelMemberFromGroup(const IpcDataInfo *ipcParams, int32_t paramNum, uintptr_t outCache);
int32_t IpcServiceGmAddMultiMembersToGroup(const IpcDataInfo *ipcParams, int32_t paramNum, uintptr_t outCache);
int32_t IpcServiceGmDelMultiMembersFromGroup(const IpcDataInfo *ipcParams, int32_t paramNum, uintptr_t outCache);
int32_t IpcServiceGmProcessData(const IpcDataInfo *ipcParams, int32_t paramNum, uintptr_t outCache);
int32_t IpcServiceGmApplyRegisterInfo(const IpcDataInfo *ipcParams, int32_t paramNum, uintptr_t outCache);
int32_t IpcServiceGmCheckAccessToGroup(const IpcDataInfo *ipcParams, int32_t paramNum, uintptr_t outCache);
int32_t IpcServiceGmGetPkInfoList(const IpcDataInfo *ipcParams, int32_t paramNum, uintptr_t outCache);
int32_t IpcServiceGmGetGroupInfoById(const IpcDataInfo *ipcParams, int32_t paramNum, uintptr_t outCache);
int32_t IpcServiceGmGetGroupInfo(const IpcDataInfo *ipcParams, int32_t paramNum, uintptr_t outCache);
int32_t IpcServiceGmGetJoinedGroups(const IpcDataInfo *ipcParams, int32_t paramNum, uintptr_t outCache);
int32_t IpcServiceGmGetRelatedGroups(const IpcDataInfo *ipcParams, int32_t paramNum, uintptr_t outCache);
int32_t IpcServiceGmGetDeviceInfoById(const IpcDataInfo *ipcParams, int32_t paramNum, uintptr_t outCache);
int32_t IpcServiceGmGetTrustedDevices(const IpcDataInfo *ipcParams, int32_t paramNum, uintptr_t outCache);
int32_t IpcServiceGmIsDeviceInGroup(const IpcDataInfo *ipcParams, int32_t paramNum, uintptr_t outCache);
int32_t IpcServiceGmCancelRequest(const IpcDataInfo *ipcParams, int32_t paramNum, uintptr_t outCache);

// Group Auth Interfaces
int32_t IpcServiceGaProcessData(const IpcDataInfo *ipcParams, int32_t paramNum, uintptr_t outCache);
int32_t IpcServiceGaAuthDevice(const IpcDataInfo *ipcParams, int32_t paramNum, uintptr_t outCache);
int32_t IpcServiceGaCancelRequest(const IpcDataInfo *ipcParams, int32_t paramNum, uintptr_t outCache);
int32_t IpcServiceGaGetRealInfo(const IpcDataInfo *ipcParams, int32_t paramNum, uintptr_t outCache);
int32_t IpcServiceGaGetPseudonymId(const IpcDataInfo *ipcParams, int32_t paramNum, uintptr_t outCache);

// Direct Auth Interfaces
int32_t IpcServiceDaProcessCredential(const IpcDataInfo *ipcParams, int32_t paramNum, uintptr_t outCache);
int32_t IpcServiceDaAuthDevice(const IpcDataInfo *ipcParams, int32_t paramNum, uintptr_t outCache);
int32_t IpcServiceDaProcessData(const IpcDataInfo *ipcParams, int32_t paramNum, uintptr_t outCache);
int32_t IpcServiceDaCancelRequest(const IpcDataInfo *ipcParams, int32_t paramNum, uintptr_t outCache);

// Credential Manager Interfaces - IS
int32_t IpcServiceCmAddCredential(const IpcDataInfo *ipcParams, int32_t paramNum, uintptr_t outCache);
int32_t IpcServiceCmRegCredChangeListener(const IpcDataInfo *ipcParams, int32_t paramNum, uintptr_t outCache);
int32_t IpcServiceCmUnRegCredChangeListener(const IpcDataInfo *ipcParams, int32_t paramNum, uintptr_t outCache);
int32_t IpcServiceCmExportCredential(const IpcDataInfo *ipcParams, int32_t paramNum, uintptr_t outCache);
int32_t IpcServiceCmQueryCredentialByParams(const IpcDataInfo *ipcParams, int32_t paramNum, uintptr_t outCache);
int32_t IpcServiceCmQueryCredentialByCredId(const IpcDataInfo *ipcParams, int32_t paramNum, uintptr_t outCache);
int32_t IpcServiceCmDeleteCredential(const IpcDataInfo *ipcParams, int32_t paramNum, uintptr_t outCache);
int32_t IpcServiceCmUpdateCredInfo(const IpcDataInfo *ipcParams, int32_t paramNum, uintptr_t outCache);
int32_t IpcServiceCaAuthDevice(const IpcDataInfo *ipcParams, int32_t paramNum, uintptr_t outCache);
int32_t IpcServiceCaProcessCredData(const IpcDataInfo *ipcParams, int32_t paramNum, uintptr_t outCache);

int32_t MainRescInit(void);
void DeMainRescInit(void);

#ifdef __cplusplus
}
#endif

#endif // IPC_SERVICE_COMMON_H