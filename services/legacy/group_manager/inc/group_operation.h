/*
 * Copyright (C) 2021-2025 Huawei Device Co., Ltd.
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

#ifndef GROUP_OPERATION_H
#define GROUP_OPERATION_H

#include "device_auth.h"
#include "base_group_manager_task.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    const char* deviceId;
    bool isUdid;
} DeviceQueryParams;

typedef struct {
    int32_t (*createGroup)(int32_t osAccountId, int64_t requestId, const char *appId, const char *createParams);
    int32_t (*deleteGroup)(int32_t osAccountId, int64_t requestId, const char *appId, const char *disbandParams);
    int32_t (*addMemberToGroup)(int32_t osAccountId, int64_t requestId, const char *appId, const char *addParams);
    int32_t (*processBindData)(int64_t requestId, const uint8_t *data, uint32_t dataLen);
    int32_t (*deleteMember)(int32_t osAccountId, int64_t requestId, const char *appId, const char *deleteParams);
    int32_t (*addMultiMembers)(int32_t osAccountId, const char *appId, const char *addParams);
    int32_t (*delMultiMembers)(int32_t osAccountId, const char *appId, const char *deleteParams);
    int32_t (*regCallback)(const char *appId, const DeviceAuthCallback *callback);
    int32_t (*unRegCallback)(const char *appId);
    int32_t (*regListener)(const char *appId, const DataChangeListener *listener);
    int32_t (*unRegListener)(const char *appId);
    int32_t (*getRegisterInfo)(const char *reqJsonStr, char **returnRegisterInfo);
    int32_t (*checkAccessToGroup)(int32_t osAccountId, const char *appId, const char *groupId);
    int32_t (*getAccessibleGroupInfoById)(int32_t osAccountId, const char *appId, const char *groupId,
        char **returnGroupInfo);
    int32_t (*getAccessibleGroupInfo)(int32_t osAccountId, const char *appId, const char *queryParams,
        char **returnGroupVec, uint32_t *groupNum);
    int32_t (*getAccessibleJoinedGroups)(int32_t osAccountId, const char *appId, int groupType,
        char **returnGroupVec, uint32_t *groupNum);
    int32_t (*getAccessibleRelatedGroups)(int32_t osAccountId, const char *appId, const char *peerDeviceId,
        char **returnGroupVec, uint32_t *groupNum);
    int32_t (*getAccessibleDeviceInfoById)(int32_t osAccountId, const char *appId,
        const DeviceQueryParams *devQueryParams, const char *groupId, char **returnDeviceInfo);
    int32_t (*getAccessibleTrustedDevices)(int32_t osAccountId, const char *appId, const char *groupId,
        char **returnDevInfoVec, uint32_t *deviceNum);
    bool (*isDeviceInAccessibleGroup)(int32_t osAccountId, const char *appId, const char *groupId,
        const char *deviceId, bool isUdid);
    int32_t (*getPkInfoList)(int32_t osAccountId, const char *appId, const char *queryParams, char **returnInfoList,
        uint32_t *returnInfoNum);
    void (*destroyInfo)(char **returnInfo);
} GroupImpl;

int32_t InitGroupRelatedModule(void);
void DestroyGroupRelatedModule(void);
const GroupImpl *GetGroupImplInstance(void);
bool IsGroupSupport(void);

typedef void (*TaskFunc)(HcTaskBase *task);

void DestroyGroupManagerTask(HcTaskBase *task);

int32_t BindCallbackToTask(GroupManagerTask *task, const CJson *jsonParams);
int32_t AddReqInfoToJson(int64_t requestId, const char *appId, CJson *jsonParams);
int32_t AddBindParamsToJson(int operationCode, int64_t requestId, const char *appId, CJson *jsonParams);
int32_t InitAndPushGMTask(int32_t osAccountId, int32_t opCode, int64_t reqId, CJson *params, TaskFunc func);

#ifdef __cplusplus
}
#endif
#endif
