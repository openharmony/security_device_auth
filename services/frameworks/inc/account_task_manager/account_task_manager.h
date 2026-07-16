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

#ifndef ACCOUNT_TASK_MANAGER_H
#define ACCOUNT_TASK_MANAGER_H

#include <stdint.h>

#include "json_utils.h"

#ifdef DEVAUTH_ENABLE_OS_ACCOUNT_MULTI_PROFILE
#include "device_auth_ext.h"
#endif

#ifdef __cplusplus
extern "C" {
#endif

int32_t InitAccountTaskManager(void);
void DestroyAccountTaskManager(void);
bool HasAccountPlugin(void);
int32_t ExecuteAccountAuthCmd(int32_t osAccountId, int32_t cmdId, const CJson *in, CJson *out);
int32_t CreateAccountAuthSession(int32_t *sessionId, const CJson *in, CJson *out);
int32_t ProcessAccountAuthSession(int32_t *sessionId, const CJson *in, CJson *out, int32_t *status);
int32_t DestroyAccountAuthSession(int32_t sessionId);

#ifdef DEVAUTH_ENABLE_OS_ACCOUNT_MULTI_PROFILE
int32_t AddDeviceTrustRelation(int32_t osAccountId, const char *userId, const char *groupId,
    const char *udid);
int32_t DelDeviceTrustRelation(int32_t osAccountId, const char *userId, const char *groupId,
    const char *udid);
bool IsDeviceExistInGroupForUser(int32_t osAccountId, const char *userId, const char *groupId,
    const char *udid);
bool IsDeviceExistInGroup(int32_t osAccountId, const char *groupId, const char *udid);
bool IsDeviceExistInUser(int32_t osAccountId, const char *userId, const char *udid);
int32_t AddCredTrustRelation(int32_t osAccountId, const char *userId, const char *credId);
int32_t DelCredTrustRelation(int32_t osAccountId, const char *userId, const char *credId);
bool IsCredReferencedByUser(int32_t osAccountId, const char *userId, const char *credId);
bool IsCredReferenced(int32_t osAccountId, const char *credId);
int32_t NotifyAccountSwitch(int32_t osAccountId, const char *fromUserId, const char *toUserId,
    AccountSwitchGroupCallback groupCallback, AccountSwitchCredCallback credCallback);
bool HasTrustRelationDbPlugin(void);
#endif

void IncreaseLoadCount(void);
void DecreaseLoadCount(void);

#ifdef __cplusplus
}
#endif
#endif