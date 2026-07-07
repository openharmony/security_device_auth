/*
 * Copyright (C) 2026 Huawei Device Co., Ltd.
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

#ifndef TRUST_DATABASE_PLUGIN_PROXY_H
#define TRUST_DATABASE_PLUGIN_PROXY_H

#include <stdbool.h>
#include <stdint.h>
#include "device_auth_ext.h"
#include "json_utils.h"

#ifdef __cplusplus
extern "C" {
#endif

int32_t SetTrustDatabasePlugin(const CJson *inputParams, TrustDatabaseExtPlug *trustDatabasePlugin);
int32_t InsertDeviceTrustRelation(int32_t osAccountId, const char *userId, const char *groupId,
    const char *udid);
int32_t DeleteDeviceTrustRelation(int32_t osAccountId, const char *userId, const char *groupId,
    const char *udid);
bool IsDeviceReferencedByGroupAndUser(int32_t osAccountId, const char *userId, const char *groupId,
    const char *udid);
bool IsDeviceReferencedByGroup(int32_t osAccountId, const char *groupId, const char *udid);
bool IsDeviceReferencedByUser(int32_t osAccountId, const char *userId, const char *udid);
int32_t InsertCredTrustRelation(int32_t osAccountId, const char *userId, const char *credId);
int32_t DeleteCredTrustRelation(int32_t osAccountId, const char *userId, const char *credId);
bool IsCredRelationReferencedByUser(int32_t osAccountId, const char *userId, const char *credId);
bool IsCredRelationReferenced(int32_t osAccountId, const char *credId);
int32_t OnAccountSwitch(int32_t osAccountId, const char *fromUserId, const char *toUserId,
    AccountSwitchGroupCallback groupCallback, AccountSwitchCredCallback credCallback);
void DestoryTrustDatabasePlugin(void);
bool HasTrustDatabasePlugin(void);

#ifdef __cplusplus
}
#endif
#endif