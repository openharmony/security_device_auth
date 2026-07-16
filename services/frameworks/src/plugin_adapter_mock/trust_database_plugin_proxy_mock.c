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

#include "trust_database_plugin_proxy.h"

#include "device_auth_defines.h"

int32_t SetTrustDatabasePlugin(const CJson *inputParams, TrustDatabaseExtPlug *trustDatabasePlugin)
{
    (void)inputParams;
    (void)trustDatabasePlugin;
    return HC_ERR_NOT_SUPPORT;
}

int32_t InsertDeviceTrustRelation(int32_t osAccountId, const char *userId, const char *groupId,
    const char *udid)
{
    (void)osAccountId;
    (void)userId;
    (void)groupId;
    (void)udid;
    return HC_ERR_NOT_SUPPORT;
}

int32_t DeleteDeviceTrustRelation(int32_t osAccountId, const char *userId, const char *groupId,
    const char *udid)
{
    (void)osAccountId;
    (void)userId;
    (void)groupId;
    (void)udid;
    return HC_ERR_NOT_SUPPORT;
}

bool IsDeviceReferencedByGroupAndUser(int32_t osAccountId, const char *userId, const char *groupId,
    const char *udid)
{
    (void)osAccountId;
    (void)userId;
    (void)groupId;
    (void)udid;
    return false;
}

bool IsDeviceReferencedByGroup(int32_t osAccountId, const char *groupId, const char *udid)
{
    (void)osAccountId;
    (void)groupId;
    (void)udid;
    return false;
}

bool IsDeviceReferencedByUser(int32_t osAccountId, const char *userId, const char *udid)
{
    (void)osAccountId;
    (void)userId;
    (void)udid;
    return false;
}

int32_t InsertCredTrustRelation(int32_t osAccountId, const char *userId, const char *credId)
{
    (void)osAccountId;
    (void)userId;
    (void)credId;
    return HC_ERR_NOT_SUPPORT;
}

int32_t DeleteCredTrustRelation(int32_t osAccountId, const char *userId, const char *credId)
{
    (void)osAccountId;
    (void)userId;
    (void)credId;
    return HC_ERR_NOT_SUPPORT;
}

bool IsCredRelationReferencedByUser(int32_t osAccountId, const char *userId, const char *credId)
{
    (void)osAccountId;
    (void)userId;
    (void)credId;
    return false;
}

bool IsCredRelationReferenced(int32_t osAccountId, const char *credId)
{
    (void)osAccountId;
    (void)credId;
    return false;
}

int32_t OnAccountSwitch(int32_t osAccountId, const char *fromUserId, const char *toUserId,
    AccountSwitchGroupCallback groupCallback, AccountSwitchCredCallback credCallback)
{
    (void)osAccountId;
    (void)fromUserId;
    (void)toUserId;
    (void)groupCallback;
    (void)credCallback;
    return HC_ERR_NOT_SUPPORT;
}

void DestoryTrustDatabasePlugin(void) {}

bool HasTrustDatabasePlugin(void)
{
    return false;
}