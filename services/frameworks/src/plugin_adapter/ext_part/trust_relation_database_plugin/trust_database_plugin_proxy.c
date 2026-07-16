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
#include "hc_log.h"

static TrustDatabaseExtPlug *g_trustDatabasePlugin = NULL;

int32_t SetTrustDatabasePlugin(const CJson *inputParams, TrustDatabaseExtPlug *trustDatabasePlugin)
{
    if (trustDatabasePlugin == NULL || trustDatabasePlugin->insertGroupTrustRelation == NULL ||
        trustDatabasePlugin->deleteGroupTrustRelation == NULL ||
        trustDatabasePlugin->isGroupRelationReferencedByUser == NULL ||
        trustDatabasePlugin->isGroupRelationReferenced == NULL ||
        trustDatabasePlugin->insertCredTrustRelation == NULL ||
        trustDatabasePlugin->deleteCredTrustRelation == NULL ||
        trustDatabasePlugin->isCredRelationReferencedByUser == NULL ||
        trustDatabasePlugin->isCredRelationReferenced == NULL ||
        trustDatabasePlugin->isDeviceRelationReferencedByUser == NULL ||
        trustDatabasePlugin->onAccountSwitched == NULL ||
        trustDatabasePlugin->base.init == NULL ||
        trustDatabasePlugin->base.destroy ==  NULL) {
        LOGE("[TRUST_DATABASE_PLUGIN]: invalid input params!");
        return HC_ERR_INVALID_PARAMS;
    }
    int32_t res = trustDatabasePlugin->base.init(&trustDatabasePlugin->base,
        inputParams, NULL);
    if (res != HC_SUCCESS) {
        LOGE("[TRUST_DATABASE_PLUGIN]: init failed!");
        return res;
    }
    g_trustDatabasePlugin = trustDatabasePlugin;
    return HC_SUCCESS;
}

int32_t InsertDeviceTrustRelation(int32_t osAccountId, const char *userId, const char *groupId,
    const char *udid)
{
    if (g_trustDatabasePlugin == NULL) {
        LOGE("[TRUST_DATABASE_PLUGIN]: plugin is null!");
        return HC_ERR_NULL_PTR;
    }
    return g_trustDatabasePlugin->insertGroupTrustRelation(osAccountId, userId, groupId, udid);
}

int32_t DeleteDeviceTrustRelation(int32_t osAccountId, const char *userId, const char *groupId,
    const char *udid)
{
    if (g_trustDatabasePlugin == NULL) {
        LOGE("[TRUST_DATABASE_PLUGIN]: plugin is null!");
        return HC_ERR_NULL_PTR;
    }
    return g_trustDatabasePlugin->deleteGroupTrustRelation(osAccountId, userId, groupId, udid);
}

bool IsDeviceReferencedByGroupAndUser(int32_t osAccountId, const char *userId, const char *groupId,
    const char *udid)
{
    if (g_trustDatabasePlugin == NULL) {
        LOGE("[TRUST_DATABASE_PLUGIN]: plugin is null!");
        return false;
    }
    bool isReferenced = false;
    if (g_trustDatabasePlugin->isGroupRelationReferencedByUser(
        osAccountId, userId, groupId, udid, &isReferenced) != HC_SUCCESS) {
        LOGE("[TRUST_DATABASE_PLUGIN]: call failed!");
        return false;
    }
    return isReferenced;
}

bool IsDeviceReferencedByGroup(int32_t osAccountId, const char *groupId, const char *udid)
{
    if (g_trustDatabasePlugin == NULL) {
        LOGE("[TRUST_DATABASE_PLUGIN]: plugin is null!");
        return false;
    }
    bool isReferenced = false;
    if (g_trustDatabasePlugin->isGroupRelationReferenced(osAccountId, groupId, udid, &isReferenced) != HC_SUCCESS) {
        LOGE("[TRUST_DATABASE_PLUGIN]: call failed!");
        return false;
    }
    return isReferenced;
}

int32_t InsertCredTrustRelation(int32_t osAccountId, const char *userId, const char *credId)
{
    if (g_trustDatabasePlugin == NULL) {
        LOGE("[TRUST_DATABASE_PLUGIN]: plugin is null!");
        return HC_ERR_NULL_PTR;
    }
    return g_trustDatabasePlugin->insertCredTrustRelation(osAccountId, userId, credId);
}

int32_t DeleteCredTrustRelation(int32_t osAccountId, const char *userId, const char *credId)
{
    if (g_trustDatabasePlugin == NULL) {
        LOGE("[TRUST_DATABASE_PLUGIN]: plugin is null!");
        return HC_ERR_NULL_PTR;
    }
    return g_trustDatabasePlugin->deleteCredTrustRelation(osAccountId, userId, credId);
}

bool IsCredRelationReferencedByUser(int32_t osAccountId, const char *userId, const char *credId)
{
    if (g_trustDatabasePlugin == NULL) {
        LOGE("[TRUST_DATABASE_PLUGIN]: plugin is null!");
        return false;
    }
    bool isReferenced = false;
    if (g_trustDatabasePlugin->isCredRelationReferencedByUser(
        osAccountId, userId, credId, &isReferenced) != HC_SUCCESS) {
        LOGE("[TRUST_DATABASE_PLUGIN]: call failed!");
        return false;
    }
    return isReferenced;
}

bool IsCredRelationReferenced(int32_t osAccountId, const char *credId)
{
    if (g_trustDatabasePlugin == NULL) {
        LOGE("[TRUST_DATABASE_PLUGIN]: plugin is null!");
        return false;
    }
    bool isReferenced = false;
    if (g_trustDatabasePlugin->isCredRelationReferenced(osAccountId, credId, &isReferenced) != HC_SUCCESS) {
        LOGE("[TRUST_DATABASE_PLUGIN]: call failed!");
        return false;
    }
    return isReferenced;
}

bool IsDeviceReferencedByUser(int32_t osAccountId, const char *userId, const char *udid)
{
    if (g_trustDatabasePlugin == NULL) {
        LOGE("[TRUST_DATABASE_PLUGIN]: plugin is null!");
        return false;
    }
    bool isReferenced = false;
    if (g_trustDatabasePlugin->isDeviceRelationReferencedByUser(
        osAccountId, userId, udid, &isReferenced) != HC_SUCCESS) {
        LOGE("[TRUST_DATABASE_PLUGIN]: call failed!");
        return false;
    }
    return isReferenced;
}

int32_t OnAccountSwitch(int32_t osAccountId, const char *fromUserId, const char *toUserId,
    AccountSwitchGroupCallback groupCallback, AccountSwitchCredCallback credCallback)
{
    if (g_trustDatabasePlugin == NULL) {
        LOGE("[TRUST_DATABASE_PLUGIN]: plugin is null!");
        return HC_ERR_NULL_PTR;
    }
    return g_trustDatabasePlugin->onAccountSwitched(osAccountId, fromUserId, toUserId, groupCallback, credCallback);
}

void DestoryTrustDatabasePlugin(void)
{
    if (g_trustDatabasePlugin != NULL) {
        g_trustDatabasePlugin->base.destroy(&g_trustDatabasePlugin->base);
        g_trustDatabasePlugin = NULL;
    }
}

bool HasTrustDatabasePlugin(void)
{
    if (g_trustDatabasePlugin == NULL) {
        LOGE("[TRUST_DATABASE_PLUGIN]: plugin is invalid!");
        return false;
    }
    return true;
}