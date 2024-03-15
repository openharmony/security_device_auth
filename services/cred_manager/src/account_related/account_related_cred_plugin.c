/*
 * Copyright (C) 2023 Huawei Device Co., Ltd.
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

#include "account_related_cred_plugin.h"

#include "account_auth_plugin_proxy.h"
#include "asy_token_manager.h"
#include "hc_log.h"
#include "sym_token_manager.h"

static int32_t ProcessAsyTokens(int32_t osAccountId, int32_t cmdId, CJson *in, CJson *out)
{
    switch (cmdId) {
        case IMPORT_SELF_CREDENTIAL:
        case IMPORT_TRUSTED_CREDENTIALS:
            return GetAccountAuthTokenManager()->addToken(osAccountId, cmdId, in);
        case DELETE_SELF_CREDENTIAL:
        case DELETE_TRUSTED_CREDENTIALS: {
            const char *userId = GetStringFromJson(in, FIELD_USER_ID);
            if (userId == NULL) {
                LOGE("Failed to get user id.");
                return HC_ERR_JSON_GET;
            }
            const char *deviceId = GetStringFromJson(in, FIELD_DEVICE_ID);
            if (deviceId == NULL) {
                LOGE("Failed to get deviceId from json!");
                return HC_ERR_JSON_GET;
            }
            return GetAccountAuthTokenManager()->deleteToken(osAccountId, userId, deviceId);
        }
        case REQUEST_SIGNATURE:
            if (out == NULL) {
                LOGE("Params: out is null.");
                return HC_ERR_NULL_PTR;
            }
            return GetAccountAuthTokenManager()->getRegisterProof(in, out);
        default:
            LOGE("Operation is not supported for: %d.", cmdId);
            return HC_ERR_NOT_SUPPORT;
    }
}

static int32_t ProcessSymTokens(int32_t osAccountId, int32_t cmdId, CJson *in, CJson *out)
{
    (void)out;
    switch (cmdId) {
        case IMPORT_SELF_CREDENTIAL:
        case IMPORT_TRUSTED_CREDENTIALS:
            return GetSymTokenManager()->addToken(osAccountId, cmdId, in);
        case DELETE_SELF_CREDENTIAL:
        case DELETE_TRUSTED_CREDENTIALS: {
            const char *userId = GetStringFromJson(in, FIELD_USER_ID);
            if (userId == NULL) {
                LOGE("Failed to get userId from json!");
                return HC_ERR_JSON_GET;
            }
            const char *deviceId = GetStringFromJson(in, FIELD_DEVICE_ID);
            if (deviceId == NULL) {
                LOGE("Failed to get deviceId from json!");
                return HC_ERR_JSON_GET;
            }
            return GetSymTokenManager()->deleteToken(osAccountId, userId, deviceId);
        }
        default:
            LOGE("Operation is not supported for: %d.", cmdId);
            return HC_ERR_NOT_SUPPORT;
    }
}

static int32_t ProcessAccountCredentials(int32_t osAccountId, int32_t cmdId, CJson *in, CJson *out)
{
    if (HasAccountAuthPlugin() == HC_SUCCESS) {
        return ExcuteCredMgrCmd(osAccountId, cmdId, in, out);
    }
    if (in == NULL) {
        LOGE("The input param: in is null.");
        return HC_ERR_NULL_PTR;
    }
    int32_t credentialType = INVALID_CRED;
    if (GetIntFromJson(in, FIELD_CREDENTIAL_TYPE, &credentialType) != HC_SUCCESS) {
        LOGE("Failed to get credentialType from json!");
        return HC_ERR_JSON_GET;
    }
    if (credentialType == ASYMMETRIC_CRED) {
        return ProcessAsyTokens(osAccountId, cmdId, in, out);
    } else if (credentialType == SYMMETRIC_CRED) {
        return ProcessSymTokens(osAccountId, cmdId, in, out);
    } else {
        LOGE("Invalid credential type! [CredType]: %d", credentialType);
        return HC_ERR_NOT_SUPPORT;
    }
}

static int32_t InitAccountRelatedCredPlugin(void)
{
    InitTokenManager();
    InitSymTokenManager();
    return HC_SUCCESS;
}

static void DestroyAccountRelatedCredPlugin(void)
{
    DestroyTokenManager();
    DestroySymTokenManager();
}

static CredPlugin g_instance = {
    .pluginName = ACCOUNT_RELATED_PLUGIN,
    .init = InitAccountRelatedCredPlugin,
    .destroy = DestroyAccountRelatedCredPlugin,
    .procCred = ProcessAccountCredentials
};

CredPlugin *GetAccountRelatedCredPlugin(void)
{
    return &g_instance;
}
