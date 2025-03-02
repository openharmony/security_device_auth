/*
 * Copyright (C) 2025 Huawei Device Co., Ltd.
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

#include "credential_data_manager.h"

#include "common_defs.h"
#include "device_auth_defines.h"
#include "hc_dev_info.h"
#include "hc_types.h"
#include "securec.h"

static const uint8_t DEFAULT_CRED_PARAM_VAL = 0;

QueryCredentialParams InitQueryCredentialParams(void)
{
    QueryCredentialParams params = {
        .deviceId = NULL,
        .credOwner = NULL,
        .credId = NULL,
        .userId = NULL,
        .credType = DEFAULT_CRED_PARAM_VAL,
        .ownerUid = DEFAULT_CRED_PARAM_VAL,
        .subject = DEFAULT_CRED_PARAM_VAL,
        .issuer = DEFAULT_CRED_PARAM_VAL,
    };
    return params;
}

Credential *CreateCredential(void)
{
    return NULL;
}

void DestroyCredential(Credential *credential)
{
    (void)credential;
    return;
}

Credential *DeepCopyCredential(const Credential *entry)
{
    (void)entry;
    return NULL;
}

void ClearCredentialVec(CredentialVec *vec)
{
    (void)vec;
    return;
}

int32_t GenerateReturnCredInfo(const Credential *credential, CJson *returnJson)
{
    (void)credential;
    (void)returnJson;
    return IS_ERR_NOT_SUPPORT;
}

int32_t AddCredToDb(int32_t osAccountId, const Credential *entry)
{
    (void)osAccountId;
    (void)entry;
    return IS_ERR_NOT_SUPPORT;
}

int32_t DelCredential(int32_t osAccountId, const QueryCredentialParams *params)
{
    (void)osAccountId;
    (void)params;
    return IS_ERR_NOT_SUPPORT;
}

int32_t QueryCredentials(int32_t osAccountId, const QueryCredentialParams *params, CredentialVec *vec)
{
    (void)osAccountId;
    (void)params;
    (void)vec;
    return IS_ERR_NOT_SUPPORT;
}

int32_t SaveOsAccountCredDb(int32_t osAccountId)
{
    (void)osAccountId;
    return IS_ERR_NOT_SUPPORT;
}

int32_t InitCredDatabase(void)
{
    return IS_ERR_NOT_SUPPORT;
}

void DestroyCredDatabase(void)
{
    return;
}