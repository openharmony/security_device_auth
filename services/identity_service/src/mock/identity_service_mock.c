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

#include "identity_service.h"

#include "common_defs.h"

int32_t AddCredential(int32_t osAccountId, const char *requestParams, char **returnData)
{
    (void)osAccountId;
    (void)requestParams;
    (void)returnData;
    return IS_ERR_NOT_SUPPORT;
}

int32_t ExportCredential(int32_t osAccountId, const char *credId, char **returnData)
{
    (void)osAccountId;
    (void)credId;
    (void)returnData;
    return IS_ERR_NOT_SUPPORT;
}

int32_t QueryCredentialByParams(int32_t osAccountId, const char *requestParams, char **returnData)
{
    (void)osAccountId;
    (void)requestParams;
    (void)returnData;
    return IS_ERR_NOT_SUPPORT;
}

int32_t QueryCredInfoByCredIdAndUid(int32_t osAccountId, int32_t uid, const char *credId,
    char **returnData)
{
    (void)osAccountId;
    (void)uid;
    (void)credId;
    (void)returnData;
    return IS_ERR_NOT_SUPPORT;    
}

int32_t QueryCredInfoByCredId(int32_t osAccountId, const char *credId, char **returnData)
{
    (void)osAccountId;
    (void)credId;
    (void)returnData;
    return IS_ERR_NOT_SUPPORT;
}

int32_t DeleteCredential(int32_t osAccountId, const char *credId)
{
    (void)osAccountId;
    (void)credId;
    return IS_ERR_NOT_SUPPORT;
}

int32_t DeleteCredByParams(int32_t osAccountId, const char *requestParams, char **returnData)
{
    (void)osAccountId;
    (void)requestParams;
    (void)returnData;
    return IS_ERR_NOT_SUPPORT;
}

int32_t UpdateCredInfo(int32_t osAccountId, const char *credId, const char *requestParams)
{
    (void)osAccountId;
    (void)credId;
    (void)requestParams;
    return IS_ERR_NOT_SUPPORT;
}

int32_t AgreeCredential(int32_t osAccountId, const char *selfCredId, const char *requestParams, char **returnData)
{
    (void)osAccountId;
    (void)selfCredId;
    (void)requestParams;
    (void)returnData;
    return IS_ERR_NOT_SUPPORT;
}

int32_t BatchUpdateCredentials(int32_t osAccountId, const char *requestParams, char **returnData)
{
    (void)osAccountId;
    (void)requestParams;
    (void)returnData;
    return IS_ERR_NOT_SUPPORT;
}

int32_t RegisterChangeListener(const char *appId, CredChangeListener *listener)
{
    (void)appId;
    (void)listener;
    return IS_ERR_NOT_SUPPORT;
}

int32_t UnregisterChangeListener(const char *appId)
{
    (void)appId;
    return IS_ERR_NOT_SUPPORT;
}

void DestroyInfo(char **returnData)
{
    (void)returnData;
    return;
}

int32_t InitIdentityService(void)
{
    return IS_SUCCESS;
}

void DestroyIdentityService(void)
{
    return;
}