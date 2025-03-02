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


#include "identity_operation.h"

#include "alg_defs.h"
#include "alg_loader.h"
#include "clib_error.h"
#include "device_auth.h"
#include "device_auth_defines.h"
#include "hal_error.h"
#include "hc_log.h"
#include "identity_service_defines.h"

int32_t GetCredentialById(int32_t osAccountId, const char *credId, Credential **returnEntry)
{
    (void)osAccountId;
    (void)credId;
    (void)returnEntry;
    return IS_ERR_NOT_SUPPORT;
}

int32_t GenerateCredId(int32_t osAccountId, Credential *credential, Uint8Buff *credIdByte)
{
    (void)osAccountId;
    (void)credential;
    (void)credIdByte;
    return IS_ERR_NOT_SUPPORT;
}

int32_t AddKeyValueToHuks(int32_t osAccountId, Uint8Buff *credIdByte, Credential *credential, uint8_t method,
    Uint8Buff *keyValue)
{
    (void)osAccountId;
    (void)credential;
    (void)credIdByte;
    (void)method;
    (void)keyValue;
    return IS_ERR_NOT_SUPPORT;
}

int32_t GetValidKeyAlias(int32_t osAccountId, const char *credId, Uint8Buff *credIdHashBuff)
{
    (void)osAccountId;
    (void)credId;
    (void)credIdHashBuff;
    return IS_ERR_NOT_SUPPORT;
}

int32_t AddCredAndSaveDb(int32_t osAccountId, Credential *credential)
{
    (void)osAccountId;
    (void)credential;
    return IS_ERR_NOT_SUPPORT;
}

int32_t CheckAndSetCredInfo(int32_t osAccountId,
    Credential *credential, CJson *json, uint8_t *method, Uint8Buff *keyValue)
{
    (void)osAccountId;
    (void)credential;
    (void)json;
    (void)method;
    (void)keyValue;
    return IS_ERR_NOT_SUPPORT;
}

int32_t SetQueryParamsFromJson(QueryCredentialParams *queryParams, CJson *json)
{
    (void)queryParams;
    (void)json;
    return IS_ERR_NOT_SUPPORT;
}

int32_t GetCredIdsFromCredVec(int32_t osAccountId, CJson *reqJson, CredentialVec *credentialVec, CJson *credIdJson)
{
    (void)osAccountId;
    (void)reqJson;
    (void)credentialVec;
    (void)credIdJson;
    return IS_ERR_NOT_SUPPORT;
}

int32_t UpdateInfoFromJson(Credential *credential, CJson *json)
{
    (void)credential;
    (void)json;
    return IS_ERR_NOT_SUPPORT;
}

int32_t DelCredById(int32_t osAccountId, const char *credId)
{
    (void)osAccountId;
    (void)credId;
    return IS_ERR_NOT_SUPPORT;
}

int32_t AddKeyValueToReturn(Uint8Buff keyValue, char **returnData)
{
    (void)keyValue;
    (void)returnData;
    return IS_ERR_NOT_SUPPORT;
}

int32_t GenerateReturnEmptyArrayStr(char **returnVec)
{
    (void)returnVec;
    return IS_ERR_NOT_SUPPORT;
}

int32_t CheckOwnerUidPermission(Credential *credential)
{
    (void)credential;
    return IS_ERR_NOT_SUPPORT;
}

int32_t GenerateCredKeyAlias(const char *credId, const char *deviceId, Uint8Buff *alias)
{
    (void)credId;
    (void)deviceId;
    (void)alias;
    return IS_ERR_NOT_SUPPORT;
}

int32_t SetAgreeCredInfo(int32_t osAccountId, CJson *reqJson,
    Credential *agreeCredential, Uint8Buff *keyValue, Uint8Buff *agreeCredIdByte)
{
    (void)osAccountId;
    (void)reqJson;
    (void)agreeCredential;
    (void)keyValue;
    (void)agreeCredIdByte;
    return IS_ERR_NOT_SUPPORT;
}

int32_t ImportAgreeKeyValue(int32_t osAccountId, Credential *agreeCredential, Uint8Buff *keyValue,
    Uint8Buff *peerKeyAlias)
{
    (void)osAccountId;
    (void)agreeCredential;
    (void)keyValue;
    (void)peerKeyAlias;
    return IS_ERR_NOT_SUPPORT;
}

int32_t CheckAndDelInvalidCred(int32_t osAccountId, const char *selfCredId, Uint8Buff *selfCredIdByte)
{
    (void)osAccountId;
    (void)selfCredId;
    (void)selfCredIdByte;
    return IS_ERR_NOT_SUPPORT;
}

int32_t ComputePskAndDelInvalidKey(int32_t osAccountId, uint8_t credAlgo, Uint8Buff *selfCredIdByte,
    Uint8Buff *peerKeyAlias, Uint8Buff *agreeCredIdByte)
{
    (void)osAccountId;
    (void)credAlgo;
    (void)selfCredIdByte;
    (void)peerKeyAlias;
    (void)agreeCredIdByte;
    return IS_ERR_NOT_SUPPORT;
}

int32_t SetRequiredParamsFromJson(QueryCredentialParams *queryParams, CJson *baseInfoJson)
{
    (void)queryParams;
    (void)baseInfoJson;
    return IS_ERR_NOT_SUPPORT;
}

int32_t SetUpdateToQueryParams(CJson *json, QueryCredentialParams *queryParams)
{
    (void)json;
    (void)queryParams;
    return IS_ERR_NOT_SUPPORT;
}

int32_t AddUpdateInfoToJson(QueryCredentialParams *queryParams, CJson *baseInfoJson)
{
    (void)queryParams;
    (void)baseInfoJson;
    return IS_ERR_NOT_SUPPORT;
}

int32_t EraseUpdateCredIdInSelfVec(CredentialVec *updateCredVec, CredentialVec *selfCredVec)
{
    (void)updateCredVec;
    (void)selfCredVec;
    return IS_ERR_NOT_SUPPORT;
}

int32_t GetQueryJsonStr(CJson *baseInfoJson, char **queryJsonStr)
{
    (void)baseInfoJson;
    (void)queryJsonStr;
    return IS_ERR_NOT_SUPPORT;
}

int32_t GetUpdateCredVec(int32_t osAccountId, CJson *updateInfo,
    QueryCredentialParams *queryParams, CredentialVec *updateCredVec)
{
    (void)osAccountId;
    (void)updateInfo;
    (void)queryParams;
    (void)updateCredVec;
    return IS_ERR_NOT_SUPPORT;
}

bool IsCredHashMatch(Credential *credential, CJson *reqJson)
{
    (void)credential;
    (void)reqJson;
    return false;
}
