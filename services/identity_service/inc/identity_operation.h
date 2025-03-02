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

#ifndef IDENTITY_OPERATION_H
#define IDENTITY_OPERATION_H

#include "cred_listener.h"
#include "credential_data_manager.h"
#include "uint8buff_utils.h"

#ifdef __cplusplus
extern "C" {
#endif

int32_t AddCredAndSaveDb(int32_t osAccountId, Credential *credential);
int32_t AddKeyValueToHuks(int32_t osAccountId, Uint8Buff *credIdByte, Credential *credential, uint8_t method,
    Uint8Buff *publicKey);
int32_t AddKeyValueToReturn(Uint8Buff keyValue, char **returnData);
int32_t AddUpdateInfoToJson(QueryCredentialParams *queryParams, CJson *baseInfoJson);
int32_t GetValidKeyAlias(int32_t osAccountId, const char *credId, Uint8Buff *credIdHashBuff);
int32_t CheckOwnerUidPermission(Credential *credential);
int32_t CheckAndDelInvalidCred(int32_t osAccountId, const char *selfCredId, Uint8Buff *selfCredIdByte);
int32_t ComputePskAndDelInvalidKey(int32_t osAccountId, uint8_t credAlgo,
    Uint8Buff *selfCredIdByte, Uint8Buff *peerKeyAlias, Uint8Buff *agreeCredIdByte);
int32_t DelCredById(int32_t osAccountId, const char *credId);
int32_t EraseUpdateCredIdInSelfVec(CredentialVec *updateCredVec, CredentialVec *selfCredVec);

int32_t GenerateCredId(int32_t osAccountId, Credential *credential, Uint8Buff *credIdByte);
int32_t GenerateCredKeyAlias(const char *credId, const char *deviceId, Uint8Buff *alias);
int32_t GenerateReturnEmptyArrayStr(char **returnVec);
int32_t GetCredentialById(int32_t osAccountId, const char *credId, Credential **returnEntry);
int32_t GetCredIdsFromCredVec(int32_t osAccountId, CJson *reqJson, CredentialVec *credentialVec, CJson *credIdJson);
int32_t GetQueryJsonStr(CJson *baseInfoJson, char **queryJsonStr);
int32_t GetUpdateCredVec(int32_t osAccountId, CJson *updateInfo,
    QueryCredentialParams *queryParams, CredentialVec *updateCredVec);
int32_t ImportAgreeKeyValue(int32_t osAccountId, Credential *agreeCredential, Uint8Buff *keyValue,
    Uint8Buff *peerKeyAlias);
bool IsCredHashMatch(Credential *credential, CJson *reqJson);

int32_t CheckAndSetCredInfo(int32_t osAccountId, Credential *credential, CJson *json, uint8_t *method,
    Uint8Buff *publicKey);
int32_t SetAgreeCredInfo(int32_t osAccountId, CJson *reqJson,
    Credential *agreeCredential, Uint8Buff *keyValue, Uint8Buff *agreeCredIdByte);
int32_t SetQueryParamsFromJson(QueryCredentialParams *queryParams, CJson *json);
int32_t SetRequiredParamsFromJson(QueryCredentialParams *queryParams, CJson *baseInfoJson);
int32_t SetUpdateToQueryParams(CJson *json, QueryCredentialParams *queryParams);
int32_t UpdateInfoFromJson(Credential *credential, CJson *json);

#ifdef __cplusplus
}
#endif

#endif // IDENTITY_OPERATION_H
