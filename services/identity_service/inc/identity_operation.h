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

#define FIELD_CRED_TYPE "credType"
#define FIELD_CREDENTIAL_FORMAT "credentialFormat"
#define FIELD_METHOD "method"
#define FIELD_ALGORITHM_TYPE "algorithmType"
#define FIELD_SUBJECT "subject"
#define FIELD_ISSUER "issuer"
#define FIELD_KEY_VALUE "keyValue"
#define FIELD_DEVICE_ID "deviceId"
#define FIELD_PEER_USER_SPACE_ID "peerUserSpaceId"
#define FIELD_AUTHORIZED_ACCOUNT_LIST "authorizedAccountList"
#define FIELD_AUTHORIZED_SCOPE "authorizedScope"
#define FIELD_CRED_OWNER "credOwner"
#define FIELD_EXTEND_INFO "extendInfo"
#define FIELD_CRED_ID "credId"
#define FIELD_PROOF_TYPE "proofType"
#define FIELD_KEY_FORMAT "keyFormat"
#define FIELD_OS_ACCOUNT_ID "osAccountId"
#define FIELD_INTERFACE_PERMISSION "ohos.permission.ACCESS_DEVICE_AUTH_CRED_MGR"
#define DEFAULT_VAL 0
#define RAND_NUM_LENGTH 16
#define KEY_VALUE_MAX_LENGTH 128
#define PAKE_ED25519_KEY_PAIR_LEN 32
#define MAX_INT64_SIZE 20
#define MAX_CRED_SIZE 5000
#define SELE_ECC_KEY_LEN 32
#define AES_128_KEY_LEN 16
#define DEFAULT_EX_INFO_VAL (-1)

#ifdef __cplusplus
extern "C" {
#endif

enum {
    METHOD_GENERATE = 1,
    METHOD_IMPORT = 2,
};

enum {
    ACCOUNTT_RELATED = 1,
    ACCOUNTT_UNRELATED = 2,
};

enum {
    SYMMETRIC_KEY = 1,
    ASYMMETRIC_PUB_KEY = 2,
    ASYMMETRIC_KEY = 3,
    X509_CERT = 4,
};

enum {
    ALGO_TYPE_AES_256 = 1,
    ALGO_TYPE_AES_128 = 2,
    ALGO_TYPE_P256 = 3,
    ALGO_TYPE_ED25519 = 4,
};

enum {
    SELF_DEVICE = 1,
    OTHER_DEVICE = 2,
};

enum {
    SYSTEM_ACCOUNT = 1,
    APP_ACCOUNT = 2,
    DOMANIN_ACCOUNT = 3,
};

enum {
    PROOF_TYPE_PSK  = 1,
    PROOF_TYPE_PKI  = 2,
};

enum {
    SCOPE_DEVICE = 1,
    SCOPE_USER = 2,
    SCOPE_APP = 3,
};

int32_t AddCredAndSaveDb(int32_t osAccountId, Credential *credential);
int32_t AddKeyValueToHuks(int32_t osAccountId, Uint8Buff credIdByte, Credential *credential, uint8_t method,
    Uint8Buff publicKey);
int32_t AddKeyValueToReturn(Uint8Buff keyValue, char **returnData);
int32_t CheckCredIdExistInHuks(int32_t osAccountId, const char *credId, Uint8Buff *credIdHashBuff);
int32_t DelCredById(int32_t osAccountId, const char *credId);

int32_t GenerateCredId(int32_t osAccountId, Credential *credential, Uint8Buff *credIdByte);
int32_t GenerateReturnEmptyArrayStr(char **returnVec);
int32_t GetCredentialById(int32_t osAccountId, const char *credId, Credential **returnEntry);
int32_t GetCredIdsFromCredVec(CredentialVec credentialVec, CJson *credIdJson, int32_t osAccountId);

int32_t CheckAndSetCredInfo(int32_t osAccountId, Credential *credential, CJson *json, uint8_t *method,
    Uint8Buff *publicKey);
int32_t SetQueryParamsFromJson(QueryCredentialParams *queryParams, CJson *json);
int32_t UpdateInfoFromJson(Credential *credential, CJson *json);

#ifdef __cplusplus
}
#endif

#endif // IDENTITY_OPERATION_H
