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

#ifndef CREDENTIAL_DATA_MANAGER_H
#define CREDENTIAL_DATA_MANAGER_H

#include <stdbool.h>
#include "hc_string_vector.h"
#include "json_utils.h"

#define MAX_STRING_LEN 256

typedef struct {
    /* unique index*/
    HcString credId;
    /* device */
    HcString deviceId;
    HcString peerUserSpaceId;
    uint8_t subject;
    /* user */
    HcString userId;
    uint8_t issuer;
    /* key */
    uint8_t credType;
    uint8_t keyFormat;
    uint8_t algorithmType;
    uint8_t proofType;
    /* access permission*/
    StringVector authorizedAccountList;
    StringVector authorizedAppList;
    StringVector authorizedDeviceList;
    uint8_t authorizedScope;
    HcString credOwner;
    int32_t ownerUid;
    /* extention info*/
    HcString extendInfo;
} Credential;
DECLARE_HC_VECTOR(CredentialVec, Credential*)

typedef struct {
    const char *credId;
    const char *deviceId;
    const char *peerUserSpaceId;
    uint8_t subject;
    const char *userId;
    uint8_t issuer;
    uint8_t credType;
    uint8_t keyFormat;
    uint8_t algorithmType;
    uint8_t proofType;
    uint8_t authorizedScope;
    const char *credOwner;
    int32_t ownerUid;
} QueryCredentialParams;

#ifdef __cplusplus
extern "C" {
#endif

int32_t InitCredDatabase(void);
void DestroyCredDatabase(void);

int32_t AddCredToDb(int32_t osAccountId, const Credential *credential);
int32_t DelCredential(int32_t osAccountId, const QueryCredentialParams *delParams);
int32_t QueryCredentials(int32_t osAccountId, const QueryCredentialParams *queryParams,
    CredentialVec *vec);
int32_t SaveOsAccountCredDb(int32_t osAccountId);

Credential *DeepCopyCredential(const Credential *credential);

QueryCredentialParams InitQueryCredentialParams(void);
int32_t GenerateReturnCredInfo(const Credential *credential, CJson *returnJson);

Credential *CreateCredential(void);
void DestroyCredential(Credential *groupEntry);

CredentialVec CreateCredentialVec(void);
void ClearCredentialVec(CredentialVec *vec);

#ifdef __cplusplus
}
#endif
#endif
