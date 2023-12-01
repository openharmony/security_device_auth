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

#ifndef AUTH_IDENTITY_MANAGER_H
#define AUTH_IDENTITY_MANAGER_H

#include "alg_defs.h"
#include "alg_loader.h"
#include "common_defs.h"
#include "das_task_common.h"
#include "device_auth_defines.h"
#include "hc_log.h"
#include "hc_types.h"
#include "identity_common.h"
#include "identity_defines.h"
#include "json_utils.h"
#include "securec.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    AUTH_IDENTITY_TYPE_INVALID = -1,
    AUTH_IDENTITY_TYPE_GROUP,
    AUTH_IDENTITY_TYPE_PIN,
    AUTH_IDENTITY_TYPE_P2P,
} AuthIdentityType;

typedef struct {
    int32_t (*getCredInfosByPeerIdentity)(const CJson *in, IdentityInfoVec *vec);
    int32_t (*getCredInfoByPeerUrl)(const CJson *in, const Uint8Buff *presharedUrl, IdentityInfo **returnInfo);
    int32_t (*getSharedSecretByUrl)(
        const CJson *in, const Uint8Buff *presharedUrl, ProtocolAlgType protocolType, Uint8Buff *sharedSecret);
    int32_t (*getCredInfoByPeerCert)(const CJson *in, const CertInfo *certInfo, IdentityInfo **returnInfo);
    int32_t (*getSharedSecretByPeerCert)(
        const CJson *in, const CertInfo *peerCertInfo, ProtocolAlgType protocolType, Uint8Buff *sharedSecret);
} AuthIdentity;

typedef struct {
    int32_t (*queryCredential)(const char *reqJsonStr, char **returnData);
    int32_t (*genarateCredential)(const char *reqJsonStr, char **returnData);
    int32_t (*importCredential)(const char *reqJsonStr, char **returnData);
    int32_t (*deleteCredential)(const char *reqJsonStr, char **returnData);
} CredentialOperator;

typedef struct {
    const AuthIdentity *(*getAuthIdentityByType)(AuthIdentityType type);
    const CredentialOperator *(*getCredentialOperator)(void);
} AuthIdentityManager;

const AuthIdentity *GetGroupAuthIdentity(void);
const AuthIdentity *GetPinAuthIdentity(void);
const AuthIdentity *GetP2pAuthIdentity(void);
const AuthIdentity *GetAuthIdentityByType(AuthIdentityType type);
const CredentialOperator *GetCredentialOperator(void);
const AuthIdentityManager *GetAuthIdentityManager(void);

#ifdef __cplusplus
}
#endif

#endif // AUTH_IDENTITY_MANAGER_H