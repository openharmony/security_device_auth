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

#ifndef CREDS_MANAGER_DEFINES_H
#define CREDS_MANAGER_DEFINES_H

#include "alg_defs.h"
#include "hc_vector.h"
#include "string_util.h"

#define PRESHARED_URL_CREDENTIAL_TYPE "credentialType"
#define PRESHARED_URL_KEY_TYPE "keyType"
#define PRESHARED_URL_TRUST_TYPE "trustType"

#define SHARED_KEY_ALIAS "sharedKeyAlias"
#define KEY_INFO_PERSISTENT_TOKEN "persistent_token"
#define TMP_AUTH_KEY_FACTOR "hichain_tmp_auth_enc_key"
#define ASCII_CASE_DIFFERENCE_VALUE 32
#define P256_SHARED_SECRET_KEY_SIZE 32
#define AUTH_TOKEN_SIZE 32
#define PAKE_KEY_ALIAS_LEN 64
#define PAKE_NONCE_LEN 32
#define PAKE_PSK_LEN 32
#define ISO_PSK_LEN 32
#define SEED_LEN 32
#define ISO_KEY_ALIAS_LEN 32

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    KEY_TYPE_SYM,
    KEY_TYPE_ASYM
} KeyType;

typedef enum {
    TRUST_TYPE_PIN,
    TRUST_TYPE_P2P,
    TRUST_TYPE_UID
} TrustType;

typedef enum {
    PRE_SHARED,
    CERTIFICATED
} IdentityProofType;

typedef enum {
    ALG_EC_SPEKE = 0x0001,
    ALG_DL_SPEKE = 0x0002,
    ALG_ISO = 0x0004
} ProtocolAlgType;

typedef enum {
    CMD_EXCHANGE_PK = 0x0001,
    CMD_IMPORT_AUTH_CODE = 0x0002,
    CMD_ADD_TRUST_DEVICE = 0x0004,
} ExpandProcessCmd;

typedef struct {
    ProtocolAlgType protocolType;
    uint32_t expandProcessCmds;
} ProtocolEntity;
DECLARE_HC_VECTOR(ProtocolEntityVec, ProtocolEntity*)

typedef struct {
    Uint8Buff pkInfoStr;
    Uint8Buff pkInfoSignature;
    Algorithm signAlg;
} CertInfo;

typedef struct {
    Uint8Buff preSharedUrl;
    CertInfo certInfo;
} IdentityProof;

typedef struct {
    IdentityProofType proofType;
    IdentityProof proof;
    ProtocolEntityVec protocolVec;
} IdentityInfo;
DECLARE_HC_VECTOR(IdentityInfoVec, IdentityInfo*)

#ifdef __cplusplus
}
#endif

#endif