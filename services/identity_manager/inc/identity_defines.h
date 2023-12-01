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

#ifndef AUTH_IDENTITY_DEFINE_H
#define AUTH_IDENTITY_DEFINE_H

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
#define KEY_TYPE_PAIR_LEN 2
#define PAKE_ED25519_KEY_PAIR_LEN 32
#define PAKE_ED25519_KEY_STR_LEN 64
#define AUTH_CODE_LEN 32
#define KEY_ALIAS_LEN 32
#define PACKAGE_NAME_MAX_LEN 256
#define SERVICE_TYPE_MAX_LEN 256
#define AUTH_ID_MAX_LEN 64

#ifdef __cplusplus
extern "C" {
#endif

typedef enum { KEY_TYPE_SYM, KEY_TYPE_ASYM } KeyType;

typedef enum { TRUST_TYPE_PIN, TRUST_TYPE_P2P, TRUST_TYPE_UID } TrustType;

typedef enum { PRE_SHARED, CERTIFICATED } IdentityProofType;

typedef enum { ALG_EC_SPEKE = 0x0001, ALG_DL_SPEKE = 0x0002, ALG_ISO = 0x0004 } ProtocolAlgType;

typedef enum {
    KEY_ALIAS_ACCESSOR_PK = 0,
    KEY_ALIAS_CONTROLLER_PK = 1,
    KEY_ALIAS_LT_KEY_PAIR = 2,
    KEY_ALIAS_KEK = 3,
    KEY_ALIAS_DEK = 4,
    KEY_ALIAS_TMP = 5,
    KEY_ALIAS_PSK = 6,
    KEY_ALIAS_AUTH_TOKEN = 7,
    KEY_ALIAS_P2P_AUTH = 8,

    KEY_ALIAS_TYPE_END
} KeyAliasType; // 0 ~ 2^8-1, don't change the order

uint8_t *GetKeyTypePair(KeyAliasType keyAliasType);

typedef enum {
    CMD_EXCHANGE_PK = 0x0001,
    CMD_IMPORT_AUTH_CODE = 0x0002,
    CMD_ADD_TRUST_DEVICE = 0x0004,
    CMD_MK_AGREE = 0x0008,
} ExpandProcessCmd;

typedef enum {
    DEFAULT_ID_TYPE = 0,
    P2P_DIRECT_AUTH = 1,
} IdentityInfoType;

typedef struct {
    ProtocolAlgType protocolType;
    uint32_t expandProcessCmds;
} ProtocolEntity;
DECLARE_HC_VECTOR(ProtocolEntityVec, ProtocolEntity *)

typedef struct {
    Uint8Buff pkInfoStr;
    Uint8Buff pkInfoSignature;
    Algorithm signAlg;
    bool isPseudonym;
} CertInfo;

typedef struct {
    Uint8Buff preSharedUrl;
    CertInfo certInfo;
} IdentityProof;

typedef struct {
    IdentityProofType proofType;
    IdentityProof proof;
    ProtocolEntityVec protocolVec;
    int32_t IdInfoType;
} IdentityInfo;
DECLARE_HC_VECTOR(IdentityInfoVec, IdentityInfo *)

#ifdef __cplusplus
}
#endif

#endif