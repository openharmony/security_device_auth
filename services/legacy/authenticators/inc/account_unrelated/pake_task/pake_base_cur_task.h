/*
 * Copyright (C) 2021 Huawei Device Co., Ltd.
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

#ifndef PAKE_BASE_CUR_TASK_H
#define PAKE_BASE_CUR_TASK_H

#include "das_module_defines.h"
#include "hc_types.h"
#include "json_utils.h"
#include "pake_defs.h"

#define HICHAIN_RETURN_KEY "hichain_return_key"
#define TMP_AUTH_KEY_FACTOR "hichain_tmp_auth_enc_key"
#define FIELD_P2P_PSEUDONYM_ID "pdId"
#define FIELD_PSEUDONYM_CHALLENGE "pdChlg"
#define FIELD_IS_PSEUDONYM_SUPPORTED "isPdSupported"
#define FIELD_SELF_NEXT_PSEUDONYM_ID "selfNextPseudonymId"
#define FIELD_PEER_NEXT_PSEUDONYM_ID "peerNextPseudonymId"
#define FIELD_SELF_NEXT_PSEUDONYM_CHALLENGE "selfNextPseudonymChallenge"

#define PAKE_KEY_ALIAS_LEN 64
#define PAKE_ED25519_KEY_PAIR_LEN 32
#define PAKE_NONCE_LEN 32
#define PAKE_PSK_LEN 32
#define PSEUDONYM_CHALLENGE_LEN 16
#define PSEUDONYM_ID_LEN 32
#define PSEUDONYM_COMBINE_CHALLENGE_LEN 32

typedef struct {
    Uint8Buff selfNextPseudonymId;
    Uint8Buff selfNextPseudonymChallenge;
    Uint8Buff peerNextPseudonymId;
} PseudonymPskExtInfo;


typedef struct PakeParamsT {
    PakeBaseParams baseParams;

    bool isPskSupported;
    Uint8Buff returnKey;
    Uint8Buff nonce;
    int32_t opCode;
    int32_t userType;
    int32_t userTypePeer;
    char *packageName;
    char *serviceType;
    bool isPseudonym;
    PseudonymPskExtInfo pseudonymExtInfo;
    uint8_t selfNextPseudonymChallenge[PSEUDONYM_CHALLENGE_LEN];
    uint8_t peerNextPseudonymChallenge[PSEUDONYM_CHALLENGE_LEN];
    bool isSelfFromUpgrade;
    bool isPeerFromUpgrade;
} PakeParams;

typedef struct AsyBaseCurTaskT {
    CurTaskType (*getCurTaskType)(void);
    void (*destroyTask)(struct AsyBaseCurTaskT *);
    int(*process)(struct AsyBaseCurTaskT *, PakeParams *params, const CJson *in, CJson *out, int *status);
    int taskStatus;
} AsyBaseCurTask;

#ifdef __cplusplus
extern "C" {
#endif

#ifdef __cplusplus
}
#endif

#endif
