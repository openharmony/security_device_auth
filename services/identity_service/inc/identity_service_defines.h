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

#ifndef IDENTITY_SERVICE_DEFINES_H
#define IDENTITY_SERVICE_DEFINES_H

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
#define FIELD_AUTHORIZED_DEVICE_LIST "authorizedDeviceList"
#define FIELD_AUTHORIZED_APP_LIST "authorizedAppList"
#define FIELD_AUTHORIZED_SCOPE "authorizedScope"
#define FIELD_CRED_OWNER "credOwner"
#define FIELD_EXTEND_INFO "extendInfo"
#define FIELD_CRED_ID "credId"
#define FIELD_PROOF_TYPE "proofType"
#define FIELD_KEY_FORMAT "keyFormat"
#define FIELD_OS_ACCOUNT_ID "osAccountId"
#define FIELD_BASE_CRED_INFO "baseCredInfo"
#define FIELD_ADD_CRED_PARAM_LIST "addCredParamList"
#define FIELD_CRED_ID_LIST "credIdList"
#define FIELD_BASE_INFO "baseInfo"
#define FIELD_UPDATE_LISTS "updateLists"
#define DEFAULT_VAL 0
#define RAND_NUM_LENGTH 16
#define KEY_VALUE_MAX_LENGTH 128
#define PAKE_ED25519_KEY_PAIR_LEN 32
#define MAX_INT64_SIZE 20
#define MAX_CRED_SIZE 5000
#define ALGO_KEY_LEN 32
#define AES_128_KEY_LEN 16
#define PSK_LEN 32
#define DEFAULT_EX_INFO_VAL (-1)
#define UPDATE_MATCHED_NUM_ZERO 0
#define UPDATE_MATCHED_NUM_ONE 1
#define DEV_AUTH_UID 3333
#define DEV_CAST_UID 7073

#ifdef __cplusplus
extern "C" {
#endif


enum {
    METHOD_GENERATE = 1,
    METHOD_IMPORT = 2,
};

enum {
    ACCOUNT_RELATED = 1,
    ACCOUNT_UNRELATED = 2,
    ACCOUNT_SHARED = 3,
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
    SUBJECT_MASTER_CONTROLLER = 1,
    SUBJECT_ACCESSORY_DEVICE = 2,
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

#ifdef __cplusplus
}
#endif

#endif