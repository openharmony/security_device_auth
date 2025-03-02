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

#ifndef ALG_LOADER_H
#define ALG_LOADER_H

#include "alg_defs.h"
#include "hks_api.h"
#include "hks_param.h"
#include "hks_type.h"
#include "hal_error.h"
#include "hc_types.h"

#define BITS_PER_BYTE 8
#define ECC_PK_LEN 32

#define CAL_ARRAY_SIZE(arr) ((sizeof(arr)) / (sizeof((arr)[0])))

#define CHECK_LEN_ZERO_RETURN_ERROR_CODE(len, paramTag) \
    do { \
        if ((len) == 0) { \
            LOGE("%s is invalid length.", (paramTag)); \
            return HAL_ERR_INVALID_LEN; \
        } \
    } while (0)

#define CHECK_PTR_RETURN_HAL_ERROR_CODE(ptr, paramTag) \
    do { \
        if ((ptr) == NULL) { \
            LOGE("%s is null.", (paramTag)); \
            return HAL_ERR_NULL_PTR; \
        } \
    } while (0)

#define CHECK_LEN_LOWER_RETURN(len, min, paramTag) \
    do { \
        if ((len) < (min)) { \
            LOGE("%s is invalid length.", (paramTag)); \
            return HAL_ERR_INVALID_LEN; \
        } \
    } while (0)

#define CHECK_LEN_HIGHER_RETURN(len, max, paramTag) \
    do { \
        if ((len) > (max)) { \
            LOGE("%s is invalid length.", (paramTag)); \
            return HAL_ERR_INVALID_LEN; \
        } \
    } while (0)

#define CHECK_LEN_EQUAL_RETURN(len, value, paramTag) \
    do { \
        if ((len) != (value)) { \
            LOGE("%s is invalid length.", (paramTag)); \
            return HAL_ERR_INVALID_LEN; \
        } \
    } while (0)

struct KeyRoleInfo {
    uint8_t userType;
    uint8_t pairType;
    uint8_t reserved1;
    uint8_t reserved2;
};

union KeyRoleInfoUnion {
    struct KeyRoleInfo roleInfoStruct;
    uint32_t roleInfo;
};

#ifdef __cplusplus
extern "C" {
#endif

int32_t CheckKeyParams(const KeyParams *keyParams);
void FreeParamSet(struct HksParamSet *paramSet);
int32_t ConstructParamSet(struct HksParamSet **out, const struct HksParam *inParam,
    const uint32_t inParamNum);
int32_t BigNumExpMod(const Uint8Buff *base, const Uint8Buff *exp, const char *bigNumHex,
    Uint8Buff *outNum);
void MoveDeKeyToCe(bool isKeyAlias, int32_t osAccountId, const struct HksBlob *keyAliasBlob);
int32_t ConstructCheckParamSet(bool isDeStorage, int32_t osAccountId, struct HksParamSet **paramSet);
int32_t ConstructDeleteParamSet(bool isDeStorage, int32_t osAccountId, struct HksParamSet **paramSet);
int32_t ConstructHmacParamSet(bool isDeStorage, int32_t osAccountId, bool isAlias,
    struct HksParamSet **hmacParamSet);
int32_t CheckHmacParams(const KeyParams *keyParams, const Uint8Buff *message, const Uint8Buff *outHmac);
int32_t ConstructDeriveParamSet(const KeyParams *keyParams, const Uint8Buff *message,
    struct HksParamSet **deriveParamSet);
int32_t ConstructFinishParamSet(const KeyParams *keyParams, struct HksParamSet **finishParamSet);
int32_t CheckHmacWithThreeStageParams(const KeyParams *keyParams, const Uint8Buff *message,
    const Uint8Buff *outHmac);
int32_t ConstructHkdfParamSet(bool isDeStorage, const KeyParams *keyParams, const Uint8Buff *salt,
    const Uint8Buff *keyInfo, struct HksParamSet **paramSet);
int32_t CheckHkdfParams(const KeyParams *keyParams, const Uint8Buff *salt, const Uint8Buff *outHkdf);
int32_t ConstructPseudonymParamSet(const KeyParams *keyParams, const Uint8Buff *pskKeyAlias,
    const struct HksBlob *extInfoBlob, uint32_t outLen, struct HksParamSet **paramSet);
int32_t CheckPskParams(const KeyParams *keyParams, const Uint8Buff *pskKeyAlias, const Uint8Buff *outPsk);
int32_t GetExtInfoByParamSet(const struct HksParamSet *outParamSet, Uint8Buff *outExtInfo);
int32_t ConstructGetKeyExtInfoParamSet(const KeyParams *keyParams, struct HksParamSet **paramSet);
int32_t CheckAesGcmEncryptParam(const KeyParams *keyParams, const Uint8Buff *plain,
    const GcmParam *encryptInfo, Uint8Buff *outCipher);
int32_t ConstructAesGcmEncryptParamSet(const GcmParam *encryptInfo, const KeyParams *keyParams,
    struct HksParamSet **paramSet);
int32_t CheckAesGcmDecryptParam(const KeyParams *keyParams, const Uint8Buff *cipher,
    const GcmParam *decryptInfo, Uint8Buff *outPlain);
int32_t ConstructAesGcmDecryptParamSet(const GcmParam *decryptInfo, const KeyParams *keyParams,
    struct HksParamSet **paramSet);
int32_t ConstructInitParamsP256(struct HksParamSet **initParamSet, const KeyParams *keyParams);
int32_t ConstructFinishParamsP256(struct HksParamSet **finishParamSet, const KeyParams *keyParams,
    const struct HksBlob *sharedKeyAliasBlob);
int32_t ConstructAgreeWithStorageParams(struct HksParamSet **paramSet, uint32_t keyLen, Algorithm algo,
    const KeyParams *priKeyParams, const KeyBuff *pubKeyBuff);
int32_t CheckAgreeWithStorageParams(const KeyParams *priKeyParams, const KeyBuff *pubKeyBuff,
    uint32_t sharedKeyLen, const Uint8Buff *sharedKeyAlias);
void MoveSharedKeyToCe(const KeyParams *priKeyParams, const struct HksBlob *sharedKeyAlias);
int32_t CheckAgreeParams(const KeyParams *priKeyParams, const KeyBuff *pubKey, const Uint8Buff *sharedKey);
int32_t ConstructAgreeParamSet(const KeyParams *keyParams, Algorithm algo, const Uint8Buff *sharedKey,
    struct HksParamSet **paramSet);
int32_t ConstructGenerateKeyPairWithStorageParams(struct HksParamSet **paramSet, Algorithm algo,
    uint32_t keyLen, KeyPurpose purpose, const KeyParams *authIdParams);
int32_t CheckGenerateKeyPairParams(const KeyParams *keyParams, const ExtraInfo *exInfo, uint32_t keyLen);
int32_t ConstructGenerateKeyPairParams(struct HksParamSet **paramSet, Algorithm algo, uint32_t keyLen);
int32_t ConstructExportParams(bool isDeStorage, int32_t osAccountId, struct HksParamSet **paramSet);
int32_t CheckExportParams(const KeyParams *keyParams, const Uint8Buff *outPubKey);
int32_t ConstructSignParams(bool isDeStorage, int32_t osAccountId, struct HksParamSet **paramSet,
    Algorithm algo);
int32_t CheckSignParams(const KeyParams *keyParams, const Uint8Buff *message,
    const Uint8Buff *outSignature);
int32_t ConstructVerifyParams(struct HksParamSet **paramSet, const KeyParams *keyParams, Algorithm algo);
int32_t CheckVerifyParams(const KeyParams *keyParams, const Uint8Buff *message,
    const Uint8Buff *signature);
int32_t ConstructImportPublicKeyParams(struct HksParamSet **paramSet, Algorithm algo, uint32_t keyLen,
    const KeyParams *authIdParams, const union KeyRoleInfoUnion *roleInfoUnion);
int32_t CheckImportPubKeyParams(const KeyParams *keyParams, const Uint8Buff *pubKey,
    const ExtraInfo *exInfo);
bool CheckBigNumCompareParams(const Uint8Buff *a, const Uint8Buff *b, int *res);
int32_t ConstructImportSymmetricKeyParam(struct HksParamSet **paramSet, const KeyParams *keyParams,
    uint32_t keyLen, KeyPurpose purpose, const ExtraInfo *exInfo);
int32_t CheckImportSymmetricKeyParams(const KeyParams *keyParams, const Uint8Buff *authToken);


#ifdef __cplusplus
}
#endif

#endif