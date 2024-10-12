/*
 * Copyright (C) 2021-2023 Huawei Device Co., Ltd.
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

#include "huks_adapter.h"
#include "huks_adapter_diff_impl.h"
#include "hc_log.h"
#include "hks_api.h"
#include "hks_param.h"
#include "hks_type.h"
#include "mbedtls_ec_adapter.h"
#include "string_util.h"

#define BASE_IMPORT_PARAMS_LEN 7
#define EXT_IMPORT_PARAMS_LEN 2
#define ECDH_COMMON_SIZE_P256 512
#define BASE_HMAC_PARAMS_LEN 3
#define BASE_HMAC_DERIVE_PARAMS_LEN 5
#define BASE_HMAC_FINISH_PARAMS_LEN 3
#define BASE_AGREE_WITH_STORAGE_PARAMS_LEN 9
#define BASE_HKDF_PARAMS_LEN 6
#define BASE_COMPUTE_PSEUDONYM_PSK_PARAMS_LEN 11
#define BASE_SIGN_PARAMS_LEN 3
#define BASE_ENCRYPT_PARAMS_LEN 7
#define BASE_DECRYPT_PARAMS_LEN 7
#define BASE_AGREE_INIT_PARAMS_LEN 3
#define BASE_AGREE_FINISH_PARAMS_LEN 7
#define BASE_AGREE_PARAMS_LEN 3
#define BASE_GENERATE_KEY_PAIR_PARAMS_LEN 6
#define BASE_VERIFY_PARAMS_LEN 4
#define BASE_IMPORT_PUB_KEY_PARAMS_LEN 8
#define EXT_DE_PARAMS_LEN 1
#define EXT_CE_PARAMS_LEN 2
#define PSEUDONYM_KEY_FACTOR "hichain_pseudonym_psk_key"
#define PSEUDONYM_KEY_LEBEL "hichain_pseudonym_psk_label"

static uint32_t g_purposeToHksKeyPurpose[] = {
    HKS_KEY_PURPOSE_MAC,
    HKS_KEY_PURPOSE_DERIVE,
    HKS_KEY_PURPOSE_SIGN | HKS_KEY_PURPOSE_VERIFY,
    HKS_KEY_PURPOSE_AGREE
};

static enum HksKeyAlg g_algToHksAlgorithm[] = {
    HKS_ALG_ED25519,
    HKS_ALG_X25519,
    HKS_ALG_ECC
};

static int32_t CheckKeyParams(const KeyParams *keyParams)
{
    CHECK_PTR_RETURN_HAL_ERROR_CODE(keyParams, "keyParams");
    CHECK_PTR_RETURN_HAL_ERROR_CODE(keyParams->keyBuff.key, "keyParams->keyBuff.key");
    CHECK_LEN_ZERO_RETURN_ERROR_CODE(keyParams->keyBuff.keyLen, "keyParams->keyBuff.keyLen");
    return HAL_SUCCESS;
}

static int32_t BaseCheckParams(const Uint8Buff **inParams, const char **paramTags, uint32_t len)
{
    for (uint32_t i = 0; i < len; i++) {
        CHECK_PTR_RETURN_HAL_ERROR_CODE(inParams[i], paramTags[i]);
        CHECK_PTR_RETURN_HAL_ERROR_CODE(inParams[i]->val, paramTags[i]);
        CHECK_LEN_ZERO_RETURN_ERROR_CODE(inParams[i]->length, paramTags[i]);
    }
    return HAL_SUCCESS;
}

static void FreeParamSet(struct HksParamSet *paramSet)
{
    if (paramSet == NULL) {
        return;
    }
    HksFreeParamSet(&paramSet);
}

static int32_t ConstructParamSet(struct HksParamSet **out, const struct HksParam *inParam,
    const uint32_t inParamNum)
{
    struct HksParamSet *paramSet = NULL;
    int32_t res = HksInitParamSet(&paramSet);
    if (res != HKS_SUCCESS) {
        LOGE("init param set failed, res = %d", res);
        return HAL_ERR_INIT_PARAM_SET_FAILED;
    }

    res = HksAddParams(paramSet, inParam, inParamNum);
    if (res != HKS_SUCCESS) {
        LOGE("add param failed, res = %d", res);
        FreeParamSet(paramSet);
        return HAL_ERR_ADD_PARAM_FAILED;
    }

    res = HksBuildParamSet(&paramSet);
    if (res != HKS_SUCCESS) {
        LOGE("build param set failed, res = %d", res);
        FreeParamSet(paramSet);
        return HAL_ERR_BUILD_PARAM_SET_FAILED;
    }

    *out = paramSet;
    return HAL_SUCCESS;
}

static int32_t Sha256(const Uint8Buff *message, Uint8Buff *hash)
{
    CHECK_PTR_RETURN_HAL_ERROR_CODE(message, "message");
    CHECK_PTR_RETURN_HAL_ERROR_CODE(message->val, "message->val");
    CHECK_LEN_ZERO_RETURN_ERROR_CODE(message->length, "message->length");

    CHECK_PTR_RETURN_HAL_ERROR_CODE(hash, "hash");
    CHECK_PTR_RETURN_HAL_ERROR_CODE(hash->val, "hash->val");
    CHECK_LEN_EQUAL_RETURN(hash->length, SHA256_LEN, "hash->length");

    struct HksBlob srcBlob = { message->length, message->val };
    struct HksBlob hashBlob = { hash->length, hash->val };
    struct HksParamSet *paramSet = NULL;
    struct HksParam digestParam[] = {
        {
            .tag = HKS_TAG_DIGEST,
            .uint32Param = HKS_DIGEST_SHA256
        }
    };
    int32_t res = ConstructParamSet(&paramSet, digestParam, CAL_ARRAY_SIZE(digestParam));
    if (res != HAL_SUCCESS) {
        LOGE("construct param set failed, res = %d", res);
        return res;
    }

    res = HksHash(paramSet, &srcBlob, &hashBlob);
    if (res != HKS_SUCCESS || hashBlob.size != SHA256_LEN) {
        LOGE("[HUKS]: HksHash fail. [Res]: %d", res);
        FreeParamSet(paramSet);
        return HAL_FAILED;
    }

    FreeParamSet(paramSet);
    return HAL_SUCCESS;
}

static int32_t GenerateRandom(Uint8Buff *rand)
{
    CHECK_PTR_RETURN_HAL_ERROR_CODE(rand, "rand");
    CHECK_PTR_RETURN_HAL_ERROR_CODE(rand->val, "rand->val");
    CHECK_LEN_ZERO_RETURN_ERROR_CODE(rand->length, "rand->length");

    struct HksBlob randBlob = { rand->length, rand->val };
    int32_t res = HksGenerateRandom(NULL, &randBlob);
    if (res != HKS_SUCCESS) {
        LOGE("[HUKS]: HksGenerateRandom fail. [Res]: %d", res);
        return HAL_FAILED;
    }

    return HAL_SUCCESS;
}

static uint32_t GetParamLen(bool isDeStorage, uint32_t baseLen)
{
#ifdef DEV_AUTH_ENABLE_CE
    if (isDeStorage) {
        return baseLen + EXT_DE_PARAMS_LEN;
    } else {
        return baseLen + EXT_CE_PARAMS_LEN;
    }
#else
    (void)isDeStorage;
    return baseLen;
#endif
}

static void AddStorageExtParams(struct HksParam *params, bool isDeStorage, uint32_t *idx, int32_t osAccountId)
{
#ifdef DEV_AUTH_ENABLE_CE
    if (isDeStorage) {
        params[*idx].tag = HKS_TAG_AUTH_STORAGE_LEVEL;
        params[(*idx)++].uint32Param = HKS_AUTH_STORAGE_LEVEL_DE;
    } else {
        params[*idx].tag = HKS_TAG_AUTH_STORAGE_LEVEL;
        params[(*idx)++].uint32Param = HKS_AUTH_STORAGE_LEVEL_CE;
        params[*idx].tag = HKS_TAG_SPECIFIC_USER_ID;
        params[(*idx)++].uint32Param = osAccountId;
    }
#else
    (void)params;
    (void)isDeStorage;
    (void)idx;
    (void)osAccountId;
#endif
}

static int32_t ConstructDeParamSet(struct HksParamSet **paramSet)
{
    struct HksParam keyParam[] = {
        {
            .tag = HKS_TAG_AUTH_STORAGE_LEVEL,
            .uint32Param = HKS_AUTH_STORAGE_LEVEL_DE
        }
    };

    int32_t res = ConstructParamSet(paramSet, keyParam, CAL_ARRAY_SIZE(keyParam));
    if (res != HAL_SUCCESS) {
        LOGE("Construct de param set failed, res = %d", res);
    }
    return res;
}

static int32_t ConstructCeParamSet(int32_t osAccountId, struct HksParamSet **paramSet)
{
    struct HksParam keyParam[] = {
        {
            .tag = HKS_TAG_AUTH_STORAGE_LEVEL,
            .uint32Param = HKS_AUTH_STORAGE_LEVEL_CE
        }, {
            .tag = HKS_TAG_SPECIFIC_USER_ID,
            .uint32Param = osAccountId
        }
    };

    int32_t res = ConstructParamSet(paramSet, keyParam, CAL_ARRAY_SIZE(keyParam));
    if (res != HAL_SUCCESS) {
        LOGE("Construct ce param set failed, res = %d", res);
    }
    return res;
}

static int32_t ChangeStorageLevel(const struct HksBlob *keyAliasBlob, const struct HksParamSet *deParamSet,
    const struct HksParamSet *ceParamSet)
{
#ifdef DEV_AUTH_ENABLE_CE
    return HksChangeStorageLevel(keyAliasBlob, deParamSet, ceParamSet);
#else
    (void)keyAliasBlob;
    (void)deParamSet;
    (void)ceParamSet;
    return HKS_SUCCESS;
#endif
}

static void MoveDeKeyToCe(bool isKeyAlias, int32_t osAccountId, const struct HksBlob *keyAliasBlob)
{
    if (!isKeyAlias) {
        return;
    }
    struct HksParamSet *deParamSet = NULL;
    if (ConstructDeParamSet(&deParamSet) != HAL_SUCCESS) {
        return;
    }
    struct HksParamSet *ceParamSet = NULL;
    if (ConstructCeParamSet(osAccountId, &ceParamSet) != HAL_SUCCESS) {
        return;
    }
    int32_t res = ChangeStorageLevel(keyAliasBlob, deParamSet, ceParamSet);
    if (res != HKS_SUCCESS) {
        LOGE("Failed to move de key to ce!");
    }
}

static int32_t ConstructCheckParamSet(bool isDeStorage, int32_t osAccountId, struct HksParamSet **paramSet)
{
    uint32_t len = GetParamLen(isDeStorage, 0);
    if (len == 0) {
        return HAL_SUCCESS;
    }
    struct HksParam *checkParams = (struct HksParam *)HcMalloc(sizeof(struct HksParam) * len, 0);
    if (checkParams == NULL) {
        LOGE("Malloc for checkParams failed.");
        return HAL_ERR_BAD_ALLOC;
    }
    uint32_t idx = 0;
    AddStorageExtParams(checkParams, isDeStorage, &idx, osAccountId);
    int32_t res = ConstructParamSet(paramSet, checkParams, idx);
    HcFree(checkParams);
    if (res != HAL_SUCCESS) {
        LOGE("Failed to construct check param set, res: %d", res);
    }
    return res;
}

static int32_t CheckKeyExist(const Uint8Buff *keyAlias, bool isDeStorage, int32_t osAccountId)
{
    CHECK_PTR_RETURN_HAL_ERROR_CODE(keyAlias, "keyAlias");
    CHECK_PTR_RETURN_HAL_ERROR_CODE(keyAlias->val, "keyAlias->val");
    CHECK_LEN_ZERO_RETURN_ERROR_CODE(keyAlias->length, "keyAlias->length");

    struct HksParamSet *deParamSet = NULL;
    int32_t res = ConstructCheckParamSet(true, osAccountId, &deParamSet);
    if (res != HAL_SUCCESS) {
        return res;
    }
    struct HksParamSet *ceParamSet = NULL;
    res = ConstructCheckParamSet(false, osAccountId, &ceParamSet);
    if (res != HAL_SUCCESS) {
        FreeParamSet(deParamSet);
        return res;
    }
    struct HksBlob keyAliasBlob = { keyAlias->length, keyAlias->val };
    if (isDeStorage) {
        res = HksKeyExist(&keyAliasBlob, deParamSet);
        if (res == HKS_SUCCESS) {
            MoveDeKeyToCe(true, osAccountId, &keyAliasBlob);
        } else {
            res = HksKeyExist(&keyAliasBlob, ceParamSet);
        }
    } else {
        res = HksKeyExist(&keyAliasBlob, ceParamSet);
        if (res != HKS_SUCCESS) {
            res = HksKeyExist(&keyAliasBlob, deParamSet);
        }
    }
    FreeParamSet(deParamSet);
    FreeParamSet(ceParamSet);
    if (res != HKS_SUCCESS) {
        LOGI("[HUKS]: HksKeyExist fail. [Res]: %d", res);
        return HAL_FAILED;
    }

    return HAL_SUCCESS;
}

static int32_t ConstructDeleteParamSet(bool isDeStorage, int32_t osAccountId, struct HksParamSet **paramSet)
{
    uint32_t len = GetParamLen(isDeStorage, 0);
    if (len == 0) {
        return HAL_SUCCESS;
    }
    struct HksParam *deleteParams = (struct HksParam *)HcMalloc(sizeof(struct HksParam) * len, 0);
    if (deleteParams == NULL) {
        LOGE("Malloc for deleteParams failed.");
        return HAL_ERR_BAD_ALLOC;
    }
    uint32_t idx = 0;
    AddStorageExtParams(deleteParams, isDeStorage, &idx, osAccountId);
    int32_t res = ConstructParamSet(paramSet, deleteParams, idx);
    HcFree(deleteParams);
    if (res != HAL_SUCCESS) {
        LOGE("Failed to construct delete param set, res: %d", res);
    }
    return res;
}

static int32_t DeleteKey(const Uint8Buff *keyAlias, bool isDeStorage, int32_t osAccountId)
{
    CHECK_PTR_RETURN_HAL_ERROR_CODE(keyAlias, "keyAlias");
    CHECK_PTR_RETURN_HAL_ERROR_CODE(keyAlias->val, "keyAlias->val");
    CHECK_LEN_ZERO_RETURN_ERROR_CODE(keyAlias->length, "keyAlias->length");

    struct HksParamSet *deParamSet = NULL;
    int32_t res = ConstructDeleteParamSet(true, osAccountId, &deParamSet);
    if (res != HAL_SUCCESS) {
        return res;
    }
    struct HksParamSet *ceParamSet = NULL;
    res = ConstructDeleteParamSet(false, osAccountId, &ceParamSet);
    if (res != HAL_SUCCESS) {
        FreeParamSet(deParamSet);
        return res;
    }
    struct HksBlob keyAliasBlob = { keyAlias->length, keyAlias->val };

    LOGI("[HUKS]: HksDeleteKey enter.");
    if (isDeStorage) {
        res = HksDeleteKey(&keyAliasBlob, deParamSet);
        if (res != HKS_SUCCESS) {
            res = HksDeleteKey(&keyAliasBlob, ceParamSet);
        }
    } else {
        res = HksDeleteKey(&keyAliasBlob, ceParamSet);
        if (res != HKS_SUCCESS) {
            res = HksDeleteKey(&keyAliasBlob, deParamSet);
        }
    }
    LOGI("[HUKS]: HksDeleteKey quit. [Res]: %d", res);

    FreeParamSet(deParamSet);
    FreeParamSet(ceParamSet);
    if (res == HKS_ERROR_NOT_EXIST) {
        LOGI("Key not exists.");
        return HAL_SUCCESS;
    }
    if (res != HKS_SUCCESS) {
        LOGE("[HUKS]: HksDeleteKey fail. [Res]: %d", res);
        return HAL_FAILED;
    }
    return HAL_SUCCESS;
}

static int32_t ConstructHmacParamSet(bool isDeStorage, int32_t osAccountId, bool isAlias,
    struct HksParamSet **hmacParamSet)
{
    uint32_t len = GetParamLen(isDeStorage, BASE_HMAC_PARAMS_LEN);
    struct HksParam *hmacParams = (struct HksParam *)HcMalloc(sizeof(struct HksParam) * len, 0);
    if (hmacParams == NULL) {
        LOGE("Malloc for hmacParams failed.");
        return HAL_ERR_BAD_ALLOC;
    }
    uint32_t idx = 0;
    hmacParams[idx].tag = HKS_TAG_PURPOSE;
    hmacParams[idx++].uint32Param = HKS_KEY_PURPOSE_MAC;
    hmacParams[idx].tag = HKS_TAG_DIGEST;
    hmacParams[idx++].uint32Param = HKS_DIGEST_SHA256;
    hmacParams[idx].tag = HKS_TAG_IS_KEY_ALIAS;
    hmacParams[idx++].boolParam = isAlias;
    AddStorageExtParams(hmacParams, isDeStorage, &idx, osAccountId);
    int32_t res = ConstructParamSet(hmacParamSet, hmacParams, idx);
    HcFree(hmacParams);
    if (res != HAL_SUCCESS) {
        LOGE("Construct hmac param set failed, res = %d", res);
    }
    return res;
}

static int32_t CheckHmacParams(const KeyParams *keyParams, const Uint8Buff *message, const Uint8Buff *outHmac)
{
    int32_t res = CheckKeyParams(keyParams);
    if (res != HAL_SUCCESS) {
        return res;
    }
    const Uint8Buff *inParams[] = { message, outHmac };
    const char *paramTags[] = { "message", "outHmac" };
    res = BaseCheckParams(inParams, paramTags, CAL_ARRAY_SIZE(inParams));
    if (res != HAL_SUCCESS) {
        return res;
    }
    CHECK_LEN_EQUAL_RETURN(outHmac->length, HMAC_LEN, "outHmac->length");
    return HAL_SUCCESS;
}

static int32_t ComputeHmac(const KeyParams *keyParams, const Uint8Buff *message, Uint8Buff *outHmac)
{
    int32_t res = CheckHmacParams(keyParams, message, outHmac);
    if (res != HAL_SUCCESS) {
        return res;
    }

    struct HksParamSet *deParamSet = NULL;
    res = ConstructHmacParamSet(true, keyParams->osAccountId, keyParams->keyBuff.isAlias, &deParamSet);
    if (res != HAL_SUCCESS) {
        return res;
    }
    struct HksParamSet *ceParamSet = NULL;
    res = ConstructHmacParamSet(false, keyParams->osAccountId, keyParams->keyBuff.isAlias, &ceParamSet);
    if (res != HAL_SUCCESS) {
        FreeParamSet(deParamSet);
        return res;
    }
    struct HksBlob keyBlob = { keyParams->keyBuff.keyLen, keyParams->keyBuff.key };
    struct HksBlob srcBlob = { message->length, message->val };
    struct HksBlob hmacBlob = { outHmac->length, outHmac->val };

    LOGI("[HUKS]: HksMac enter.");
    if (keyParams->isDeStorage) {
        res = HksMac(&keyBlob, deParamSet, &srcBlob, &hmacBlob);
    } else {
        res = HksMac(&keyBlob, ceParamSet, &srcBlob, &hmacBlob);
        if (res != HKS_SUCCESS  || hmacBlob.size != HMAC_LEN) {
            res = HksMac(&keyBlob, deParamSet, &srcBlob, &hmacBlob);
        }
    }
    LOGI("[HUKS]: HksMac quit. [Res]: %d", res);
    FreeParamSet(deParamSet);
    FreeParamSet(ceParamSet);
    if (res != HKS_SUCCESS  || hmacBlob.size != HMAC_LEN) {
        LOGE("[HUKS]: HksMac fail. [Res]: %d", res);
        return HAL_FAILED;
    }
    return HAL_SUCCESS;
}

static int32_t ConstructDeriveParamSet(const KeyParams *keyParams, const Uint8Buff *message,
    struct HksParamSet **deriveParamSet)
{
    struct HksBlob srcBlob = { message->length, message->val };
    uint32_t len = GetParamLen(keyParams->isDeStorage, BASE_HMAC_DERIVE_PARAMS_LEN);
    struct HksParam *hmacDeriveParams = (struct HksParam *)HcMalloc(sizeof(struct HksParam) * len, 0);
    if (hmacDeriveParams == NULL) {
        LOGE("Malloc for hmacDeriveParams failed.");
        return HAL_ERR_BAD_ALLOC;
    }
    uint32_t idx = 0;
    hmacDeriveParams[idx].tag = HKS_TAG_ALGORITHM;
    hmacDeriveParams[idx++].uint32Param = HKS_ALG_HMAC;
    hmacDeriveParams[idx].tag = HKS_TAG_PURPOSE;
    hmacDeriveParams[idx++].uint32Param = HKS_KEY_PURPOSE_DERIVE;
    hmacDeriveParams[idx].tag = HKS_TAG_DIGEST;
    hmacDeriveParams[idx++].uint32Param = HKS_DIGEST_SHA256;
    hmacDeriveParams[idx].tag = HKS_TAG_DERIVE_KEY_SIZE;
    hmacDeriveParams[idx++].uint32Param = HMAC_LEN;
    hmacDeriveParams[idx].tag = HKS_TAG_INFO;
    hmacDeriveParams[idx++].blob = srcBlob;
    AddStorageExtParams(hmacDeriveParams, keyParams->isDeStorage, &idx, keyParams->osAccountId);
    int32_t res = ConstructParamSet(deriveParamSet, hmacDeriveParams, idx);
    HcFree(hmacDeriveParams);
    if (res != HAL_SUCCESS) {
        LOGE("Construct derive param set failed, res = %d", res);
    }
    return res;
}

static int32_t ConstructFinishParamSet(const KeyParams *keyParams, struct HksParamSet **finishParamSet)
{
    uint32_t len = GetParamLen(keyParams->isDeStorage, BASE_HMAC_FINISH_PARAMS_LEN);
    struct HksParam *hmacFinishParams = (struct HksParam *)HcMalloc(sizeof(struct HksParam) * len, 0);
    if (hmacFinishParams == NULL) {
        LOGE("Malloc for hmacFinishParams failed.");
        return HAL_ERR_BAD_ALLOC;
    }
    uint32_t idx = 0;
    hmacFinishParams[idx].tag = HKS_TAG_ALGORITHM;
    hmacFinishParams[idx++].uint32Param = HKS_ALG_AES;
    hmacFinishParams[idx].tag = HKS_TAG_KEY_SIZE;
    hmacFinishParams[idx++].uint32Param = HKS_AES_KEY_SIZE_256;
    hmacFinishParams[idx].tag = HKS_TAG_PURPOSE;
    hmacFinishParams[idx++].uint32Param = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT;
    AddStorageExtParams(hmacFinishParams, keyParams->isDeStorage, &idx, keyParams->osAccountId);
    int32_t res = ConstructParamSet(finishParamSet, hmacFinishParams, idx);
    HcFree(hmacFinishParams);
    if (res != HAL_SUCCESS) {
        LOGE("Construct finish param set failed, res = %d", res);
    }
    return res;
}

static int32_t CheckHmacWithThreeStageParams(const KeyParams *keyParams, const Uint8Buff *message,
    const Uint8Buff *outHmac)
{
    int32_t res = CheckKeyParams(keyParams);
    if (res != HAL_SUCCESS) {
        return res;
    }
    const Uint8Buff *inParams[] = { message, outHmac };
    const char *paramTags[] = { "message", "outHmac" };
    res = BaseCheckParams(inParams, paramTags, CAL_ARRAY_SIZE(inParams));
    if (res != HAL_SUCCESS) {
        return res;
    }
    CHECK_LEN_EQUAL_RETURN(outHmac->length, HMAC_LEN, "outHmac->length");
    return HAL_SUCCESS;
}

static int32_t ComputeHmacWithThreeStageInner(const KeyParams *keyParams, const Uint8Buff *message, Uint8Buff *outHmac)
{
    struct HksParamSet *deriveParamSet = NULL;
    int32_t res = ConstructDeriveParamSet(keyParams, message, &deriveParamSet);
    if (res != HAL_SUCCESS) {
        return res;
    }

    struct HksParamSet *finishParamSet = NULL;
    res = ConstructFinishParamSet(keyParams, &finishParamSet);
    if (res != HAL_SUCCESS) {
        FreeParamSet(deriveParamSet);
        return res;
    }
    uint8_t handle[sizeof(uint64_t)] = { 0 };
    struct HksBlob handleDerive = { sizeof(uint64_t), handle };
    struct HksBlob keyAliasBlob = { keyParams->keyBuff.keyLen, keyParams->keyBuff.key };
    res = HksInit(&keyAliasBlob, deriveParamSet, &handleDerive, NULL);
    if (res != HKS_SUCCESS) {
        LOGE("Failed to init derive params!");
        FreeParamSet(deriveParamSet);
        FreeParamSet(finishParamSet);
        return HAL_FAILED;
    }
    uint8_t tmpOut[2048] = { 0 };
    struct HksBlob outData = { 2048, tmpOut };
    struct HksBlob inData = { 0, NULL };
    res = HksUpdate(&handleDerive, deriveParamSet, &inData, &outData);
    FreeParamSet(deriveParamSet);
    if (res != HKS_SUCCESS) {
        LOGE("Failed to update derive params!");
        FreeParamSet(finishParamSet);
        return HAL_FAILED;
    }
    struct HksBlob hmacBlob = { outHmac->length, outHmac->val };
    res = HksFinish(&handleDerive, finishParamSet, &inData, &hmacBlob);
    FreeParamSet(finishParamSet);
    if (res != HKS_SUCCESS || hmacBlob.size != HMAC_LEN) {
        LOGE("Compute hmac with three stage failed! [Res]: %d, [size]: %d", res, hmacBlob.size);
        return HAL_FAILED;
    }
    return HAL_SUCCESS;
}

static int32_t ComputeHmacWithThreeStage(const KeyParams *keyParams, const Uint8Buff *message, Uint8Buff *outHmac)
{
    int32_t res = CheckHmacWithThreeStageParams(keyParams, message, outHmac);
    if (res != HAL_SUCCESS) {
        return res;
    }

    res = ComputeHmacWithThreeStageInner(keyParams, message, outHmac);
    if (!keyParams->isDeStorage) {
        return res;
    }
    if (res == HAL_SUCCESS) {
        struct HksBlob keyAliasBlob = { keyParams->keyBuff.keyLen, keyParams->keyBuff.key };
        MoveDeKeyToCe(keyParams->keyBuff.isAlias, keyParams->osAccountId, &keyAliasBlob);
    } else {
        KeyParams ceParams = {
            .keyBuff = { keyParams->keyBuff.key, keyParams->keyBuff.keyLen, keyParams->keyBuff.isAlias },
            .isDeStorage = false,
            .osAccountId = keyParams->osAccountId
        };
        res = ComputeHmacWithThreeStageInner(&ceParams, message, outHmac);
    }
    return res;
}

static int32_t ConstructHkdfParamSet(bool isDeStorage, const KeyParams *keyParams, const Uint8Buff *salt,
    const Uint8Buff *keyInfo, struct HksParamSet **paramSet)
{
    struct HksBlob saltBlob = { salt->length, salt->val };
    struct HksBlob keyInfoBlob = { 0, NULL };
    if (keyInfo != NULL) {
        keyInfoBlob.size = keyInfo->length;
        keyInfoBlob.data = keyInfo->val;
    }
    uint32_t len = GetParamLen(isDeStorage, BASE_HKDF_PARAMS_LEN);
    struct HksParam *hkdfParams = (struct HksParam *)HcMalloc(sizeof(struct HksParam) * len, 0);
    if (hkdfParams == NULL) {
        LOGE("Malloc for hkdfParams failed.");
        return HAL_ERR_BAD_ALLOC;
    }
    uint32_t idx = 0;
    hkdfParams[idx].tag = HKS_TAG_PURPOSE;
    hkdfParams[idx++].uint32Param = HKS_KEY_PURPOSE_DERIVE;
    hkdfParams[idx].tag = HKS_TAG_ALGORITHM;
    hkdfParams[idx++].uint32Param = HKS_ALG_HKDF;
    hkdfParams[idx].tag = HKS_TAG_DIGEST;
    hkdfParams[idx++].uint32Param = HKS_DIGEST_SHA256;
    hkdfParams[idx].tag = HKS_TAG_SALT;
    hkdfParams[idx++].blob = saltBlob;
    hkdfParams[idx].tag = HKS_TAG_INFO;
    hkdfParams[idx++].blob = keyInfoBlob;
    hkdfParams[idx].tag = HKS_TAG_IS_KEY_ALIAS;
    hkdfParams[idx++].boolParam = keyParams->keyBuff.isAlias;
    AddStorageExtParams(hkdfParams, isDeStorage, &idx, keyParams->osAccountId);
    int32_t res = ConstructParamSet(paramSet, hkdfParams, idx);
    HcFree(hkdfParams);
    if (res != HAL_SUCCESS) {
        LOGE("Failed to construct hkdf param set, res: %d", res);
    }
    return res;
}

static int32_t CheckHkdfParams(const KeyParams *keyParams, const Uint8Buff *salt, const Uint8Buff *outHkdf)
{
    int32_t res = CheckKeyParams(keyParams);
    if (res != HAL_SUCCESS) {
        return res;
    }
    const Uint8Buff *inParams[] = { salt, outHkdf };
    const char *paramTags[] = { "salt", "outHkdf" };
    return BaseCheckParams(inParams, paramTags, CAL_ARRAY_SIZE(inParams));
}

static int32_t ComputeHkdf(const KeyParams *keyParams, const Uint8Buff *salt, const Uint8Buff *keyInfo,
    Uint8Buff *outHkdf)
{
    int32_t res = CheckHkdfParams(keyParams, salt, outHkdf);
    if (res != HAL_SUCCESS) {
        return res;
    }

    struct HksBlob srcKeyBlob = { keyParams->keyBuff.keyLen, keyParams->keyBuff.key };
    struct HksBlob derivedKeyBlob = { outHkdf->length, outHkdf->val };

    struct HksParamSet *deParamSet = NULL;
    res = ConstructHkdfParamSet(true, keyParams, salt, keyInfo, &deParamSet);
    if (res != HAL_SUCCESS) {
        return res;
    }
    struct HksParamSet *ceParamSet = NULL;
    res = ConstructHkdfParamSet(false, keyParams, salt, keyInfo, &ceParamSet);
    if (res != HAL_SUCCESS) {
        FreeParamSet(deParamSet);
        return res;
    }

    LOGI("[HUKS]: HksDeriveKey enter.");
    if (keyParams->isDeStorage) {
        res = HksDeriveKey(deParamSet, &srcKeyBlob, &derivedKeyBlob);
        if (res == HKS_SUCCESS) {
            MoveDeKeyToCe(keyParams->keyBuff.isAlias, keyParams->osAccountId, &srcKeyBlob);
        } else {
            res = HksDeriveKey(ceParamSet, &srcKeyBlob, &derivedKeyBlob);
        }
    } else {
        res = HksDeriveKey(ceParamSet, &srcKeyBlob, &derivedKeyBlob);
        if (res != HKS_SUCCESS) {
            res = HksDeriveKey(deParamSet, &srcKeyBlob, &derivedKeyBlob);
        }
    }
    LOGI("[HUKS]: HksDeriveKey quit. [Res]: %d", res);
    FreeParamSet(deParamSet);
    FreeParamSet(ceParamSet);
    if (res != HKS_SUCCESS) {
        LOGE("[HUKS]: HksDeriveKey fail. [Res]: %d", res);
        return HAL_FAILED;
    }
    return HAL_SUCCESS;
}

static int32_t ConstructPseudonymParamSet(const KeyParams *keyParams, const Uint8Buff *pskKeyAlias,
    const struct HksBlob *extInfoBlob, uint32_t outLen, struct HksParamSet **paramSet)
{
    struct HksBlob saltBlob = { HcStrlen(PSEUDONYM_KEY_FACTOR), (uint8_t *)PSEUDONYM_KEY_FACTOR };
    struct HksBlob keyInfoBlob = { HcStrlen(PSEUDONYM_KEY_LEBEL), (uint8_t *)PSEUDONYM_KEY_LEBEL };
    struct HksBlob pskAliasBlob = { pskKeyAlias->length, pskKeyAlias->val };
    uint32_t len = GetParamLen(keyParams->isDeStorage, BASE_COMPUTE_PSEUDONYM_PSK_PARAMS_LEN);
    struct HksParam *hkdfParams = (struct HksParam *)HcMalloc(sizeof(struct HksParam) * len, 0);
    if (hkdfParams == NULL) {
        LOGE("Malloc for hkdfParams failed.");
        return HAL_ERR_BAD_ALLOC;
    }
    uint32_t idx = 0;
    hkdfParams[idx].tag = HKS_TAG_PURPOSE;
    hkdfParams[idx++].uint32Param = HKS_KEY_PURPOSE_DERIVE;
    hkdfParams[idx].tag = HKS_TAG_ALGORITHM;
    hkdfParams[idx++].uint32Param = HKS_ALG_HKDF;
    hkdfParams[idx].tag = HKS_TAG_DIGEST;
    hkdfParams[idx++].uint32Param = HKS_DIGEST_SHA256;
    hkdfParams[idx].tag = HKS_TAG_SALT;
    hkdfParams[idx++].blob = saltBlob;
    hkdfParams[idx].tag = HKS_TAG_INFO;
    hkdfParams[idx++].blob = keyInfoBlob;
    hkdfParams[idx].tag = HKS_TAG_IS_KEY_ALIAS;
    hkdfParams[idx++].boolParam = true;
    hkdfParams[idx].tag = HKS_TAG_KEY_STORAGE_FLAG;
    hkdfParams[idx++].uint32Param = HKS_STORAGE_ONLY_USED_IN_HUKS;
    hkdfParams[idx].tag = HKS_TAG_DERIVE_AGREE_KEY_STORAGE_FLAG;
    hkdfParams[idx++].uint32Param = HKS_STORAGE_ONLY_USED_IN_HUKS;
    hkdfParams[idx].tag = HKS_TAG_KEY_SIZE;
    hkdfParams[idx++].uint32Param = outLen * BITS_PER_BYTE;
    hkdfParams[idx].tag = HKS_TAG_KEY_ALIAS;
    hkdfParams[idx++].blob = pskAliasBlob;
    hkdfParams[idx].tag = HKS_TAG_EXT_INFO;
    hkdfParams[idx++].blob = *extInfoBlob;
    AddStorageExtParams(hkdfParams, keyParams->isDeStorage, &idx, keyParams->osAccountId);
    int32_t res = ConstructParamSet(paramSet, hkdfParams, idx);
    HcFree(hkdfParams);
    return res;
}

static int32_t CheckPskParams(const KeyParams *keyParams, const Uint8Buff *pskKeyAlias, const Uint8Buff *outPsk)
{
    int32_t res = CheckKeyParams(keyParams);
    if (res != HAL_SUCCESS) {
        return res;
    }
    const Uint8Buff *inParams[] = { pskKeyAlias, outPsk };
    const char *paramTags[] = { "pskKeyAlias", "outPsk" };
    return BaseCheckParams(inParams, paramTags, CAL_ARRAY_SIZE(inParams));
}

static int32_t ComputePseudonymPskInner(const KeyParams *keyParams, const Uint8Buff *pskKeyAlias,
    const Uint8Buff *extInfo, Uint8Buff *outPsk)
{
    struct HksBlob srcKeyBlob = { keyParams->keyBuff.keyLen, keyParams->keyBuff.key };
    struct HksBlob derivedKeyBlob = { outPsk->length, outPsk->val };
    struct HksBlob extInfoBlob = { 0, NULL };
    if (extInfo != NULL) {
        extInfoBlob.data = extInfo->val;
        extInfoBlob.size = extInfo->length;
    }
    struct HksParamSet *paramSet = NULL;
    int32_t res = ConstructPseudonymParamSet(keyParams, pskKeyAlias, &extInfoBlob, outPsk->length, &paramSet);
    if (res != HAL_SUCCESS) {
        LOGE("Construct param set failed!");
        return res;
    }

    LOGI("[HUKS]: HksDeriveKey enter.");
    res = HksDeriveKey(paramSet, &srcKeyBlob, &derivedKeyBlob);
    FreeParamSet(paramSet);
    LOGI("[HUKS]: HksDeriveKey quit. [Res]: %d", res);
    if (res != HKS_SUCCESS) {
        LOGE("[HUKS]: HksDeriveKey fail. [Res]: %d", res);
        return HAL_FAILED;
    }
    return HAL_SUCCESS;
}

// pseudonym psk alias：sha256(serviceType bytes+peerAuthId bytes+{0x00, 0x07})
static int32_t ComputePseudonymPsk(const KeyParams *keyParams, const Uint8Buff *pskKeyAlias,
    const Uint8Buff *extInfo, Uint8Buff *outPsk)
{
    int32_t res = CheckPskParams(keyParams, pskKeyAlias, outPsk);
    if (res != HAL_SUCCESS) {
        return res;
    }

    res = ComputePseudonymPskInner(keyParams, pskKeyAlias, extInfo, outPsk);
    if (!keyParams->isDeStorage) {
        return res;
    }
    if (res == HAL_SUCCESS) {
        struct HksBlob keyAliasBlob = { keyParams->keyBuff.keyLen, keyParams->keyBuff.key };
        MoveDeKeyToCe(keyParams->keyBuff.isAlias, keyParams->osAccountId, &keyAliasBlob);
    } else {
        KeyParams ceParams = {
            .keyBuff = { keyParams->keyBuff.key, keyParams->keyBuff.keyLen, keyParams->keyBuff.isAlias },
            .isDeStorage = false,
            .osAccountId = keyParams->osAccountId
        };
        res = ComputePseudonymPskInner(&ceParams, pskKeyAlias, extInfo, outPsk);
    }
    return res;
}

static int32_t ConstructOutParamSet(struct HksParamSet **outParamSet)
{
    int32_t res = HksInitParamSet(outParamSet);
    if (res != HKS_SUCCESS) {
        LOGE("init out param set failed, res = %d", res);
        return HAL_ERR_INIT_PARAM_SET_FAILED;
    }

    uint32_t outParamSetSize = 2048;
    uint8_t *blobVal = (uint8_t *)HcMalloc(outParamSetSize, 0);
    if (blobVal == NULL) {
        LOGE("Failed to alloc memory for out blob value!");
        HksFreeParamSet(outParamSet);
        return HAL_ERR_BAD_ALLOC;
    }
    struct HksParam getParam = {
        .tag = HKS_TAG_SYMMETRIC_KEY_DATA,
        .blob = { .size = outParamSetSize, .data = blobVal }
    };

    res = HksAddParams(*outParamSet, &getParam, 1);
    if (res != HKS_SUCCESS) {
        LOGE("Failed to add param!");
        HksFreeParamSet(outParamSet);
        HcFree(blobVal);
        return HAL_ERR_ADD_PARAM_FAILED;
    }

    res = HksBuildParamSet(outParamSet);
    HcFree(blobVal);
    if (res != HKS_SUCCESS) {
        LOGE("build param set failed, res = %d", res);
        HksFreeParamSet(outParamSet);
        return HAL_ERR_BUILD_PARAM_SET_FAILED;
    }
    return HAL_SUCCESS;
}

static int32_t GetExtInfoByParamSet(const struct HksParamSet *outParamSet, Uint8Buff *outExtInfo)
{
    struct HksParam *extInfoParam = NULL;
    int32_t res = HksGetParam(outParamSet, HKS_TAG_EXT_INFO, &extInfoParam);
    if (res != HKS_SUCCESS) {
        LOGE("Failed to get extInfoParam!");
        return HAL_FAILED;
    }
    if (extInfoParam->blob.data == NULL || extInfoParam->blob.size == 0) {
        LOGE("Extra info blob is null!");
        return HAL_FAILED;
    }
    uint8_t *tmpExtInfoVal = (uint8_t *)HcMalloc(extInfoParam->blob.size, 0);
    if (tmpExtInfoVal == NULL) {
        LOGE("Failed to alloc memory for extInfo value!");
        return HAL_ERR_BAD_ALLOC;
    }
    if (memcpy_s(tmpExtInfoVal, extInfoParam->blob.size, extInfoParam->blob.data, extInfoParam->blob.size) != EOK) {
        LOGE("Failed to copy extInfo!");
        HcFree(tmpExtInfoVal);
        return HAL_ERR_MEMORY_COPY;
    }
    outExtInfo->val = tmpExtInfoVal;
    outExtInfo->length = extInfoParam->blob.size;
    return HAL_SUCCESS;
}

static int32_t ConstructGetKeyExtInfoParamSet(const KeyParams *keyParams, struct HksParamSet **paramSet)
{
    uint32_t len = GetParamLen(keyParams->isDeStorage, 0);
    if (len == 0) {
        return HAL_SUCCESS;
    }
    struct HksParam *getParams = (struct HksParam *)HcMalloc(sizeof(struct HksParam) * len, 0);
    if (getParams == NULL) {
        LOGE("Malloc for getParams failed.");
        return HAL_ERR_BAD_ALLOC;
    }
    uint32_t idx = 0;
    AddStorageExtParams(getParams, keyParams->isDeStorage, &idx, keyParams->osAccountId);
    int32_t res = ConstructParamSet(paramSet, getParams, idx);
    HcFree(getParams);
    if (res != HAL_SUCCESS) {
        LOGE("Failed to construct get param set, res: %d", res);
    }
    return res;
}

static int32_t GetKeyExtInfoInner(const KeyParams *keyParams, Uint8Buff *outExtInfo)
{
    struct HksParamSet *paramSet = NULL;
    int32_t res = ConstructGetKeyExtInfoParamSet(keyParams, &paramSet);
    if (res != HAL_SUCCESS) {
        return res;
    }
    struct HksParamSet *outParamSet = NULL;
    res = ConstructOutParamSet(&outParamSet);
    if (res != HAL_SUCCESS) {
        FreeParamSet(paramSet);
        return res;
    }
    struct HksBlob keyAliasBlob = { keyParams->keyBuff.keyLen, keyParams->keyBuff.key };
    res = HksGetKeyParamSet(&keyAliasBlob, paramSet, outParamSet);
    FreeParamSet(paramSet);
    if (res != HKS_SUCCESS) {
        LOGE("Failed to get key param set!");
        FreeParamSet(outParamSet);
        return HAL_FAILED;
    }
    res = GetExtInfoByParamSet(outParamSet, outExtInfo);
    FreeParamSet(outParamSet);
    return res;
}

static int32_t GetKeyExtInfo(const KeyParams *keyParams, Uint8Buff *outExtInfo)
{
    int32_t res = CheckKeyParams(keyParams);
    if (res != HAL_SUCCESS) {
        return res;
    }
    if (outExtInfo == NULL) {
        LOGE("outExtInfo is null!");
        return HAL_ERR_NULL_PTR;
    }

    res = GetKeyExtInfoInner(keyParams, outExtInfo);
    if (!keyParams->isDeStorage) {
        return res;
    }
    if (res == HAL_SUCCESS) {
        struct HksBlob keyAliasBlob = { keyParams->keyBuff.keyLen, keyParams->keyBuff.key };
        MoveDeKeyToCe(keyParams->keyBuff.isAlias, keyParams->osAccountId, &keyAliasBlob);
    } else {
        KeyParams ceParams = {
            .keyBuff = { keyParams->keyBuff.key, keyParams->keyBuff.keyLen, keyParams->keyBuff.isAlias },
            .isDeStorage = false,
            .osAccountId = keyParams->osAccountId
        };
        res = GetKeyExtInfoInner(&ceParams, outExtInfo);
    }
    return res;
}

static int32_t CheckAesGcmEncryptParam(const KeyParams *keyParams, const Uint8Buff *plain,
    const GcmParam *encryptInfo, Uint8Buff *outCipher)
{
    int32_t res = CheckKeyParams(keyParams);
    if (res != HAL_SUCCESS) {
        return res;
    }
    const Uint8Buff *inParams[] = { plain, outCipher };
    const char* paramTags[] = { "plain", "outCipher" };
    res = BaseCheckParams(inParams, paramTags, CAL_ARRAY_SIZE(inParams));
    if (res != HAL_SUCCESS) {
        return res;
    }

    CHECK_PTR_RETURN_HAL_ERROR_CODE(encryptInfo, "encryptInfo");
    CHECK_PTR_RETURN_HAL_ERROR_CODE(encryptInfo->aad, "aad");
    CHECK_LEN_ZERO_RETURN_ERROR_CODE(encryptInfo->aadLen, "aadLen");
    CHECK_PTR_RETURN_HAL_ERROR_CODE(encryptInfo->nonce, "nonce");
    CHECK_LEN_LOWER_RETURN(encryptInfo->nonceLen, HKS_AE_NONCE_LEN, "nonceLen");
    CHECK_LEN_LOWER_RETURN(outCipher->length, plain->length + HKS_AE_TAG_LEN, "outCipher");

    return HAL_SUCCESS;
}

static int32_t ConstructAesGcmEncryptParamSet(const GcmParam *encryptInfo, const KeyParams *keyParams,
    struct HksParamSet **paramSet)
{
    struct HksBlob nonceBlob = { encryptInfo->nonceLen, encryptInfo->nonce };
    struct HksBlob aadBlob = { encryptInfo->aadLen, encryptInfo->aad };
    uint32_t len = GetParamLen(keyParams->isDeStorage, BASE_ENCRYPT_PARAMS_LEN);
    struct HksParam *encryptParams = (struct HksParam *)HcMalloc(sizeof(struct HksParam) * len, 0);
    if (encryptParams == NULL) {
        LOGE("Malloc for encryptParams failed.");
        return HAL_ERR_BAD_ALLOC;
    }
    uint32_t idx = 0;
    encryptParams[idx].tag = HKS_TAG_PURPOSE;
    encryptParams[idx++].uint32Param = HKS_KEY_PURPOSE_ENCRYPT;
    encryptParams[idx].tag = HKS_TAG_ALGORITHM;
    encryptParams[idx++].uint32Param = HKS_ALG_AES;
    encryptParams[idx].tag = HKS_TAG_BLOCK_MODE;
    encryptParams[idx++].uint32Param = HKS_MODE_GCM;
    encryptParams[idx].tag = HKS_TAG_PADDING;
    encryptParams[idx++].uint32Param = HKS_PADDING_NONE;
    encryptParams[idx].tag = HKS_TAG_NONCE;
    encryptParams[idx++].blob = nonceBlob;
    encryptParams[idx].tag = HKS_TAG_ASSOCIATED_DATA;
    encryptParams[idx++].blob = aadBlob;
    encryptParams[idx].tag = HKS_TAG_IS_KEY_ALIAS;
    encryptParams[idx++].boolParam = keyParams->keyBuff.isAlias;
    AddStorageExtParams(encryptParams, keyParams->isDeStorage, &idx, keyParams->osAccountId);
    int32_t res = ConstructParamSet(paramSet, encryptParams, idx);
    HcFree(encryptParams);
    if (res != HAL_SUCCESS) {
        LOGE("Failed to construct encrypt param set, res: %d", res);
    }
    return res;
}

static int32_t AesGcmEncrypt(const KeyParams *keyParams, const Uint8Buff *plain, const GcmParam *encryptInfo,
    Uint8Buff *outCipher)
{
    int32_t res = CheckAesGcmEncryptParam(keyParams, plain, encryptInfo, outCipher);
    if (res != HAL_SUCCESS) {
        return res;
    }

    struct HksBlob keyBlob = { keyParams->keyBuff.keyLen, keyParams->keyBuff.key };
    struct HksBlob plainBlob = { plain->length, plain->val };
    struct HksBlob cipherBlob = { outCipher->length, outCipher->val };

    struct HksParamSet *paramSet = NULL;
    res = ConstructAesGcmEncryptParamSet(encryptInfo, keyParams, &paramSet);
    if (res != HAL_SUCCESS) {
        return res;
    }

    LOGI("[HUKS]: HksEncrypt enter.");
    res = HksEncrypt(&keyBlob, paramSet, &plainBlob, &cipherBlob);
    FreeParamSet(paramSet);
    LOGI("[HUKS]: HksEncrypt quit. [Res]: %d", res);
    if (res != HKS_SUCCESS) {
        LOGE("[HUKS]: HksEncrypt fail. [Res]: %d", res);
        return HAL_FAILED;
    }
    return HAL_SUCCESS;
}

static int32_t CheckAesGcmDecryptParam(const KeyParams *keyParams, const Uint8Buff *cipher,
    const GcmParam *decryptInfo, Uint8Buff *outPlain)
{
    int32_t res = CheckKeyParams(keyParams);
    if (res != HAL_SUCCESS) {
        return res;
    }
    const Uint8Buff *inParams[] = { cipher, outPlain };
    const char *paramTags[] = { "cipher", "outPlain" };
    res = BaseCheckParams(inParams, paramTags, CAL_ARRAY_SIZE(inParams));
    if (res != HAL_SUCCESS) {
        return res;
    }

    CHECK_PTR_RETURN_HAL_ERROR_CODE(decryptInfo, "decryptInfo");
    CHECK_PTR_RETURN_HAL_ERROR_CODE(decryptInfo->aad, "aad");
    CHECK_LEN_ZERO_RETURN_ERROR_CODE(decryptInfo->aadLen, "aadLen");
    CHECK_PTR_RETURN_HAL_ERROR_CODE(decryptInfo->nonce, "nonce");
    CHECK_LEN_LOWER_RETURN(decryptInfo->nonceLen, HKS_AE_NONCE_LEN, "nonceLen");
    CHECK_LEN_LOWER_RETURN(outPlain->length, cipher->length - HKS_AE_TAG_LEN, "outPlain");

    return HAL_SUCCESS;
}

static int32_t ConstructAesGcmDecryptParamSet(const GcmParam *decryptInfo, const KeyParams *keyParams,
    struct HksParamSet **paramSet)
{
    struct HksBlob nonceBlob = { decryptInfo->nonceLen, decryptInfo->nonce };
    struct HksBlob aadBlob = { decryptInfo->aadLen, decryptInfo->aad };
    uint32_t len = GetParamLen(keyParams->isDeStorage, BASE_DECRYPT_PARAMS_LEN);
    struct HksParam *decryptParams = (struct HksParam *)HcMalloc(sizeof(struct HksParam) * len, 0);
    if (decryptParams == NULL) {
        LOGE("Malloc for decryptParams failed.");
        return HAL_ERR_BAD_ALLOC;
    }
    uint32_t idx = 0;
    decryptParams[idx].tag = HKS_TAG_PURPOSE;
    decryptParams[idx++].uint32Param = HKS_KEY_PURPOSE_DECRYPT;
    decryptParams[idx].tag = HKS_TAG_ALGORITHM;
    decryptParams[idx++].uint32Param = HKS_ALG_AES;
    decryptParams[idx].tag = HKS_TAG_BLOCK_MODE;
    decryptParams[idx++].uint32Param = HKS_MODE_GCM;
    decryptParams[idx].tag = HKS_TAG_PADDING;
    decryptParams[idx++].uint32Param = HKS_PADDING_NONE;
    decryptParams[idx].tag = HKS_TAG_NONCE;
    decryptParams[idx++].blob = nonceBlob;
    decryptParams[idx].tag = HKS_TAG_ASSOCIATED_DATA;
    decryptParams[idx++].blob = aadBlob;
    decryptParams[idx].tag = HKS_TAG_IS_KEY_ALIAS;
    decryptParams[idx++].boolParam = keyParams->keyBuff.isAlias;
    AddStorageExtParams(decryptParams, keyParams->isDeStorage, &idx, keyParams->osAccountId);
    int32_t res = ConstructParamSet(paramSet, decryptParams, idx);
    HcFree(decryptParams);
    if (res != HAL_SUCCESS) {
        LOGE("Failed to construct decrypt param set, res: %d", res);
    }
    return res;
}

static int32_t AesGcmDecrypt(const KeyParams *keyParams, const Uint8Buff *cipher, const GcmParam *decryptInfo,
    Uint8Buff *outPlain)
{
    int32_t res = CheckAesGcmDecryptParam(keyParams, cipher, decryptInfo, outPlain);
    if (res != HAL_SUCCESS) {
        return res;
    }

    struct HksBlob keyBlob = { keyParams->keyBuff.keyLen, keyParams->keyBuff.key };
    struct HksBlob cipherBlob = { cipher->length, cipher->val };
    struct HksBlob plainBlob = { outPlain->length, outPlain->val };

    struct HksParamSet *paramSet = NULL;
    res = ConstructAesGcmDecryptParamSet(decryptInfo, keyParams, &paramSet);
    if (res != HAL_SUCCESS) {
        return res;
    }

    LOGI("[HUKS]: HksDecrypt enter.");
    res = HksDecrypt(&keyBlob, paramSet, &cipherBlob, &plainBlob);
    FreeParamSet(paramSet);
    LOGI("[HUKS]: HksDecrypt quit. [Res]: %d", res);
    if (res != HKS_SUCCESS) {
        LOGE("[HUKS]: HksDecrypt fail. [Res]: %d", res);
        return HAL_FAILED;
    }
    return HAL_SUCCESS;
}

static int32_t HashToPoint(const Uint8Buff *hash, Algorithm algo, Uint8Buff *outEcPoint)
{
    CHECK_PTR_RETURN_HAL_ERROR_CODE(hash, "hash");
    CHECK_PTR_RETURN_HAL_ERROR_CODE(hash->val, "hash->val");
    CHECK_LEN_EQUAL_RETURN(hash->length, SHA256_LEN, "hash->length");
    CHECK_PTR_RETURN_HAL_ERROR_CODE(outEcPoint, "outEcPoint");
    CHECK_PTR_RETURN_HAL_ERROR_CODE(outEcPoint->val, "outEcPoint->val");

    if (algo != X25519 && algo != P256) {
        LOGE("Compute algo: %d.", algo);
        return HAL_ERR_INVALID_PARAM;
    }
    if (algo == P256) {
        LOGI("Compute HashToPoint for P256");
        return MbedtlsHashToPoint(hash, outEcPoint);
    }

    CHECK_LEN_EQUAL_RETURN(outEcPoint->length, SHA256_LEN, "outEcPoint->length");
    return HashToPointX25519(hash, outEcPoint);
}

static int32_t ConstructInitParamsP256(struct HksParamSet **initParamSet, const KeyParams *keyParams)
{
    uint32_t len = GetParamLen(keyParams->isDeStorage, BASE_AGREE_INIT_PARAMS_LEN);
    struct HksParam *initParams = (struct HksParam *)HcMalloc(sizeof(struct HksParam) * len, 0);
    if (initParams == NULL) {
        LOGE("Malloc for initParams failed.");
        return HAL_ERR_BAD_ALLOC;
    }
    uint32_t idx = 0;
    initParams[idx].tag = HKS_TAG_ALGORITHM;
    initParams[idx++].uint32Param = HKS_ALG_ECDH;
    initParams[idx].tag = HKS_TAG_PURPOSE;
    initParams[idx++].uint32Param = HKS_KEY_PURPOSE_AGREE;
    initParams[idx].tag = HKS_TAG_KEY_SIZE;
    initParams[idx++].uint32Param = HKS_ECC_KEY_SIZE_256;
    AddStorageExtParams(initParams, keyParams->isDeStorage, &idx, keyParams->osAccountId);
    int32_t res = ConstructParamSet(initParamSet, initParams, idx);
    HcFree(initParams);
    if (res != HAL_SUCCESS) {
        LOGE("Construct init param set failed, res = %d", res);
    }
    return res;
}

static int32_t ConstructFinishParamsP256(struct HksParamSet **finishParamSet, const KeyParams *keyParams,
    const struct HksBlob *sharedKeyAliasBlob)
{
    uint32_t len = GetParamLen(keyParams->isDeStorage, BASE_AGREE_FINISH_PARAMS_LEN);
    struct HksParam *finishParams = (struct HksParam *)HcMalloc(sizeof(struct HksParam) * len, 0);
    if (finishParams == NULL) {
        LOGE("Malloc for finishParams failed.");
        return HAL_ERR_BAD_ALLOC;
    }
    uint32_t idx = 0;
    finishParams[idx].tag = HKS_TAG_KEY_STORAGE_FLAG;
    finishParams[idx++].uint32Param = HKS_STORAGE_PERSISTENT;
    finishParams[idx].tag = HKS_TAG_IS_KEY_ALIAS;
    finishParams[idx++].boolParam = true;
    finishParams[idx].tag = HKS_TAG_ALGORITHM;
    finishParams[idx++].uint32Param = HKS_ALG_AES;
    finishParams[idx].tag = HKS_TAG_KEY_SIZE;
    finishParams[idx++].uint32Param = HKS_AES_KEY_SIZE_256;
    finishParams[idx].tag = HKS_TAG_PURPOSE;
    finishParams[idx++].uint32Param = HKS_KEY_PURPOSE_DERIVE;
    finishParams[idx].tag = HKS_TAG_DIGEST;
    finishParams[idx++].uint32Param = HKS_DIGEST_SHA256;
    finishParams[idx].tag = HKS_TAG_KEY_ALIAS;
    finishParams[idx++].blob = *sharedKeyAliasBlob;
    AddStorageExtParams(finishParams, keyParams->isDeStorage, &idx, keyParams->osAccountId);
    int32_t res = ConstructParamSet(finishParamSet, finishParams, idx);
    HcFree(finishParams);
    if (res != HAL_SUCCESS) {
        LOGE("Construct finish param set failed, res = %d", res);
    }
    return res;
}

static int32_t AgreeSharedSecretWithStorageP256(const KeyParams *priKeyParams, const KeyBuff *pubKeyBuff,
    const struct HksBlob *sharedKeyAliasBlob)
{
    struct HksParamSet *initParamSet = NULL;
    struct HksParamSet *finishParamSet = NULL;
    int32_t res = ConstructInitParamsP256(&initParamSet, priKeyParams);
    if (res != HAL_SUCCESS) {
        return res;
    }
    res = ConstructFinishParamsP256(&finishParamSet, priKeyParams, sharedKeyAliasBlob);
    if (res != HAL_SUCCESS) {
        FreeParamSet(initParamSet);
        return res;
    }
    struct HksBlob priKeyAliasBlob = { priKeyParams->keyBuff.keyLen, priKeyParams->keyBuff.key };
    struct HksBlob pubKeyBlob = { pubKeyBuff->keyLen, pubKeyBuff->key };
    uint8_t handle[sizeof(uint64_t)] = { 0 };
    struct HksBlob handleBlob = { sizeof(uint64_t), handle };
    uint8_t outDataUpdate[ECDH_COMMON_SIZE_P256] = { 0 };
    struct HksBlob outDataUpdateBlob = { ECDH_COMMON_SIZE_P256, outDataUpdate };
    uint8_t outDataFinish[ECDH_COMMON_SIZE_P256] = { 0 };
    struct HksBlob outDataFinishBlob = { ECDH_COMMON_SIZE_P256, outDataFinish };
    do {
        res = HksInit(&priKeyAliasBlob, initParamSet, &handleBlob, NULL);
        if (res != HKS_SUCCESS) {
            LOGE("Huks agree P256 key: HksInit failed, res = %d", res);
            res = HAL_ERR_HUKS;
            break;
        }
        res = HksUpdate(&handleBlob, initParamSet, &pubKeyBlob, &outDataUpdateBlob);
        if (res != HKS_SUCCESS) {
            LOGE("Huks agree P256 key: HksUpdate failed, res = %d", res);
            res = HAL_ERR_HUKS;
            break;
        }
        LOGI("[HUKS]: HksFinish enter.");
        res = HksFinish(&handleBlob, finishParamSet, &pubKeyBlob, &outDataFinishBlob);
        LOGI("[HUKS]: HksFinish quit. [Res]: %d", res);
        if (res != HKS_SUCCESS) {
            LOGE("[HUKS]: HksFinish fail. [Res]: %d", res);
            res = HAL_ERR_HUKS;
            break;
        }
    } while (0);
    FreeParamSet(initParamSet);
    FreeParamSet(finishParamSet);
    return res;
}

static int32_t ConstructAgreeWithStorageParams(struct HksParamSet **paramSet, uint32_t keyLen, Algorithm algo,
    const KeyParams *priKeyParams, const KeyBuff *pubKeyBuff)
{
    struct HksBlob priKeyBlob = { priKeyParams->keyBuff.keyLen, priKeyParams->keyBuff.key };
    struct HksBlob pubKeyBlob = { pubKeyBuff->keyLen, pubKeyBuff->key };
    uint32_t len = GetParamLen(priKeyParams->isDeStorage, BASE_AGREE_WITH_STORAGE_PARAMS_LEN);
    struct HksParam *agreeParams = (struct HksParam *)HcMalloc(sizeof(struct HksParam) * len, 0);
    if (agreeParams == NULL) {
        LOGE("Malloc for agreeParams failed.");
        return HAL_ERR_BAD_ALLOC;
    }
    uint32_t idx = 0;
    agreeParams[idx].tag = HKS_TAG_ALGORITHM;
    agreeParams[idx++].uint32Param = HKS_ALG_AES;
    agreeParams[idx].tag = HKS_TAG_KEY_SIZE;
    agreeParams[idx++].uint32Param = keyLen * BITS_PER_BYTE;
    agreeParams[idx].tag = HKS_TAG_PURPOSE;
    agreeParams[idx++].uint32Param = HKS_KEY_PURPOSE_DERIVE;
    agreeParams[idx].tag = HKS_TAG_DIGEST;
    agreeParams[idx++].uint32Param = HKS_DIGEST_SHA256;
    agreeParams[idx].tag = HKS_TAG_KEY_GENERATE_TYPE;
    agreeParams[idx++].uint32Param = HKS_KEY_GENERATE_TYPE_AGREE;
    agreeParams[idx].tag = HKS_TAG_AGREE_ALG;
    agreeParams[idx++].uint32Param = g_algToHksAlgorithm[algo]; // only support HKS_ALG_ED25519 and HKS_ALG_X25519
    agreeParams[idx].tag = HKS_TAG_AGREE_PRIVATE_KEY_ALIAS;
    agreeParams[idx++].blob = priKeyBlob;
    agreeParams[idx].tag = HKS_TAG_AGREE_PUBLIC_KEY;
    agreeParams[idx++].blob = pubKeyBlob;
    agreeParams[idx].tag = HKS_TAG_AGREE_PUBLIC_KEY_IS_KEY_ALIAS;
    agreeParams[idx++].boolParam = pubKeyBuff->isAlias;
    AddStorageExtParams(agreeParams, priKeyParams->isDeStorage, &idx, priKeyParams->osAccountId);
    int32_t res = ConstructParamSet(paramSet, agreeParams, idx);
    HcFree(agreeParams);
    if (res != HAL_SUCCESS) {
        LOGE("Construct agree param set failed, res = %d", res);
    }
    return res;
}

static int32_t CheckAgreeWithStorageParams(const KeyParams *priKeyParams, const KeyBuff *pubKeyBuff,
    uint32_t sharedKeyLen, const Uint8Buff *sharedKeyAlias)
{
    int32_t res = CheckKeyParams(priKeyParams);
    if (res != HAL_SUCCESS) {
        return res;
    }
    CHECK_PTR_RETURN_HAL_ERROR_CODE(pubKeyBuff, "pubKeyBuff");
    CHECK_PTR_RETURN_HAL_ERROR_CODE(pubKeyBuff->key, "pubKeyBuff->key");
    CHECK_LEN_ZERO_RETURN_ERROR_CODE(pubKeyBuff->keyLen, "pubKeyBuff->keyLen");
    CHECK_PTR_RETURN_HAL_ERROR_CODE(sharedKeyAlias, "sharedKeyAlias");
    CHECK_PTR_RETURN_HAL_ERROR_CODE(sharedKeyAlias->val, "sharedKeyAlias->val");
    CHECK_LEN_ZERO_RETURN_ERROR_CODE(sharedKeyAlias->length, "sharedKeyAlias->length");
    CHECK_LEN_ZERO_RETURN_ERROR_CODE(sharedKeyLen, "sharedKeyLen");
    return HAL_SUCCESS;
}

static void MoveSharedKeyToCe(const KeyParams *priKeyParams, const struct HksBlob *sharedKeyAlias)
{
    struct HksBlob priKeyBlob = { priKeyParams->keyBuff.keyLen, priKeyParams->keyBuff.key };
    MoveDeKeyToCe(priKeyParams->keyBuff.isAlias, priKeyParams->osAccountId, &priKeyBlob);
    MoveDeKeyToCe(true, priKeyParams->osAccountId, sharedKeyAlias);
}

static int32_t AgreeSharedSecretWithStorage(const KeyParams *priKeyParams, const KeyBuff *pubKeyBuff,
    Algorithm algo, uint32_t sharedKeyLen, const Uint8Buff *sharedKeyAlias)
{
    int32_t res = CheckAgreeWithStorageParams(priKeyParams, pubKeyBuff, sharedKeyLen, sharedKeyAlias);
    if (res != HAL_SUCCESS) {
        return res;
    }

    struct HksBlob sharedKeyAliasBlob = { sharedKeyAlias->length, sharedKeyAlias->val };
    if (g_algToHksAlgorithm[algo] == HKS_ALG_ECC) {
        LOGI("Hks agree key with storage for P256.");
        return AgreeSharedSecretWithStorageP256(priKeyParams, pubKeyBuff, &sharedKeyAliasBlob);
    }
    struct HksParamSet *deParamSet = NULL;
    KeyParams keyParams = {
        .keyBuff = { priKeyParams->keyBuff.key, priKeyParams->keyBuff.keyLen, priKeyParams->keyBuff.isAlias },
        .isDeStorage = true,
        .osAccountId = priKeyParams->osAccountId
    };
    res = ConstructAgreeWithStorageParams(&deParamSet, sharedKeyLen, algo, &keyParams, pubKeyBuff);
    if (res != HAL_SUCCESS) {
        return res;
    }
    struct HksParamSet *ceParamSet = NULL;
    keyParams.isDeStorage = false;
    res = ConstructAgreeWithStorageParams(&ceParamSet, sharedKeyLen, algo, &keyParams, pubKeyBuff);
    if (res != HAL_SUCCESS) {
        FreeParamSet(deParamSet);
        return res;
    }

    LOGI("[HUKS]: HksGenerateKey enter.");
    if (priKeyParams->isDeStorage) {
        res = HksGenerateKey(&sharedKeyAliasBlob, deParamSet, NULL);
        if (res == HKS_SUCCESS) {
            MoveSharedKeyToCe(priKeyParams, &sharedKeyAliasBlob);
        } else {
            res = HksGenerateKey(&sharedKeyAliasBlob, ceParamSet, NULL);
        }
    } else {
        res = HksGenerateKey(&sharedKeyAliasBlob, ceParamSet, NULL);
        if (res != HKS_SUCCESS) {
            res = HksGenerateKey(&sharedKeyAliasBlob, deParamSet, NULL);
        }
    }
    LOGI("[HUKS]: HksGenerateKey quit. [Res]: %d", res);
    FreeParamSet(deParamSet);
    FreeParamSet(ceParamSet);
    if (res != HKS_SUCCESS) {
        LOGE("[HUKS]: HksGenerateKey fail. [Res]: %d", res);
        return HAL_FAILED;
    }
    return HAL_SUCCESS;
}

static int32_t CheckAgreeParams(const KeyParams *priKeyParams, const KeyBuff *pubKey, const Uint8Buff *sharedKey)
{
    int32_t res = CheckKeyParams(priKeyParams);
    if (res != HAL_SUCCESS) {
        return res;
    }
    CHECK_PTR_RETURN_HAL_ERROR_CODE(pubKey, "pubKey");
    CHECK_PTR_RETURN_HAL_ERROR_CODE(pubKey->key, "pubKey->key");
    CHECK_LEN_ZERO_RETURN_ERROR_CODE(pubKey->keyLen, "pubKey->keyLen");
    CHECK_PTR_RETURN_HAL_ERROR_CODE(sharedKey, "sharedKey");
    CHECK_PTR_RETURN_HAL_ERROR_CODE(sharedKey->val, "sharedKey->val");
    CHECK_LEN_ZERO_RETURN_ERROR_CODE(sharedKey->length, "sharedKey->length");
    return HAL_SUCCESS;
}

static int32_t ConstructAgreeParamSet(const KeyParams *keyParams, Algorithm algo, const Uint8Buff *sharedKey,
    struct HksParamSet **paramSet)
{
    uint32_t len = GetParamLen(keyParams->isDeStorage, BASE_AGREE_PARAMS_LEN);
    struct HksParam *agreeParams = (struct HksParam *)HcMalloc(sizeof(struct HksParam) * len, 0);
    if (agreeParams == NULL) {
        LOGE("Malloc for agreeParams failed.");
        return HAL_ERR_BAD_ALLOC;
    }
    uint32_t idx = 0;
    agreeParams[idx].tag = HKS_TAG_ALGORITHM;
    agreeParams[idx++].uint32Param = g_algToHksAlgorithm[algo]; // only support HKS_ALG_X25519 now
    agreeParams[idx].tag = HKS_TAG_KEY_SIZE;
    agreeParams[idx++].uint32Param = sharedKey->length * BITS_PER_BYTE;
    agreeParams[idx].tag = HKS_TAG_IS_KEY_ALIAS;
    agreeParams[idx++].boolParam = keyParams->keyBuff.isAlias;
    AddStorageExtParams(agreeParams, keyParams->isDeStorage, &idx, keyParams->osAccountId);
    int32_t res = ConstructParamSet(paramSet, agreeParams, idx);
    HcFree(agreeParams);
    if (res != HAL_SUCCESS) {
        LOGE("Construct agree param set failed, res = %d", res);
    }
    return res;
}

static int32_t AgreeSharedSecret(const KeyParams *priKeyParams, const KeyBuff *pubKey, Algorithm algo,
    Uint8Buff *sharedKey)
{
    int32_t res = CheckAgreeParams(priKeyParams, pubKey, sharedKey);
    if (res != HAL_SUCCESS) {
        return res;
    }

    if (g_algToHksAlgorithm[algo] == HKS_ALG_ECC) {
        LOGI("Hks agree key for P256.");
        KeyBuff priKey = { priKeyParams->keyBuff.key, priKeyParams->keyBuff.keyLen, priKeyParams->keyBuff.isAlias };
        return MbedtlsAgreeSharedSecret(&priKey, pubKey, sharedKey);
    }

    struct HksBlob priKeyBlob = { priKeyParams->keyBuff.keyLen, priKeyParams->keyBuff.key };
    struct HksBlob pubKeyBlob = { pubKey->keyLen, pubKey->key };
    struct HksBlob sharedKeyBlob = { sharedKey->length, sharedKey->val };

    struct HksParamSet *paramSet = NULL;
    res = ConstructAgreeParamSet(priKeyParams, algo, sharedKey, &paramSet);
    if (res != HAL_SUCCESS) {
        return res;
    }

    LOGI("[HUKS]: HksAgreeKey enter.");
    res = HksAgreeKey(paramSet, &priKeyBlob, &pubKeyBlob, &sharedKeyBlob);
    FreeParamSet(paramSet);
    LOGI("[HUKS]: HksAgreeKey quit. [Res]: %d", res);
    if (res != HKS_SUCCESS) {
        LOGE("[HUKS]: HksAgreeKey fail. [Res]: %d", res);
        return HAL_FAILED;
    }
    return HAL_SUCCESS;
}

static int32_t BigNumExpMod(const Uint8Buff *base, const Uint8Buff *exp, const char *bigNumHex, Uint8Buff *outNum)
{
    const Uint8Buff *inParams[] = { base, exp, outNum };
    const char *paramTags[] = { "base", "exp", "outNum" };
    int32_t res = BaseCheckParams(inParams, paramTags, CAL_ARRAY_SIZE(inParams));
    if (res != HAL_SUCCESS) {
        return res;
    }

    CHECK_PTR_RETURN_HAL_ERROR_CODE(bigNumHex, "bigNumHex");
    uint32_t primeLen = HcStrlen(bigNumHex) / BYTE_TO_HEX_OPER_LENGTH;
    if ((primeLen != BIG_PRIME_LEN_384) && (primeLen != BIG_PRIME_LEN_256)) {
        LOGE("Not support big number len %d", outNum->length);
        return HAL_FAILED;
    }
    CHECK_LEN_EQUAL_RETURN(outNum->length, primeLen, "outNum->length");

    struct HksBlob baseBlob = { base->length, base->val };
    struct HksBlob expBlob = { exp->length, exp->val };
    struct HksBlob outNumBlob = { outNum->length, outNum->val };
    struct HksBlob bigNumBlob = { 0, NULL };
    bigNumBlob.size = outNum->length;
    bigNumBlob.data = (uint8_t *)HcMalloc(bigNumBlob.size, 0);
    if (bigNumBlob.data == NULL) {
        LOGE("malloc bigNumBlob.data failed.");
        return HAL_ERR_BAD_ALLOC;
    }
    res = HexStringToByte(bigNumHex, bigNumBlob.data, bigNumBlob.size);
    if (res != HAL_SUCCESS) {
        LOGE("HexStringToByte for bigNumHex failed.");
        HcFree(bigNumBlob.data);
        return res;
    }

    res = HksBnExpMod(&outNumBlob, &baseBlob, &expBlob, &bigNumBlob);
    if (res != HKS_SUCCESS) {
        LOGE("Huks calculate big number exp mod failed, res = %d", res);
        HcFree(bigNumBlob.data);
        return HAL_FAILED;
    }
    outNum->length = outNumBlob.size;

    HcFree(bigNumBlob.data);
    return HAL_SUCCESS;
}

static int32_t ConstructGenerateKeyPairWithStorageParams(struct HksParamSet **paramSet, Algorithm algo,
    uint32_t keyLen, KeyPurpose purpose, const KeyParams *authIdParams)
{
    struct HksBlob authIdBlob = { authIdParams->keyBuff.keyLen, authIdParams->keyBuff.key };
    uint32_t len = GetParamLen(authIdParams->isDeStorage, BASE_GENERATE_KEY_PAIR_PARAMS_LEN);
    struct HksParam *generateParams = (struct HksParam *)HcMalloc(sizeof(struct HksParam) * len, 0);
    if (generateParams == NULL) {
        LOGE("Malloc for generateParams failed.");
        return HAL_ERR_BAD_ALLOC;
    }
    uint32_t idx = 0;
    generateParams[idx].tag = HKS_TAG_ALGORITHM;
    generateParams[idx++].uint32Param = g_algToHksAlgorithm[algo];
    generateParams[idx].tag = HKS_TAG_KEY_STORAGE_FLAG;
    generateParams[idx++].uint32Param = HKS_STORAGE_PERSISTENT;
    generateParams[idx].tag = HKS_TAG_PURPOSE;
    generateParams[idx++].uint32Param = g_purposeToHksKeyPurpose[purpose];
    generateParams[idx].tag = HKS_TAG_KEY_SIZE;
    generateParams[idx++].uint32Param = keyLen * BITS_PER_BYTE;
    generateParams[idx].tag = HKS_TAG_KEY_AUTH_ID;
    generateParams[idx++].blob = authIdBlob;
    generateParams[idx].tag = HKS_TAG_DIGEST;
    generateParams[idx++].uint32Param = HKS_DIGEST_SHA256;
    AddStorageExtParams(generateParams, authIdParams->isDeStorage, &idx, authIdParams->osAccountId);
    int32_t res = ConstructParamSet(paramSet, generateParams, idx);
    HcFree(generateParams);
    if (res != HAL_SUCCESS) {
        LOGE("Construct generate key pair param set failed, res = %d", res);
    }
    return res;
}

static int32_t CheckGenerateKeyPairParams(const KeyParams *keyParams, const ExtraInfo *exInfo, uint32_t keyLen)
{
    int32_t res = CheckKeyParams(keyParams);
    if (res != HAL_SUCCESS)  {
        return res;
    }
    CHECK_PTR_RETURN_HAL_ERROR_CODE(exInfo, "exInfo");
    CHECK_PTR_RETURN_HAL_ERROR_CODE(exInfo->authId.val, "authId->val");
    CHECK_LEN_ZERO_RETURN_ERROR_CODE(exInfo->authId.length, "authId->length");
    CHECK_LEN_ZERO_RETURN_ERROR_CODE(keyLen, "keyLen");
    return HAL_SUCCESS;
}

static int32_t GenerateKeyPairWithStorage(const KeyParams *keyParams, uint32_t keyLen, Algorithm algo,
    KeyPurpose purpose, const ExtraInfo *exInfo)
{
    int32_t res = CheckGenerateKeyPairParams(keyParams, exInfo, keyLen);
    if (res != HAL_SUCCESS) {
        return res;
    }

    KeyParams authIdParams = {
        .keyBuff = { exInfo->authId.val, exInfo->authId.length, true },
        .isDeStorage = keyParams->isDeStorage,
        .osAccountId = keyParams->osAccountId
    };
    struct HksParamSet *paramSet = NULL;
    res = ConstructGenerateKeyPairWithStorageParams(&paramSet, algo, keyLen, purpose, &authIdParams);
    if (res != HAL_SUCCESS) {
        return res;
    }
    struct HksBlob keyAliasBlob = { keyParams->keyBuff.keyLen, keyParams->keyBuff.key };

    LOGI("[HUKS]: HksGenerateKey enter.");
    res = HksGenerateKey(&keyAliasBlob, paramSet, NULL);
    FreeParamSet(paramSet);
    LOGI("[HUKS]: HksGenerateKey quit. [Res]: %d", res);
    if (res != HKS_SUCCESS) {
        LOGE("[HUKS]: HksGenerateKey fail. [Res]: %d", res);
        return HAL_FAILED;
    }
    return HAL_SUCCESS;
}

static int32_t GetKeyPair(struct HksParamSet *outParamSet, Uint8Buff *outPriKey, Uint8Buff *outPubKey)
{
    int32_t res = HksFreshParamSet(outParamSet, false); /* false means fresh by local, not through IPC */
    if (res != HKS_SUCCESS) {
        LOGE("fresh param set failed, res:%d", res);
        return HAL_ERR_FRESH_PARAM_SET_FAILED;
    }

    struct HksParam *pubKeyParam = NULL;
    res = HksGetParam(outParamSet, HKS_TAG_ASYMMETRIC_PUBLIC_KEY_DATA, &pubKeyParam);
    if (res != HKS_SUCCESS) {
        LOGE("get pub key from param set failed, res:%d", res);
        return HAL_ERR_GET_PARAM_FAILED;
    }

    struct HksParam *priKeyParam = NULL;
    res = HksGetParam(outParamSet, HKS_TAG_ASYMMETRIC_PRIVATE_KEY_DATA, &priKeyParam);
    if (res != HKS_SUCCESS) {
        LOGE("get priv key from param set failed, res:%d", res);
        return HAL_ERR_GET_PARAM_FAILED;
    }

    if (memcpy_s(outPubKey->val, outPubKey->length, pubKeyParam->blob.data, pubKeyParam->blob.size) != EOK) {
        LOGE("parse x25519 output param set memcpy public key failed!");
        return HAL_ERR_MEMORY_COPY;
    }
    outPubKey->length = pubKeyParam->blob.size;

    if (memcpy_s(outPriKey->val, outPriKey->length, priKeyParam->blob.data, priKeyParam->blob.size) != EOK) {
        LOGE("parse x25519 output param set memcpy private key failed!");
        return HAL_ERR_MEMORY_COPY;
    }
    outPriKey->length = priKeyParam->blob.size;

    return HAL_SUCCESS;
}

static int32_t ConstructGenerateKeyPairParams(struct HksParamSet **paramSet, Algorithm algo, uint32_t keyLen)
{
    struct HksParam keyParam[] = {
        {
            .tag = HKS_TAG_KEY_STORAGE_FLAG,
            .uint32Param = HKS_STORAGE_TEMP
        }, {
            .tag = HKS_TAG_ALGORITHM,
            .uint32Param = g_algToHksAlgorithm[algo]
        }, {
            .tag = HKS_TAG_KEY_SIZE,
            .uint32Param = keyLen * BITS_PER_BYTE
        }, {
            .tag = HKS_TAG_IS_KEY_ALIAS,
            .uint32Param = false
        }
    };

    int32_t res = ConstructParamSet(paramSet, keyParam, CAL_ARRAY_SIZE(keyParam));
    if (res != HAL_SUCCESS) {
        LOGE("Construct param set failed, res = %d", res);
        return res;
    }
    return res;
}

static int32_t GenerateKeyPair(Algorithm algo, Uint8Buff *outPriKey, Uint8Buff *outPubKey)
{
    CHECK_PTR_RETURN_HAL_ERROR_CODE(outPriKey, "outPriKey");
    CHECK_PTR_RETURN_HAL_ERROR_CODE(outPriKey->val, "outPriKey->key");
    CHECK_LEN_ZERO_RETURN_ERROR_CODE(outPriKey->length, "outPriKey->keyLen");
    CHECK_PTR_RETURN_HAL_ERROR_CODE(outPubKey, "outPubKey");
    CHECK_PTR_RETURN_HAL_ERROR_CODE(outPubKey->val, "outPubKey->key");
    CHECK_LEN_ZERO_RETURN_ERROR_CODE(outPubKey->length, "outPubKey->keyLen");

    if (outPriKey->length != outPubKey->length) {
        LOGE("key len not equal.");
        return HAL_ERR_INVALID_LEN;
    }
    uint32_t keyLen = outPriKey->length;

    struct HksParamSet *paramSet = NULL;
    struct HksParamSet *outParamSet = NULL;
    int32_t res = ConstructGenerateKeyPairParams(&paramSet, algo, keyLen);
    if (res != HAL_SUCCESS) {
        return res;
    }

    /* need 2 HksParam struct for outPriKey and outPubKey */
    uint32_t outParamSetSize = sizeof(struct HksParamSet) +
        2 * (sizeof(struct HksParam)) + outPriKey->length + outPubKey->length;
    outParamSet = (struct HksParamSet *)HcMalloc(outParamSetSize, 0);
    if (outParamSet == NULL) {
        LOGE("allocate buffer for output param set failed");
        res = HAL_ERR_BAD_ALLOC;
        goto ERR;
    }
    outParamSet->paramSetSize = outParamSetSize;

    LOGI("[HUKS]: HksGenerateKey enter.");
    res = HksGenerateKey(NULL, paramSet, outParamSet);
    LOGI("[HUKS]: HksGenerateKey quit. [Res]: %d", res);
    if (res != HKS_SUCCESS) {
        LOGI("[HUKS]: HksGenerateKey quit. [Res]: %d", res);
        res = HAL_FAILED;
        goto ERR;
    }

    res = GetKeyPair(outParamSet, outPriKey, outPubKey);
    if (res != HAL_SUCCESS) {
        LOGE("parse x25519 output param set failed, res:%d", res);
        goto ERR;
    }
ERR:
    FreeParamSet(paramSet);
    HcFree(outParamSet);
    return res;
}

static int32_t ConstructExportParams(bool isDeStorage, int32_t osAccountId, struct HksParamSet **paramSet)
{
    uint32_t len = GetParamLen(isDeStorage, 0);
    if (len == 0) {
        return HAL_SUCCESS;
    }
    struct HksParam *exportParams = (struct HksParam *)HcMalloc(sizeof(struct HksParam) * len, 0);
    if (exportParams == NULL) {
        LOGE("Malloc for exportParams failed.");
        return HAL_ERR_BAD_ALLOC;
    }
    uint32_t idx = 0;
    AddStorageExtParams(exportParams, isDeStorage, &idx, osAccountId);
    int32_t res = ConstructParamSet(paramSet, exportParams, idx);
    HcFree(exportParams);
    if (res != HAL_SUCCESS) {
        LOGE("Failed to construct export param set, res: %d", res);
    }
    return res;
}

static int32_t CheckExportParams(const KeyParams *keyParams, const Uint8Buff *outPubKey)
{
    int32_t res = CheckKeyParams(keyParams);
    if (res != HAL_SUCCESS) {
        return res;
    }
    CHECK_PTR_RETURN_HAL_ERROR_CODE(outPubKey, "outPubKey");
    CHECK_PTR_RETURN_HAL_ERROR_CODE(outPubKey->val, "outPubKey->val");
    CHECK_LEN_ZERO_RETURN_ERROR_CODE(outPubKey->length, "outPubKey->length");
    return HAL_SUCCESS;
}

static int32_t ExportPublicKey(const KeyParams *keyParams, Uint8Buff *outPubKey)
{
    int32_t res = CheckExportParams(keyParams, outPubKey);
    if (res != HAL_SUCCESS) {
        return res;
    }

    struct HksParamSet *deParamSet = NULL;
    res = ConstructExportParams(true, keyParams->osAccountId, &deParamSet);
    if (res != HAL_SUCCESS) {
        return res;
    }
    struct HksParamSet *ceParamSet = NULL;
    res = ConstructExportParams(false, keyParams->osAccountId, &ceParamSet);
    if (res != HAL_SUCCESS) {
        FreeParamSet(deParamSet);
        return res;
    }
    struct HksBlob keyAliasBlob = { keyParams->keyBuff.keyLen, keyParams->keyBuff.key };
    struct HksBlob keyBlob = { outPubKey->length, outPubKey->val };

    LOGI("[HUKS]: HksExportPublicKey enter.");
    if (keyParams->isDeStorage) {
        res = HksExportPublicKey(&keyAliasBlob, deParamSet, &keyBlob);
        if (res == HKS_SUCCESS) {
            MoveDeKeyToCe(true, keyParams->osAccountId, &keyAliasBlob);
        } else {
            res = HksExportPublicKey(&keyAliasBlob, ceParamSet, &keyBlob);
        }
    } else {
        res = HksExportPublicKey(&keyAliasBlob, ceParamSet, &keyBlob);
        if (res != HKS_SUCCESS) {
            res = HksExportPublicKey(&keyAliasBlob, deParamSet, &keyBlob);
        }
    }
    LOGI("[HUKS]: HksExportPublicKey quit. [Res]: %d", res);
    FreeParamSet(deParamSet);
    FreeParamSet(ceParamSet);
    if (res != HKS_SUCCESS) {
        LOGE("[HUKS]: HksExportPublicKey failed. [Res]: %d", res);
        return HAL_FAILED;
    }
    outPubKey->length = keyBlob.size;
    return HAL_SUCCESS;
}

static int32_t ConstructSignParams(bool isDeStorage, int32_t osAccountId, struct HksParamSet **paramSet,
    Algorithm algo)
{
    uint32_t len = GetParamLen(isDeStorage, BASE_SIGN_PARAMS_LEN);
    struct HksParam *signParams = (struct HksParam *)HcMalloc(sizeof(struct HksParam) * len, 0);
    if (signParams == NULL) {
        LOGE("Malloc for signParams failed.");
        return HAL_ERR_BAD_ALLOC;
    }
    uint32_t idx = 0;
    signParams[idx].tag = HKS_TAG_PURPOSE;
    signParams[idx++].uint32Param = HKS_KEY_PURPOSE_SIGN;
    signParams[idx].tag = HKS_TAG_ALGORITHM;
    signParams[idx++].uint32Param = g_algToHksAlgorithm[algo]; // only support HKS_ALG_ED25519 and HKS_ALG_ECC.
    signParams[idx].tag = HKS_TAG_DIGEST;
    signParams[idx++].uint32Param = HKS_DIGEST_SHA256;
    AddStorageExtParams(signParams, isDeStorage, &idx, osAccountId);
    int32_t res = ConstructParamSet(paramSet, signParams, idx);
    HcFree(signParams);
    if (res != HAL_SUCCESS) {
        LOGE("Construct sign param set failed, res = %d", res);
    }
    return res;
}

static int32_t CheckSignParams(const KeyParams *keyParams, const Uint8Buff *message,
    const Uint8Buff *outSignature)
{
    int32_t res = CheckKeyParams(keyParams);
    if (res != HAL_SUCCESS) {
        return res;
    }
    const Uint8Buff *inParams[] = { message, outSignature };
    const char *paramTags[] = { "message", "outSignature" };
    return BaseCheckParams(inParams, paramTags, CAL_ARRAY_SIZE(inParams));
}

static int32_t Sign(const KeyParams *keyParams, const Uint8Buff *message, Algorithm algo,
    Uint8Buff *outSignature)
{
    int32_t res = CheckSignParams(keyParams, message, outSignature);
    if (res != HAL_SUCCESS) {
        return res;
    }

    uint8_t messageHashVal[SHA256_LEN] = { 0 };
    Uint8Buff messageHash = { messageHashVal, SHA256_LEN };
    res = Sha256(message, &messageHash);
    if (res != HAL_SUCCESS) {
        LOGE("Sha256 failed.");
        return res;
    }
    struct HksParamSet *deParamSet = NULL;
    res = ConstructSignParams(true, keyParams->osAccountId, &deParamSet, algo);
    if (res != HAL_SUCCESS) {
        return res;
    }
    struct HksParamSet *ceParamSet = NULL;
    res = ConstructSignParams(false, keyParams->osAccountId, &ceParamSet, algo);
    if (res != HAL_SUCCESS) {
        FreeParamSet(deParamSet);
        return res;
    }
    struct HksBlob keyAliasBlob = { keyParams->keyBuff.keyLen, keyParams->keyBuff.key };
    struct HksBlob messageBlob = { messageHash.length, messageHash.val };
    struct HksBlob signatureBlob = { outSignature->length, outSignature->val };

    LOGI("[HUKS]: HksSign enter.");
    if (keyParams->isDeStorage) {
        res = HksSign(&keyAliasBlob, deParamSet, &messageBlob, &signatureBlob);
        if (res == HKS_SUCCESS) {
            MoveDeKeyToCe(keyParams->keyBuff.isAlias, keyParams->osAccountId, &keyAliasBlob);
        } else {
            res = HksSign(&keyAliasBlob, ceParamSet, &messageBlob, &signatureBlob);
        }
    } else {
        res = HksSign(&keyAliasBlob, ceParamSet, &messageBlob, &signatureBlob);
        if (res != HKS_SUCCESS) {
            res = HksSign(&keyAliasBlob, deParamSet, &messageBlob, &signatureBlob);
        }
    }
    LOGI("[HUKS]: HksSign quit. [Res]: %d", res);
    FreeParamSet(deParamSet);
    FreeParamSet(ceParamSet);
    if (res != HKS_SUCCESS) {
        LOGE("[HUKS]: HksSign fail. [Res]: %d", res);
        return HAL_FAILED;
    }
    outSignature->length = signatureBlob.size;
    return HAL_SUCCESS;
}

static int32_t ConstructVerifyParams(struct HksParamSet **paramSet, const KeyParams *keyParams, Algorithm algo)
{
    uint32_t len = GetParamLen(keyParams->isDeStorage, BASE_VERIFY_PARAMS_LEN);
    struct HksParam *verifyParams = (struct HksParam *)HcMalloc(sizeof(struct HksParam) * len, 0);
    if (verifyParams == NULL) {
        LOGE("Malloc for verifyParams failed.");
        return HAL_ERR_BAD_ALLOC;
    }
    uint32_t idx = 0;
    verifyParams[idx].tag = HKS_TAG_PURPOSE;
    verifyParams[idx++].uint32Param = HKS_KEY_PURPOSE_VERIFY;
    verifyParams[idx].tag = HKS_TAG_ALGORITHM;
    verifyParams[idx++].uint32Param = g_algToHksAlgorithm[algo]; // only support HKS_ALG_ED25519 and HKS_ALG_ECC.
    verifyParams[idx].tag = HKS_TAG_IS_KEY_ALIAS;
    verifyParams[idx++].boolParam = keyParams->keyBuff.isAlias;
    verifyParams[idx].tag = HKS_TAG_DIGEST;
    verifyParams[idx++].uint32Param = HKS_DIGEST_SHA256;
    AddStorageExtParams(verifyParams, keyParams->isDeStorage, &idx, keyParams->osAccountId);
    int32_t res = ConstructParamSet(paramSet, verifyParams, idx);
    HcFree(verifyParams);
    if (res != HAL_SUCCESS) {
        LOGE("Construct verify param set failed, res = %d", res);
    }
    return res;
}

static int32_t CheckVerifyParams(const KeyParams *keyParams, const Uint8Buff *message,
    const Uint8Buff *signature)
{
    int32_t res = CheckKeyParams(keyParams);
    if (res != HAL_SUCCESS) {
        return res;
    }
    const Uint8Buff *inParams[] = { message, signature };
    const char *paramTags[] = { "message", "signature" };
    return BaseCheckParams(inParams, paramTags, CAL_ARRAY_SIZE(inParams));
}

static int32_t Verify(const KeyParams *keyParams, const Uint8Buff *message, Algorithm algo,
    const Uint8Buff *signature)
{
    int32_t res = CheckVerifyParams(keyParams, message, signature);
    if (res != HAL_SUCCESS) {
        return res;
    }

    uint8_t messageHashVal[SHA256_LEN] = { 0 };
    Uint8Buff messageHash = { messageHashVal, SHA256_LEN };
    res = Sha256(message, &messageHash);
    if (res != HAL_SUCCESS) {
        LOGE("Sha256 failed.");
        return res;
    }

    struct HksParamSet *paramSet = NULL;
    res = ConstructVerifyParams(&paramSet, keyParams, algo);
    if (res != HAL_SUCCESS) {
        return res;
    }
    struct HksBlob keyAliasBlob = { keyParams->keyBuff.keyLen, keyParams->keyBuff.key };
    struct HksBlob messageBlob = { messageHash.length, messageHash.val };
    struct HksBlob signatureBlob = { signature->length, signature->val };

    LOGI("[HUKS]: HksVerify enter.");
    res = HksVerify(&keyAliasBlob, paramSet, &messageBlob, &signatureBlob);
    FreeParamSet(paramSet);
    LOGI("[HUKS]: HksVerify quit. [Res]: %d", res);
    if ((res != HKS_SUCCESS)) {
        LOGE("[HUKS]: HksVerify fail. [Res]: %d", res);
        return HAL_FAILED;
    }
    return HAL_SUCCESS;
}

static int32_t ConstructImportPublicKeyParams(struct HksParamSet **paramSet, Algorithm algo, uint32_t keyLen,
    const KeyParams *authIdParams, const union KeyRoleInfoUnion *roleInfoUnion)
{
    if (g_algToHksAlgorithm[algo] == HKS_ALG_ECC) {
        keyLen = ECC_PK_LEN;
    }
    struct HksBlob authIdBlob = { authIdParams->keyBuff.keyLen, authIdParams->keyBuff.key };
    uint32_t len = GetParamLen(authIdParams->isDeStorage, BASE_IMPORT_PUB_KEY_PARAMS_LEN);
    struct HksParam *importParams = (struct HksParam *)HcMalloc(sizeof(struct HksParam) * len, 0);
    if (importParams == NULL) {
        LOGE("Malloc for importParams failed.");
        return HAL_ERR_BAD_ALLOC;
    }
    uint32_t idx = 0;
    importParams[idx].tag = HKS_TAG_ALGORITHM;
    importParams[idx++].uint32Param = g_algToHksAlgorithm[algo];
    importParams[idx].tag = HKS_TAG_KEY_SIZE;
    importParams[idx++].uint32Param = keyLen * BITS_PER_BYTE;
    importParams[idx].tag = HKS_TAG_PADDING;
    importParams[idx++].uint32Param = HKS_PADDING_NONE;
    importParams[idx].tag = HKS_TAG_KEY_AUTH_ID;
    importParams[idx++].blob = authIdBlob;
    importParams[idx].tag = HKS_TAG_IS_ALLOWED_WRAP;
    importParams[idx++].boolParam = true;
    importParams[idx].tag = HKS_TAG_PURPOSE;
    importParams[idx++].uint32Param = HKS_KEY_PURPOSE_VERIFY;
    importParams[idx].tag = HKS_TAG_KEY_ROLE;
    importParams[idx++].uint32Param = roleInfoUnion->roleInfo;
    importParams[idx].tag = HKS_TAG_DIGEST;
    importParams[idx++].uint32Param = HKS_DIGEST_SHA256;
    AddStorageExtParams(importParams, authIdParams->isDeStorage, &idx, authIdParams->osAccountId);
    int32_t res = ConstructParamSet(paramSet, importParams, idx);
    HcFree(importParams);
    if (res != HAL_SUCCESS) {
        LOGE("Construct import param set failed, res = %d", res);
    }
    return res;
}

static int32_t CheckImportPubKeyParams(const KeyParams *keyParams, const Uint8Buff *pubKey,
    const ExtraInfo *exInfo)
{
    int32_t res = CheckKeyParams(keyParams);
    if (res != HAL_SUCCESS) {
        return res;
    }
    CHECK_PTR_RETURN_HAL_ERROR_CODE(pubKey, "pubKey");
    CHECK_PTR_RETURN_HAL_ERROR_CODE(pubKey->val, "pubKey->val");
    CHECK_LEN_ZERO_RETURN_ERROR_CODE(pubKey->length, "pubKey->length");
    CHECK_PTR_RETURN_HAL_ERROR_CODE(exInfo, "exInfo");
    CHECK_PTR_RETURN_HAL_ERROR_CODE(exInfo->authId.val, "authId->val");
    CHECK_LEN_ZERO_RETURN_ERROR_CODE(exInfo->authId.length, "authId->length");
    CHECK_LEN_HIGHER_RETURN(exInfo->pairType, PAIR_TYPE_END - 1, "pairType");
    return HAL_SUCCESS;
}

static int32_t ImportPublicKey(const KeyParams *keyParams, const Uint8Buff *pubKey, Algorithm algo,
    const ExtraInfo *exInfo)
{
    int32_t res = CheckImportPubKeyParams(keyParams, pubKey, exInfo);
    if (res != HAL_SUCCESS) {
        return res;
    }

    union KeyRoleInfoUnion roleInfoUnion;
    roleInfoUnion.roleInfoStruct.userType = (uint8_t)exInfo->userType;
    roleInfoUnion.roleInfoStruct.pairType = (uint8_t)exInfo->pairType;
    roleInfoUnion.roleInfoStruct.reserved1 = (uint8_t)0;
    roleInfoUnion.roleInfoStruct.reserved2 = (uint8_t)0;

    KeyParams authIdParams = {
        .keyBuff = { exInfo->authId.val, exInfo->authId.length, true },
        .isDeStorage = keyParams->isDeStorage,
        .osAccountId = keyParams->osAccountId
    };
    struct HksParamSet *paramSet = NULL;
    res = ConstructImportPublicKeyParams(&paramSet, algo, pubKey->length, &authIdParams, &roleInfoUnion);
    if (res != HAL_SUCCESS) {
        return res;
    }
    struct HksBlob keyAliasBlob = { keyParams->keyBuff.keyLen, keyParams->keyBuff.key };
    struct HksBlob pubKeyBlob = { pubKey->length, pubKey->val };

    LOGI("[HUKS]: HksImportKey enter.");
    res = HksImportKey(&keyAliasBlob, paramSet, &pubKeyBlob);
    FreeParamSet(paramSet);
    LOGI("[HUKS]: HksImportKey quit. [Res]: %d", res);
    if (res != HKS_SUCCESS) {
        LOGE("[HUKS]: HksImportKey fail. [Res]: %d", res);
        return HAL_FAILED;
    }
    return HAL_SUCCESS;
}

static bool CheckBigNumCompareParams(const Uint8Buff *a, const Uint8Buff *b, int *res)
{
    if ((a == NULL || a->val == NULL) && (b == NULL || b->val == NULL)) {
        *res = 0; // a = b
        return false;
    }
    if ((a == NULL || a->val == NULL) && (b != NULL && b->val != NULL)) {
        *res = 1; // a < b
        return false;
    }
    if ((a != NULL && a->val != NULL) && (b == NULL || b->val == NULL)) {
        *res = -1; // a > b
        return false;
    }
    return true;
}

static int32_t BigNumCompare(const Uint8Buff *a, const Uint8Buff *b)
{
    int res = 0;
    if (!CheckBigNumCompareParams(a, b, &res)) {
        return res;
    }
    const uint8_t *tmpA = a->val;
    const uint8_t *tmpB = b->val;
    uint32_t len = a->length;
    if (a->length < b->length) {
        for (uint32_t i = 0; i < b->length - a->length; i++) {
            if (b->val[i] > 0) {
                return 1; // a < b
            }
        }
        tmpA = a->val;
        tmpB = b->val + b->length - a->length;
        len = a->length;
    }
    if (a->length > b->length) {
        for (uint32_t i = 0; i < a->length - b->length; i++) {
            if (a->val[i] > 0) {
                return -1; // a > b
            }
        }
        tmpA = a->val + a->length - b->length;
        tmpB = b->val;
        len = b->length;
    }
    for (uint32_t i = 0; i < len; i++) {
        if (*(tmpA + i) > *(tmpB + i)) {
            return -1; // a > b
        }
        if (*(tmpA + i) < *(tmpB + i)) {
            return 1; // a < b
        }
    }
    return 0; // a == b
}

static bool CheckDlPublicKey(const Uint8Buff *key, const char *primeHex)
{
    if (key == NULL || key->val == NULL || primeHex == NULL) {
        LOGE("Params is null.");
        return false;
    }
    uint8_t min = 1;

    uint32_t innerKeyLen = HcStrlen(primeHex) / BYTE_TO_HEX_OPER_LENGTH;
    if (key->length > innerKeyLen) {
        LOGE("Key length > prime number length.");
        return false;
    }
    uint8_t *primeByte = (uint8_t *)HcMalloc(innerKeyLen, 0);
    if (primeByte == NULL) {
        LOGE("Malloc for primeByte failed.");
        return false;
    }
    if (HexStringToByte(primeHex, primeByte, innerKeyLen) != HAL_SUCCESS) {
        LOGE("Convert prime number from hex string to byte failed.");
        HcFree(primeByte);
        return false;
    }
    /*
     * P - 1, since the last byte of large prime number must be greater than 1,
     * needn't to think about borrowing forward
     */
    primeByte[innerKeyLen - 1] -= 1;

    Uint8Buff minBuff = { &min, sizeof(uint8_t) };
    if (BigNumCompare(key, &minBuff) >= 0) {
        LOGE("Pubkey is invalid, key <= 1.");
        HcFree(primeByte);
        return false;
    }

    Uint8Buff primeBuff = { primeByte, innerKeyLen };
    if (BigNumCompare(key, &primeBuff) <= 0) {
        LOGE("Pubkey is invalid, key >= p - 1.");
        HcFree(primeByte);
        return false;
    }

    HcFree(primeByte);
    return true;
}

static bool CheckEcPublicKey(const Uint8Buff *pubKey, Algorithm algo)
{
    (void)pubKey;
    (void)algo;
    return true;
}

static int32_t InitImportParam(const KeyParams *keyParams, const ExtraInfo *exInfo, struct HksParam **importParam)
{
    if (exInfo != NULL) {
        CHECK_PTR_RETURN_HAL_ERROR_CODE(exInfo->authId.val, "authId");
        CHECK_LEN_ZERO_RETURN_ERROR_CODE(exInfo->authId.length, "authId");
        CHECK_LEN_HIGHER_RETURN(exInfo->pairType, PAIR_TYPE_END - 1, "pairType");
    }
    uint32_t baseLen = ((exInfo == NULL) ? BASE_IMPORT_PARAMS_LEN : (BASE_IMPORT_PARAMS_LEN + EXT_IMPORT_PARAMS_LEN));
    uint32_t len = GetParamLen(keyParams->isDeStorage, baseLen);
    *importParam = (struct HksParam *)HcMalloc(sizeof(struct HksParam) * len, 0);
    if (*importParam == NULL) {
        LOGE("Malloc for importParam failed.");
        return HAL_ERR_BAD_ALLOC;
    }
    return HAL_SUCCESS;
}

static int32_t ConstructImportSymmetricKeyParam(struct HksParamSet **paramSet, const KeyParams *keyParams,
    uint32_t keyLen, KeyPurpose purpose, const ExtraInfo *exInfo)
{
    struct HksParam *importParam = NULL;
    int32_t res = InitImportParam(keyParams, exInfo, &importParam);
    if (res != HAL_SUCCESS) {
        return res;
    }
    uint32_t idx = 0;
    if (exInfo != NULL) {
        struct HksBlob authIdBlob = { 0, NULL };
        union KeyRoleInfoUnion roleInfoUnion;
        (void)memset_s(&roleInfoUnion, sizeof(roleInfoUnion), 0, sizeof(roleInfoUnion));
        authIdBlob.size = exInfo->authId.length;
        authIdBlob.data = exInfo->authId.val;
        roleInfoUnion.roleInfoStruct.userType = (uint8_t)exInfo->userType;
        roleInfoUnion.roleInfoStruct.pairType = (uint8_t)exInfo->pairType;
        importParam[idx].tag = HKS_TAG_KEY_AUTH_ID;
        importParam[idx++].blob = authIdBlob;
        importParam[idx].tag = HKS_TAG_KEY_ROLE;
        importParam[idx++].uint32Param = roleInfoUnion.roleInfo;
    }

    importParam[idx].tag = HKS_TAG_ALGORITHM;
    importParam[idx++].uint32Param = HKS_ALG_AES;
    importParam[idx].tag = HKS_TAG_KEY_SIZE;
    importParam[idx++].uint32Param = keyLen * BITS_PER_BYTE;
    importParam[idx].tag = HKS_TAG_PADDING;
    importParam[idx++].uint32Param = HKS_PADDING_NONE;
    importParam[idx].tag = HKS_TAG_IS_ALLOWED_WRAP;
    importParam[idx++].boolParam = false;
    importParam[idx].tag = HKS_TAG_PURPOSE;
    importParam[idx++].uint32Param = g_purposeToHksKeyPurpose[purpose];
    importParam[idx].tag = HKS_TAG_BLOCK_MODE;
    importParam[idx++].uint32Param = HKS_MODE_GCM;
    importParam[idx].tag = HKS_TAG_DIGEST;
    importParam[idx++].uint32Param = HKS_DIGEST_SHA256;
    AddStorageExtParams(importParam, keyParams->isDeStorage, &idx, keyParams->osAccountId);
    res = ConstructParamSet(paramSet, importParam, idx);
    HcFree(importParam);
    return res;
}

static int32_t CheckImportSymmetricKeyParams(const KeyParams *keyParams, const Uint8Buff *authToken)
{
    int32_t res = CheckKeyParams(keyParams);
    if (res != HAL_SUCCESS) {
        return res;
    }
    const Uint8Buff *inParams[] = { authToken };
    const char *paramTags[] = { "authToken" };
    return BaseCheckParams(inParams, paramTags, CAL_ARRAY_SIZE(inParams));
}

static int32_t ImportSymmetricKey(const KeyParams *keyParams, const Uint8Buff *authToken, KeyPurpose purpose,
    const ExtraInfo *exInfo)
{
    int32_t res = CheckImportSymmetricKeyParams(keyParams, authToken);
    if (res != HAL_SUCCESS) {
        return res;
    }

    struct HksParamSet *paramSet = NULL;
    res = ConstructImportSymmetricKeyParam(&paramSet, keyParams, authToken->length, purpose, exInfo);
    if (res != HAL_SUCCESS) {
        LOGE("construct param set failed, res = %d", res);
        return res;
    }
    struct HksBlob keyAliasBlob = { keyParams->keyBuff.keyLen, keyParams->keyBuff.key };
    struct HksBlob symKeyBlob = { authToken->length, authToken->val };

    LOGI("[HUKS]: HksImportKey enter.");
    res = HksImportKey(&keyAliasBlob, paramSet, &symKeyBlob);
    FreeParamSet(paramSet);
    LOGI("[HUKS]: HksImportKey quit. [Res]: %d", res);
    if (res != HKS_SUCCESS) {
        LOGE("[HUKS]: HksImportKey fail. [Res]: %d", res);
        return HAL_FAILED;
    }
    return HAL_SUCCESS;
}

static const AlgLoader g_huksLoader = {
    .initAlg = InitHks,
    .sha256 = Sha256,
    .generateRandom = GenerateRandom,
    .computeHmac = ComputeHmac,
    .computeHmacWithThreeStage = ComputeHmacWithThreeStage,
    .computeHkdf = ComputeHkdf,
    .computePseudonymPsk = ComputePseudonymPsk,
    .getKeyExtInfo = GetKeyExtInfo,
    .importSymmetricKey = ImportSymmetricKey,
    .checkKeyExist = CheckKeyExist,
    .deleteKey = DeleteKey,
    .aesGcmEncrypt = AesGcmEncrypt,
    .aesGcmDecrypt = AesGcmDecrypt,
    .hashToPoint = HashToPoint,
    .agreeSharedSecretWithStorage = AgreeSharedSecretWithStorage,
    .agreeSharedSecret = AgreeSharedSecret,
    .bigNumExpMod = BigNumExpMod,
    .generateKeyPairWithStorage = GenerateKeyPairWithStorage,
    .generateKeyPair = GenerateKeyPair,
    .exportPublicKey = ExportPublicKey,
    .sign = Sign,
    .verify = Verify,
    .importPublicKey = ImportPublicKey,
    .checkDlPublicKey = CheckDlPublicKey,
    .checkEcPublicKey = CheckEcPublicKey,
    .bigNumCompare = BigNumCompare,
    .base64Encode = MbedtlsBase64Encode,
    .base64Decode = MbedtlsBase64Decode
};

const AlgLoader *GetRealLoaderInstance(void)
{
    return &g_huksLoader;
}
