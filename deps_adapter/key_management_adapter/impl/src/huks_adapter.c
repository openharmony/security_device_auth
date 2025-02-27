/*
 * Copyright (C) 2021-2025 Huawei Device Co., Ltd.
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
#include "huks_adapter_utils.h"

#include "huks_adapter_diff_impl.h"
#include "hc_log.h"
#include "mbedtls_ec_adapter.h"
#include "string_util.h"

#define ECDH_COMMON_SIZE_P256 512

static enum HksKeyAlg g_algToHksAlgorithm[] = {
    HKS_ALG_ED25519,
    HKS_ALG_X25519,
    HKS_ALG_ECC,
    HKS_ALG_AES,
};

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
        return HAL_ERR_HUKS;
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

    if (res == HKS_ERROR_NOT_EXIST) {
        LOGE("[HUKS]: Key not exist. [Res]: %d", res);
        return HAL_ERR_KEY_NOT_EXIST;
    }
    if (res != HKS_SUCCESS) {
        LOGE("[HUKS]: HksKeyExist fail. [Res]: %d", res);
        return HAL_ERR_HUKS;
    }

    return HAL_SUCCESS;
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
        return HAL_ERR_HUKS;
    }
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

static void DoAbortHks(struct HksBlob *handleDerive, struct HksParamSet *deriveParamSet)
{
    int32_t res = HksAbort(handleDerive, deriveParamSet);
    if (res != HKS_SUCCESS) {
        LOGE("Failed to abort huks, res:%d", res);
    }
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
    uint8_t tmpOut[2048] = { 0 };
    struct HksBlob outData = { 2048, tmpOut };
    struct HksBlob inData = { 0, NULL };
    struct HksBlob hmacBlob = { outHmac->length, outHmac->val };
    do {
        res = HksInit(&keyAliasBlob, deriveParamSet, &handleDerive, NULL);
        if (res != HKS_SUCCESS) {
            LOGE("Failed to init derive params!");
            res = HAL_FAILED;
            break;
        }
        res = HksUpdate(&handleDerive, deriveParamSet, &inData, &outData);
        if (res != HKS_SUCCESS) {
            LOGE("Failed to update derive params!");
            DoAbortHks(&handleDerive, deriveParamSet);
            res = HAL_FAILED;
            break;
        }
        res = HksFinish(&handleDerive, finishParamSet, &inData, &hmacBlob);
        if (res != HKS_SUCCESS || hmacBlob.size != HMAC_LEN) {
            LOGE("Compute hmac with three stage failed! [Res]: %d, [size]: %d", res, hmacBlob.size);
            DoAbortHks(&handleDerive, finishParamSet);
            res = HAL_FAILED;
            break;
        }
    } while (0);
    FreeParamSet(deriveParamSet);
    FreeParamSet(finishParamSet);
    return res;
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
            DoAbortHks(&handleBlob, initParamSet);
            res = HAL_ERR_HUKS;
            break;
        }
        LOGI("[HUKS]: HksFinish enter.");
        res = HksFinish(&handleBlob, finishParamSet, &pubKeyBlob, &outDataFinishBlob);
        LOGI("[HUKS]: HksFinish quit. [Res]: %d", res);
        if (res != HKS_SUCCESS) {
            LOGE("[HUKS]: HksFinish fail. [Res]: %d", res);
            DoAbortHks(&handleBlob, finishParamSet);
            res = HAL_ERR_HUKS;
            break;
        }
    } while (0);
    FreeParamSet(initParamSet);
    FreeParamSet(finishParamSet);
    return res;
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
        return HAL_ERR_HUKS;
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
        return HAL_ERR_HUKS;
    }
    outPubKey->length = keyBlob.size;
    return HAL_SUCCESS;
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
        return HAL_ERR_HUKS;
    }
    return HAL_SUCCESS;
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
    if (algo == P256) {
        LOGI("Start check P256 public key");
        return MbedtlsIsP256PublicKeyValid(pubKey);
    } else if (algo == X25519) {
        LOGI("Start check X25519 public key");
        return MbedtlsIsX25519PublicKeyValid(pubKey);
    }
    LOGE("Algorithm not support!");
    return false;
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
