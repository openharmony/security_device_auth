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

#include "huks_adapter.h"
#include "hal_error.h"
#include "hc_file.h"
#include "hc_log.h"
#include "hc_types.h"
#include "hc_dev_info.h"
#include "hks_api.h"
#include "hks_param.h"
#include "hks_type.h"
#include "string_util.h"

#define BASE_IMPORT_PARAMS_LEN 7
#define EXT_IMPORT_PARAMS_LEN 2

static enum HksKeyPurpose g_purposeToHksKeyPurpose[] = {
    HKS_KEY_PURPOSE_MAC,
    HKS_KEY_PURPOSE_DERIVE
};

static int32_t BaseCheckParams(const Uint8Buff **inParams, const char **paramTags, uint32_t len)
{
    for (uint32_t i = 0; i < len; i++) {
        CHECK_PTR_RETURN_HAL_ERROR_CODE(inParams[i], paramTags[i]);
        CHECK_PTR_RETURN_HAL_ERROR_CODE(inParams[i]->val, paramTags[i]);
        CHECK_LEN_ZERO_RETURN_ERROR_CODE(inParams[i]->length, paramTags[i]);
    }
    return HAL_SUCCESS;
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
        HksFreeParamSet(&paramSet);
        return HAL_ERR_ADD_PARAM_FAILED;
    }

    res = HksBuildParamSet(&paramSet);
    if (res != HKS_SUCCESS) {
        LOGE("build param set failed, res = %d", res);
        HksFreeParamSet(&paramSet);
        return HAL_ERR_BUILD_PARAM_SET_FAILED;
    }

    *out = paramSet;
    return HAL_SUCCESS;
}

static int32_t InitHks(void)
{
    LOGI("[HUKS]: HksInitialize enter.");
    int32_t res = HksInitialize();
    LOGI("[HUKS]: HksInitialize quit. [Res]: %d", res);
    if (res == HKS_SUCCESS) {
        return HAL_SUCCESS;
    }

    if ((res != HKS_ERROR_INVALID_KEY_FILE) && (res != HKS_ERROR_CRYPTO_ENGINE_ERROR) &&
        (res != HKS_ERROR_UPDATE_ROOT_KEY_MATERIAL_FAIL)) {
        LOGE("[HUKS]: HksInitialize fail. [Res]: %d", res);
        return HAL_ERR_INIT_FAILED;
    }

    LOGI("Start to delete local database file!");
    HcFileRemove(GetStoragePath());
    LOGI("Delete local database file successfully!");
    LOGI("[HUKS]: HksRefreshKeyInfo enter.");
    res = HksRefreshKeyInfo();
    LOGI("[HUKS]: HksRefreshKeyInfo quit. [Res]: %d", res);
    if (res != HKS_SUCCESS) {
        LOGE("[HUKS]: HksRefreshKeyInfo failed, res: %d", res);
        return HAL_ERR_INIT_FAILED;
    }
    LOGI("[HUKS]: HksInitialize enter.");
    res = HksInitialize();
    LOGI("[HUKS]: HksInitialize quit. [Res]: %d", res);
    if (res != HKS_SUCCESS) {
        LOGE("[HUKS]: HksInitialize fail. [Res]: %d", res);
        return HAL_ERR_INIT_FAILED;
    }

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
        HksFreeParamSet(&paramSet);
        return HAL_FAILED;
    }

    HksFreeParamSet(&paramSet);
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

static int32_t CheckKeyExist(const Uint8Buff *keyAlias)
{
    CHECK_PTR_RETURN_HAL_ERROR_CODE(keyAlias, "keyAlias");
    CHECK_PTR_RETURN_HAL_ERROR_CODE(keyAlias->val, "keyAlias->val");
    CHECK_LEN_ZERO_RETURN_ERROR_CODE(keyAlias->length, "keyAlias->length");

    struct HksBlob keyAliasBlob = { keyAlias->length, keyAlias->val };
    int32_t res = HksKeyExist(&keyAliasBlob, NULL);
    if (res != HKS_SUCCESS) {
        LOGI("[HUKS]: HksKeyExist fail. [Res]: %d", res);
        return HAL_FAILED;
    }

    return HAL_SUCCESS;
}

static int32_t DeleteKey(const Uint8Buff *keyAlias)
{
    CHECK_PTR_RETURN_HAL_ERROR_CODE(keyAlias, "keyAlias");
    CHECK_PTR_RETURN_HAL_ERROR_CODE(keyAlias->val, "keyAlias->val");
    CHECK_LEN_ZERO_RETURN_ERROR_CODE(keyAlias->length, "keyAlias->length");

    struct HksBlob keyAliasBlob = { keyAlias->length, keyAlias->val };
    LOGI("[HUKS]: HksDeleteKey enter.");
    int32_t res = HksDeleteKey(&keyAliasBlob, NULL);
    LOGI("[HUKS]: HksDeleteKey quit. [Res]: %d", res);
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

static int32_t ComputeHmac(const Uint8Buff *key, const Uint8Buff *message, Uint8Buff *outHmac, bool isAlias)
{
    const Uint8Buff *inParams[] = { key, message, outHmac };
    const char *paramTags[] = {"key", "message", "outHmac"};
    int32_t res = BaseCheckParams(inParams, paramTags, CAL_ARRAY_SIZE(inParams));
    if (res != HAL_SUCCESS) {
        return res;
    }
    CHECK_LEN_EQUAL_RETURN(outHmac->length, HMAC_LEN, "outHmac->length");

    struct HksBlob keyBlob = { key->length, key->val };
    struct HksBlob srcBlob = { message->length, message->val };
    struct HksBlob hmacBlob = { outHmac->length, outHmac->val };
    struct HksParamSet *paramSet = NULL;
    struct HksParam hmacParam[] = {
        {
            .tag = HKS_TAG_PURPOSE,
            .uint32Param = HKS_KEY_PURPOSE_MAC
        }, {
            .tag = HKS_TAG_DIGEST,
            .uint32Param = HKS_DIGEST_SHA256
        }, {
            .tag = HKS_TAG_IS_KEY_ALIAS,
            .boolParam = isAlias
        }
    };
    res = ConstructParamSet(&paramSet, hmacParam, CAL_ARRAY_SIZE(hmacParam));
    if (res != HAL_SUCCESS) {
        LOGE("construct param set failed, res = %d", res);
        return res;
    }

    LOGI("[HUKS]: HksMac enter.");
    res = HksMac(&keyBlob, paramSet, &srcBlob, &hmacBlob);
    LOGI("[HUKS]: HksMac quit. [Res]: %d", res);
    if (res != HKS_SUCCESS  || hmacBlob.size != HMAC_LEN) {
        LOGE("[HUKS]: HksMac fail. [Res]: %d", res);
        HksFreeParamSet(&paramSet);
        return HAL_FAILED;
    }

    HksFreeParamSet(&paramSet);
    return HAL_SUCCESS;
}

static int32_t ComputeHkdf(const Uint8Buff *baseKey, const Uint8Buff *salt, const Uint8Buff *keyInfo,
    Uint8Buff *outHkdf, bool isAlias)
{
    const Uint8Buff *inParams[] = { baseKey, salt, outHkdf };
    const char *paramTags[] = { "baseKey", "salt", "outHkdf" };
    int32_t res = BaseCheckParams(inParams, paramTags, CAL_ARRAY_SIZE(inParams));
    if (res != HAL_SUCCESS) {
        return res;
    }

    struct HksBlob srcKeyBlob = { baseKey->length, baseKey->val };
    struct HksBlob saltBlob = { salt->length, salt->val };
    struct HksBlob keyInfoBlob = { 0, NULL };
    if (keyInfo != NULL) {
        keyInfoBlob.size = keyInfo->length;
        keyInfoBlob.data = keyInfo->val;
    }
    struct HksBlob derivedKeyBlob = { outHkdf->length, outHkdf->val };

    struct HksParamSet *paramSet = NULL;
    struct HksParam hkdfParam[] = {
        { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_DERIVE },
        { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_HKDF },
        { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_SHA256 },
        { .tag = HKS_TAG_SALT, .blob = saltBlob },
        { .tag = HKS_TAG_INFO, .blob = keyInfoBlob },
        { .tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = isAlias }
    };

    res = ConstructParamSet(&paramSet, hkdfParam, CAL_ARRAY_SIZE(hkdfParam));
    if (res != HAL_SUCCESS) {
        return res;
    }

    LOGI("[HUKS]: HksDeriveKey enter.");
    res = HksDeriveKey(paramSet, &srcKeyBlob, &derivedKeyBlob);
    LOGI("[HUKS]: HksDeriveKey quit. [Res]: %d", res);
    if (res != HKS_SUCCESS) {
        LOGE("[HUKS]: HksDeriveKey fail. [Res]: %d", res);
        HksFreeParamSet(&paramSet);
        return HAL_FAILED;
    }

    HksFreeParamSet(&paramSet);
    return HAL_SUCCESS;
}

static int32_t CheckAesGcmEncryptParam(const Uint8Buff *key, const Uint8Buff *plain, const GcmParam *encryptInfo,
    Uint8Buff *outCipher)
{
    const Uint8Buff *inParams[] = { key, plain, outCipher };
    const char* paramTags[] = { "key", "plain", "outCipher" };
    int32_t res = BaseCheckParams(inParams, paramTags, CAL_ARRAY_SIZE(inParams));
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

static int32_t AesGcmEncrypt(const Uint8Buff *key, const Uint8Buff *plain,
    const GcmParam *encryptInfo, bool isAlias, Uint8Buff *outCipher)
{
    int32_t res = CheckAesGcmEncryptParam(key, plain, encryptInfo, outCipher);
    if (res != HAL_SUCCESS) {
        return res;
    }

    struct HksBlob keyBlob = { key->length, key->val };
    struct HksBlob plainBlob = { plain->length, plain->val };
    struct HksBlob cipherBlob = { outCipher->length, outCipher->val };

    struct HksParamSet *paramSet = NULL;
    struct HksParam encryptParam[] = {
        {
            .tag = HKS_TAG_PURPOSE,
            .uint32Param = HKS_KEY_PURPOSE_ENCRYPT
        }, {
            .tag = HKS_TAG_ALGORITHM,
            .uint32Param = HKS_ALG_AES
        }, {
            .tag = HKS_TAG_BLOCK_MODE,
            .uint32Param = HKS_MODE_GCM
        }, {
            .tag = HKS_TAG_PADDING,
            .uint32Param = HKS_PADDING_NONE
        }, {
            .tag = HKS_TAG_NONCE,
            .blob = { encryptInfo->nonceLen, encryptInfo->nonce }
        }, {
            .tag = HKS_TAG_ASSOCIATED_DATA,
            .blob = { encryptInfo->aadLen, encryptInfo->aad }
        }, {
            .tag = HKS_TAG_IS_KEY_ALIAS,
            .boolParam = isAlias
        }
    };

    res = ConstructParamSet(&paramSet, encryptParam, CAL_ARRAY_SIZE(encryptParam));
    if (res != HAL_SUCCESS) {
        LOGE("construct param set failed, res = %d", res);
        return res;
    }

    LOGI("[HUKS]: HksEncrypt enter.");
    res = HksEncrypt(&keyBlob, paramSet, &plainBlob, &cipherBlob);
    LOGI("[HUKS]: HksEncrypt quit. [Res]: %d", res);
    if (res != HKS_SUCCESS) {
        LOGE("[HUKS]: HksEncrypt fail. [Res]: %d", res);
        HksFreeParamSet(&paramSet);
        return HAL_FAILED;
    }

    HksFreeParamSet(&paramSet);
    return HAL_SUCCESS;
}

static int32_t CheckAesGcmDecryptParam(const Uint8Buff *key, const Uint8Buff *cipher, const GcmParam *decryptInfo,
    Uint8Buff *outPlain)
{
    const Uint8Buff *inParams[] = { key, cipher, outPlain };
    const char *paramTags[] = { "key", "cipher", "outPlain" };
    int32_t res = BaseCheckParams(inParams, paramTags, CAL_ARRAY_SIZE(inParams));
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

static int32_t AesGcmDecrypt(const Uint8Buff *key, const Uint8Buff *cipher,
    const GcmParam *decryptInfo, bool isAlias, Uint8Buff *outPlain)
{
    int32_t res = CheckAesGcmDecryptParam(key, cipher, decryptInfo, outPlain);
    if (res != HAL_SUCCESS) {
        return res;
    }

    struct HksBlob keyBlob = { key->length, key->val };
    struct HksBlob cipherBlob = { cipher->length, cipher->val };
    struct HksBlob plainBlob = { outPlain->length, outPlain->val };

    struct HksParamSet *paramSet = NULL;
    struct HksParam decryptParam[] = {
        {
            .tag = HKS_TAG_PURPOSE,
            .uint32Param = HKS_KEY_PURPOSE_DECRYPT
        }, {
            .tag = HKS_TAG_ALGORITHM,
            .uint32Param = HKS_ALG_AES
        }, {
            .tag = HKS_TAG_BLOCK_MODE,
            .uint32Param = HKS_MODE_GCM
        }, {
            .tag = HKS_TAG_PADDING,
            .uint32Param = HKS_PADDING_NONE
        }, {
            .tag = HKS_TAG_NONCE,
            .blob = { decryptInfo->nonceLen, decryptInfo->nonce }
        }, {
            .tag = HKS_TAG_ASSOCIATED_DATA,
            .blob = { decryptInfo->aadLen, decryptInfo->aad }
        }, {
            .tag = HKS_TAG_IS_KEY_ALIAS,
            .boolParam = isAlias
        }
    };

    res = ConstructParamSet(&paramSet, decryptParam, CAL_ARRAY_SIZE(decryptParam));
    if (res != HAL_SUCCESS) {
        LOGE("construct param set failed, res = %d", res);
        return res;
    }

    LOGI("[HUKS]: HksDecrypt enter.");
    res = HksDecrypt(&keyBlob, paramSet, &cipherBlob, &plainBlob);
    LOGI("[HUKS]: HksDecrypt quit. [Res]: %d", res);
    if (res != HKS_SUCCESS) {
        LOGE("[HUKS]: HksDecrypt fail. [Res]: %d", res);
        HksFreeParamSet(&paramSet);
        return HAL_FAILED;
    }

    HksFreeParamSet(&paramSet);
    return HAL_SUCCESS;
}

static int32_t CheckImportSymmetricKeyParam(const Uint8Buff *keyAlias, const Uint8Buff *authToken)
{
    const Uint8Buff *inParams[] = { keyAlias, authToken };
    const char *paramTags[] = { "keyAlias", "authToken" };
    return BaseCheckParams(inParams, paramTags, CAL_ARRAY_SIZE(inParams));
}

static int32_t ConstructImportSymmetricKeyParam(struct HksParamSet **paramSet, uint32_t keyLen, KeyPurpose purpose,
    const ExtraInfo *exInfo)
{
    struct HksParam *importParam = NULL;
    struct HksBlob authIdBlob = { 0, NULL };
    union KeyRoleInfoUnion roleInfoUnion;
    (void)memset_s(&roleInfoUnion, sizeof(roleInfoUnion), 0, sizeof(roleInfoUnion));
    uint32_t idx = 0;
    if (exInfo != NULL) {
        CHECK_PTR_RETURN_HAL_ERROR_CODE(exInfo->authId.val, "authId");
        CHECK_LEN_ZERO_RETURN_ERROR_CODE(exInfo->authId.length, "authId");
        CHECK_LEN_HIGHER_RETURN(exInfo->pairType, PAIR_TYPE_END - 1, "pairType");
        importParam = (struct HksParam *)HcMalloc(sizeof(struct HksParam) *
            (BASE_IMPORT_PARAMS_LEN + EXT_IMPORT_PARAMS_LEN), 0);
        if (importParam == NULL) {
            LOGE("Malloc for importParam failed.");
            return HAL_ERR_BAD_ALLOC;
        }
        authIdBlob.size = exInfo->authId.length;
        authIdBlob.data = exInfo->authId.val;
        roleInfoUnion.roleInfoStruct.userType = (uint8_t)exInfo->userType;
        roleInfoUnion.roleInfoStruct.pairType = (uint8_t)exInfo->pairType;
        importParam[idx].tag = HKS_TAG_KEY_AUTH_ID;
        importParam[idx++].blob = authIdBlob;
        importParam[idx].tag = HKS_TAG_KEY_ROLE;
        importParam[idx++].uint32Param = roleInfoUnion.roleInfo;
    } else {
        importParam = (struct HksParam *)HcMalloc(sizeof(struct HksParam) * BASE_IMPORT_PARAMS_LEN, 0);
        if (importParam == NULL) {
            LOGE("Malloc for importParam failed.");
            return HAL_ERR_BAD_ALLOC;
        }
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
    int res = ConstructParamSet(paramSet, importParam, idx);
    if (res != HAL_SUCCESS) {
        LOGE("Construct decrypt param set failed, res = %d.", res);
    }
    HcFree(importParam);
    return res;
}

static int32_t ImportSymmetricKey(const Uint8Buff *keyAlias, const Uint8Buff *authToken, KeyPurpose purpose,
    const ExtraInfo *exInfo)
{
    int32_t res = CheckImportSymmetricKeyParam(keyAlias, authToken);
    if (res != HAL_SUCCESS) {
        return res;
    }

    struct HksBlob keyAliasBlob = { keyAlias->length, keyAlias->val };
    struct HksBlob symKeyBlob = { authToken->length, authToken->val };
    struct HksParamSet *paramSet = NULL;
    res = ConstructImportSymmetricKeyParam(&paramSet, authToken->length, purpose, exInfo);
    if (res != HAL_SUCCESS) {
        LOGE("construct param set failed, res = %d", res);
        return res;
    }

    LOGI("[HUKS]: HksImportKey enter.");
    res = HksImportKey(&keyAliasBlob, paramSet, &symKeyBlob);
    LOGI("[HUKS]: HksImportKey quit. [Res]: %d", res);
    if (res != HKS_SUCCESS) {
        LOGE("[HUKS]: HksImportKey fail. [Res]: %d", res);
        HksFreeParamSet(&paramSet);
        return res;
    }

    HksFreeParamSet(&paramSet);
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
    uint32_t primeLen = strlen(bigNumHex) / BYTE_TO_HEX_OPER_LENGTH;
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

    LOGI("[HUKS]: HksBnExpMod enter.");
    res = HksBnExpMod(&outNumBlob, &baseBlob, &expBlob, &bigNumBlob);
    LOGI("[HUKS]: HksBnExpMod quit. [Res]: %d", res);
    if (res != HKS_SUCCESS) {
        LOGE("[HUKS]: HksBnExpMod fail. [Res]: %d", res);
        HcFree(bigNumBlob.data);
        return HAL_FAILED;
    }
    outNum->length = outNumBlob.size;

    HcFree(bigNumBlob.data);
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

static int32_t HashToPoint(const Uint8Buff *hash, Algorithm algo, Uint8Buff *outEcPoint)
{
    (void)hash;
    (void)algo;
    (void)outEcPoint;
    return HAL_ERR_NOT_SUPPORTED;
}

static int32_t AgreeSharedSecretWithStorage(const KeyBuff *priKey, const KeyBuff *pubKey, Algorithm algo,
    uint32_t sharedKeyLen, const Uint8Buff *sharedKeyAlias)
{
    (void)priKey;
    (void)pubKey;
    (void)algo;
    (void)sharedKeyLen;
    (void)sharedKeyAlias;
    return HAL_ERR_NOT_SUPPORTED;
}

static int32_t AgreeSharedSecret(const KeyBuff *priKey, const KeyBuff *pubKey, Algorithm algo, Uint8Buff *sharedKey)
{
    (void)priKey;
    (void)pubKey;
    (void)algo;
    (void)sharedKey;
    return HAL_ERR_NOT_SUPPORTED;
}

static int32_t GenerateKeyPairWithStorage(const Uint8Buff *keyAlias, uint32_t keyLen, Algorithm algo,
    KeyPurpose purpose, const ExtraInfo *exInfo)
{
    (void)keyAlias;
    (void)keyLen;
    (void)algo;
    (void)purpose;
    (void)exInfo;
    return HAL_ERR_NOT_SUPPORTED;
}

static int32_t GenerateKeyPair(Algorithm algo, Uint8Buff *outPriKey, Uint8Buff *outPubKey)
{
    (void)algo;
    (void)outPriKey;
    (void)outPubKey;
    return HAL_ERR_NOT_SUPPORTED;
}

static int32_t ExportPublicKey(const Uint8Buff *keyAlias, Uint8Buff *outPubKey)
{
    (void)keyAlias;
    (void)outPubKey;
    return HAL_ERR_NOT_SUPPORTED;
}

static int32_t Sign(const Uint8Buff *keyAlias, const Uint8Buff *message, Algorithm algo,
    Uint8Buff *outSignature, bool isAlias)
{
    (void)keyAlias;
    (void)message;
    (void)algo;
    (void)outSignature;
    (void)isAlias;
    return HAL_ERR_NOT_SUPPORTED;
}

static int32_t Verify(const Uint8Buff *key, const Uint8Buff *message, Algorithm algo,
    const Uint8Buff *signature, bool isAlias)
{
    (void)key;
    (void)message;
    (void)algo;
    (void)signature;
    (void)isAlias;
    return HAL_ERR_NOT_SUPPORTED;
}

static int32_t ImportPublicKey(const Uint8Buff *keyAlias, const Uint8Buff *pubKey, Algorithm algo,
    const ExtraInfo *exInfo)
{
    (void)keyAlias;
    (void)pubKey;
    (void)algo;
    (void)exInfo;
    return HAL_ERR_NOT_SUPPORTED;
}

static bool CheckEcPublicKey(const Uint8Buff *pubKey, Algorithm algo)
{
    (void)pubKey;
    (void)algo;
    return true;
}

static const AlgLoader g_huksLoader = {
    .initAlg = InitHks,
    .sha256 = Sha256,
    .generateRandom = GenerateRandom,
    .computeHmac = ComputeHmac,
    .computeHkdf = ComputeHkdf,
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
    .bigNumCompare = BigNumCompare
};

const AlgLoader *GetRealLoaderInstance()
{
    return &g_huksLoader;
}