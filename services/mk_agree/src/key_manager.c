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

#include "key_manager.h"

#include "alg_defs.h"
#include "alg_loader.h"
#include "common_defs.h"
#include "device_auth_defines.h"
#include "hc_dev_info.h"
#include "hc_log.h"
#include "hc_types.h"
#include "json_utils.h"
#include "pseudonym_manager.h"
#include "uint8buff_utils.h"

#define PAKE_X25519_KEY_PAIR_LEN 32
#define MK_LEN 32
#define MK_DERIVE_INFO "dev_auth_mk_derivation"
#define PAKE_KEY_ALIAS_LEN 64
#define MK_ALIAS_PREFIX "MK_"
#define PSEUDONYM_PSK_ALIAS_PREFIX "PSEUDONYM_"

static int32_t ConvertHashToAlias(const Uint8Buff *keyAliasHash, Uint8Buff *outKeyAlias)
{
    uint32_t keyAliasHexLen = keyAliasHash->length * BYTE_TO_HEX_OPER_LENGTH + 1;
    char *keyAliasHex = (char *)HcMalloc(keyAliasHexLen, 0);
    if (keyAliasHex == NULL) {
        LOGE("Failed to alloc key alias hex memory!");
        return HC_ERR_ALLOC_MEMORY;
    }
    int32_t res = ByteToHexString(keyAliasHash->val, keyAliasHash->length, keyAliasHex, keyAliasHexLen);
    if (res != HC_SUCCESS) {
        LOGE("Failed to convert key alias hash to hex!");
        HcFree(keyAliasHex);
        return res;
    }
    if (memcpy_s(outKeyAlias->val, outKeyAlias->length, keyAliasHex, HcStrlen(keyAliasHex)) != EOK) {
        LOGE("Failed to copy key alias hex!");
        HcFree(keyAliasHex);
        return HC_ERR_MEMORY_COPY;
    }
    HcFree(keyAliasHex);
    return HC_SUCCESS;
}

static int32_t ConvertHashToAliasWithPrefix(const char *prefix, const Uint8Buff *keyAliasHash, Uint8Buff *keyAlias)
{
    uint32_t keyAliasHexLen = keyAliasHash->length * BYTE_TO_HEX_OPER_LENGTH + 1;
    char *keyAliasHex = (char *)HcMalloc(keyAliasHexLen, 0);
    if (keyAliasHex == NULL) {
        LOGE("Failed to alloc key alias hex memory!");
        return HC_ERR_ALLOC_MEMORY;
    }
    int32_t res = ByteToHexString(keyAliasHash->val, keyAliasHash->length, keyAliasHex, keyAliasHexLen);
    if (res != HC_SUCCESS) {
        LOGE("Failed to convert key alias hash to hex!");
        HcFree(keyAliasHex);
        return res;
    }
    uint32_t prefixLen = HcStrlen(prefix);
    if (memcpy_s(keyAlias->val, keyAlias->length, prefix, prefixLen) != EOK) {
        LOGE("Failed to copy key alias prefix!");
        HcFree(keyAliasHex);
        return HC_ERR_MEMORY_COPY;
    }
    // The remaining key alias len is less than keyAliasHexLen len after substract prefixLen,
    // so copy the remaining len other than keyAliasHexLen in order that the key alias len is 64.
    if (memcpy_s(keyAlias->val + prefixLen, keyAlias->length - prefixLen, keyAliasHex,
        keyAlias->length - prefixLen) != EOK) {
        LOGE("Failed to copy key alias hex!");
        HcFree(keyAliasHex);
        return HC_ERR_MEMORY_COPY;
    }
    HcFree(keyAliasHex);
    return HC_SUCCESS;
}

static int32_t GenerateDevKeyAlias(Uint8Buff *outKeyAlias)
{
    if (outKeyAlias == NULL) {
        LOGE("Input key alias is null!");
        return HC_ERR_INVALID_PARAMS;
    }
    char selfUdid[INPUT_UDID_LEN] = { 0 };
    int32_t res = HcGetUdid((uint8_t *)selfUdid, INPUT_UDID_LEN);
    if (res != HC_SUCCESS) {
        LOGE("Failed to get local udid!");
        return res;
    }
    uint8_t hashValue[SHA256_LEN] = { 0 };
    Uint8Buff keyAliasHash = { hashValue, SHA256_LEN };
    Uint8Buff msgBuff = { (uint8_t *)selfUdid, HcStrlen(selfUdid) };
    res = GetLoaderInstance()->sha256(&msgBuff, &keyAliasHash);
    if (res != HC_SUCCESS) {
        LOGE("Failed to generate key alias hash!");
        return res;
    }
    res = ConvertHashToAlias(&keyAliasHash, outKeyAlias);
    if (res != HC_SUCCESS) {
        LOGE("Failed to convert hash to alias!");
    }
    return res;
}

static int32_t GenerateMkAlias(const char *peerDeviceId, Uint8Buff *keyAlias)
{
    Uint8Buff peerDevIdBuff = { (uint8_t *)peerDeviceId, HcStrlen(peerDeviceId) };
    uint8_t hashValue[SHA256_LEN] = { 0 };
    Uint8Buff keyAliasHash = { hashValue, SHA256_LEN };
    int32_t res = GetLoaderInstance()->sha256(&peerDevIdBuff, &keyAliasHash);
    if (res != HC_SUCCESS) {
        LOGE("Failed to generate key alias hash!");
        return res;
    }
    res = ConvertHashToAliasWithPrefix(MK_ALIAS_PREFIX, &keyAliasHash, keyAlias);
    if (res != HC_SUCCESS) {
        LOGE("Failed to convert hash to alias!");
    }
    return res;
}

static int32_t GeneratePseudonymPskAlias(const char *peerDeviceId, Uint8Buff *keyAlias)
{
    uint8_t hashValue[SHA256_LEN] = { 0 };
    Uint8Buff keyAliasHash = { hashValue, SHA256_LEN };
    Uint8Buff peerDevIdBuff = { (uint8_t *)peerDeviceId, HcStrlen(peerDeviceId) };
    int32_t res = GetLoaderInstance()->sha256(&peerDevIdBuff, &keyAliasHash);
    if (res != HC_SUCCESS) {
        LOGE("Failed to generate key alias hash!");
        return res;
    }

    res = ConvertHashToAliasWithPrefix(PSEUDONYM_PSK_ALIAS_PREFIX, &keyAliasHash, keyAlias);
    if (res != HC_SUCCESS) {
        LOGE("Failed to convert hash to alias!");
    }
    return res;
}

static int32_t KeyDerivation(const Uint8Buff *baseAlias, const Uint8Buff *salt, bool isAlias,
    Uint8Buff *returnKey)
{
    Uint8Buff keyInfo = { (uint8_t *)MK_DERIVE_INFO, HcStrlen(MK_DERIVE_INFO) };
    int32_t res = GetLoaderInstance()->computeHkdf(baseAlias, salt, &keyInfo, returnKey, isAlias);
    if (res != HC_SUCCESS) {
        LOGE("Failed to compute hkdf!");
    }
    return res;
}

int32_t GenerateDeviceKeyPair(void)
{
    uint8_t keyAlias[PAKE_KEY_ALIAS_LEN] = { 0 };
    Uint8Buff keyAliasBuff = { keyAlias, PAKE_KEY_ALIAS_LEN };
    int32_t res = GenerateDevKeyAlias(&keyAliasBuff);
    if (res != HC_SUCCESS) {
        LOGE("Failed to generate device key alias!");
        return res;
    }
    if (GetLoaderInstance()->checkKeyExist(&keyAliasBuff) == HC_SUCCESS) {
        LOGI("Device Key pair already exists!");
        return HC_SUCCESS;
    }

    char selfUdid[INPUT_UDID_LEN] = { 0 };
    res = HcGetUdid((uint8_t *)selfUdid, INPUT_UDID_LEN);
    if (res != HC_SUCCESS) {
        LOGE("Failed to get local udid!");
        return res;
    }
    Uint8Buff authIdBuff = { (uint8_t *)selfUdid, HcStrlen(selfUdid) };
    ExtraInfo exInfo = { authIdBuff, -1, -1 };
    res = GetLoaderInstance()->generateKeyPairWithStorage(&keyAliasBuff, PAKE_X25519_KEY_PAIR_LEN, X25519,
        KEY_PURPOSE_SIGN_VERIFY, &exInfo);
    if (res != HC_SUCCESS) {
        LOGE("Failed to generate device key pair!");
        return res;
    }
    LOGI("Generate device key pair successfully!");
    return HC_SUCCESS;
}

int32_t GenerateMk(const char *peerDeviceId, const Uint8Buff *peerPubKey)
{
    if (peerDeviceId == NULL || peerPubKey == NULL) {
        LOGE("Invalid input params!");
        return HC_ERR_INVALID_PARAMS;
    }
    uint8_t mkAlias[PAKE_KEY_ALIAS_LEN] = { 0 };
    Uint8Buff mkAliasBuff = { mkAlias, PAKE_KEY_ALIAS_LEN };
    int32_t res = GenerateMkAlias(peerDeviceId, &mkAliasBuff);
    if (res != HC_SUCCESS) {
        LOGE("Failed to generate mk alias!");
        return res;
    }
    uint8_t devKeyAlias[PAKE_KEY_ALIAS_LEN] = { 0 };
    Uint8Buff devKeyAliasBuff = { devKeyAlias, PAKE_KEY_ALIAS_LEN };
    res = GenerateDevKeyAlias(&devKeyAliasBuff);
    if (res != HC_SUCCESS) {
        LOGE("Failed to generate device key alias!");
        return res;
    }
    KeyBuff selfKeyAliasBuff = { devKeyAliasBuff.val, devKeyAliasBuff.length, true };
    KeyBuff peerPubKeyBuff = { peerPubKey->val, peerPubKey->length, false };
    res = GetLoaderInstance()->agreeSharedSecretWithStorage(&selfKeyAliasBuff, &peerPubKeyBuff, X25519,
        MK_LEN, &mkAliasBuff);
    if (res != HC_SUCCESS) {
        LOGE("Failed to agree sharedSecret!");
        return res;
    }
    LOGI("Generate mk successfully!");
    return HC_SUCCESS;
}

int32_t DeleteMk(const char *peerDeviceId)
{
    if (peerDeviceId == NULL) {
        LOGE("Invalid input param!");
        return HC_ERR_INVALID_PARAMS;
    }
    uint8_t mkAlias[PAKE_KEY_ALIAS_LEN] = { 0 };
    Uint8Buff mkAliasBuff = { mkAlias, PAKE_KEY_ALIAS_LEN };
    int32_t res = GenerateMkAlias(peerDeviceId, &mkAliasBuff);
    if (res != HC_SUCCESS) {
        LOGE("Failed to generate mk alias!");
        return res;
    }
    if (GetLoaderInstance()->checkKeyExist(&mkAliasBuff) != HC_SUCCESS) {
        LOGI("mk does not exist, no need to delete!");
        return HC_SUCCESS;
    }
    res = GetLoaderInstance()->deleteKey(&mkAliasBuff);
    if (res != HC_SUCCESS) {
        LOGE("Failed to delete mk!");
        return res;
    }
    LOGI("Delete mk successfully!");
    return HC_SUCCESS;
}

int32_t GeneratePseudonymPsk(const char *peerDeviceId, const Uint8Buff *salt)
{
    if (peerDeviceId == NULL || salt == NULL) {
        LOGE("Invalid input params!");
        return HC_ERR_INVALID_PARAMS;
    }
    uint8_t pseudonymPskAlias[PAKE_KEY_ALIAS_LEN] = { 0 };
    Uint8Buff pskAliasBuff = { pseudonymPskAlias, PAKE_KEY_ALIAS_LEN };
    int32_t res = GeneratePseudonymPskAlias(peerDeviceId, &pskAliasBuff);
    if (res != HC_SUCCESS) {
        LOGE("Failed to generate pseudonym psk alias!");
        return res;
    }
    uint8_t mkAlias[PAKE_KEY_ALIAS_LEN] = { 0 };
    Uint8Buff mkAliasBuff = { mkAlias, PAKE_KEY_ALIAS_LEN };
    res = GenerateMkAlias(peerDeviceId, &mkAliasBuff);
    if (res != HC_SUCCESS) {
        LOGE("Failed to generate mk alias!");
        return res;
    }
    Uint8Buff pskBuff = { NULL, 0 };
    if (InitUint8Buff(&pskBuff, MK_LEN) != HC_SUCCESS) {
        LOGE("Failed to init pseudonym psk!");
        return HC_ERR_ALLOC_MEMORY;
    }
    res = KeyDerivation(&mkAliasBuff, salt, true, &pskBuff);
    if (res != HC_SUCCESS) {
        LOGE("Failed to derive pseudonym psk!");
        FreeUint8Buff(&pskBuff);
        return res;
    }
    res = GetLoaderInstance()->importSymmetricKey(&pskAliasBuff, &pskBuff, KEY_PURPOSE_MAC, NULL);
    ClearFreeUint8Buff(&pskBuff);
    if (res != HC_SUCCESS) {
        LOGE("Failed to import pseudonym psk!");
        return res;
    }
    LOGI("Generate and save pseudonym psk successfully!");
    return HC_SUCCESS;
}

int32_t DeletePseudonymPsk(const char *peerDeviceId)
{
    if (peerDeviceId == NULL) {
        LOGE("Invalid input param!");
        return HC_ERR_INVALID_PARAMS;
    }
    uint8_t pseudonymPskAlias[PAKE_KEY_ALIAS_LEN] = { 0 };
    Uint8Buff pskAliasBuff = { pseudonymPskAlias, PAKE_KEY_ALIAS_LEN };
    int32_t res = GeneratePseudonymPskAlias(peerDeviceId, &pskAliasBuff);
    if (res != HC_SUCCESS) {
        LOGE("Failed to generate psk alias!");
        return res;
    }
    if (GetLoaderInstance()->checkKeyExist(&pskAliasBuff) != HC_SUCCESS) {
        LOGI("Pseudonym psk does not exist, no need to delete!");
        return HC_SUCCESS;
    }
    res = GetLoaderInstance()->deleteKey(&pskAliasBuff);
    if (res != HC_SUCCESS) {
        LOGE("Failed to delete pseudonym psk!");
        return res;
    }
    LOGI("Delete pseudonym psk successfully!");
    return HC_SUCCESS;
}

int32_t GenerateAndSavePseudonymId(int32_t osAccountId, const char *peerDeviceId, const PseudonymKeyInfo *info,
    const Uint8Buff *saltBuff, Uint8Buff *returnHmac)
{
    if (peerDeviceId == NULL || info == NULL || saltBuff == NULL || returnHmac == NULL) {
        LOGE("Invalid input params!");
        return HC_ERR_INVALID_PARAMS;
    }
    uint8_t pskAliasVal[PAKE_KEY_ALIAS_LEN] = { 0 };
    Uint8Buff pskAliasBuff = { pskAliasVal, PAKE_KEY_ALIAS_LEN };
    int32_t res = GeneratePseudonymPskAlias(peerDeviceId, &pskAliasBuff);
    if (res != HC_SUCCESS) {
        LOGE("Failed to generate pseudonym psk alias!");
        return res;
    }
    uint8_t pseudonymIdVal[MK_LEN] = { 0 };
    Uint8Buff pseudonymIdBuff = { pseudonymIdVal, MK_LEN };
    res = GetLoaderInstance()->computeHmac(&pskAliasBuff, saltBuff, &pseudonymIdBuff, true);
    if (res != HC_SUCCESS) {
        LOGE("Failed to compute hmac!");
        return res;
    }
    if (DeepCopyUint8Buff(&pseudonymIdBuff, returnHmac) != HC_SUCCESS) {
        LOGE("Failed to copy hmac!");
        return HC_ERR_ALLOC_MEMORY;
    }
    uint32_t pdidLen = pseudonymIdBuff.length * BYTE_TO_HEX_OPER_LENGTH + 1;
    char *pdid = (char *)HcMalloc(pdidLen, 0);
    if (pdid == NULL) {
        LOGE("Failed to alloc memory for pdid!");
        ClearFreeUint8Buff(returnHmac);
        return HC_ERR_ALLOC_MEMORY;
    }
    res = ByteToHexString(pseudonymIdBuff.val, pseudonymIdBuff.length, pdid, pdidLen);
    if (res != HC_SUCCESS) {
        LOGE("Failed to convert pdid from byte to hex string!");
        ClearFreeUint8Buff(returnHmac);
        HcFree(pdid);
        return res;
    }
    res = GetPseudonymInstance()->savePseudonymId(osAccountId, pdid, info->peerInfo, peerDeviceId, info->pdidIndex);
    HcFree(pdid);
    if (res != HC_SUCCESS) {
        LOGE("Failed to save pdid!");
        ClearFreeUint8Buff(returnHmac);
        return res;
    }
    LOGI("Generate and save pdid successfully!");
    return HC_SUCCESS;
}

int32_t GetDevicePubKey(Uint8Buff *devicePk)
{
    if (devicePk == NULL) {
        LOGE("Invalid input param!");
        return HC_ERR_INVALID_PARAMS;
    }
    uint8_t keyAlias[PAKE_KEY_ALIAS_LEN] = { 0 };
    Uint8Buff keyAliasBuff = { keyAlias, PAKE_KEY_ALIAS_LEN };
    int32_t res = GenerateDevKeyAlias(&keyAliasBuff);
    if (res != HC_SUCCESS) {
        LOGE("Failed to generate device key alias!");
        return res;
    }
    res = GetLoaderInstance()->exportPublicKey(&keyAliasBuff, devicePk);
    if (res != HC_SUCCESS) {
        LOGE("Failed to export device pk!");
    }
    return res;
}