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

#include "das_standard_token_manager.h"
#include "alg_loader.h"
#include "das_task_common.h"
#include "hc_log.h"

static int32_t RegisterLocalIdentity(const char *pkgName, const char *serviceType, Uint8Buff *authId, int userType)
{
    const AlgLoader *loader = GetLoaderInstance();
    Uint8Buff pkgNameBuff = { (uint8_t *)pkgName, strlen(pkgName)};
    Uint8Buff serviceTypeBuff = { (uint8_t *)serviceType, strlen(serviceType) };
    KeyAliasType keyType = (KeyAliasType)userType;
    uint8_t keyAliasVal[PAKE_KEY_ALIAS_LEN] = { 0 };
    Uint8Buff keyAliasBuff = { keyAliasVal, PAKE_KEY_ALIAS_LEN };
    int32_t res = GenerateKeyAlias(&pkgNameBuff, &serviceTypeBuff, keyType, authId, &keyAliasBuff);
    if (res != HC_SUCCESS) {
        LOGE("Failed to generate identity keyPair alias!");
        return res;
    }

    res = loader->checkKeyExist(&keyAliasBuff);
    if (res == HC_SUCCESS) {
        LOGD("Key pair is exist.");
        return HC_SUCCESS;
    }

    ExtraInfo exInfo = { *authId, -1, -1 }; /* UserType and pairType are not required when generating key. */
    res = loader->generateKeyPairWithStorage(&keyAliasBuff, PAKE_ED25519_KEY_PAIR_LEN, ED25519,
        KEY_PURPOSE_SIGN_VERIFY, &exInfo);
    if (res != HC_SUCCESS) {
        LOGE("Failed to generate key pair!");
        return res;
    }
    LOGI("Key pair generated successfully!");
    return HC_SUCCESS;
}

static int32_t UnregisterLocalIdentity(const char *pkgName, const char *serviceType, Uint8Buff *authId, int userType)
{
    const AlgLoader *loader = GetLoaderInstance();
    Uint8Buff pkgNameBuff = { (uint8_t *)pkgName, strlen(pkgName)};
    Uint8Buff serviceTypeBuff = { (uint8_t *)serviceType, strlen(serviceType) };
    KeyAliasType keyType = (KeyAliasType)userType;
    uint8_t pakeKeyAliasVal[PAKE_KEY_ALIAS_LEN] = { 0 };
    Uint8Buff pakeKeyAliasBuff = { pakeKeyAliasVal, PAKE_KEY_ALIAS_LEN };
    int32_t res = GenerateKeyAlias(&pkgNameBuff, &serviceTypeBuff, keyType, authId, &pakeKeyAliasBuff);
    if (res != HC_SUCCESS) {
        LOGE("Failed to generate identity keyPair alias!");
        return res;
    }
    LOGI("KeyPair alias(HEX): %x%x%x%x****.", pakeKeyAliasVal[0], pakeKeyAliasVal[1],
        pakeKeyAliasVal[2], pakeKeyAliasVal[3]);
    res = loader->deleteKey(&pakeKeyAliasBuff);
    if (res != HC_SUCCESS) {
        LOGE("Failed to delete key pair!");
        return res;
    }
    LOGI("Key pair deleted successfully!");

    // try to delete upgrade keypair if exist.
    if (memcmp(pkgName, GROUP_MANAGER_PACKAGE_NAME, strlen(GROUP_MANAGER_PACKAGE_NAME)) == 0) {
        LOGI("Try to delete upgrade key pair.");
        res = GenerateKeyAlias(&pkgNameBuff, &serviceTypeBuff, KEY_ALIAS_LT_KEY_PAIR, authId, &pakeKeyAliasBuff);
        if (res != HC_SUCCESS) {
            LOGE("Failed to generate upgrade key pair alias!");
            return res;
        }
        res = ToLowerCase(&pakeKeyAliasBuff);
        if (res != HC_SUCCESS) {
            LOGE("Failed to convert self key alias to lower case!");
            return res;
        }
        LOGI("Upgrade key pair alias(HEX): %x%x%x%x****.", pakeKeyAliasVal[0], pakeKeyAliasVal[1],
            pakeKeyAliasVal[2], pakeKeyAliasVal[3]);
        res = loader->deleteKey(&pakeKeyAliasBuff);
        if (res != HC_SUCCESS) {
            LOGE("Failed to delete upgrade key pair!");
            return res;
        }
        LOGI("Upgrade key pair deleted successfully!");
    }

    return HC_SUCCESS;
}

static int32_t DeletePeerPubKey(const Uint8Buff *pkgNameBuff, const Uint8Buff *serviceTypeBuff, KeyAliasType keyType,
    const Uint8Buff *authIdPeer, Uint8Buff *pakeKeyAliasBuff)
{
    int32_t res = GenerateKeyAlias(pkgNameBuff, serviceTypeBuff, keyType, authIdPeer, pakeKeyAliasBuff);
    if (res != HC_SUCCESS) {
        LOGE("Failed to generate peer pub key alias!");
        return res;
    }
    LOGI("PubKey alias(HEX): %x%x%x%x****.", pakeKeyAliasBuff->val[DEV_AUTH_ZERO], pakeKeyAliasBuff->val[DEV_AUTH_ONE],
        pakeKeyAliasBuff->val[DEV_AUTH_TWO], pakeKeyAliasBuff->val[DEV_AUTH_THREE]);
    const AlgLoader *loader = GetLoaderInstance();
    res = loader->deleteKey(pakeKeyAliasBuff);
    if (res != HC_SUCCESS) {
        LOGE("Failed to delete peer public key!");
        return res;
    }
    LOGI("PubKey deleted successfully!");

    res = ToLowerCase(pakeKeyAliasBuff);
    if (res != HC_SUCCESS) {
        LOGE("Failed to convert peer key alias to lower case!");
        return res;
    }
    res = loader->deleteKey(pakeKeyAliasBuff);
    if (res != HC_SUCCESS) {
        LOGE("Failed to delete peer public key by lower case alias!");
    }
    return res;
}

static int32_t DeleteAuthPsk(const Uint8Buff *pkgNameBuff, const Uint8Buff *serviceTypeBuff,
    const Uint8Buff *authIdPeer, Uint8Buff *pakeKeyAliasBuff)
{
    int32_t res = GenerateKeyAlias(pkgNameBuff, serviceTypeBuff, KEY_ALIAS_PSK, authIdPeer, pakeKeyAliasBuff);
    if (res != HC_SUCCESS) {
        LOGE("Failed to generate psk alias!");
        return res;
    }
    LOGI("Psk alias(HEX): %x%x%x%x****.", pakeKeyAliasBuff->val[DEV_AUTH_ZERO], pakeKeyAliasBuff->val[DEV_AUTH_ONE],
        pakeKeyAliasBuff->val[DEV_AUTH_TWO], pakeKeyAliasBuff->val[DEV_AUTH_THREE]);
    const AlgLoader *loader = GetLoaderInstance();
    res = loader->deleteKey(pakeKeyAliasBuff);
    if (res != HC_SUCCESS) {
        LOGE("Failed to delete psk!");
        return res;
    }
    LOGI("Psk deleted successfully!");

    res = ToLowerCase(pakeKeyAliasBuff);
    if (res != HC_SUCCESS) {
        LOGE("Failed to convert psk alias to lower case!");
        return res;
    }
    res = loader->deleteKey(pakeKeyAliasBuff);
    if (res != HC_SUCCESS) {
        LOGE("Failed to delete psk by lower case alias!");
    }
    return res;
}

static int32_t DeletePeerAuthInfo(const char *pkgName, const char *serviceType, Uint8Buff *authIdPeer, int userTypePeer)
{
    const AlgLoader *loader = GetLoaderInstance();
    Uint8Buff pkgNameBuff = { (uint8_t *)pkgName, strlen(pkgName)};
    Uint8Buff serviceTypeBuff = { (uint8_t *)serviceType, strlen(serviceType) };
#ifdef DEV_AUTH_FUNC_TEST
    KeyAliasType keyType = KEY_ALIAS_LT_KEY_PAIR;
#else
    KeyAliasType keyType = (KeyAliasType)userTypePeer;
#endif
    uint8_t pakeKeyAliasVal[PAKE_KEY_ALIAS_LEN] = { 0 };
    Uint8Buff pakeKeyAliasBuff = { pakeKeyAliasVal, PAKE_KEY_ALIAS_LEN };
    int32_t res = DeletePeerPubKey(&pkgNameBuff, &serviceTypeBuff, keyType, authIdPeer, &pakeKeyAliasBuff);
    if (res != HC_SUCCESS) {
        return res;
    }

    res = DeleteAuthPsk(&pkgNameBuff, &serviceTypeBuff, authIdPeer, &pakeKeyAliasBuff);
    if (res != HC_SUCCESS) {
        return res;
    }

    // try to delete pseudonym psk if exist.
    res = GeneratePseudonymPskAlias(&serviceTypeBuff, authIdPeer, &pakeKeyAliasBuff);
    if (res != HC_SUCCESS) {
        LOGE("Failed to generate pseudonym psk alias!");
        return res;
    }
    res = ToLowerCase(&pakeKeyAliasBuff);
    if (res != HC_SUCCESS) {
        LOGE("Failed to convert pseudonym psk alias to lower case!");
        return res;
    }
    res = loader->deleteKey(&pakeKeyAliasBuff);
    if (res != HC_SUCCESS) {
        LOGE("Failed to delete pseudonym psk!");
        return res;
    }
    LOGI("Delete pseudonym psk successfully!");

    return HC_SUCCESS;
}

static int32_t GenerateSelfKeyAlias(const PakeParams *params, Uint8Buff *selfKeyAlias)
{
    KeyAliasType keyType = (KeyAliasType)params->userType;
    // if self data is from upgrade, key type should be key-pair.
    if (params->isSelfFromUpgrade) {
        keyType = KEY_ALIAS_LT_KEY_PAIR;
    }
    Uint8Buff packageName = { (uint8_t *)params->packageName, strlen(params->packageName) };
    Uint8Buff serviceType = { (uint8_t *)params->serviceType, strlen(params->serviceType) };
    int32_t res = GenerateKeyAlias(&packageName, &serviceType, keyType, &(params->baseParams.idSelf), selfKeyAlias);
    if (res != HC_SUCCESS) {
        LOGE("generate self key alias failed");
        return res;
    }
    if (params->isSelfFromUpgrade) {
        res = ToLowerCase(selfKeyAlias);
        if (res != HC_SUCCESS) {
            LOGE("Failed to convert self key alias to lower case!");
            return res;
        }
    }
    return HC_SUCCESS;
}

static int32_t GeneratePeerKeyAlias(const PakeParams *params, Uint8Buff *peerKeyAlias)
{
    Uint8Buff packageName = { (uint8_t *)params->packageName, strlen(params->packageName) };
    Uint8Buff serviceType = { (uint8_t *)params->serviceType, strlen(params->serviceType) };
#ifdef DEV_AUTH_FUNC_TEST
    KeyAliasType keyTypePeer = KEY_ALIAS_LT_KEY_PAIR;
#else
    KeyAliasType keyTypePeer = (KeyAliasType)params->userTypePeer;
#endif
    int32_t res = GenerateKeyAlias(&packageName, &serviceType, keyTypePeer, &(params->baseParams.idPeer), peerKeyAlias);
    if (res != HC_SUCCESS) {
        LOGE("generate peer key alias failed");
        return res;
    }
    if (params->isPeerFromUpgrade) {
        res = ToLowerCase(peerKeyAlias);
        if (res != HC_SUCCESS) {
            LOGE("Failed to convert peer key alias to lower case!");
            return res;
        }
    }
    return HC_SUCCESS;
}

static int32_t GenerateSharedKeyAlias(const PakeParams *params, Uint8Buff *sharedKeyAlias)
{
    Uint8Buff packageName = { (uint8_t *)params->packageName, strlen(params->packageName) };
    Uint8Buff serviceType = { (uint8_t *)params->serviceType, strlen(params->serviceType) };
    int32_t res = GenerateKeyAlias(&packageName, &serviceType, KEY_ALIAS_PSK, &(params->baseParams.idPeer),
        sharedKeyAlias);
    if (res != HC_SUCCESS) {
        LOGE("generate psk alias failed");
        return res;
    }
    if (params->isPeerFromUpgrade) {
        res = ToLowerCase(sharedKeyAlias);
        if (res != HC_SUCCESS) {
            LOGE("Failed to convert psk alias to lower case!");
            return res;
        }
    }
    return HC_SUCCESS;
}

static int32_t ComputeAndSavePsk(const PakeParams *params)
{
    uint8_t selfKeyAliasVal[PAKE_KEY_ALIAS_LEN] = { 0 };
    Uint8Buff selfKeyAlias = { selfKeyAliasVal, PAKE_KEY_ALIAS_LEN };
    uint8_t peerKeyAliasVal[PAKE_KEY_ALIAS_LEN] = { 0 };
    Uint8Buff peerKeyAlias = { peerKeyAliasVal, PAKE_KEY_ALIAS_LEN };
    int32_t res = GenerateSelfKeyAlias(params, &selfKeyAlias);
    if (res != HC_SUCCESS) {
        return res;
    }

    res = GeneratePeerKeyAlias(params, &peerKeyAlias);
    if (res != HC_SUCCESS) {
        return res;
    }

    res = params->baseParams.loader->checkKeyExist(&selfKeyAlias);
    if (res != HC_SUCCESS) {
        LOGE("self auth keyPair not exist");
        return res;
    }
    res = params->baseParams.loader->checkKeyExist(&peerKeyAlias);
    if (res != HC_SUCCESS) {
        LOGE("peer auth pubKey not exist");
        return res;
    }

    uint8_t sharedKeyAliasVal[PAKE_KEY_ALIAS_LEN] = { 0 };
    Uint8Buff sharedKeyAlias = { sharedKeyAliasVal, PAKE_KEY_ALIAS_LEN };
    res = GenerateSharedKeyAlias(params, &sharedKeyAlias);
    if (res != HC_SUCCESS) {
        return res;
    }

    LOGI("PubKey alias(HEX): %x%x%x%x****, priKey alias(HEX): %x%x%x%x****, psk alias(HEX): %x%x%x%x****.",
        peerKeyAliasVal[0], peerKeyAliasVal[1], peerKeyAliasVal[2], peerKeyAliasVal[3],
        selfKeyAliasVal[0], selfKeyAliasVal[1], selfKeyAliasVal[2], selfKeyAliasVal[3],
        sharedKeyAliasVal[0], sharedKeyAliasVal[1], sharedKeyAliasVal[2], sharedKeyAliasVal[3]);
    KeyBuff selfKeyAliasBuff = { selfKeyAlias.val, selfKeyAlias.length, true };
    KeyBuff peerKeyAliasBuff = { peerKeyAlias.val, peerKeyAlias.length, true };
    Algorithm alg = (params->baseParams.curveType == CURVE_256) ? P256 : ED25519;
    return params->baseParams.loader->agreeSharedSecretWithStorage(&selfKeyAliasBuff, &peerKeyAliasBuff, alg,
        PAKE_PSK_LEN, &sharedKeyAlias);
}

static int32_t GetPublicKey(const char *pkgName, const char *serviceType, Uint8Buff *authId, int userType,
                            Uint8Buff *returnPk)
{
    const AlgLoader *loader = GetLoaderInstance();
    Uint8Buff pkgNameBuff = { (uint8_t *)pkgName, strlen(pkgName) };
    Uint8Buff serviceTypeBuff = { (uint8_t *)serviceType, strlen(serviceType) };
    KeyAliasType keyType = (KeyAliasType)userType;
    uint8_t keyAliasVal[PAKE_KEY_ALIAS_LEN] = { 0 };
    Uint8Buff keyAliasBuff = { keyAliasVal, PAKE_KEY_ALIAS_LEN };
    int32_t res = GenerateKeyAlias(&pkgNameBuff, &serviceTypeBuff, keyType, authId, &keyAliasBuff);
    if (res != HC_SUCCESS) {
        LOGE("Failed to generate keyPair alias!");
        return res;
    }

    res = loader->checkKeyExist(&keyAliasBuff);
    if (res != HC_SUCCESS) {
        LOGE("Key pair is not exist!");
        res = ToLowerCase(&keyAliasBuff);
        if (res != HC_SUCCESS) {
            LOGE("Failed to convert key alias to lower case!");
            return res;
        }
        res = loader->checkKeyExist(&keyAliasBuff);
        if (res != HC_SUCCESS) {
            LOGE("Key not exist by lower case alias!");
            return res;
        }
    }

    res = loader->exportPublicKey(&keyAliasBuff, returnPk);
    if (res != HC_SUCCESS) {
        LOGE("Failed to export public key!");
        return res;
    }
    LOGI("Get public key successfully!");
    return HC_SUCCESS;
}

TokenManager g_asyTokenManagerInstance = {
    .registerLocalIdentity = RegisterLocalIdentity,
    .unregisterLocalIdentity = UnregisterLocalIdentity,
    .deletePeerAuthInfo = DeletePeerAuthInfo,
    .computeAndSavePsk = ComputeAndSavePsk,
    .getPublicKey = GetPublicKey,
};

const TokenManager *GetStandardTokenManagerInstance(void)
{
    return &g_asyTokenManagerInstance;
}