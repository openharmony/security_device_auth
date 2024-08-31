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

static int32_t RegisterLocalIdentityStd(const TokenManagerParams *params)
{
    Uint8Buff pkgNameBuff = { params->pkgName.val, params->pkgName.length };
    Uint8Buff serviceTypeBuff = { params->serviceType.val, params->serviceType.length };
    KeyAliasType keyType = (KeyAliasType)params->userType;
    uint8_t keyAliasVal[PAKE_KEY_ALIAS_LEN] = { 0 };
    Uint8Buff keyAliasBuff = { keyAliasVal, PAKE_KEY_ALIAS_LEN };
    Uint8Buff authIdBuff = { params->authId.val, params->authId.length };
    int32_t res = GenerateKeyAlias(&pkgNameBuff, &serviceTypeBuff, keyType, &authIdBuff, &keyAliasBuff);
    if (res != HC_SUCCESS) {
        LOGE("Failed to generate identity keyPair alias!");
        return res;
    }

    const AlgLoader *loader = GetLoaderInstance();
    res = loader->checkKeyExist(&keyAliasBuff, false, params->osAccountId);
    if (res == HC_SUCCESS) {
        LOGD("Key pair is exist.");
        return HC_SUCCESS;
    }

    ExtraInfo exInfo = { authIdBuff, -1, -1 }; /* UserType and pairType are not required when generating key. */
    KeyParams keyParams = { { keyAliasBuff.val, keyAliasBuff.length, true }, false, params->osAccountId };
    res = loader->generateKeyPairWithStorage(&keyParams, PAKE_ED25519_KEY_PAIR_LEN, ED25519,
        KEY_PURPOSE_SIGN_VERIFY, &exInfo);
    if (res != HC_SUCCESS) {
        LOGE("Failed to generate key pair!");
        return res;
    }
    LOGI("Key pair generated successfully!");
    return HC_SUCCESS;
}

static int32_t UnregisterLocalIdentityStd(const TokenManagerParams *params)
{
    Uint8Buff pkgNameBuff = { params->pkgName.val, params->pkgName.length };
    Uint8Buff serviceTypeBuff = { params->serviceType.val, params->serviceType.length };
    KeyAliasType keyType = (KeyAliasType)params->userType;
    uint8_t pakeKeyAliasVal[PAKE_KEY_ALIAS_LEN] = { 0 };
    Uint8Buff pakeKeyAliasBuff = { pakeKeyAliasVal, PAKE_KEY_ALIAS_LEN };
    Uint8Buff authIdBuff = { params->authId.val, params->authId.length };
    int32_t res = GenerateKeyAlias(&pkgNameBuff, &serviceTypeBuff, keyType, &authIdBuff, &pakeKeyAliasBuff);
    if (res != HC_SUCCESS) {
        LOGE("Failed to generate identity keyPair alias!");
        return res;
    }
    LOGI("KeyPair alias(HEX): %x%x%x%x****.", pakeKeyAliasVal[DEV_AUTH_ZERO], pakeKeyAliasVal[DEV_AUTH_ONE],
        pakeKeyAliasVal[DEV_AUTH_TWO], pakeKeyAliasVal[DEV_AUTH_THREE]);

    const AlgLoader *loader = GetLoaderInstance();
    res = loader->deleteKey(&pakeKeyAliasBuff, false, params->osAccountId);
    if (res != HC_SUCCESS) {
        LOGE("Failed to delete key pair!");
        return res;
    }
    LOGI("Key pair deleted successfully!");

    // try to delete upgrade keypair if exist.
    if (memcmp(params->pkgName.val, GROUP_MANAGER_PACKAGE_NAME, HcStrlen(GROUP_MANAGER_PACKAGE_NAME)) == 0) {
        LOGI("Try to delete upgrade key pair.");
        res = GenerateKeyAlias(&pkgNameBuff, &serviceTypeBuff, KEY_ALIAS_LT_KEY_PAIR, &authIdBuff, &pakeKeyAliasBuff);
        if (res != HC_SUCCESS) {
            LOGE("Failed to generate upgrade key pair alias!");
            return res;
        }
        res = ToLowerCase(&pakeKeyAliasBuff);
        if (res != HC_SUCCESS) {
            LOGE("Failed to convert self key alias to lower case!");
            return res;
        }
        LOGI("Upgrade key pair alias(HEX): %x%x%x%x****.", pakeKeyAliasVal[DEV_AUTH_ZERO],
            pakeKeyAliasVal[DEV_AUTH_ONE], pakeKeyAliasVal[DEV_AUTH_TWO], pakeKeyAliasVal[DEV_AUTH_THREE]);
        res = loader->deleteKey(&pakeKeyAliasBuff, true, params->osAccountId);
        if (res != HC_SUCCESS) {
            LOGE("Failed to delete upgrade key pair!");
            return res;
        }
        LOGI("Upgrade key pair deleted successfully!");
    }

    return HC_SUCCESS;
}

static int32_t DeletePeerPubKey(int32_t osAccountId, const Uint8Buff *pkgNameBuff, const Uint8Buff *serviceTypeBuff,
    KeyAliasType keyType, const Uint8Buff *authIdPeer)
{
    uint8_t pakeKeyAliasVal[PAKE_KEY_ALIAS_LEN] = { 0 };
    Uint8Buff pakeKeyAliasBuff = { pakeKeyAliasVal, PAKE_KEY_ALIAS_LEN };
    int32_t res = GenerateKeyAlias(pkgNameBuff, serviceTypeBuff, keyType, authIdPeer, &pakeKeyAliasBuff);
    if (res != HC_SUCCESS) {
        LOGE("Failed to generate peer pub key alias!");
        return res;
    }
    LOGI("PubKey alias(HEX): %x%x%x%x****.", pakeKeyAliasVal[DEV_AUTH_ZERO], pakeKeyAliasVal[DEV_AUTH_ONE],
        pakeKeyAliasVal[DEV_AUTH_TWO], pakeKeyAliasVal[DEV_AUTH_THREE]);
    const AlgLoader *loader = GetLoaderInstance();
    res = loader->deleteKey(&pakeKeyAliasBuff, false, osAccountId);
    if (res != HC_SUCCESS) {
        LOGE("Failed to delete peer public key!");
        return res;
    }
    LOGI("PubKey deleted successfully!");

    res = ToLowerCase(&pakeKeyAliasBuff);
    if (res != HC_SUCCESS) {
        LOGE("Failed to convert peer key alias to lower case!");
        return res;
    }
    res = loader->deleteKey(&pakeKeyAliasBuff, true, osAccountId);
    if (res != HC_SUCCESS) {
        LOGE("Failed to delete peer public key by lower case alias!");
    }
    return res;
}

static int32_t DeleteAuthPsk(int32_t osAccountId, const Uint8Buff *pkgNameBuff, const Uint8Buff *serviceTypeBuff,
    const Uint8Buff *authIdPeer)
{
    uint8_t pakeKeyAliasVal[PAKE_KEY_ALIAS_LEN] = { 0 };
    Uint8Buff pakeKeyAliasBuff = { pakeKeyAliasVal, PAKE_KEY_ALIAS_LEN };
    int32_t res = GenerateKeyAlias(pkgNameBuff, serviceTypeBuff, KEY_ALIAS_PSK, authIdPeer, &pakeKeyAliasBuff);
    if (res != HC_SUCCESS) {
        LOGE("Failed to generate psk alias!");
        return res;
    }
    LOGI("Psk alias(HEX): %x%x%x%x****.", pakeKeyAliasVal[DEV_AUTH_ZERO], pakeKeyAliasVal[DEV_AUTH_ONE],
        pakeKeyAliasVal[DEV_AUTH_TWO], pakeKeyAliasVal[DEV_AUTH_THREE]);
    const AlgLoader *loader = GetLoaderInstance();
    res = loader->deleteKey(&pakeKeyAliasBuff, false, osAccountId);
    if (res != HC_SUCCESS) {
        LOGE("Failed to delete psk!");
        return res;
    }
    res = loader->deleteKey(&pakeKeyAliasBuff, true, osAccountId);
    if (res != HC_SUCCESS) {
        LOGE("Failed to delete psk!");
        return res;
    }
    LOGI("Psk deleted successfully!");

    res = ToLowerCase(&pakeKeyAliasBuff);
    if (res != HC_SUCCESS) {
        LOGE("Failed to convert psk alias to lower case!");
        return res;
    }
    res = loader->deleteKey(&pakeKeyAliasBuff, true, osAccountId);
    if (res != HC_SUCCESS) {
        LOGE("Failed to delete psk by lower case alias!");
    }
    return res;
}

static int32_t DeletePseudonymPskStd(int32_t osAccountId, const Uint8Buff *serviceTypeBuff,
    const Uint8Buff *authIdPeer)
{
    uint8_t pakeKeyAliasVal[PAKE_KEY_ALIAS_LEN] = { 0 };
    Uint8Buff pakeKeyAliasBuff = { pakeKeyAliasVal, PAKE_KEY_ALIAS_LEN };
    int32_t res = GeneratePseudonymPskAlias(serviceTypeBuff, authIdPeer, &pakeKeyAliasBuff);
    if (res != HC_SUCCESS) {
        LOGE("Failed to generate pseudonym psk alias!");
        return res;
    }
    res = ToLowerCase(&pakeKeyAliasBuff);
    if (res != HC_SUCCESS) {
        LOGE("Failed to convert pseudonym psk alias to lower case!");
        return res;
    }
    res = GetLoaderInstance()->deleteKey(&pakeKeyAliasBuff, true, osAccountId);
    if (res != HC_SUCCESS) {
        LOGE("Failed to delete pseudonym psk!");
        return res;
    }
    LOGI("Delete pseudonym psk successfully!");
    return HC_SUCCESS;
}

static int32_t DeletePeerAuthInfoStd(const TokenManagerParams *params)
{
    Uint8Buff pkgNameBuff = { params->pkgName.val, params->pkgName.length };
    Uint8Buff serviceTypeBuff = { params->serviceType.val, params->serviceType.length };
#ifdef DEV_AUTH_FUNC_TEST
    KeyAliasType keyType = KEY_ALIAS_LT_KEY_PAIR;
#else
    KeyAliasType keyType = (KeyAliasType)params->userType;
#endif
    Uint8Buff authIdBuff = { params->authId.val, params->authId.length };
    int32_t res = DeletePeerPubKey(params->osAccountId, &pkgNameBuff, &serviceTypeBuff, keyType, &authIdBuff);
    if (res != HC_SUCCESS) {
        return res;
    }

    res = DeleteAuthPsk(params->osAccountId, &pkgNameBuff, &serviceTypeBuff, &authIdBuff);
    if (res != HC_SUCCESS) {
        return res;
    }

    // try to delete pseudonym psk if exist.
    return DeletePseudonymPskStd(params->osAccountId, &serviceTypeBuff, &authIdBuff);
}

static int32_t GenerateSelfKeyAlias(const PakeParams *params, Uint8Buff *selfKeyAlias)
{
    KeyAliasType keyType = (KeyAliasType)params->userType;
    // if self data is from upgrade, key type should be key-pair.
    if (params->isSelfFromUpgrade) {
        keyType = KEY_ALIAS_LT_KEY_PAIR;
    }
    Uint8Buff packageName = { (uint8_t *)params->packageName, HcStrlen(params->packageName) };
    Uint8Buff serviceType = { (uint8_t *)params->serviceType, HcStrlen(params->serviceType) };
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
    Uint8Buff packageName = { (uint8_t *)params->packageName, HcStrlen(params->packageName) };
    Uint8Buff serviceType = { (uint8_t *)params->serviceType, HcStrlen(params->serviceType) };
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
    Uint8Buff packageName = { (uint8_t *)params->packageName, HcStrlen(params->packageName) };
    Uint8Buff serviceType = { (uint8_t *)params->serviceType, HcStrlen(params->serviceType) };
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

static int32_t ComputeAndSavePskInner(const PakeParams *params, const Uint8Buff *selfKeyAlias,
    const Uint8Buff *peerKeyAlias, Uint8Buff *sharedKeyAlias)
{
    KeyParams selfKeyParams = {
        { selfKeyAlias->val, selfKeyAlias->length, true },
        params->isSelfFromUpgrade,
        params->baseParams.osAccountId
    };
    KeyBuff peerKeyBuff = { peerKeyAlias->val, peerKeyAlias->length, true };
    int32_t res;
    Algorithm alg = (params->baseParams.curveType == CURVE_256) ? P256 : ED25519;
    if (alg == ED25519) {
        uint8_t peerPubKeyVal[PAKE_ED25519_KEY_PAIR_LEN] = { 0 };
        Uint8Buff peerPubKeyBuff = { peerPubKeyVal, PAKE_ED25519_KEY_PAIR_LEN };
        KeyParams peerKeyParams = {
            .keyBuff = { peerKeyAlias->val, peerKeyAlias->length, true },
            .isDeStorage = params->isPeerFromUpgrade,
            .osAccountId = params->baseParams.osAccountId
        };
        res = params->baseParams.loader->exportPublicKey(&peerKeyParams, &peerPubKeyBuff);
        if (res != HC_SUCCESS) {
            LOGE("Failed to export peer public key!");
            return res;
        }
        peerKeyBuff.key = peerPubKeyBuff.val;
        peerKeyBuff.keyLen = peerPubKeyBuff.length;
        peerKeyBuff.isAlias = false;
    }
    res = params->baseParams.loader->agreeSharedSecretWithStorage(&selfKeyParams, &peerKeyBuff, alg,
        PAKE_PSK_LEN, sharedKeyAlias);
    if (res != HC_SUCCESS) {
        LOGE("Failed to agree psk!");
    }
    return res;
}

static int32_t ComputeAndSavePskStd(const PakeParams *params)
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

    res = params->baseParams.loader->checkKeyExist(&selfKeyAlias, params->isSelfFromUpgrade,
        params->baseParams.osAccountId);
    if (res != HC_SUCCESS) {
        LOGE("self auth keyPair not exist");
        return res;
    }
    res = params->baseParams.loader->checkKeyExist(&peerKeyAlias, params->isPeerFromUpgrade,
        params->baseParams.osAccountId);
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
        peerKeyAliasVal[DEV_AUTH_ZERO], peerKeyAliasVal[DEV_AUTH_ONE],
        peerKeyAliasVal[DEV_AUTH_TWO], peerKeyAliasVal[DEV_AUTH_THREE],
        selfKeyAliasVal[DEV_AUTH_ZERO], selfKeyAliasVal[DEV_AUTH_ONE],
        selfKeyAliasVal[DEV_AUTH_TWO], selfKeyAliasVal[DEV_AUTH_THREE],
        sharedKeyAliasVal[DEV_AUTH_ZERO], sharedKeyAliasVal[DEV_AUTH_ONE],
        sharedKeyAliasVal[DEV_AUTH_TWO], sharedKeyAliasVal[DEV_AUTH_THREE]);
    return ComputeAndSavePskInner(params, &selfKeyAlias, &peerKeyAlias, &sharedKeyAlias);
}

static int32_t GetPublicKeyStd(const TokenManagerParams *params, Uint8Buff *returnPk)
{
    Uint8Buff pkgNameBuff = { params->pkgName.val, params->pkgName.length };
    Uint8Buff serviceTypeBuff = { params->serviceType.val, params->serviceType.length };
    KeyAliasType keyType = (KeyAliasType)params->userType;
    uint8_t keyAliasVal[PAKE_KEY_ALIAS_LEN] = { 0 };
    Uint8Buff keyAliasBuff = { keyAliasVal, PAKE_KEY_ALIAS_LEN };
    Uint8Buff authIdBuff = { params->authId.val, params->authId.length };
    int32_t res = GenerateKeyAlias(&pkgNameBuff, &serviceTypeBuff, keyType, &authIdBuff, &keyAliasBuff);
    if (res != HC_SUCCESS) {
        LOGE("Failed to generate keyPair alias!");
        return res;
    }

    bool isDeStorage = false;
    const AlgLoader *loader = GetLoaderInstance();
    res = loader->checkKeyExist(&keyAliasBuff, false, params->osAccountId);
    if (res != HC_SUCCESS) {
        isDeStorage = true;
        res = loader->checkKeyExist(&keyAliasBuff, true, params->osAccountId);
        if (res != HC_SUCCESS) {
            res = ToLowerCase(&keyAliasBuff);
            if (res != HC_SUCCESS) {
                LOGE("Failed to convert key alias to lower case!");
                return res;
            }
            res = loader->checkKeyExist(&keyAliasBuff, true, params->osAccountId);
            if (res != HC_SUCCESS) {
                LOGE("Key not exist!");
                return res;
            }
        }
    }

    KeyParams keyParams = { { keyAliasBuff.val, keyAliasBuff.length, true }, isDeStorage, params->osAccountId };
    res = loader->exportPublicKey(&keyParams, returnPk);
    if (res != HC_SUCCESS) {
        LOGE("Failed to export public key!");
        return res;
    }
    LOGI("Get public key successfully!");
    return HC_SUCCESS;
}

TokenManager g_asyTokenManagerInstance = {
    .registerLocalIdentity = RegisterLocalIdentityStd,
    .unregisterLocalIdentity = UnregisterLocalIdentityStd,
    .deletePeerAuthInfo = DeletePeerAuthInfoStd,
    .computeAndSavePsk = ComputeAndSavePskStd,
    .getPublicKey = GetPublicKeyStd,
};

const TokenManager *GetStandardTokenManagerInstance(void)
{
    return &g_asyTokenManagerInstance;
}