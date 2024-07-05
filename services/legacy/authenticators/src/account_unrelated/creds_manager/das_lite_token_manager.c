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

#include "das_lite_token_manager.h"
#include "alg_loader.h"
#include "das_task_common.h"
#include "hc_log.h"
#include "iso_base_cur_task.h"

static int32_t UnregisterLocalIdentity(const char *pkgName, const char *serviceType, Uint8Buff *authId, int userType)
{
    (void)userType;
    const AlgLoader *loader = GetLoaderInstance();
    Uint8Buff pkgNameBuff = { (uint8_t *)pkgName, HcStrlen(pkgName) };
    Uint8Buff serviceTypeBuff = { (uint8_t *)serviceType, HcStrlen(serviceType) };

    uint8_t isoKeyAliasVal[ISO_KEY_ALIAS_LEN] = { 0 };
    Uint8Buff isoKeyAliasBuff = { isoKeyAliasVal, ISO_KEY_ALIAS_LEN };
    int32_t res = GenerateKeyAlias(&pkgNameBuff, &serviceTypeBuff, KEY_ALIAS_AUTH_TOKEN, authId, &isoKeyAliasBuff);
    if (res != HC_SUCCESS) {
        LOGE("Failed to generate authtoken alias!");
        return res;
    }
    LOGI("AuthCode alias(HEX): %x%x%x%x****.", isoKeyAliasVal[DEV_AUTH_ZERO], isoKeyAliasVal[DEV_AUTH_ONE],
        isoKeyAliasVal[DEV_AUTH_TWO], isoKeyAliasVal[DEV_AUTH_THREE]);
    res = loader->deleteKey(&isoKeyAliasBuff);
    if (res != HC_SUCCESS) {
        LOGE("Failed to delete authtoken!");
        return res;
    }
    LOGI("AuthCode deleted successfully!");

    return HC_SUCCESS;
}

static int32_t DeletePeerAuthInfo(const char *pkgName, const char *serviceType, Uint8Buff *authIdPeer, int userTypePeer)
{
    const AlgLoader *loader = GetLoaderInstance();
    Uint8Buff pkgNameBuff = { (uint8_t *)pkgName, HcStrlen(pkgName)};
    Uint8Buff serviceTypeBuff = { (uint8_t *)serviceType, HcStrlen(serviceType) };

    uint8_t isoKeyAliasVal[ISO_KEY_ALIAS_LEN] = { 0 };
    Uint8Buff isoKeyAliasBuff = { isoKeyAliasVal, ISO_KEY_ALIAS_LEN };
    int32_t res = GenerateKeyAlias(&pkgNameBuff, &serviceTypeBuff, KEY_ALIAS_AUTH_TOKEN, authIdPeer, &isoKeyAliasBuff);
    if (res != HC_SUCCESS) {
        LOGE("Failed to generate authtoken alias!");
        return res;
    }
    LOGI("AuthCode alias(HEX): %x%x%x%x****.", isoKeyAliasVal[DEV_AUTH_ZERO], isoKeyAliasVal[DEV_AUTH_ONE],
        isoKeyAliasVal[DEV_AUTH_TWO], isoKeyAliasVal[DEV_AUTH_THREE]);
    res = loader->deleteKey(&isoKeyAliasBuff);
    if (res != HC_SUCCESS) {
        LOGE("Failed to delete authtoken!");
        return res;
    }
    LOGI("AuthCode deleted successfully!");

    // try to delete upgrade auth token if exist.
    uint8_t isoUpgradeKeyAliasVal[ISO_UPGRADE_KEY_ALIAS_LEN] = { 0 };
    Uint8Buff isoUpgradeKeyAliasBuff = { isoUpgradeKeyAliasVal, ISO_UPGRADE_KEY_ALIAS_LEN };
    res = GenerateKeyAlias(&pkgNameBuff, &serviceTypeBuff, userTypePeer, authIdPeer, &isoUpgradeKeyAliasBuff);
    if (res != HC_SUCCESS) {
        LOGE("Failed to generate upgrade auth token alias!");
        return res;
    }
    res = ToLowerCase(&isoUpgradeKeyAliasBuff);
    if (res != HC_SUCCESS) {
        LOGE("Failed to convert peer key alias to lower case!");
        return res;
    }
    LOGI("Upgrade auth code alias(HEX): %x%x%x%x****.", isoUpgradeKeyAliasVal[DEV_AUTH_ZERO],
        isoUpgradeKeyAliasVal[DEV_AUTH_ONE], isoUpgradeKeyAliasVal[DEV_AUTH_TWO],
        isoUpgradeKeyAliasVal[DEV_AUTH_THREE]);
    res = loader->deleteKey(&isoUpgradeKeyAliasBuff);
    if (res != HC_SUCCESS) {
        LOGE("Failed to delete upgrade auth token!");
        return res;
    }
    LOGI("Upgrade auth code deleted successfully!");

    return HC_SUCCESS;
}

TokenManager g_symTokenManagerInstance = {
    .registerLocalIdentity = NULL,
    .unregisterLocalIdentity = UnregisterLocalIdentity,
    .deletePeerAuthInfo = DeletePeerAuthInfo,
    .computeAndSavePsk = NULL,
    .getPublicKey = NULL,
};

const TokenManager *GetLiteTokenManagerInstance(void)
{
    return &g_symTokenManagerInstance;
}