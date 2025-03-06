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

static int32_t UnregisterLocalIdentityLite(const TokenManagerParams *params)
{
    Uint8Buff pkgNameBuff = { params->pkgName.val, params->pkgName.length };
    Uint8Buff serviceTypeBuff = { params->serviceType.val, params->serviceType.length };

    uint8_t isoKeyAliasVal[ISO_KEY_ALIAS_LEN] = { 0 };
    Uint8Buff isoKeyAliasBuff = { isoKeyAliasVal, ISO_KEY_ALIAS_LEN };
    Uint8Buff authIdBuff = { params->authId.val, params->authId.length };
    int32_t res = GenerateKeyAlias(&pkgNameBuff, &serviceTypeBuff, KEY_ALIAS_AUTH_TOKEN, &authIdBuff,
        &isoKeyAliasBuff);
    if (res != HC_SUCCESS) {
        LOGE("Failed to generate authtoken alias!");
        return res;
    }
    LOGI("AuthCode alias(HEX): %" LOG_PUB "x%" LOG_PUB "x%" LOG_PUB "x%" LOG_PUB "x****.",
        isoKeyAliasVal[DEV_AUTH_ZERO], isoKeyAliasVal[DEV_AUTH_ONE], isoKeyAliasVal[DEV_AUTH_TWO],
        isoKeyAliasVal[DEV_AUTH_THREE]);

    const AlgLoader *loader = GetLoaderInstance();
    res = loader->deleteKey(&isoKeyAliasBuff, false, params->osAccountId);
    if (res != HC_SUCCESS) {
        LOGE("Failed to delete authtoken!");
        return res;
    }
    LOGI("AuthCode deleted successfully!");

    return HC_SUCCESS;
}

static int32_t DeletePeerAuthInfoLite(const TokenManagerParams *params)
{
    Uint8Buff pkgNameBuff = { params->pkgName.val, params->pkgName.length };
    Uint8Buff serviceTypeBuff = { params->serviceType.val, params->serviceType.length };

    uint8_t isoKeyAliasVal[ISO_KEY_ALIAS_LEN] = { 0 };
    Uint8Buff isoKeyAliasBuff = { isoKeyAliasVal, ISO_KEY_ALIAS_LEN };
    Uint8Buff authIdBuff = { params->authId.val, params->authId.length };
    int32_t res = GenerateKeyAlias(&pkgNameBuff, &serviceTypeBuff, KEY_ALIAS_AUTH_TOKEN, &authIdBuff,
        &isoKeyAliasBuff);
    if (res != HC_SUCCESS) {
        LOGE("Failed to generate authtoken alias!");
        return res;
    }
    LOGI("AuthCode alias(HEX): %" LOG_PUB "x%" LOG_PUB "x%" LOG_PUB "x%" LOG_PUB "x****.",
        isoKeyAliasVal[DEV_AUTH_ZERO], isoKeyAliasVal[DEV_AUTH_ONE], isoKeyAliasVal[DEV_AUTH_TWO],
        isoKeyAliasVal[DEV_AUTH_THREE]);

    const AlgLoader *loader = GetLoaderInstance();
    res = loader->deleteKey(&isoKeyAliasBuff, false, params->osAccountId);
    if (res != HC_SUCCESS) {
        LOGE("Failed to delete authtoken!");
        return res;
    }
    LOGI("AuthCode deleted successfully!");

    // try to delete upgrade auth token if exist.
    uint8_t isoUpgradeKeyAliasVal[ISO_UPGRADE_KEY_ALIAS_LEN] = { 0 };
    Uint8Buff isoUpgradeKeyAliasBuff = { isoUpgradeKeyAliasVal, ISO_UPGRADE_KEY_ALIAS_LEN };
    res = GenerateKeyAlias(&pkgNameBuff, &serviceTypeBuff, params->userType, &authIdBuff, &isoUpgradeKeyAliasBuff);
    if (res != HC_SUCCESS) {
        LOGE("Failed to generate upgrade auth token alias!");
        return res;
    }
    res = ToLowerCase(&isoUpgradeKeyAliasBuff);
    if (res != HC_SUCCESS) {
        LOGE("Failed to convert peer key alias to lower case!");
        return res;
    }
    LOGI("Upgrade auth code alias(HEX): %" LOG_PUB "x%" LOG_PUB "x%" LOG_PUB "x%" LOG_PUB "x****.",
        isoUpgradeKeyAliasVal[DEV_AUTH_ZERO], isoUpgradeKeyAliasVal[DEV_AUTH_ONE], isoUpgradeKeyAliasVal[DEV_AUTH_TWO],
        isoUpgradeKeyAliasVal[DEV_AUTH_THREE]);
    res = loader->deleteKey(&isoUpgradeKeyAliasBuff, true, params->osAccountId);
    if (res != HC_SUCCESS) {
        LOGE("Failed to delete upgrade auth token!");
        return res;
    }
    LOGI("Upgrade auth code deleted successfully!");

    return HC_SUCCESS;
}

TokenManager g_symTokenManagerInstance = {
    .registerLocalIdentity = NULL,
    .unregisterLocalIdentity = UnregisterLocalIdentityLite,
    .deletePeerAuthInfo = DeletePeerAuthInfoLite,
    .computeAndSavePsk = NULL,
    .getPublicKey = NULL,
};

const TokenManager *GetLiteTokenManagerInstance(void)
{
    return &g_symTokenManagerInstance;
}