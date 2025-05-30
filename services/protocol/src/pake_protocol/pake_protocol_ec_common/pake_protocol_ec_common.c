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

#include "pake_protocol_ec_common.h"
#include "device_auth_defines.h"
#include "hc_log.h"
#include "hc_types.h"
#include "pake_defs.h"
#include "protocol_common.h"

#define PAKE_PRIVATE_KEY_AND_MASK_HIGH 0xF8
#define PAKE_PRIVATE_KEY_AND_MASK_LOW  0x7F
#define PAKE_PRIVATE_KEY_OR_MASK_LOW   0x40

uint32_t GetPakeEcAlg(void)
{
    return PAKE_ALG_EC;
}

static int32_t GenerateEsk(PakeBaseParams *params)
{
    int32_t res;
    if (params->curveType == CURVE_256) {
        return params->loader->generateRandom(&(params->eskSelf));
    } else if (params->curveType == CURVE_25519) {
        res = params->loader->generateRandom(&(params->eskSelf));
        if (res != HC_SUCCESS) {
            LOGE("CURVE_25519: GenerateRandom for eskSelf failed, res: %" LOG_PUB "x.", res);
            return res;
        }
        params->eskSelf.val[PAKE_EC_KEY_LEN - 1] &= PAKE_PRIVATE_KEY_AND_MASK_HIGH;
        params->eskSelf.val[0] &= PAKE_PRIVATE_KEY_AND_MASK_LOW;
        params->eskSelf.val[0] |= PAKE_PRIVATE_KEY_OR_MASK_LOW;
        return HC_SUCCESS;
    } else {
        LOGE("Unsupported curve: %" LOG_PUB "d.", params->curveType);
        return HC_ERR_UNSUPPORTED_CURVE;
    }
}

static int32_t InitEcPakeParams(PakeBaseParams *params)
{
    params->eskSelf.length = PAKE_EC_KEY_LEN;
    params->innerKeyLen = PAKE_EC_KEY_LEN;
    /* P256 requires buffer for both X and Y coordinates. */
    uint32_t keyBufferLen = (params->curveType == CURVE_256) ? (params->innerKeyLen * 2) : (params->innerKeyLen);
    int32_t res = InitSingleParam(&(params->eskSelf), params->eskSelf.length);
    if (res !=  HC_SUCCESS) {
        LOGE("InitSingleParam for eskSelf failed, res: %" LOG_PUB "x.", res);
        return res;
    }
    res = InitSingleParam(&(params->epkSelf), keyBufferLen);
    if (res !=  HC_SUCCESS) {
        LOGE("InitSingleParam for epkSelf failed, res: %" LOG_PUB "x.", res);
        return res;
    }
    res = InitSingleParam(&(params->base), keyBufferLen);
    if (res !=  HC_SUCCESS) {
        LOGE("InitSingleParam for base failed, res: %" LOG_PUB "x.", res);
        return res;
    }
    return res;
}

int32_t GenerateEcPakeParams(PakeBaseParams *params, Uint8Buff *secret)
{
    int32_t res = InitEcPakeParams(params);
    if (res != HC_SUCCESS) {
        LOGE("InitEcPakeParams failed, res: %" LOG_PUB "x.", res);
        goto CLEAN_UP;
    }

    res = GenerateEsk(params);
    if (res != HC_SUCCESS) {
        LOGE("GenerateEsk failed, res: %" LOG_PUB "x.", res);
        goto CLEAN_UP;
    }

    Algorithm alg = (params->curveType == CURVE_256) ? P256 : X25519;
    res = params->loader->hashToPoint(secret, alg, &params->base);
    if (res != HC_SUCCESS) {
        LOGE("HashToPoint from secret to base failed, res: %" LOG_PUB "x.", res);
        goto CLEAN_UP;
    }
    PRINT_DEBUG_MSG(params->base.val, params->base.length, "baseValue");
    KeyParams eskSelfParams = { { params->eskSelf.val, params->eskSelf.length, false }, false, params->osAccountId };
    KeyBuff baseBuff = { params->base.val, params->base.length, false };
    PRINT_DEBUG_MSG(params->eskSelf.val, params->eskSelf.length, "eskSelf");
    res = params->loader->agreeSharedSecret(&eskSelfParams, &baseBuff, alg, &params->epkSelf);
    if (res != HC_SUCCESS) {
        LOGE("AgreeSharedSecret failed, res: %" LOG_PUB "x.", res);
        goto CLEAN_UP;
    }
    PRINT_DEBUG_MSG(params->epkSelf.val, params->epkSelf.length, "epkSelf");
    return res;
CLEAN_UP:
    CleanPakeSensitiveKeys(params);
    return res;
}

int32_t AgreeEcSharedSecret(PakeBaseParams *params, Uint8Buff *sharedSecret)
{
    int32_t res;
    /* P256 requires buffer for both X and Y coordinates. */
    uint32_t validKeyBufferLen = (params->curveType == CURVE_256) ? (PAKE_EC_KEY_LEN * 2) : (PAKE_EC_KEY_LEN);
    if (params->epkPeer.length != validKeyBufferLen) {
        LOGE("Invalid epkPeer length: %" LOG_PUB "u.", params->epkPeer.length);
        res = HC_ERR_INVALID_LEN;
        goto CLEAN_UP;
    }

    Algorithm alg = (params->curveType == CURVE_256) ? P256 : X25519;
    if (!params->loader->checkEcPublicKey(&(params->epkPeer), alg)) {
        LOGE("Check public key failed.");
        res = HC_ERR_INVALID_PUBLIC_KEY;
        goto CLEAN_UP;
    }
    PRINT_DEBUG_MSG(params->epkPeer.val, params->epkPeer.length, "epkPeer");
    KeyParams eskSelfParams = { { params->eskSelf.val, params->eskSelf.length, false }, false, params->osAccountId };
    KeyBuff epkPeerBuff = { params->epkPeer.val, params->epkPeer.length, false };
    res = params->loader->agreeSharedSecret(&eskSelfParams, &epkPeerBuff, alg, sharedSecret);
    if (res != HC_SUCCESS) {
        LOGE("AgreeSharedSecret failed, res: %" LOG_PUB "x.", res);
        goto CLEAN_UP;
    }
    PRINT_DEBUG_MSG(sharedSecret->val, sharedSecret->length, "sharedSecret");
    return res;
CLEAN_UP:
    CleanPakeSensitiveKeys(params);
    return res;
}