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

#include "pake_v1_protocol_task_common.h"
#include "das_standard_token_manager.h"
#include "das_task_common.h"
#include "hc_log.h"
#include "hc_types.h"
#include "protocol_common.h"
#include "pake_v1_protocol_common.h"
#include "pake_task_common.h"
#include "das_task_common.h"

#define ASCII_CASE_DIFFERENCE_VALUE 32

void DestroyDasPakeV1Params(PakeParams *params)
{
    if (params == NULL) {
        return;
    }

    DestroyPakeV1BaseParams(&(params->baseParams));

    if (params->returnKey.val != NULL) {
        (void)memset_s(params->returnKey.val, params->returnKey.length, 0, params->returnKey.length);
        HcFree(params->returnKey.val);
        params->returnKey.val = NULL;
    }

    if (params->pseudonymExtInfo.selfNextPseudonymId.val != NULL) {
        HcFree(params->pseudonymExtInfo.selfNextPseudonymId.val);
        params->pseudonymExtInfo.selfNextPseudonymId.val = NULL;
    }

    if (params->pseudonymExtInfo.selfNextPseudonymChallenge.val != NULL) {
        HcFree(params->pseudonymExtInfo.selfNextPseudonymChallenge.val);
        params->pseudonymExtInfo.selfNextPseudonymChallenge.val = NULL;
    }

    if (params->pseudonymExtInfo.peerNextPseudonymId.val != NULL) {
        HcFree(params->pseudonymExtInfo.peerNextPseudonymId.val);
        params->pseudonymExtInfo.peerNextPseudonymId.val = NULL;
    }
    
    HcFree(params->packageName);
    params->packageName = NULL;

    HcFree(params->serviceType);
    params->serviceType = NULL;

    HcFree(params->nonce.val);
    params->nonce.val = NULL;
}

static int32_t AllocReturnKey(PakeParams *params, const CJson *in)
{
    if (params->opCode == OP_UNBIND) {
        params->returnKey.val = NULL;
        params->returnKey.length = 0;
        return HC_SUCCESS;
    }
    int32_t res = GetIntFromJson(in, FIELD_KEY_LENGTH, (int *)&(params->returnKey.length));
    if (res != HC_SUCCESS) {
        LOGD("Get key length failed, use default, res: %" LOG_PUB "d", res);
        params->returnKey.length = DEFAULT_RETURN_KEY_LENGTH;
    }
    if (params->returnKey.length < MIN_OUTPUT_KEY_LEN || params->returnKey.length > MAX_OUTPUT_KEY_LEN) {
        LOGE("Output key length is invalid.");
        return HC_ERR_INVALID_LEN;
    }
    res = InitSingleParam(&params->returnKey, params->returnKey.length);
    if (res != HC_SUCCESS) {
        LOGE("InitSingleParam for returnKey failed, res: %" LOG_PUB "d.", res);
    }
    return res;
}

static int32_t RemoveEscapeForExtInfo(const char *extInfoStr, char **outExtInfoStr)
{
    uint32_t len = HcStrlen(extInfoStr);
    *outExtInfoStr = (char *)HcMalloc(len + 1, 0);
    if (*outExtInfoStr == NULL) {
        LOGE("Failed to alloc memory for outExtInfoStr!");
        return HC_ERR_ALLOC_MEMORY;
    }
    uint32_t j = 0;
    for (uint32_t i = 0; i < len; i++) {
        if (extInfoStr[i] == '\\') {
            i++;
            if (extInfoStr[i] == '\"') {
                (*outExtInfoStr)[j++] = '\"';
            }
        } else {
            (*outExtInfoStr)[j++] = extInfoStr[i];
        }
    }
    return HC_SUCCESS;
}

static int32_t GetInnerExtInfo(const Uint8Buff *extInfoBuff, Uint8Buff *innerExtInfo)
{
    CJson *extInfoJson = CreateJsonFromString((char *)extInfoBuff->val);
    if (extInfoJson == NULL) {
        LOGE("Failed to create extInfoJson!");
        return HC_ERR_JSON_CREATE;
    }
    const char *innerExtInfoStr = GetStringFromJson(extInfoJson, "ExtInfo");
    if (innerExtInfoStr == NULL) {
        LOGE("Failed to get inner extInfo!");
        FreeJson(extInfoJson);
        return HC_ERR_JSON_GET;
    }
    char *outInnerExtStr = NULL;
    int32_t res = RemoveEscapeForExtInfo(innerExtInfoStr, &outInnerExtStr);
    FreeJson(extInfoJson);
    if (res != HC_SUCCESS) {
        LOGE("Failed to remove escape for extInfo!");
        return res;
    }
    innerExtInfo->val = (uint8_t *)outInnerExtStr;
    innerExtInfo->length = HcStrlen(outInnerExtStr) + 1;
    return HC_SUCCESS;
}

static int32_t LoadPseudonymFlagIfNeed(PakeParams *params)
{
    uint8_t peerKeyAliasVal[PAKE_KEY_ALIAS_LEN] = { 0 };
    Uint8Buff peerKeyAlias = { peerKeyAliasVal, PAKE_KEY_ALIAS_LEN };
    TokenManagerParams tokenParams = { 0 };
    tokenParams.pkgName.val = (uint8_t *)params->packageName;
    tokenParams.pkgName.length = HcStrlen(params->packageName);
    tokenParams.serviceType.val = (uint8_t *)params->serviceType;
    tokenParams.serviceType.length = HcStrlen(params->serviceType);
    tokenParams.userType = params->userTypePeer;
    tokenParams.authId = params->baseParams.idPeer;
    int32_t res = GenerateKeyAlias(&tokenParams, &peerKeyAlias);
    if (res != HC_SUCCESS) {
        LOGE("Failed to generate peer key alias!");
        return res;
    }
    res = ToLowerCase(&peerKeyAlias);
    if (res != HC_SUCCESS) {
        LOGE("Failed to convert key alias to lower case!");
        return res;
    }
    Uint8Buff extInfoBuff = { NULL, 0 };
    KeyParams keyParams = { { peerKeyAlias.val, peerKeyAlias.length, true }, true, params->baseParams.osAccountId };
    res = params->baseParams.loader->getKeyExtInfo(&keyParams, &extInfoBuff);
    if (res != HC_SUCCESS) {
        LOGE("Failed to get public key extInfo!");
        return res;
    }
    Uint8Buff innerExtInfo = { NULL, 0 };
    res = GetInnerExtInfo(&extInfoBuff, &innerExtInfo);
    FreeUint8Buff(&extInfoBuff);
    if (res != HC_SUCCESS) {
        LOGE("Failed to get inner extInfo!");
        return res;
    }
    CJson *innerExtInfoJson = CreateJsonFromString((char *)innerExtInfo.val);
    FreeUint8Buff(&innerExtInfo);
    if (innerExtInfoJson == NULL) {
        LOGE("Failed to create inner extInfo json!");
        return HC_ERR_JSON_CREATE;
    }
    if (GetBoolFromJson(innerExtInfoJson, FIELD_IS_PSEUDONYM_SUPPORTED, &params->isPseudonym) != HC_SUCCESS) {
        LOGE("Failed to get pseudonym flag from inner extInfo!");
        FreeJson(innerExtInfoJson);
        return HC_ERR_JSON_GET;
    }
    LOGI("peer support pseudonym: %" LOG_PUB "s", params->isPseudonym ? "true" : "false");
    FreeJson(innerExtInfoJson);
    return HC_SUCCESS;
}

int32_t InitDasPakeV1Params(PakeParams *params, const CJson *in)
{
    int32_t osAccountId;
    if (GetIntFromJson(in, FIELD_OS_ACCOUNT_ID, &osAccountId) != HC_SUCCESS) {
        LOGE("Failed to get osAccountId!");
        return HC_ERR_JSON_GET;
    }
    int32_t res = InitPakeV1BaseParams(osAccountId, &(params->baseParams));
    if (res != HC_SUCCESS) {
        LOGE("InitPakeV1BaseParams failed, res: %" LOG_PUB "d.", res);
        goto ERR;
    }

    res = FillDasPakeParams(params, in);
    if (res != HC_SUCCESS) {
        LOGE("FillDasPakeParams failed, res: %" LOG_PUB "d.", res);
        goto ERR;
    }
    (void)GetBoolFromJson(in, FIELD_IS_SELF_FROM_UPGRADE, &params->isSelfFromUpgrade);
    (void)GetBoolFromJson(in, FIELD_IS_PEER_FROM_UPGRADE, &params->isPeerFromUpgrade);
    if (params->isSelfFromUpgrade) {
        LOGI("Self device is from upgrade!");
    } else {
        LOGI("Self device is not from upgrade!");
    }
    if (params->isPeerFromUpgrade) {
        LOGI("peer device is from upgrade!");
    } else {
        LOGI("peer device is not from upgrade!");
    }
    if (params->opCode == AUTHENTICATE && params->isPeerFromUpgrade) {
        (void)LoadPseudonymFlagIfNeed(params);
    }

    res = AllocReturnKey(params, in);
    if (res != HC_SUCCESS) {
        LOGE("AllocReturnKey failed, res: %" LOG_PUB "d.", res);
        goto ERR;
    }

    return HC_SUCCESS;
ERR:
    DestroyDasPakeV1Params(params);
    return res;
}

static void UpperToLowercase(Uint8Buff *hex)
{
    for (uint32_t i = 0; i < hex->length; i++) {
        if (hex->val[i] >= 'A' && hex->val[i] <= 'F') {
            hex->val[i] += ASCII_CASE_DIFFERENCE_VALUE;
        }
    }
}

static int32_t ConvertPakeV1Psk(const Uint8Buff *srcPsk, PakeParams *params)
{
    int res = InitSingleParam(&(params->baseParams.psk), PAKE_PSK_LEN * BYTE_TO_HEX_OPER_LENGTH + 1);
    if (res != HC_SUCCESS) {
        LOGE("InitSingleParam for psk failed, res: %" LOG_PUB "d.", res);
        return res;
    }

    if (ByteToHexString(srcPsk->val, srcPsk->length, (char *)params->baseParams.psk.val,
        params->baseParams.psk.length) != HC_SUCCESS) {
        LOGE("Convert psk from byte to hex string failed.");
        return HC_ERR_CONVERT_FAILED;
    }
    params->baseParams.psk.length = params->baseParams.psk.length - 1; // do not need include '\0' when using psk
    (void)UpperToLowercase(&(params->baseParams.psk));
    PRINT_DEBUG_MSG(srcPsk->val, srcPsk->length, "pskValue");
    PRINT_SENSITIVE_DATA("pskValue", (char *)params->baseParams.psk.val);
    return res;
}

static int32_t GeneratePskAlias(const PakeParams *params, Uint8Buff *pskKeyAlias)
{
    TokenManagerParams tokenParams = { 0 };
    tokenParams.pkgName.val = (uint8_t *)params->packageName;
    tokenParams.pkgName.length = HcStrlen(params->packageName);
    tokenParams.serviceType.val = (uint8_t *)params->serviceType;
    tokenParams.serviceType.length = HcStrlen(params->serviceType);
    tokenParams.userType = KEY_ALIAS_PSK;
    tokenParams.authId = params->baseParams.idPeer;
    int32_t res = GenerateKeyAlias(&tokenParams, pskKeyAlias);
    if (res != HC_SUCCESS) {
        LOGE("GenerateKeyAlias for psk failed, res: %" LOG_PUB "d.", res);
        return res;
    }
    if (params->isPeerFromUpgrade) {
        res = ToLowerCase(pskKeyAlias);
        if (res != HC_SUCCESS) {
            LOGE("Failed to convert psk alias to lower case!");
            return res;
        }
    }
    return HC_SUCCESS;
}

int32_t FillPskWithDerivedKeyHex(PakeParams *params)
{
    int32_t res;
    if (!(params->baseParams.isClient)) {
        res = params->baseParams.loader->generateRandom(&(params->nonce));
        if (res != HC_SUCCESS) {
            LOGE("Generate nonce failed, res: %" LOG_PUB "d.", res);
            return res;
        }
    }
    uint8_t pskAliasVal[PAKE_KEY_ALIAS_LEN] = { 0 };
    Uint8Buff pskAlias = { pskAliasVal, PAKE_KEY_ALIAS_LEN };
    res = GeneratePskAlias(params, &pskAlias);
    if (res != HC_SUCCESS) {
        return res;
    }

    LOGI("Psk alias(HEX): %" LOG_PUB "x%" LOG_PUB "x%" LOG_PUB "x%" LOG_PUB "x****.", pskAliasVal[DEV_AUTH_ZERO],
        pskAliasVal[DEV_AUTH_ONE], pskAliasVal[DEV_AUTH_TWO], pskAliasVal[DEV_AUTH_THREE]);
    bool isDeStorage = params->isSelfFromUpgrade;
    if (params->baseParams.loader->checkKeyExist(&pskAlias, isDeStorage, params->baseParams.osAccountId) !=
        HC_SUCCESS) {
        res = GetStandardTokenManagerInstance()->computeAndSavePsk(params);
        if (res != HC_SUCCESS) {
            LOGE("ComputeAndSavePsk failed, res: %" LOG_PUB "d.", res);
            return res;
        }
    }

    uint8_t pskVal[PAKE_PSK_LEN] = { 0 };
    Uint8Buff pskByte = { pskVal, PAKE_PSK_LEN };
    Uint8Buff keyInfo = { (uint8_t *)TMP_AUTH_KEY_FACTOR, HcStrlen(TMP_AUTH_KEY_FACTOR) };
    KeyParams keyParams = { { pskAlias.val, pskAlias.length, true }, isDeStorage, params->baseParams.osAccountId };
    PRINT_DEBUG_MSG(params->nonce.val, params->nonce.length, "nonceValue");
    res = params->baseParams.loader->computeHkdf(&keyParams, &(params->nonce), &keyInfo, &pskByte);
    if (res != HC_SUCCESS) {
        LOGE("ComputeHkdf for psk failed, res: %" LOG_PUB "d.", res);
        FreeAndCleanKey(&(params->baseParams.psk));
        return res;
    }

    res = ConvertPakeV1Psk(&pskByte, params);
    if (res != HC_SUCCESS) {
        LOGE("ConvertPakeV1Psk failed, res: %" LOG_PUB "d.", res);
        FreeAndCleanKey(&(params->baseParams.psk));
    }
    return res;
}

static int32_t FillPseudonymPskExtInfo(PseudonymPskExtInfo *extInfo, const CJson *extInfoJson)
{
    uint8_t *tmpSefNextIdVal = (uint8_t *)HcMalloc(PSEUDONYM_ID_LEN, 0);
    if (tmpSefNextIdVal == NULL) {
        LOGE("Failed to alloc memory for self next pseudonym id!");
        return HC_ERR_ALLOC_MEMORY;
    }
    if (GetByteFromJson(extInfoJson, FIELD_SELF_NEXT_PSEUDONYM_ID, tmpSefNextIdVal, PSEUDONYM_ID_LEN) != HC_SUCCESS) {
        LOGE("Failed to get self next pseudonym id!");
        HcFree(tmpSefNextIdVal);
        return HC_ERR_JSON_GET;
    }
    uint8_t *tmpSelfNextChallengeVal = (uint8_t *)HcMalloc(PSEUDONYM_CHALLENGE_LEN, 0);
    if (tmpSelfNextChallengeVal == NULL) {
        LOGE("Failed to alloc memory for self next pseudonym challenge!");
        HcFree(tmpSefNextIdVal);
        return HC_ERR_ALLOC_MEMORY;
    }
    if (GetByteFromJson(extInfoJson, FIELD_SELF_NEXT_PSEUDONYM_CHALLENGE, tmpSelfNextChallengeVal,
        PSEUDONYM_CHALLENGE_LEN) != HC_SUCCESS) {
        LOGE("Failed to get self next pseudonym challenge!");
        HcFree(tmpSefNextIdVal);
        HcFree(tmpSelfNextChallengeVal);
        return HC_ERR_JSON_GET;
    }
    uint8_t *tmpPeerNextIdVal = (uint8_t *)HcMalloc(PSEUDONYM_ID_LEN, 0);
    if (tmpPeerNextIdVal == NULL) {
        LOGE("Failed to alloc memory for peer next pseudonym id!");
        HcFree(tmpSefNextIdVal);
        HcFree(tmpSelfNextChallengeVal);
        return HC_ERR_ALLOC_MEMORY;
    }
    if (GetByteFromJson(extInfoJson, FIELD_PEER_NEXT_PSEUDONYM_ID, tmpPeerNextIdVal, PSEUDONYM_ID_LEN) != HC_SUCCESS) {
        LOGE("Failed to get peer next pseudonym id!");
        HcFree(tmpSefNextIdVal);
        HcFree(tmpSelfNextChallengeVal);
        HcFree(tmpPeerNextIdVal);
        return HC_ERR_JSON_GET;
    }
    extInfo->selfNextPseudonymId.val = tmpSefNextIdVal;
    extInfo->selfNextPseudonymId.length = PSEUDONYM_ID_LEN;
    extInfo->selfNextPseudonymChallenge.val = tmpSelfNextChallengeVal;
    extInfo->selfNextPseudonymChallenge.length = PSEUDONYM_CHALLENGE_LEN;
    extInfo->peerNextPseudonymId.val = tmpPeerNextIdVal;
    extInfo->peerNextPseudonymId.length = PSEUDONYM_ID_LEN;
    return HC_SUCCESS;
}

int32_t LoadPseudonymExtInfoIfNeed(PakeParams *params)
{
    if (params == NULL) {
        LOGE("Invalid params!");
        return HC_ERR_INVALID_PARAMS;
    }
    Uint8Buff serviceTypeBuff = { (uint8_t *)params->serviceType, HcStrlen(params->serviceType) };
    uint8_t pskAliasVal[PAKE_KEY_ALIAS_LEN] = { 0 };
    Uint8Buff pskAliasBuff = { pskAliasVal, PAKE_KEY_ALIAS_LEN };
    int32_t res = GeneratePseudonymPskAlias(&serviceTypeBuff, &(params->baseParams.idPeer), &pskAliasBuff);
    if (res != HC_SUCCESS) {
        LOGE("Failed to generate pseudonym psk alias!");
        return res;
    }
    res = ToLowerCase(&pskAliasBuff);
    if (res != HC_SUCCESS) {
        LOGE("Failed to convert key alias to lower case!");
        return res;
    }
    Uint8Buff extInfoBuff = { NULL, 0 };
    KeyParams keyParams = { { pskAliasBuff.val, pskAliasBuff.length, true }, true, params->baseParams.osAccountId };
    res = params->baseParams.loader->getKeyExtInfo(&keyParams, &extInfoBuff);
    if (res != HC_SUCCESS) {
        LOGE("Failed to get pseudonym psk extInfo!");
        return res;
    }
    Uint8Buff innerExtInfo = { NULL, 0 };
    res = GetInnerExtInfo(&extInfoBuff, &innerExtInfo);
    FreeUint8Buff(&extInfoBuff);
    if (res != HC_SUCCESS) {
        LOGE("Failed to get inner extInfo!");
        return res;
    }
    CJson *innerExtInfoJson = CreateJsonFromString((char *)innerExtInfo.val);
    FreeUint8Buff(&innerExtInfo);
    if (innerExtInfoJson == NULL) {
        LOGE("Failed to create inner extInfo json!");
        return HC_ERR_JSON_CREATE;
    }
    res = FillPseudonymPskExtInfo(&params->pseudonymExtInfo, innerExtInfoJson);
    FreeJson(innerExtInfoJson);
    if (res != HC_SUCCESS) {
        LOGE("Failed to fill pseudonym psk ext info!");
    }
    return res;
}

static int32_t CombinePseudonymChallenge(Uint8Buff *combinedChallengeBuff, const Uint8Buff *pseudonymChallengeBuff,
    const Uint8Buff *nextPseudonymChallengeBuff)
{
    uint32_t totalLen = combinedChallengeBuff->length;
    uint32_t usedLen = 0;
    if (memcpy_s(combinedChallengeBuff->val, totalLen, pseudonymChallengeBuff->val,
        pseudonymChallengeBuff->length) != EOK) {
        LOGE("Copy pseudonym challenge failed!");
        return HC_ERR_MEMORY_COPY;
    }
    usedLen = usedLen + pseudonymChallengeBuff->length;

    if (memcpy_s(combinedChallengeBuff->val + usedLen, totalLen - usedLen, nextPseudonymChallengeBuff->val,
        nextPseudonymChallengeBuff->length) != EOK) {
        LOGE("Copy next pseudonym challenge failed!");
        return HC_ERR_MEMORY_COPY;
    }
    return HC_SUCCESS;
}

static int32_t GeneratePseudonymPskIfNotExist(const PakeParams *params)
{
    uint8_t baseKeyAliasVal[PAKE_KEY_ALIAS_LEN] = { 0 };
    Uint8Buff baseKeyAlias = { baseKeyAliasVal, PAKE_KEY_ALIAS_LEN };
    TokenManagerParams tokenParams = { 0 };
    tokenParams.pkgName.val = (uint8_t *)params->packageName;
    tokenParams.pkgName.length = HcStrlen(params->packageName);
    tokenParams.serviceType.val = (uint8_t *)params->serviceType;
    tokenParams.serviceType.length = HcStrlen(params->serviceType);
    tokenParams.userType = KEY_ALIAS_PSK;
    tokenParams.authId = params->baseParams.idPeer;
    int32_t res = GenerateKeyAlias(&tokenParams, &baseKeyAlias);
    if (res != HC_SUCCESS) {
        LOGE("Failed to generate base key alias!");
        return res;
    }
    res = ToLowerCase(&baseKeyAlias);
    if (res != HC_SUCCESS) {
        LOGE("Failed to convert psk alias to lower case!");
        return res;
    }
    uint8_t pskAliasVal[PAKE_KEY_ALIAS_LEN] = { 0 };
    Uint8Buff pskAliasBuff = { pskAliasVal, PAKE_KEY_ALIAS_LEN };
    Uint8Buff serviceTypeBuff = { (uint8_t *)params->serviceType, HcStrlen(params->serviceType) };
    res = GeneratePseudonymPskAlias(&serviceTypeBuff, &params->baseParams.idPeer, &pskAliasBuff);
    if (res != HC_SUCCESS) {
        LOGE("Failed to generate psk alias!");
        return res;
    }
    res = ToLowerCase(&pskAliasBuff);
    if (res != HC_SUCCESS) {
        LOGE("Failed to convert pseudonym psk alias to lower case!");
        return res;
    }
    if (params->baseParams.loader->checkKeyExist(&pskAliasBuff, true, params->baseParams.osAccountId) == HC_SUCCESS) {
        LOGI("Pseudonym psk already exist.");
        return HC_SUCCESS;
    }
    uint8_t outKeyVal[PAKE_PSK_LEN] = { 0 };
    Uint8Buff outKeyBuff = { outKeyVal, PAKE_PSK_LEN };
    KeyParams keyParams = { { baseKeyAlias.val, baseKeyAlias.length, true }, true, params->baseParams.osAccountId };
    res = params->baseParams.loader->computePseudonymPsk(&keyParams, &pskAliasBuff, NULL, &outKeyBuff);
    if (res != HC_SUCCESS) {
        LOGE("Failed to compute pseudonym psk!");
    }
    return res;
}

static int32_t AddPseudonymIdToPayload(CJson *payload, const Uint8Buff *pseudonymIdBuff)
{
    uint32_t hexLen = pseudonymIdBuff->length * BYTE_TO_HEX_OPER_LENGTH + 1;
    char *hexStr = (char *)HcMalloc(hexLen, 0);
    if (hexStr == NULL) {
        LOGE("Failed to alloc memory for pseudonym id hex!");
        return HC_ERR_ALLOC_MEMORY;
    }
    int32_t res = ByteToHexString(pseudonymIdBuff->val, pseudonymIdBuff->length, hexStr, hexLen);
    if (res != HC_SUCCESS) {
        LOGE("Failed to convert pseudonym id from byte to hex!");
        HcFree(hexStr);
        return res;
    }
    Uint8Buff hexBuff = {
        .val = (uint8_t *)hexStr,
        .length = HcStrlen(hexStr)
    };
    res = ToLowerCase(&hexBuff);
    if (res != HC_SUCCESS) {
        LOGE("Failed to convert pseudonym id hex to lower case!");
        HcFree(hexStr);
        return res;
    }
    if (AddStringToJson(payload, FIELD_P2P_PSEUDONYM_ID, hexStr) != HC_SUCCESS) {
        LOGE("Failed to add pseudonym id hex to payload!");
        HcFree(hexStr);
        return HC_ERR_JSON_ADD;
    }
    HcFree(hexStr);
    return HC_SUCCESS;
}

static int32_t AddPseudonymChallengeToPayload(CJson *payload, const Uint8Buff *pseudonymChlgBuff)
{
    uint32_t hexLen = pseudonymChlgBuff->length * BYTE_TO_HEX_OPER_LENGTH + 1;
    char *hexStr = (char *)HcMalloc(hexLen, 0);
    if (hexStr == NULL) {
        LOGE("Failed to alloc memory for pseudonym challenge hex!");
        return HC_ERR_ALLOC_MEMORY;
    }
    int32_t res = ByteToHexString(pseudonymChlgBuff->val, pseudonymChlgBuff->length, hexStr, hexLen);
    if (res != HC_SUCCESS) {
        LOGE("Failed to convert pseudonym challenge from byte to hex!");
        HcFree(hexStr);
        return res;
    }
    Uint8Buff hexBuff = {
        .val = (uint8_t *)hexStr,
        .length = HcStrlen(hexStr)
    };
    res = ToLowerCase(&hexBuff);
    if (res != HC_SUCCESS) {
        LOGE("Failed to convert pseudonym challenge hex to lower case!");
        HcFree(hexStr);
        return res;
    }
    if (AddStringToJson(payload, FIELD_PSEUDONYM_CHALLENGE, hexStr) != HC_SUCCESS) {
        LOGE("Failed to add pseudonym challenge hex to payload!");
        HcFree(hexStr);
        return HC_ERR_JSON_ADD;
    }
    HcFree(hexStr);
    return HC_SUCCESS;
}

static int32_t GenerateSelfPseudonymChlgAndId(const PakeParams *params, Uint8Buff *pseudonymChlgBuff,
    Uint8Buff *pseudonymIdBuff)
{
    int32_t res = GeneratePseudonymPskIfNotExist(params);
    if (res != HC_SUCCESS) {
        return res;
    }
    res = params->baseParams.loader->generateRandom(pseudonymChlgBuff);
    if (res != HC_SUCCESS) {
        LOGE("Failed to generate pseudonym challenge!");
        return res;
    }
    Uint8Buff serviceTypeBuff = { (uint8_t *)params->serviceType, HcStrlen(params->serviceType) };
    uint8_t pskAliasVal[PAKE_KEY_ALIAS_LEN] = { 0 };
    Uint8Buff pskAlias = { pskAliasVal, PAKE_KEY_ALIAS_LEN };
    res = GeneratePseudonymPskAlias(&serviceTypeBuff, &(params->baseParams.idPeer), &pskAlias);
    if (res != HC_SUCCESS) {
        LOGE("Failed to generate pseudonym psk alias!");
        return res;
    }
    res = ToLowerCase(&pskAlias);
    if (res != HC_SUCCESS) {
        LOGE("Failed to convert pseudonym psk alias to lower case!");
        return res;
    }
    KeyParams pskAliasParams = { { pskAlias.val, pskAlias.length, true }, true, params->baseParams.osAccountId };
    res = params->baseParams.loader->computeHmacWithThreeStage(&pskAliasParams, pseudonymChlgBuff, pseudonymIdBuff);
    if (res != HC_SUCCESS) {
        LOGE("Failed to generate pseudonym id!");
    }
    return res;
}

static int32_t GetSelfPseudonymChlgAndIdByExtInfo(const PakeParams *params, Uint8Buff *pseudonymChallengeBuff,
    Uint8Buff *pseudonymIdBuff)
{
    if (memcpy_s(pseudonymChallengeBuff->val, pseudonymChallengeBuff->length,
        params->pseudonymExtInfo.selfNextPseudonymChallenge.val,
        params->pseudonymExtInfo.selfNextPseudonymChallenge.length) != EOK) {
        LOGE("Failed to copy pseudonym challenge!");
        return HC_ERR_MEMORY_COPY;
    }
    if (memcpy_s(pseudonymIdBuff->val, pseudonymIdBuff->length, params->pseudonymExtInfo.selfNextPseudonymId.val,
        params->pseudonymExtInfo.selfNextPseudonymId.length) != EOK) {
        LOGE("Failed to copy pseudonym id!");
        return HC_ERR_MEMORY_COPY;
    }
    return HC_SUCCESS;
}

int32_t AddPseudonymIdAndChallenge(PakeParams *params, CJson *payload)
{
    if (params == NULL || payload == NULL) {
        LOGE("Invalid params!");
        return HC_ERR_INVALID_PARAMS;
    }
    uint8_t pseudonymChallenge[PSEUDONYM_CHALLENGE_LEN] = { 0 };
    Uint8Buff pseudonymChallengeBuff = { pseudonymChallenge, PSEUDONYM_CHALLENGE_LEN };
    uint8_t pseudonymId[PSEUDONYM_ID_LEN] = { 0 };
    Uint8Buff pseudonymIdBuff = { pseudonymId, PSEUDONYM_ID_LEN };
    int32_t res;
    if (params->pseudonymExtInfo.selfNextPseudonymId.val == NULL ||
        params->pseudonymExtInfo.selfNextPseudonymChallenge.val == NULL) {
        LOGW("Saved next pseudonym id or challenge is null, generate it!");
        res = GenerateSelfPseudonymChlgAndId(params, &pseudonymChallengeBuff, &pseudonymIdBuff);
    } else {
        LOGI("Saved next pseudonym id or challenge is not null, use it directly.");
        res = GetSelfPseudonymChlgAndIdByExtInfo(params, &pseudonymChallengeBuff, &pseudonymIdBuff);
    }
    if (res != HC_SUCCESS) {
        return res;
    }
    Uint8Buff nextPseudonymChallengeBuff = { params->selfNextPseudonymChallenge, PSEUDONYM_CHALLENGE_LEN };
    res = params->baseParams.loader->generateRandom(&nextPseudonymChallengeBuff);
    if (res != HC_SUCCESS) {
        LOGE("Failed to generate next pseudonym challenge!");
        return res;
    }
    res = AddPseudonymIdToPayload(payload, &pseudonymIdBuff);
    if (res != HC_SUCCESS) {
        LOGE("Failed to add pdid to payload!");
        return res;
    }
    uint8_t combinedChallenge[PSEUDONYM_COMBINE_CHALLENGE_LEN] = { 0 };
    Uint8Buff combinedChallengeBuff = { combinedChallenge, PSEUDONYM_COMBINE_CHALLENGE_LEN };
    res = CombinePseudonymChallenge(&combinedChallengeBuff, &pseudonymChallengeBuff, &nextPseudonymChallengeBuff);
    if (res != HC_SUCCESS) {
        LOGE("Failed to combine pseudonym challenge!");
        return res;
    }
    res = AddPseudonymChallengeToPayload(payload, &combinedChallengeBuff);
    if (res != HC_SUCCESS) {
        LOGE("Failed to add pdChlg to payload!");
    }
    return res;
}

static int32_t CheckPseudonymIdByCompute(const PakeParams *params, const Uint8Buff *peerPseudonymChallengeBuff,
    const Uint8Buff *peerPseudonymIdBuff, bool *isEqual)
{
    int32_t res = GeneratePseudonymPskIfNotExist(params);
    if (res != HC_SUCCESS) {
        LOGE("Failed to generate pseudonym psk!");
        return res;
    }
    Uint8Buff serviceTypeBuff = { (uint8_t *)params->serviceType, HcStrlen(params->serviceType) };
    uint8_t pskAliasVal[PAKE_KEY_ALIAS_LEN] = { 0 };
    Uint8Buff pskAlias = { pskAliasVal, PAKE_KEY_ALIAS_LEN };
    res = GeneratePseudonymPskAlias(&serviceTypeBuff, &(params->baseParams.idPeer), &pskAlias);
    if (res != HC_SUCCESS) {
        LOGE("Failed to generate pseudonym psk alias!");
        return res;
    }
    res = ToLowerCase(&pskAlias);
    if (res != HC_SUCCESS) {
        LOGE("Failed to convert pseudonym psk alias to lower case!");
        return res;
    }
    uint8_t computePeerPseudonymId[PSEUDONYM_ID_LEN] = { 0 };
    Uint8Buff computePeerPseudonymIdBuff = { computePeerPseudonymId, PSEUDONYM_ID_LEN };
    KeyParams pskAliasParams = { { pskAlias.val, pskAlias.length, true }, true, params->baseParams.osAccountId };
    res = params->baseParams.loader->computeHmacWithThreeStage(&pskAliasParams, peerPseudonymChallengeBuff,
        &computePeerPseudonymIdBuff);
    if (res != HC_SUCCESS) {
        LOGE("Failed to generate peer pseudonym id!");
        return res;
    }
    *isEqual = (memcmp(peerPseudonymIdBuff->val, computePeerPseudonymId, PSEUDONYM_ID_LEN) == 0);
    return HC_SUCCESS;
}

static int32_t GetPeerChallenge(const CJson *payload, Uint8Buff *peerPseudonymChallengeBuff, PakeParams *params)
{
    uint8_t peerChallenge[PSEUDONYM_COMBINE_CHALLENGE_LEN] = { 0 };
    if (GetByteFromJson(payload, FIELD_PSEUDONYM_CHALLENGE, peerChallenge,
        PSEUDONYM_COMBINE_CHALLENGE_LEN) != HC_SUCCESS) {
        LOGE("Failed to get peer challenge!");
        return HC_ERR_JSON_GET;
    }
    if (memcpy_s(peerPseudonymChallengeBuff->val, PSEUDONYM_CHALLENGE_LEN, peerChallenge,
        PSEUDONYM_CHALLENGE_LEN) != EOK) {
        LOGE("Failed to copy peer pseudonym challenge!");
        return HC_ERR_MEMORY_COPY;
    }
    if (memcpy_s(params->peerNextPseudonymChallenge, PSEUDONYM_CHALLENGE_LEN,
        peerChallenge + PSEUDONYM_CHALLENGE_LEN, PSEUDONYM_CHALLENGE_LEN) != EOK) {
        LOGE("Failed to copy peer next pseudonym challenge!");
        return HC_ERR_MEMORY_COPY;
    }
    return HC_SUCCESS;
}

int32_t CheckPseudonymId(PakeParams *params, const CJson *in)
{
    if (params == NULL || in == NULL) {
        LOGE("Invalid params!");
        return HC_ERR_INVALID_PARAMS;
    }
    const CJson *payload = GetObjFromJson(in, FIELD_PAYLOAD);
    if (payload == NULL) {
        LOGE("Failed to get payload!");
        return HC_ERR_JSON_GET;
    }
    uint8_t peerPseudonymId[PSEUDONYM_ID_LEN] = { 0 };
    if (GetByteFromJson(payload, FIELD_P2P_PSEUDONYM_ID, peerPseudonymId, PSEUDONYM_ID_LEN) != HC_SUCCESS) {
        LOGE("Failed to get peer pseudonym id!");
        return HC_ERR_JSON_GET;
    }
    uint8_t peerPseudonymChallenge[PSEUDONYM_CHALLENGE_LEN] = { 0 };
    Uint8Buff peerPseudonymChallengeBuff = { peerPseudonymChallenge, PSEUDONYM_CHALLENGE_LEN };
    int32_t res = GetPeerChallenge(payload, &peerPseudonymChallengeBuff, params);
    if (res != HC_SUCCESS) {
        return res;
    }
    bool isEqual = false;
    if (params->pseudonymExtInfo.peerNextPseudonymId.val != NULL) {
        isEqual = (memcmp(peerPseudonymId, params->pseudonymExtInfo.peerNextPseudonymId.val, PSEUDONYM_ID_LEN) == 0);
    }
    if (!isEqual) {
        Uint8Buff peerPseudonymIdBuff = { peerPseudonymId, PSEUDONYM_ID_LEN };
        res = CheckPseudonymIdByCompute(params, &peerPseudonymChallengeBuff, &peerPseudonymIdBuff, &isEqual);
        if (res != HC_SUCCESS) {
            LOGE("Failed to check pseudonym id by compute!");
            return res;
        }
    }
    if (!isEqual) {
        LOGE("Check pseudonym id failed!");
        return HC_ERR_MEMORY_COMPARE;
    }
    LOGI("Check pseudonym id succeed.");
    return HC_SUCCESS;
}

static int32_t GeneratePseudonymPskExtInfo(const PakeParams *params, const Uint8Buff *selfNextPseudonymIdBuff,
    const Uint8Buff *peerNextPseudonymIdBuff, Uint8Buff *extInfoBuff)
{
    CJson *extInfoJson = CreateJson();
    if (extInfoJson == NULL) {
        LOGE("Failed to create extInfo json!");
        return HC_ERR_JSON_CREATE;
    }
    if (AddByteToJson(extInfoJson, FIELD_SELF_NEXT_PSEUDONYM_ID, selfNextPseudonymIdBuff->val,
        PSEUDONYM_ID_LEN) != HC_SUCCESS) {
        LOGE("Failed to add self next pseudonym id!");
        FreeJson(extInfoJson);
        return HC_ERR_JSON_ADD;
    }
    if (AddByteToJson(extInfoJson, FIELD_SELF_NEXT_PSEUDONYM_CHALLENGE, params->selfNextPseudonymChallenge,
        PSEUDONYM_CHALLENGE_LEN) != HC_SUCCESS) {
        LOGE("Failed to add self next pseudonym challenge!");
        FreeJson(extInfoJson);
        return HC_ERR_JSON_ADD;
    }
    if (AddByteToJson(extInfoJson, FIELD_PEER_NEXT_PSEUDONYM_ID, peerNextPseudonymIdBuff->val,
        PSEUDONYM_ID_LEN) != HC_SUCCESS) {
        LOGE("Failed to add peer next pseudonym id!");
        FreeJson(extInfoJson);
        return HC_ERR_JSON_ADD;
    }
    char *extInfoJsonStr = PackJsonToString(extInfoJson);
    FreeJson(extInfoJson);
    if (extInfoJsonStr == NULL) {
        LOGE("Failed to pack extInfo json to string!");
        return HC_ERR_PACKAGE_JSON_TO_STRING_FAIL;
    }
    extInfoBuff->val = (uint8_t *)extInfoJsonStr;
    extInfoBuff->length = HcStrlen(extInfoJsonStr) + 1;
    return HC_SUCCESS;
}

static int32_t SaveExtInfoToPseudonymPsk(const PakeParams *params, const Uint8Buff *extInfoStrBuff,
    const Uint8Buff *pskAliasBuff)
{
    uint8_t baseKeyAliasVal[PAKE_KEY_ALIAS_LEN] = { 0 };
    Uint8Buff baseKeyAlias = { baseKeyAliasVal, PAKE_KEY_ALIAS_LEN };
    TokenManagerParams tokenParams = { 0 };
    tokenParams.pkgName.val = (uint8_t *)params->packageName;
    tokenParams.pkgName.length = HcStrlen(params->packageName);
    tokenParams.serviceType.val = (uint8_t *)params->serviceType;
    tokenParams.serviceType.length = HcStrlen(params->serviceType);
    tokenParams.userType = KEY_ALIAS_PSK;
    tokenParams.authId = params->baseParams.idPeer;
    int32_t res = GenerateKeyAlias(&tokenParams, &baseKeyAlias);
    if (res != HC_SUCCESS) {
        LOGE("Failed to generate psk alias!");
        return res;
    }
    res = ToLowerCase(&baseKeyAlias);
    if (res != HC_SUCCESS) {
        LOGE("Failed to convert psk alias to lower case!");
        return res;
    }
    uint8_t outKeyVal[PAKE_PSK_LEN] = { 0 };
    Uint8Buff outKeyBuff = { outKeyVal, PAKE_PSK_LEN };
    KeyParams keyParams = { { baseKeyAlias.val, baseKeyAlias.length, true }, true, params->baseParams.osAccountId };
    res = params->baseParams.loader->computePseudonymPsk(&keyParams, pskAliasBuff, extInfoStrBuff,
        &outKeyBuff);
    if (res != HC_SUCCESS) {
        LOGE("Failed to save extInfo to pseudonym psk!");
    }
    return res;
}

int32_t SaveNextPseudonymIdAndChallenge(PakeParams *params)
{
    int32_t res = GeneratePseudonymPskIfNotExist(params);
    if (res != HC_SUCCESS) {
        return res;
    }
    Uint8Buff serviceTypeBuff = { (uint8_t *)params->serviceType, HcStrlen(params->serviceType) };
    uint8_t pskAliasVal[PAKE_KEY_ALIAS_LEN] = { 0 };
    Uint8Buff pskAlias = { pskAliasVal, PAKE_KEY_ALIAS_LEN };
    res = GeneratePseudonymPskAlias(&serviceTypeBuff, &(params->baseParams.idPeer), &pskAlias);
    if (res != HC_SUCCESS) {
        LOGE("Failed to generate pseudonym psk alias!");
        return res;
    }
    res = ToLowerCase(&pskAlias);
    if (res != HC_SUCCESS) {
        LOGE("Failed to convert pseudonym psk alias to lower case!");
        return res;
    }
    uint8_t selfNextPseudonymId[PSEUDONYM_ID_LEN] = { 0 };
    Uint8Buff selfNextPseudonymIdBuff = { selfNextPseudonymId, PSEUDONYM_ID_LEN };
    Uint8Buff selfNextPseudonymChallengeBuff = { params->selfNextPseudonymChallenge, PSEUDONYM_CHALLENGE_LEN };
    KeyParams pskAliasParams = { { pskAlias.val, pskAlias.length, true }, true, params->baseParams.osAccountId };
    res = params->baseParams.loader->computeHmacWithThreeStage(&pskAliasParams, &selfNextPseudonymChallengeBuff,
        &selfNextPseudonymIdBuff);
    if (res != HC_SUCCESS) {
        LOGE("Failed to compute next self pseudonym id!");
        return res;
    }
    uint8_t peerNextPseudonymId[PSEUDONYM_ID_LEN] = { 0 };
    Uint8Buff peerNextPseudonymIdBuff = { peerNextPseudonymId, PSEUDONYM_ID_LEN };
    Uint8Buff peerNextPseudonymChallengeBuff = { params->peerNextPseudonymChallenge, PSEUDONYM_CHALLENGE_LEN };
    res = params->baseParams.loader->computeHmacWithThreeStage(&pskAliasParams, &peerNextPseudonymChallengeBuff,
        &peerNextPseudonymIdBuff);
    if (res != HC_SUCCESS) {
        LOGE("Failed to compute next peer pseudonym id!");
        return res;
    }
    Uint8Buff extInfoStrBuff = { NULL, 0 };
    res = GeneratePseudonymPskExtInfo(params, &selfNextPseudonymIdBuff, &peerNextPseudonymIdBuff, &extInfoStrBuff);
    if (res != HC_SUCCESS) {
        return res;
    }
    res = SaveExtInfoToPseudonymPsk(params, &extInfoStrBuff, &pskAlias);
    FreeJsonString((char *)extInfoStrBuff.val);
    return res;
}