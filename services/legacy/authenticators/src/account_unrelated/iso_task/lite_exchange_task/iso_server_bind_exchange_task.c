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

#include "iso_server_bind_exchange_task.h"
#include "das_task_common.h"
#include "das_module_defines.h"
#include "hc_log.h"
#include "hc_types.h"
#include "iso_protocol_common.h"
#include "iso_task_common.h"
#include "protocol_common.h"

enum {
    TASK_TYPE_BEGIN = 1,
    TASK_TYPE_FINAL,
};

static CurTaskType GetTaskType(void)
{
    return TASK_TYPE_BIND_LITE_EXCHANGE;
}

void DestroyServerBindExchangeTask(struct SymBaseCurTaskT *task)
{
    HcFree(task);
}

static int Process(struct SymBaseCurTaskT *task, IsoParams *params, const CJson *in, CJson *out, int32_t *status)
{
    IsoServerBindExchangeTask *realTask = (IsoServerBindExchangeTask *)task;
    if (realTask->taskBase.taskStatus < TASK_TYPE_BEGIN) {
        LOGE("task status failed");
        return HC_ERR_BAD_MESSAGE;
    }

    if (realTask->taskBase.taskStatus > TASK_TYPE_BEGIN) {
        LOGI("Message is repeated, ignore it, status: %" LOG_PUB "d.", realTask->taskBase.taskStatus);
        *status = IGNORE_MSG;
        return HC_SUCCESS;
    }
    int res;
    int32_t message = 0;
    res = GetIntFromJson(in, FIELD_MESSAGE, &message);
    if (res != 0 || message != ISO_CLIENT_BIND_EXCHANGE_CONFIRM) {
        return HC_ERR_BAD_MESSAGE;
    }
    res = CheckEncResult(params, in, RESULT_AAD);
    if (res != 0) {
        LOGE("CheckEncResult failed, res:%" LOG_PUB "d", res);
        DeleteAuthCode(params);
        return res;
    }
    res = SendResultToFinalSelf(params, out, false);
    if (res != 0) {
        LOGE("SendResultToFinalSelf failed, res:%" LOG_PUB "d", res);
        DeleteAuthCode(params);
        return res;
    }
    realTask->taskBase.taskStatus = TASK_TYPE_FINAL;
    *status = FINISH;
    return res;
}

static int DecryptChallenge(const IsoParams *params, const CJson *in, uint8_t *challenge, uint32_t challengeLen)
{
    (void)challengeLen;
    int res;
    uint8_t *encData = NULL;
    uint8_t *nonce = NULL;

    encData = (uint8_t *)HcMalloc(ENC_CHALLENGE_LEN, 0);
    if (encData == NULL) {
        res = HC_ERR_ALLOC_MEMORY;
        goto ERR;
    }
    GOTO_ERR_AND_SET_RET(GetByteFromJson(in, FIELD_ENC_DATA, encData, ENC_CHALLENGE_LEN), res);
    nonce = (uint8_t *)HcMalloc(NONCE_SIZE, 0);
    if (nonce == NULL) {
        res = HC_ERR_ALLOC_MEMORY;
        goto ERR;
    }
    GOTO_ERR_AND_SET_RET(GetByteFromJson(in, FIELD_NONCE, nonce, NONCE_SIZE), res);
    Uint8Buff encDataBuf = { encData, ENC_CHALLENGE_LEN };
    GcmParam gcmParam;
    gcmParam.aad = (uint8_t *)EXCHANGE_AAD;
    gcmParam.aadLen = (uint32_t)HcStrlen(EXCHANGE_AAD);
    gcmParam.nonce = nonce;
    gcmParam.nonceLen = NONCE_SIZE;
    Uint8Buff challengeBuf = { challenge, CHALLENGE_SIZE };
    KeyParams keyParams = {
        { params->baseParams.sessionKey.val, params->baseParams.sessionKey.length, false },
        false,
        params->baseParams.osAccountId
    };
    res = params->baseParams.loader->aesGcmDecrypt(&keyParams, &encDataBuf, &gcmParam, &challengeBuf);
    if (res != 0) {
        LOGE("decrypt challenge failed, res:%" LOG_PUB "d", res);
        goto ERR;
    }
ERR:
    HcFree(encData);
    HcFree(nonce);
    return res;
}

static int32_t ImportAuthCode(const IsoParams *params, const Uint8Buff *authCodeBuf)
{
    uint8_t *keyAlias = (uint8_t *)HcMalloc(ISO_KEY_ALIAS_LEN, 0);
    if (keyAlias == NULL) {
        LOGE("Failed to alloc memory for keyAlias!");
        return HC_ERR_ALLOC_MEMORY;
    }
    int32_t res = GenerateKeyAliasInIso(params, keyAlias, ISO_KEY_ALIAS_LEN, true);
    if (res != 0) {
        LOGE("GenerateKeyAliasInIso failed, res:%" LOG_PUB "d", res);
        HcFree(keyAlias);
        return res;
    }

    LOGI("AuthCode alias(HEX): %" LOG_PUB "x%" LOG_PUB "x%" LOG_PUB "x%" LOG_PUB "x****.", keyAlias[DEV_AUTH_ZERO],
        keyAlias[DEV_AUTH_ONE], keyAlias[DEV_AUTH_TWO], keyAlias[DEV_AUTH_THREE]);
    Uint8Buff keyAliasBuf = { keyAlias, ISO_KEY_ALIAS_LEN };
    ExtraInfo exInfo = { { params->baseParams.authIdPeer.val, params->baseParams.authIdPeer.length },
        params->peerUserType, PAIR_TYPE_BIND };
    KeyParams keyAliasParams = { { keyAliasBuf.val, keyAliasBuf.length, true }, false, params->baseParams.osAccountId };
    res = params->baseParams.loader->importSymmetricKey(&keyAliasParams, authCodeBuf, KEY_PURPOSE_MAC, &exInfo);
    HcFree(keyAlias);
    return res;
}

static int GenAndEncAuthCode(const IsoParams *params, Uint8Buff *nonceBuf, const Uint8Buff *challengeBuf,
    Uint8Buff *encAuthCodeBuf)
{
    int res;
    uint8_t *authCode = (uint8_t *)HcMalloc(AUTH_CODE_LEN, 0);
    if (authCode == NULL) {
        res = HC_ERR_ALLOC_MEMORY;
        goto ERR;
    }
    Uint8Buff authCodeBuf = { authCode, AUTH_CODE_LEN };
    res = params->baseParams.loader->generateRandom(&authCodeBuf);
    if (res != 0) {
        LOGE("generate auth code failed, res:%" LOG_PUB "d", res);
        goto ERR;
    }

    res = params->baseParams.loader->generateRandom(nonceBuf);
    if (res != 0) {
        LOGE("generate nonce failed, res:%" LOG_PUB "d", res);
        goto ERR;
    }
    GcmParam gcmParam = { nonceBuf->val, nonceBuf->length, challengeBuf->val, challengeBuf->length };
    KeyParams keyParams = {
        { params->baseParams.sessionKey.val, params->baseParams.sessionKey.length, false },
        false,
        params->baseParams.osAccountId
    };
    res = params->baseParams.loader->aesGcmEncrypt(&keyParams, &authCodeBuf, &gcmParam, encAuthCodeBuf);
    if (res != 0) {
        LOGE("encrypt auth code failed, res:%" LOG_PUB "d", res);
        goto ERR;
    }

    res = ImportAuthCode(params, &authCodeBuf);
    if (res != 0) {
        LOGE("Import auth code failed, res: %" LOG_PUB "x.", res);
        goto ERR;
    }
ERR:
    FreeAndCleanKey(&authCodeBuf);
    return res;
}

static int GenerateAuthCodeAndImport(const IsoParams *params, CJson *out, uint8_t *challenge, uint32_t challengeLen)
{
    int res;
    uint8_t *nonce = NULL;
    uint8_t *encAuthCode = NULL;
    CJson *payload = NULL;
    CJson *sendToPeer = NULL;

    nonce = (uint8_t *)HcMalloc(NONCE_SIZE, 0);
    if (nonce == NULL) {
        res = HC_ERR_ALLOC_MEMORY;
        goto ERR;
    }
    encAuthCode = (uint8_t *)HcMalloc(AUTH_CODE_LEN + TAG_LEN, 0);
    if (encAuthCode == NULL) {
        res = HC_ERR_ALLOC_MEMORY;
        goto ERR;
    }
    Uint8Buff encAuthCodeBuf = { encAuthCode, AUTH_CODE_LEN + TAG_LEN };
    Uint8Buff nonceBuf = { nonce, NONCE_SIZE };
    Uint8Buff challengeBuf = { challenge, challengeLen };

    res = GenAndEncAuthCode(params, &nonceBuf, &challengeBuf, &encAuthCodeBuf);
    if (res != 0) {
        LOGE("GenAndEncAuthCode failed, res:%" LOG_PUB "d", res);
        goto ERR;
    }
    payload = CreateJson();
    if (payload == NULL) {
        res = HC_ERR_ALLOC_MEMORY;
        goto ERR;
    }
    sendToPeer = CreateJson();
    if (sendToPeer == NULL) {
        res = HC_ERR_ALLOC_MEMORY;
        goto ERR;
    }
    GOTO_ERR_AND_SET_RET(AddIntToJson(sendToPeer, FIELD_MESSAGE, ISO_SERVER_BIND_EXCHANGE_RET), res);
    GOTO_ERR_AND_SET_RET(AddByteToJson(payload, FIELD_ENC_AUTH_TOKEN, encAuthCodeBuf.val, encAuthCodeBuf.length), res);
    GOTO_ERR_AND_SET_RET(AddByteToJson(payload, FIELD_NONCE, nonceBuf.val, nonceBuf.length), res);
    GOTO_ERR_AND_SET_RET(AddObjToJson(sendToPeer, FIELD_PAYLOAD, payload), res);
    GOTO_ERR_AND_SET_RET(AddObjToJson(out, FIELD_SEND_TO_PEER, sendToPeer), res);

ERR:
    HcFree(nonce);
    HcFree(encAuthCode);
    FreeJson(payload);
    FreeJson(sendToPeer);
    return res;
}

static int ServerBindExchangeStart(const IsoParams *params, IsoServerBindExchangeTask *task,
    const CJson *in, CJson *out, int32_t *status)
{
    int res;
    uint8_t *challenge = (uint8_t *)HcMalloc(CHALLENGE_SIZE, 0);
    if (challenge == NULL) {
        res = HC_ERR_ALLOC_MEMORY;
        goto ERR;
    }
    res = DecryptChallenge(params, in, challenge, CHALLENGE_SIZE);
    if (res != 0) {
        LOGE("decrypt challenge failed, res:%" LOG_PUB "d", res);
        goto ERR;
    }
    res = GenerateAuthCodeAndImport(params, out, challenge, CHALLENGE_SIZE);
    if (res != 0) {
        LOGE("GenerateAuthCodeAndImport failed, res:%" LOG_PUB "d", res);
        goto ERR;
    }
    task->taskBase.taskStatus = TASK_TYPE_BEGIN;
    *status = CONTINUE;
ERR:
    HcFree(challenge);
    return res;
}

SymBaseCurTask *CreateServerBindExchangeTask(IsoParams *params, const CJson *in, CJson *out, int32_t *status)
{
    IsoServerBindExchangeTask *task = (IsoServerBindExchangeTask *)HcMalloc(sizeof(IsoServerBindExchangeTask), 0);
    if (task == NULL) {
        return NULL;
    }
    task->taskBase.destroyTask = DestroyServerBindExchangeTask;
    task->taskBase.process = Process;
    task->taskBase.getCurTaskType = GetTaskType;
    int res = ServerBindExchangeStart(params, task, in, out, status);
    if (res != 0) {
        DestroyServerBindExchangeTask((struct SymBaseCurTaskT *)task);
        return NULL;
    }
    return (SymBaseCurTask *)task;
}
