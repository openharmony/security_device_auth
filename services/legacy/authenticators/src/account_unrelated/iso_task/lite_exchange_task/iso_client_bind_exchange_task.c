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

#include "iso_client_bind_exchange_task.h"
#include "alg_defs.h"
#include "das_task_common.h"
#include "das_module_defines.h"
#include "hc_log.h"
#include "hc_types.h"
#include "iso_protocol_common.h"
#include "iso_task_common.h"
#include "securec.h"

enum {
    TASK_TYPE_BEGIN = 1,
    TASK_TYPE_FINAL,
};

static CurTaskType GetTaskType(void)
{
    return TASK_TYPE_BIND_LITE_EXCHANGE;
}

static void DestroyCreateClientBindExchangeTask(struct SymBaseCurTaskT *task)
{
    HcFree(task);
}

static int DecAndImportInner(IsoClientBindExchangeTask *realTask, const IsoParams *params,
    const Uint8Buff *nonceBuf, const Uint8Buff *encDataBuf, Uint8Buff *authCodeBuf)
{
    int res;
    uint8_t *keyAliasVal = (uint8_t *)HcMalloc(ISO_KEY_ALIAS_LEN, 0);
    if (keyAliasVal == NULL) {
        res = HC_ERR_ALLOC_MEMORY;
        goto ERR;
    }
    Uint8Buff keyAlias = { keyAliasVal, ISO_KEY_ALIAS_LEN };
    GcmParam gcmParam;
    gcmParam.aad = realTask->challenge;
    gcmParam.aadLen = sizeof(realTask->challenge);
    gcmParam.nonce = nonceBuf->val;
    gcmParam.nonceLen = nonceBuf->length;
    KeyParams keyParams = {
        { params->baseParams.sessionKey.val, params->baseParams.sessionKey.length, false },
        false,
        params->baseParams.osAccountId
    };
    res = params->baseParams.loader->aesGcmDecrypt(&keyParams, encDataBuf, &gcmParam, authCodeBuf);
    if (res != 0) {
        LOGE("gcm decrypt failed, res:%" LOG_PUB "d", res);
        goto ERR;
    }
    res = GenerateKeyAliasInIso(params, keyAliasVal, ISO_KEY_ALIAS_LEN, true);
    if (res != 0) {
        LOGE("GenerateKeyAliasInIso failed, res:%" LOG_PUB "d", res);
        goto ERR;
    }

    LOGI("AuthCode alias(HEX): %" LOG_PUB "x%" LOG_PUB "x%" LOG_PUB "x%" LOG_PUB "x****.", keyAliasVal[DEV_AUTH_ZERO],
        keyAliasVal[DEV_AUTH_ONE], keyAliasVal[DEV_AUTH_TWO], keyAliasVal[DEV_AUTH_THREE]);
    ExtraInfo exInfo = { { params->baseParams.authIdPeer.val, params->baseParams.authIdPeer.length },
        params->peerUserType, PAIR_TYPE_BIND };
    KeyParams keyAliasParams = { { keyAlias.val, keyAlias.length, true }, false, params->baseParams.osAccountId };
    res = params->baseParams.loader->importSymmetricKey(&keyAliasParams, authCodeBuf, KEY_PURPOSE_MAC, &exInfo);
    if (res != 0) {
        LOGE("ImportSymmetricKey failed, res: %" LOG_PUB "x.", res);
        goto ERR;
    }
ERR:
    HcFree(keyAliasVal);
    return res;
}

static int DecAndImportAuthCode(IsoClientBindExchangeTask *realTask, const IsoParams *params, const CJson *in)
{
    uint8_t *nonce = NULL;
    uint8_t *encData = NULL;
    uint8_t *authCode = NULL;
    int encDataLen = AUTH_CODE_LEN + TAG_LEN;
    int res;
    nonce = (uint8_t *)HcMalloc(NONCE_SIZE, 0);
    if (nonce == NULL) {
        res = HC_ERR_ALLOC_MEMORY;
        goto ERR;
    }
    encData = (uint8_t *)HcMalloc(encDataLen, 0);
    if (encData == NULL) {
        res = HC_ERR_ALLOC_MEMORY;
        goto ERR;
    }
    GOTO_ERR_AND_SET_RET(GetByteFromJson(in, FIELD_NONCE, nonce, NONCE_SIZE), res);
    GOTO_ERR_AND_SET_RET(GetByteFromJson(in, FIELD_ENC_AUTH_TOKEN, encData, encDataLen), res);

    Uint8Buff encDataBuf = { encData, encDataLen };
    authCode = (uint8_t *)HcMalloc(AUTH_CODE_LEN, 0);
    if (authCode == NULL) {
        res = HC_ERR_ALLOC_MEMORY;
        goto ERR;
    }
    Uint8Buff authCodeBuf = { authCode, AUTH_CODE_LEN };
    Uint8Buff nonceBuf = { nonce, NONCE_SIZE };

    res = DecAndImportInner(realTask, params, &nonceBuf, &encDataBuf, &authCodeBuf);
    if (res != 0) {
        LOGE("DecAndImportInner failed, res:%" LOG_PUB "d", res);
    }
ERR:
    HcFree(nonce);
    HcFree(encData);
    if (authCode != NULL) {
        (void)memset_s(authCode, AUTH_CODE_LEN, 0, AUTH_CODE_LEN);
    }
    HcFree(authCode);
    return res;
}

static int Process(struct SymBaseCurTaskT *task, IsoParams *params, const CJson *in, CJson *out, int32_t *status)
{
    IsoClientBindExchangeTask *realTask = (IsoClientBindExchangeTask *)task;
    if (realTask->taskBase.taskStatus < TASK_TYPE_BEGIN) {
        LOGE("Invalid taskStatus: %" LOG_PUB "d", realTask->taskBase.taskStatus);
        return HC_ERR_BAD_MESSAGE;
    }
    if (realTask->taskBase.taskStatus > TASK_TYPE_BEGIN) {
        LOGI("Message is repeated, ignore it, status: %" LOG_PUB "d.", realTask->taskBase.taskStatus);
        *status = IGNORE_MSG;
        return HC_SUCCESS;
    }
    int32_t message = 0;
    int res;
    res = GetIntFromJson(in, FIELD_MESSAGE, &message);
    if (res != 0 || message != ISO_SERVER_BIND_EXCHANGE_RET) {
        return HC_ERR_BAD_MESSAGE;
    }
    res = DecAndImportAuthCode(realTask, params, in);
    if (res != 0) {
        LOGE("dec and import authCode failed, res:%" LOG_PUB "d", res);
        return res;
    }
    res = GenEncResult(params, ISO_CLIENT_BIND_EXCHANGE_CONFIRM, out, RESULT_AAD, false);
    if (res == HC_SUCCESS) {
        realTask->taskBase.taskStatus = TASK_TYPE_FINAL;
        *status = FINISH;
    }
    return res;
}

static int ClientBindAesEncrypt(IsoClientBindExchangeTask *task, const IsoParams *params,
    uint8_t **encData, uint8_t **nonce)
{
    Uint8Buff challengeBuf = { task->challenge, sizeof(task->challenge) };
    int res = params->baseParams.loader->generateRandom(&challengeBuf);
    if (res != 0) {
        LOGE("generate random failed, res:%" LOG_PUB "d", res);
        return res;
    }
    *nonce = (uint8_t *)HcMalloc(NONCE_SIZE, 0);
    if (*nonce == NULL) {
        LOGE("malloc nonce failed");
        return HC_ERR_ALLOC_MEMORY;
    }
    Uint8Buff nonceBuf = { *nonce, NONCE_SIZE };
    res = params->baseParams.loader->generateRandom(&nonceBuf);
    if (res != 0) {
        LOGE("generateRandom failed, res:%" LOG_PUB "d", res);
        return res;
    }
    *encData = (uint8_t *)HcMalloc(sizeof(task->challenge) + TAG_LEN, 0);
    if (*encData == NULL) {
        return HC_ERR_ALLOC_MEMORY;
    }
    GcmParam gcmParams;
    gcmParams.aad = (uint8_t *)EXCHANGE_AAD;
    gcmParams.aadLen = (uint32_t)HcStrlen(EXCHANGE_AAD);
    gcmParams.nonce = *nonce;
    gcmParams.nonceLen = NONCE_SIZE;
    Uint8Buff outBuf = { *encData, sizeof(task->challenge) + TAG_LEN };
    KeyParams keyParams = {
        { params->baseParams.sessionKey.val, params->baseParams.sessionKey.length, false },
        false,
        params->baseParams.osAccountId
    };
    res = params->baseParams.loader->aesGcmEncrypt(&keyParams, &challengeBuf, &gcmParams, &outBuf);
    if (res != 0) {
        LOGE("encrypt failed, res:%" LOG_PUB "d", res);
        return res;
    }
    return res;
}

static int ClientBindExchangeStart(const IsoParams *params, IsoClientBindExchangeTask *task, CJson *out,
                                   int32_t *status)
{
    uint8_t *nonce = NULL;
    uint8_t *encData = NULL;
    CJson *payload = NULL;
    CJson *sendToPeer = NULL;

    // execute
    int res = ClientBindAesEncrypt(task, params, &encData, &nonce);
    if (res != 0) {
        goto ERR;
    }

    // package message
    sendToPeer = CreateJson();
    if (sendToPeer == NULL) {
        res = HC_ERR_ALLOC_MEMORY;
        goto ERR;
    }
    payload = CreateJson();
    if (payload == NULL) {
        res = HC_ERR_ALLOC_MEMORY;
        goto ERR;
    }
    GOTO_ERR_AND_SET_RET(AddIntToJson(sendToPeer, FIELD_MESSAGE, ISO_CLIENT_BIND_EXCHANGE_CMD), res);
    GOTO_ERR_AND_SET_RET(AddByteToJson(payload, FIELD_NONCE, nonce, NONCE_SIZE), res);
    GOTO_ERR_AND_SET_RET(AddByteToJson(payload, FIELD_ENC_DATA, encData, sizeof(task->challenge) + TAG_LEN), res);
    GOTO_ERR_AND_SET_RET(AddObjToJson(sendToPeer, FIELD_PAYLOAD, payload), res);
    GOTO_ERR_AND_SET_RET(AddObjToJson(out, FIELD_SEND_TO_PEER, sendToPeer), res);

    task->taskBase.taskStatus = TASK_TYPE_BEGIN;
    *status = CONTINUE;
ERR:
    FreeJson(payload);
    FreeJson(sendToPeer);
    HcFree(nonce);
    HcFree(encData);
    return res;
}

SymBaseCurTask *CreateClientBindExchangeTask(IsoParams *params, const CJson *in, CJson *out, int32_t *status)
{
    (void)in;
    IsoClientBindExchangeTask *task = (IsoClientBindExchangeTask *)HcMalloc(sizeof(IsoClientBindExchangeTask), 0);
    if (task == NULL) {
        LOGE("Failed to malloc client bind exchange task.");
        return NULL;
    }
    task->taskBase.destroyTask = DestroyCreateClientBindExchangeTask;
    task->taskBase.process = Process;
    task->taskBase.getCurTaskType = GetTaskType;
    int res = ClientBindExchangeStart(params, task, out, status);
    if (res != 0) {
        DestroyCreateClientBindExchangeTask((struct SymBaseCurTaskT *)task);
        return NULL;
    }
    return (SymBaseCurTask *)task;
}
