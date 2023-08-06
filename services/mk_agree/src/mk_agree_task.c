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

#include "mk_agree_task.h"

#include "alg_loader.h"
#include "common_defs.h"
#include "device_auth_defines.h"
#include "hc_dev_info.h"
#include "hc_log.h"
#include "hc_types.h"
#include "key_manager.h"
#include "uint8buff_utils.h"

#define PAKE_X25519_KEY_PAIR_LEN 32

static int32_t GeneratePakeRequestPayload(PakeMkAgreeTask *pakeTask, CJson *payload)
{
    Uint8Buff saltBuff = { pakeTask->clientSalt, SALT_LEN };
    int32_t res = pakeTask->taskBase.loader->generateRandom(&saltBuff);
    if (res != HC_SUCCESS) {
        LOGE("Failed to generate client salt!");
        return res;
    }
    Uint8Buff devicePk = { NULL, 0 };
    if (InitUint8Buff(&devicePk, PAKE_X25519_KEY_PAIR_LEN) != HC_SUCCESS) {
        LOGE("Failed to init devicePk!");
        return HC_ERR_ALLOC_MEMORY;
    }
    res = GetDevicePubKey(&devicePk);
    if (res != HC_SUCCESS) {
        LOGE("Failed to get device pk!");
        FreeUint8Buff(&devicePk);
        return res;
    }
    if (AddByteToJson(payload, FIELD_SALT, pakeTask->clientSalt, SALT_LEN) != HC_SUCCESS) {
        LOGE("Failed to add salt to payload!");
        ClearFreeUint8Buff(&devicePk);
        return HC_ERR_JSON_ADD;
    }
    if (AddByteToJson(payload, FIELD_PUBLIC_KEY, devicePk.val, devicePk.length) != HC_SUCCESS) {
        LOGE("Failed to add devicePk to payload!");
        ClearFreeUint8Buff(&devicePk);
        return HC_ERR_JSON_ADD;
    }
    ClearFreeUint8Buff(&devicePk);
    return HC_SUCCESS;
}

static int32_t GeneratePakeRequestPayloadData(PakeMkAgreeTask *pakeTask, Uint8Buff *payloadData)
{
    CJson *payload = CreateJson();
    if (payload == NULL) {
        LOGE("Failed to create payload!");
        return HC_ERR_JSON_CREATE;
    }
    int32_t res = GeneratePakeRequestPayload(pakeTask, payload);
    if (res != HC_SUCCESS) {
        LOGE("Failed to generate pake request payload!");
        FreeJson(payload);
        return res;
    }
    char *payloadStr = PackJsonToString(payload);
    FreeJson(payload);
    if (payloadStr == NULL) {
        LOGE("Failed to pack payload json to string!");
        return HC_ERR_PACKAGE_JSON_TO_STRING_FAIL;
    }
    uint32_t payloadLen = HcStrlen(payloadStr);
    if (InitUint8Buff(payloadData, payloadLen + 1) != HC_SUCCESS) {
        LOGE("Failed to init payload data!");
        FreeJsonString(payloadStr);
        return HC_ERR_ALLOC_MEMORY;
    }
    if (memcpy_s(payloadData->val, payloadData->length, payloadStr, payloadLen) != EOK) {
        LOGE("Failed to copy payload!");
        FreeJsonString(payloadStr);
        FreeUint8Buff(payloadData);
        return HC_ERR_MEMORY_COPY;
    }
    FreeJsonString(payloadStr);
    return HC_SUCCESS;
}

static int32_t GeneratePakeResponsePayload(PakeMkAgreeTask *pakeTask, const Uint8Buff *kcfData, CJson *payload)
{
    Uint8Buff devicePk = { NULL, 0 };
    if (InitUint8Buff(&devicePk, PAKE_X25519_KEY_PAIR_LEN) != HC_SUCCESS) {
        LOGE("Failed to init devicePk!");
        return HC_ERR_ALLOC_MEMORY;
    }
    int32_t res = GetDevicePubKey(&devicePk);
    if (res != HC_SUCCESS) {
        LOGE("Failed to get device public key!");
        FreeUint8Buff(&devicePk);
        return res;
    }
    if (AddByteToJson(payload, FIELD_SALT, pakeTask->serverSalt, SALT_LEN) != HC_SUCCESS) {
        LOGE("Failed to add server salt!");
        ClearFreeUint8Buff(&devicePk);
        return HC_ERR_JSON_ADD;
    }
    if (AddByteToJson(payload, FIELD_PUBLIC_KEY, devicePk.val, devicePk.length) != HC_SUCCESS) {
        LOGE("Failed to add device public key!");
        ClearFreeUint8Buff(&devicePk);
        return HC_ERR_JSON_ADD;
    }
    ClearFreeUint8Buff(&devicePk);
    if (AddByteToJson(payload, FIELD_KCF_DATA, kcfData->val, kcfData->length) != HC_SUCCESS) {
        LOGE("Failed to add kcf data!");
        return HC_ERR_JSON_ADD;
    }
    return HC_SUCCESS;
}

static int32_t CombineSalt(const Uint8Buff *firstSalt, const Uint8Buff *secondSalt, Uint8Buff *returnSalt)
{
    int32_t res = InitUint8Buff(returnSalt, firstSalt->length + secondSalt->length);
    if (res != HC_SUCCESS) {
        LOGE("Failed to init return salt!");
        return res;
    }
    if (memcpy_s(returnSalt->val, returnSalt->length, firstSalt->val, firstSalt->length) != EOK) {
        LOGE("Failed to memcpy the first salt!");
        FreeUint8Buff(returnSalt);
        return HC_ERR_MEMORY_COPY;
    }
    if (memcpy_s(returnSalt->val + firstSalt->length, returnSalt->length - firstSalt->length,
        secondSalt->val, secondSalt->length) != EOK) {
        LOGE("Failed to memcpy server salt!");
        FreeUint8Buff(returnSalt);
        return HC_ERR_MEMORY_COPY;
    }
    return HC_SUCCESS;
}

static int32_t ComputeKcfData(PakeMkAgreeTask *pakeTask, const Uint8Buff *firstSalt, const Uint8Buff *secondSalt,
    Uint8Buff *returnKcfData)
{
    Uint8Buff saltBuff = { NULL, 0 };
    int32_t res = CombineSalt(firstSalt, secondSalt, &saltBuff);
    if (res != HC_SUCCESS) {
        LOGE("Failed to combine salt!");
        return res;
    }
    Uint8Buff tmpKcfData = { NULL, 0 };
    PseudonymKeyInfo info = { pakeTask->taskBase.peerInfo, pakeTask->taskBase.pdidIndex };
    res = GenerateAndSavePseudonymId(pakeTask->taskBase.osAccountId, pakeTask->taskBase.peerUdid,
        &info, &saltBuff, &tmpKcfData);
    FreeUint8Buff(&saltBuff);
    if (res != HC_SUCCESS) {
        LOGE("Failed to generate and save pdid!");
        return res;
    }
    returnKcfData->val = tmpKcfData.val;
    returnKcfData->length = tmpKcfData.length;
    return HC_SUCCESS;
}

static int32_t GeneratePakeResponsePayloadData(PakeMkAgreeTask *pakeTask, Uint8Buff *payloadData)
{
    Uint8Buff kcfData = { NULL, 0 };
    if (InitUint8Buff(&kcfData, HMAC_LEN) != HC_SUCCESS) {
        LOGE("Failed to init kcf data!");
        return HC_ERR_ALLOC_MEMORY;
    }
    Uint8Buff clientSaltBuff = { pakeTask->clientSalt, SALT_LEN };
    Uint8Buff serverSaltBuff = { pakeTask->serverSalt, SALT_LEN };
    int32_t res = ComputeKcfData(pakeTask, &serverSaltBuff, &clientSaltBuff, &kcfData);
    if (res != HC_SUCCESS) {
        LOGE("Failed to compute kcf data!");
        FreeUint8Buff(&kcfData);
        return res;
    }
    CJson *payload = CreateJson();
    if (payload == NULL) {
        LOGE("Failed to create payload!");
        ClearFreeUint8Buff(&kcfData);
        return HC_ERR_JSON_CREATE;
    }
    res = GeneratePakeResponsePayload(pakeTask, &kcfData, payload);
    ClearFreeUint8Buff(&kcfData);
    if (res != HC_SUCCESS) {
        LOGE("Failed to generate pake response payload!");
        FreeJson(payload);
        return res;
    }
    char *payloadStr = PackJsonToString(payload);
    FreeJson(payload);
    if (payloadStr == NULL) {
        LOGE("Failed to pack payload json to string!");
        return HC_ERR_PACKAGE_JSON_TO_STRING_FAIL;
    }
    uint32_t payloadLen = HcStrlen(payloadStr);
    if (InitUint8Buff(payloadData, payloadLen + 1) != HC_SUCCESS) {
        LOGE("Failed to init payload data!");
        FreeJsonString(payloadStr);
        return HC_ERR_ALLOC_MEMORY;
    }
    if (memcpy_s(payloadData->val, payloadData->length, payloadStr, payloadLen) != EOK) {
        LOGE("Failed to copy payload!");
        FreeJsonString(payloadStr);
        FreeUint8Buff(payloadData);
        return HC_ERR_MEMORY_COPY;
    }
    FreeJsonString(payloadStr);
    return HC_SUCCESS;
}

static int32_t AddSelfUdidToSendData(CJson *sendData)
{
    char udid[INPUT_UDID_LEN] = { 0 };
    int32_t res = HcGetUdid((uint8_t *)udid, INPUT_UDID_LEN);
    if (res != HC_SUCCESS) {
        LOGE("Failed to get local udid! res: %d", res);
        return res;
    }
    return AddStringToJson(sendData, FIELD_PEER_UDID, udid);
}

static int32_t GeneratePakeRequestData(PakeMkAgreeTask *pakeTask, CJson *out)
{
    Uint8Buff payloadData = { NULL, 0 };
    int32_t res = GeneratePakeRequestPayloadData(pakeTask, &payloadData);
    if (res != HC_SUCCESS) {
        LOGE("Failed to generate pake request payload data!");
        return res;
    }
    CJson *sendData = CreateJson();
    if (sendData == NULL) {
        LOGE("Failed to create send data json!");
        ClearFreeUint8Buff(&payloadData);
        return HC_ERR_JSON_CREATE;
    }
    if (AddByteToJson(sendData, FIELD_PAYLOAD, payloadData.val, payloadData.length) != HC_SUCCESS) {
        LOGE("Failed to add payload data to json!");
        ClearFreeUint8Buff(&payloadData);
        FreeJson(sendData);
        return HC_ERR_JSON_ADD;
    }
    ClearFreeUint8Buff(&payloadData);
    res = AddSelfUdidToSendData(sendData);
    if (res != HC_SUCCESS) {
        LOGE("Failed to add self udid to json!");
        FreeJson(sendData);
        return res;
    }
    if (AddIntToJson(sendData, MK_AGREE_MESSAGE_CODE, START_MK_AGREE_REQUEST) != HC_SUCCESS) {
        LOGE("Failed to add message code to json!");
        FreeJson(sendData);
        return HC_ERR_JSON_ADD;
    }
    if (AddObjToJson(out, FIELD_SEND_TO_PEER, sendData) != HC_SUCCESS) {
        LOGE("Failed to add send data!");
        FreeJson(sendData);
        return HC_ERR_JSON_ADD;
    }
    FreeJson(sendData);
    return HC_SUCCESS;
}

static int32_t StartPakeMkAgreeRequest(MkAgreeTaskBase *task, CJson *out)
{
    LOGI("start pake mk agree request!");
    PakeMkAgreeTask *pakeTask = (PakeMkAgreeTask *)task;
    int32_t res = GeneratePakeRequestData(pakeTask, out);
    if (res != HC_SUCCESS) {
        LOGE("Failed to generate pake request data!");
        return res;
    }
    task->taskStatus = STATUS_WAIT_MK_RESPONSE;
    LOGI("start pake mk agree request successfully!");
    return HC_SUCCESS;
}

static int32_t GenerateMkByPeer(PakeMkAgreeTask *pakeTask, const CJson *payload)
{
    const char *peerDevPkStr = GetStringFromJson(payload, FIELD_PUBLIC_KEY);
    if (peerDevPkStr == NULL) {
        LOGE("Failed to get peer device pk string!");
        return HC_ERR_JSON_GET;
    }
    uint32_t peerDevPkLen = HcStrlen(peerDevPkStr) / BYTE_TO_HEX_OPER_LENGTH;
    uint8_t *peerDevPkVal = (uint8_t *)HcMalloc(peerDevPkLen, 0);
    if (peerDevPkVal == NULL) {
        LOGE("Failed to alloc memory for peer device pk!");
        return HC_ERR_ALLOC_MEMORY;
    }
    int32_t res = HexStringToByte(peerDevPkStr, peerDevPkVal, peerDevPkLen);
    if (res != HC_SUCCESS) {
        LOGE("Failed to convert peer device pk from string to byte!");
        HcFree(peerDevPkVal);
        return res;
    }
    Uint8Buff peerPkBuff = { peerDevPkVal, peerDevPkLen };
    res = GenerateMk(pakeTask->taskBase.peerUdid, &peerPkBuff);
    HcFree(peerDevPkVal);
    if (res != HC_SUCCESS) {
        LOGE("Failed to generate mk!");
        return res;
    }
    Uint8Buff clientSaltBuff = { pakeTask->clientSalt, SALT_LEN };
    Uint8Buff serverSaltBuff = { pakeTask->serverSalt, SALT_LEN };
    Uint8Buff saltBuff = { NULL, 0 };
    res = CombineSalt(&clientSaltBuff, &serverSaltBuff, &saltBuff);
    if (res != HC_SUCCESS) {
        LOGE("Failed to combine salt!");
        return res;
    }
    res = GeneratePseudonymPsk(pakeTask->taskBase.peerUdid, &saltBuff);
    FreeUint8Buff(&saltBuff);
    if (res != HC_SUCCESS) {
        LOGE("Failed to generate and save tmp mk!");
    }
    return res;
}

static int32_t GeneratePakeResponseData(PakeMkAgreeTask *pakeTask, CJson *out)
{
    Uint8Buff payloadData = { NULL, 0 };
    int32_t res = GeneratePakeResponsePayloadData(pakeTask, &payloadData);
    if (res != HC_SUCCESS) {
        LOGE("Failed to generate pake response payload data!");
        return res;
    }
    CJson *sendData = CreateJson();
    if (sendData == NULL) {
        LOGE("Failed to create send data json!");
        ClearFreeUint8Buff(&payloadData);
        return HC_ERR_JSON_CREATE;
    }
    if (AddByteToJson(sendData, FIELD_PAYLOAD, payloadData.val, payloadData.length) != HC_SUCCESS) {
        LOGE("Failed to add payload data to json!");
        ClearFreeUint8Buff(&payloadData);
        FreeJson(sendData);
        return HC_ERR_JSON_ADD;
    }
    ClearFreeUint8Buff(&payloadData);
    res = AddSelfUdidToSendData(sendData);
    if (res != HC_SUCCESS) {
        LOGE("Failed to add self udid to json!");
        FreeJson(sendData);
        return res;
    }
    if (AddIntToJson(sendData, MK_AGREE_MESSAGE_CODE, SEND_MK_AGREE_RESPONSE) != HC_SUCCESS) {
        LOGE("Failed to add message code to json!");
        FreeJson(sendData);
        return HC_ERR_JSON_ADD;
    }
    if (AddObjToJson(out, FIELD_SEND_TO_PEER, sendData) != HC_SUCCESS) {
        LOGE("Failed to add send data!");
        FreeJson(sendData);
        return HC_ERR_JSON_ADD;
    }
    FreeJson(sendData);
    return HC_SUCCESS;
}

static int32_t ParsePakeData(const CJson *in, Uint8Buff *payload)
{
    const char *payloadStr = GetStringFromJson(in, FIELD_PAYLOAD);
    if (payloadStr == NULL) {
        LOGE("Failed to get payloadStr!");
        return HC_ERR_JSON_GET;
    }
    uint32_t payloadLen = HcStrlen(payloadStr) / BYTE_TO_HEX_OPER_LENGTH;
    if (InitUint8Buff(payload, payloadLen) != HC_SUCCESS) {
        LOGE("Failed to init payload!");
        return HC_ERR_ALLOC_MEMORY;
    }
    int32_t res = HexStringToByte(payloadStr, payload->val, payload->length);
    if (res != HC_SUCCESS) {
        LOGE("Failed to convert payload data from hex string to byte!");
        FreeUint8Buff(payload);
    }
    return res;
}

static int32_t ProcessPakeMkAgreeRequest(MkAgreeTaskBase *task, const CJson *in, CJson *out)
{
    LOGI("process pake mk agree request!");
    PakeMkAgreeTask *pakeTask = (PakeMkAgreeTask *)task;
    if (task->taskStatus != STATUS_WAIT_MK_REQUEST) {
        LOGE("Task status not match!");
        return HC_ERR_INVALID_PARAMS;
    }
    Uint8Buff payloadBuff = { NULL, 0 };
    int32_t res = ParsePakeData(in, &payloadBuff);
    if (res != HC_SUCCESS) {
        LOGE("Failed to parse pake request data!");
        return res;
    }
    CJson *payload = CreateJsonFromString((const char *)payloadBuff.val);
    ClearFreeUint8Buff(&payloadBuff);
    if (payload == NULL) {
        LOGE("Failed to create payload json!");
        return HC_ERR_JSON_CREATE;
    }
    if (GetByteFromJson(payload, FIELD_SALT, pakeTask->clientSalt, SALT_LEN) != HC_SUCCESS) {
        LOGE("Failed to get client salt from payload!");
        FreeJson(payload);
        return HC_ERR_JSON_GET;
    }
    Uint8Buff serverSaltBuff = { pakeTask->serverSalt, SALT_LEN };
    res = pakeTask->taskBase.loader->generateRandom(&serverSaltBuff);
    if (res != HC_SUCCESS) {
        FreeJson(payload);
        LOGE("Failed to generate server salt!");
        return res;
    }
    res = GenerateMkByPeer(pakeTask, payload);
    FreeJson(payload);
    if (res != HC_SUCCESS) {
        LOGE("Failed to generate mk by peer!");
        return res;
    }
    res = GeneratePakeResponseData(pakeTask, out);
    if (res != HC_SUCCESS) {
        LOGE("Failed to generate pake response data!");
        return res;
    }
    task->taskStatus = STATUS_FINISH;
    LOGI("process pake mk agree request successfully!");
    return HC_SUCCESS;
}

static int32_t VerifyPeerKcf(PakeMkAgreeTask *pakeTask, const CJson *payload)
{
    const char *kcfDataStr = GetStringFromJson(payload, FIELD_KCF_DATA);
    if (kcfDataStr == NULL) {
        LOGE("Failed to get kcf data!");
        return HC_ERR_JSON_GET;
    }
    uint32_t kcfDataLen = HcStrlen(kcfDataStr) / BYTE_TO_HEX_OPER_LENGTH;
    uint8_t *kcfDataVal = (uint8_t *)HcMalloc(kcfDataLen, 0);
    if (kcfDataVal == NULL) {
        LOGE("Failed to alloc memory for kcf data!");
        return HC_ERR_ALLOC_MEMORY;
    }
    int32_t res = HexStringToByte(kcfDataStr, kcfDataVal, kcfDataLen);
    if (res != HC_SUCCESS) {
        LOGE("Failed to convert kcf data from hex string to byte!");
        HcFree(kcfDataVal);
        return res;
    }
    Uint8Buff recoverKcfBuff = { NULL, 0 };
    Uint8Buff clientSaltBuff = { pakeTask->clientSalt, SALT_LEN };
    Uint8Buff serverSaltBuff = { pakeTask->serverSalt, SALT_LEN };
    res = ComputeKcfData(pakeTask, &serverSaltBuff, &clientSaltBuff, &recoverKcfBuff);
    if (res != HC_SUCCESS) {
        LOGE("Failed to comput recover kcf data!");
        HcFree(kcfDataVal);
        return res;
    }
    if ((recoverKcfBuff.length != kcfDataLen) || memcmp(recoverKcfBuff.val, kcfDataVal, kcfDataLen) != 0) {
        LOGE("Kcf data not equal!");
        HcFree(kcfDataVal);
        ClearFreeUint8Buff(&recoverKcfBuff);
        return HC_ERR_MEMORY_COMPARE;
    }
    HcFree(kcfDataVal);
    ClearFreeUint8Buff(&recoverKcfBuff);
    return HC_SUCCESS;
}

static int32_t ProcessPakeMkAgreeResponse(MkAgreeTaskBase *task, const CJson *in)
{
    LOGI("process pake mk agree response!");
    PakeMkAgreeTask *pakeTask = (PakeMkAgreeTask *)task;
    if (task->taskStatus != STATUS_WAIT_MK_RESPONSE) {
        LOGE("Task status not match!");
        return HC_ERR_INVALID_PARAMS;
    }
    Uint8Buff payloadBuff = { NULL, 0 };
    int32_t res = ParsePakeData(in, &payloadBuff);
    if (res != HC_SUCCESS) {
        LOGE("Failed to parse pake response data!");
        return res;
    }
    CJson *payload = CreateJsonFromString((const char *)payloadBuff.val);
    ClearFreeUint8Buff(&payloadBuff);
    if (payload == NULL) {
        LOGE("Failed to create payload json!");
        return HC_ERR_JSON_CREATE;
    }
    if (GetByteFromJson(payload, FIELD_SALT, pakeTask->serverSalt, SALT_LEN) != HC_SUCCESS) {
        LOGE("Failed to get server salt!");
        FreeJson(payload);
        return HC_ERR_JSON_GET;
    }
    res = GenerateMkByPeer(pakeTask, payload);
    if (res != HC_SUCCESS) {
        LOGE("Failed to generate mk by peer!");
        FreeJson(payload);
        return res;
    }
    res = VerifyPeerKcf(pakeTask, payload);
    FreeJson(payload);
    if (res != HC_SUCCESS) {
        LOGE("Failed to verify kcf data!");
        return res;
    }
    task->taskStatus = STATUS_FINISH;
    LOGI("process pake mk agree response successfully!");
    return HC_SUCCESS;
}

static int32_t GetDuplicateUdid(const CJson *params, char **returnUdid)
{
    const char *udid = GetStringFromJson(params, FIELD_PEER_UDID);
    if (udid == NULL) {
        LOGE("Failed to get udid from json!");
        return HC_ERR_JSON_GET;
    }
    uint32_t udidLen = HcStrlen(udid);
    *returnUdid = (char *)HcMalloc(udidLen + 1, 0);
    if (*returnUdid == NULL) {
        LOGE("Failed to allocate return udid memory!");
        return HC_ERR_ALLOC_MEMORY;
    }
    if (memcpy_s(*returnUdid, udidLen + 1, udid, udidLen) != EOK) {
        LOGE("Failed to copy udid!");
        HcFree(*returnUdid);
        *returnUdid = NULL;
        return HC_ERR_MEMORY_COPY;
    }
    return HC_SUCCESS;
}

static int32_t ProcessPakeMkAgreeTask(MkAgreeTaskBase *task, const CJson *in, CJson *out)
{
    if (task == NULL || out == NULL) {
        LOGE("Invalid input params!");
        return HC_ERR_INVALID_PARAMS;
    }
    if (task->taskStatus == STATUS_INIT) {
        return StartPakeMkAgreeRequest(task, out);
    }
    if (in == NULL) {
        LOGE("in param is null!");
        return HC_ERR_INVALID_PARAMS;
    }
    int32_t msgCode;
    if (GetIntFromJson(in, MK_AGREE_MESSAGE_CODE, &msgCode) != HC_SUCCESS) {
        LOGE("Failed to get message code!");
        return HC_ERR_JSON_GET;
    }
    int32_t res = GetDuplicateUdid(in, &task->peerUdid);
    if (res != HC_SUCCESS) {
        LOGE("Failed to get peer udid!");
        return res;
    }
    switch (msgCode) {
        case START_MK_AGREE_REQUEST:
            res = ProcessPakeMkAgreeRequest(task, in, out);
            break;
        case SEND_MK_AGREE_RESPONSE:
            res = ProcessPakeMkAgreeResponse(task, in);
            break;
        default:
            LOGE("Invalid message code!");
            res = HC_ERR_CASE;
            break;
    }
    if (res != HC_SUCCESS) {
        LOGE("Failed to process mk agree task!");
    }
    return res;
}

static void DestroyPakeMkAgreeTask(MkAgreeTaskBase *task)
{
    if (task == NULL) {
        return;
    }
    HcFree(task->peerInfo);
    task->peerInfo = NULL;
    HcFree(task->pdidIndex);
    task->pdidIndex = NULL;
    HcFree(task->peerUdid);
    task->peerUdid = NULL;
    HcFree(task);
}

static int32_t InitTaskParams(MkAgreeTaskBase *task, const CJson *in)
{
    if (GetIntFromJson(in, FIELD_OS_ACCOUNT_ID, &task->osAccountId) != HC_SUCCESS) {
        LOGE("Failed to get osAccountId!");
        return HC_ERR_JSON_GET;
    }
    const char *peerInfo = GetStringFromJson(in, FIELD_REAL_INFO);
    if (peerInfo == NULL) {
        LOGE("Failed to get peerInfo!");
        return HC_ERR_JSON_GET;
    }
    if (DeepCopyString(peerInfo, &task->peerInfo) != HC_SUCCESS) {
        LOGE("Failed to copy peerInfo!");
        return HC_ERR_ALLOC_MEMORY;
    }
    const char *pdidIndex = GetStringFromJson(in, FIELD_INDEX_KEY);
    if (pdidIndex == NULL) {
        LOGE("Failed to get pdidIndex!");
        return HC_ERR_JSON_GET;
    }
    if (DeepCopyString(pdidIndex, &task->pdidIndex) != HC_SUCCESS) {
        LOGE("Failed to copy pdidIndex!");
        return HC_ERR_ALLOC_MEMORY;
    }
    task->loader = GetLoaderInstance();
    return HC_SUCCESS;
}

static int32_t CreatePakeMkAgreeTask(bool isClient, const CJson *in, MkAgreeTaskBase **returnTask)
{
    PakeMkAgreeTask *task = (PakeMkAgreeTask *)HcMalloc(sizeof(PakeMkAgreeTask), 0);
    if (task == NULL) {
        LOGE("Failed to alloc pake task memory!");
        return HC_ERR_ALLOC_MEMORY;
    }
    if (isClient) {
        task->taskBase.taskStatus = STATUS_INIT;
    } else {
        task->taskBase.taskStatus = STATUS_WAIT_MK_REQUEST;
    }
    task->taskBase.taskType = TASK_TYPE_PAKE;
    task->taskBase.process = ProcessPakeMkAgreeTask;
    task->taskBase.destroy = DestroyPakeMkAgreeTask;

    int32_t res = InitTaskParams((MkAgreeTaskBase *)task, in);
    if (res != HC_SUCCESS) {
        DestroyPakeMkAgreeTask((MkAgreeTaskBase *)task);
        return res;
    }

    *returnTask = (MkAgreeTaskBase *)task;
    return HC_SUCCESS;
}

int32_t CreateMkAgreeTask(int protocolType, const CJson *in, MkAgreeTaskBase **returnTask)
{
    if (in == NULL || returnTask == NULL)  {
        LOGE("Invalid input params!");
        return HC_ERR_INVALID_PARAMS;
    }
    bool isClient = false;
    if (GetBoolFromJson(in, FIELD_IS_CLIENT, &isClient) != HC_SUCCESS) {
        LOGE("Failed to get isClient!");
        return HC_ERR_JSON_GET;
    }
    int32_t res;
    switch (protocolType) {
        case TASK_TYPE_ISO:
            LOGE("ISO is not supported!");
            res = HC_ERR_NOT_SUPPORT;
            break;
        case TASK_TYPE_PAKE:
            res = CreatePakeMkAgreeTask(isClient, in, returnTask);
            break;
        default:
            LOGE("Invalid protocol type");
            res = HC_ERR_INVALID_PARAMS;
            break;
    }
    return res;
}