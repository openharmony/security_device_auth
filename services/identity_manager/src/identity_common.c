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

#include "group_auth_data_operation.h"
#include "hc_dev_info.h"
#include "hc_log.h"
#include "hc_vector.h"
#include "identity_manager.h"

static void UpperToLowercase(Uint8Buff *hex)
{
    for (uint32_t i = 0; i < hex->length; i++) {
        if (hex->val[i] >= 'A' && hex->val[i] <= 'F') {
            hex->val[i] += ASCII_CASE_DIFFERENCE_VALUE;
        }
    }
}

int32_t ConvertPsk(const Uint8Buff *srcPsk, Uint8Buff *sharedSecret)
{
    uint32_t len = PAKE_PSK_LEN * BYTE_TO_HEX_OPER_LENGTH;
    sharedSecret->val = (uint8_t *)HcMalloc(len + 1, 0);
    if (sharedSecret->val == NULL) {
        LOGE("Failed to alloc memory for sharedSecret!");
        return HC_ERR_ALLOC_MEMORY;
    }

    if (ByteToHexString(srcPsk->val, srcPsk->length, (char *)sharedSecret->val, len + 1) != HC_SUCCESS) {
        LOGE("Convert psk from byte to hex string failed!");
        HcFree(sharedSecret->val);
        return HC_ERR_CONVERT_FAILED;
    }
    sharedSecret->length = len;
    (void)UpperToLowercase(sharedSecret);
    return HC_SUCCESS;
}

int32_t SetPreSharedUrlForProof(const char *urlStr, Uint8Buff *preSharedUrl)
{
    uint32_t urlLen = HcStrlen(urlStr);
    preSharedUrl->val = (uint8_t *)HcMalloc(urlLen + 1, 0);
    if (preSharedUrl->val == NULL) {
        LOGE("Failed to alloc preSharedUrl memory!");
        return HC_ERR_ALLOC_MEMORY;
    }
    if (memcpy_s(preSharedUrl->val, urlLen + 1, urlStr, urlLen) != EOK) {
        LOGE("Failed to copy url string to preSharedUrl");
        HcFree(preSharedUrl->val);
        preSharedUrl->val = NULL;
        return HC_ERR_MEMORY_COPY;
    }
    preSharedUrl->length = urlLen + 1;
    return HC_SUCCESS;
}

CJson *CreateCredUrlJson(int32_t credentailType, int32_t keyType, int32_t trustType)
{
    CJson *urlJson = CreateJson();
    if (urlJson == NULL) {
        LOGE("Failed to create url json!");
        return NULL;
    }
    if (AddIntToJson(urlJson, PRESHARED_URL_CREDENTIAL_TYPE, credentailType) != HC_SUCCESS) {
        LOGE("Failed to add credential type!");
        FreeJson(urlJson);
        return NULL;
    }
    if (AddIntToJson(urlJson, PRESHARED_URL_KEY_TYPE, keyType) != HC_SUCCESS) {
        LOGE("Failed to add key type!");
        FreeJson(urlJson);
        return NULL;
    }
    if (AddIntToJson(urlJson, PRESHARED_URL_TRUST_TYPE, trustType) != HC_SUCCESS) {
        LOGE("Failed to add trust type!");
        FreeJson(urlJson);
        return NULL;
    }

    return urlJson;
}

#if 1

IMPLEMENT_HC_VECTOR(ProtocolEntityVec, ProtocolEntity *, 1)
IMPLEMENT_HC_VECTOR(IdentityInfoVec, IdentityInfo *, 1)

int32_t GetSelfDeviceEntry(int32_t osAccountId, const char *groupId, TrustedDeviceEntry *deviceEntry)
{
    char selfUdid[INPUT_UDID_LEN] = { 0 };
    int32_t ret = HcGetUdid((uint8_t *)selfUdid, INPUT_UDID_LEN);
    if (ret != HC_SUCCESS) {
        LOGE("Failed to get local udid!");
        return ret;
    }
    return GaGetTrustedDeviceEntryById(osAccountId, selfUdid, true, groupId, deviceEntry);
}

const char *GetPeerDevIdFromJson(const CJson *in, bool *isUdid)
{
    const char *deviceId = GetStringFromJson(in, FIELD_PEER_UDID);
    if (deviceId != NULL) {
        *isUdid = true;
        return deviceId;
    }
    return GetStringFromJson(in, FIELD_PEER_AUTH_ID);
}

int32_t GetPeerDeviceEntry(
    int32_t osAccountId, const CJson *in, const char *groupId, TrustedDeviceEntry *returnDeviceEntry)
{
    bool isUdid = false;
    const char *peerDeviceId = GetPeerDevIdFromJson(in, &isUdid);
    if (peerDeviceId == NULL) {
        LOGE("Failed to get peer deviceId!");
        return HC_ERR_JSON_GET;
    }
    return GaGetTrustedDeviceEntryById(osAccountId, peerDeviceId, isUdid, groupId, returnDeviceEntry);
}

void FreeBuffData(Uint8Buff *buff)
{
    if (buff == NULL) {
        return;
    }
    HcFree(buff->val);
    buff->val = NULL;
    buff->length = 0;
}

IdentityInfo *CreateIdentityInfo(void)
{
    IdentityInfo *info = (IdentityInfo *)HcMalloc(sizeof(IdentityInfo), 0);
    if (info == NULL) {
        LOGE("Failed to alloc memory for identity info!");
        return NULL;
    }
    info->protocolVec = CreateProtocolEntityVec();
    return info;
}

void DestroyIdentityInfo(IdentityInfo *info)
{
    if (info == NULL) {
        return;
    }

    FreeBuffData(&info->proof.preSharedUrl);
    FreeBuffData(&info->proof.certInfo.pkInfoStr);
    FreeBuffData(&info->proof.certInfo.pkInfoSignature);
    ClearProtocolEntityVec(&info->protocolVec);

    HcFree(info);
}

void ClearIdentityInfoVec(IdentityInfoVec *vec)
{
    uint32_t index;
    IdentityInfo **info;
    FOR_EACH_HC_VECTOR(*vec, index, info)
    {
        DestroyIdentityInfo(*info);
    }
    DESTROY_HC_VECTOR(IdentityInfoVec, vec);
}

void ClearProtocolEntityVec(ProtocolEntityVec *vec)
{
    uint32_t index;
    ProtocolEntity **entity;
    FOR_EACH_HC_VECTOR(*vec, index, entity)
    {
        HcFree(*entity);
    }
    DESTROY_HC_VECTOR(ProtocolEntityVec, vec);
}

#endif