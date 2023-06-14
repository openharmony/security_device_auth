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

#include "creds_operation_utils.h"

#include "creds_manager_defines.h"
#include "device_auth.h"
#include "device_auth_defines.h"
#include "group_auth_data_operation.h"
#include "hc_dev_info.h"
#include "hc_log.h"
#include "hc_types.h"
#include "json_utils.h"
#include "string_util.h"

IMPLEMENT_HC_VECTOR(ProtocolEntityVec, ProtocolEntity*, 1)
IMPLEMENT_HC_VECTOR(IdentityInfoVec, IdentityInfo*, 1)

static int32_t SetProtocolsForPinType(IdentityInfo *info)
{
#ifdef ENABLE_P2P_BIND_EC_SPEKE
    ProtocolEntity *ecSpekeEntity = (ProtocolEntity *)HcMalloc(sizeof(ProtocolEntity), 0);
    if (ecSpekeEntity == NULL) {
        LOGE("Failed to alloc memory for ec speke entity!");
        return HC_ERR_ALLOC_MEMORY;
    }
    ecSpekeEntity->protocolType = ALG_EC_SPEKE;
    ecSpekeEntity->expandProcessCmds = CMD_EXCHANGE_PK | CMD_ADD_TRUST_DEVICE;
    info->protocolVec.pushBack(&info->protocolVec, (const ProtocolEntity **)&ecSpekeEntity);
#endif

    ProtocolEntity *dlSpekeEntity = (ProtocolEntity *)HcMalloc(sizeof(ProtocolEntity), 0);
    if (dlSpekeEntity == NULL) {
        LOGE("Failed to alloc memory for dl speke entity!");
        return HC_ERR_ALLOC_MEMORY;
    }
    dlSpekeEntity->protocolType = ALG_DL_SPEKE;
    dlSpekeEntity->expandProcessCmds = CMD_IMPORT_AUTH_CODE | CMD_ADD_TRUST_DEVICE;
    info->protocolVec.pushBack(&info->protocolVec, (const ProtocolEntity **)&dlSpekeEntity);

#ifdef ENABLE_P2P_BIND_ISO
    ProtocolEntity *isoEntity = (ProtocolEntity *)HcMalloc(sizeof(ProtocolEntity), 0);
    if (isoEntity == NULL) {
        LOGE("Failed to alloc memory for iso entity!");
        return HC_ERR_ALLOC_MEMORY;
    }
    isoEntity->protocolType = ALG_ISO;
    isoEntity->expandProcessCmds = CMD_IMPORT_AUTH_CODE | CMD_ADD_TRUST_DEVICE;
    info->protocolVec.pushBack(&info->protocolVec, (const ProtocolEntity **)&isoEntity);
#endif

    return HC_SUCCESS;
}

static int32_t SetProtocolsForUidType(IdentityInfo *info)
{
#ifdef ENABLE_ACCOUNT_AUTH_ISO
    ProtocolEntity *entity = (ProtocolEntity *)HcMalloc(sizeof(ProtocolEntity), 0);
    if (entity == NULL) {
        LOGE("Failed to alloc memory for entity!");
        return HC_ERR_ALLOC_MEMORY;
    }
    entity->protocolType = ALG_ISO;
    entity->expandProcessCmds = CMD_ADD_TRUST_DEVICE;
    info->protocolVec.pushBack(&info->protocolVec, (const ProtocolEntity **)&entity);
#else
    (void)info;
#endif

    return HC_SUCCESS;
}

static int32_t SetProtocolsForP2pType(int32_t keyType, IdentityInfo *info)
{
    if (keyType == KEY_TYPE_ASYM) {
    #ifdef ENABLE_P2P_AUTH_EC_SPEKE
        ProtocolEntity *entity = (ProtocolEntity *)HcMalloc(sizeof(ProtocolEntity), 0);
        if (entity == NULL) {
            LOGE("Failed to alloc memory for entity!");
            return HC_ERR_ALLOC_MEMORY;
        }
        entity->protocolType = ALG_EC_SPEKE;
        info->protocolVec.pushBack(&info->protocolVec, (const ProtocolEntity **)&entity);
    #else
        (void)info;
    #endif
    } else {
    #ifdef ENABLE_P2P_AUTH_ISO
        ProtocolEntity *entity = (ProtocolEntity *)HcMalloc(sizeof(ProtocolEntity), 0);
        if (entity == NULL) {
            LOGE("Failed to alloc memory for entity!");
            return HC_ERR_ALLOC_MEMORY;
        }
        entity->protocolType = ALG_ISO;
        info->protocolVec.pushBack(&info->protocolVec, (const ProtocolEntity **)&entity);
    #else
        (void)info;
    #endif
    }

    return HC_SUCCESS;
}

static int32_t SetPreSharedUrlForProof(const char *urlStr, Uint8Buff *preSharedUrl)
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

static int32_t SetProtocolsForPresharedCred(int32_t trustType, int32_t keyType, IdentityInfo *info)
{
    if (trustType == TRUST_TYPE_PIN) {
        return SetProtocolsForPinType(info);
    } else if (trustType == TRUST_TYPE_UID) {
        return SetProtocolsForUidType(info);
    } else {
        return SetProtocolsForP2pType(keyType, info);
    }
}

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

int32_t GetPeerDeviceEntry(int32_t osAccountId, const CJson *in, const char *groupId,
    TrustedDeviceEntry *returnDeviceEntry)
{
    bool isUdid = false;
    const char *peerDeviceId = GetPeerDevIdFromJson(in, &isUdid);
    if (peerDeviceId == NULL) {
        LOGE("Failed to get peer deviceId!");
        return HC_ERR_JSON_GET;
    }
    return GaGetTrustedDeviceEntryById(osAccountId, peerDeviceId, isUdid, groupId, returnDeviceEntry);
}

int32_t GetIdentityInfoByType(int32_t keyType, int32_t trustType, const char *groupId, IdentityInfo *info)
{
    CJson *urlJson = CreateJson();
    if (urlJson == NULL) {
        LOGE("Failed to create url json!");
        return HC_ERR_JSON_CREATE;
    }
    if (AddIntToJson(urlJson, PRESHARED_URL_CREDENTIAL_TYPE, PRE_SHARED) != HC_SUCCESS) {
        LOGE("Failed to add credential type!");
        FreeJson(urlJson);
        return HC_ERR_JSON_ADD;
    }
    if (AddIntToJson(urlJson, PRESHARED_URL_KEY_TYPE, keyType) != HC_SUCCESS) {
        LOGE("Failed to add key type!");
        FreeJson(urlJson);
        return HC_ERR_JSON_ADD;
    }
    if (AddIntToJson(urlJson, PRESHARED_URL_TRUST_TYPE, trustType) != HC_SUCCESS) {
        LOGE("Failed to add trust type!");
        FreeJson(urlJson);
        return HC_ERR_JSON_ADD;
    }
    if ((trustType == TRUST_TYPE_P2P || trustType == TRUST_TYPE_UID) &&
        AddStringToJson(urlJson, FIELD_GROUP_ID, groupId) != HC_SUCCESS) {
        LOGE("Failed to add group id!");
        FreeJson(urlJson);
        return HC_ERR_JSON_ADD;
    }
    char *urlStr = PackJsonToString(urlJson);
    FreeJson(urlJson);
    if (urlStr == NULL) {
        LOGE("Failed to pack url json to string!");
        return HC_ERR_PACKAGE_JSON_TO_STRING_FAIL;
    }

    int32_t ret = SetPreSharedUrlForProof(urlStr, &info->proof.preSharedUrl);
    FreeJsonString(urlStr);
    if (ret != HC_SUCCESS) {
        LOGE("Failed to set preSharedUrl of proof!");
        return ret;
    }

    ret = SetProtocolsForPresharedCred(trustType, keyType, info);
    if (ret != HC_SUCCESS) {
        LOGE("Failed to set protocols!");
        return ret;
    }

    info->proofType = PRE_SHARED;
    return ret;
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
    FOR_EACH_HC_VECTOR(*vec, index, info) {
        DestroyIdentityInfo(*info);
    }
    DESTROY_HC_VECTOR(IdentityInfoVec, vec);
}

void ClearProtocolEntityVec(ProtocolEntityVec *vec)
{
    uint32_t index;
    ProtocolEntity **entity;
    FOR_EACH_HC_VECTOR(*vec, index, entity) {
        HcFree(*entity);
    }
    DESTROY_HC_VECTOR(ProtocolEntityVec, vec);
}