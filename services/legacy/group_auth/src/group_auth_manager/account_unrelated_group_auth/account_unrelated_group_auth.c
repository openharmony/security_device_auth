/*
 * Copyright (C) 2021-2023 Huawei Device Co., Ltd.
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

#include "account_unrelated_group_auth.h"
#include "common_defs.h"
#include "compatible_auth_sub_session_common.h"
#include "device_auth_defines.h"
#include "group_auth_data_operation.h"
#include "hc_log.h"
#include "hc_time.h"
#include "hc_types.h"
#include "json_utils.h"
#include "os_account_adapter.h"
#include "performance_dumper.h"
#include "string_util.h"

static void OnDasFinish(int64_t requestId, const CJson *authParam, const CJson *out,
    const DeviceAuthCallback *callback);
static int32_t FillNonAccountAuthInfo(int32_t osAccountId, const TrustedGroupEntry *entry,
    const TrustedDeviceEntry *localAuthInfo, CJson *paramsData);
static int32_t GetAuthParamsVecForServer(const CJson *dataFromClient, ParamsVecForAuth *authParamsVec);
static int32_t CombineDasServerConfirmParams(const CJson *confirmationJson, CJson *dataFromClient);

static NonAccountGroupAuth g_nonAccountGroupAuth = {
    .base.onFinish = OnDasFinish,
    .base.fillDeviceAuthInfo = FillNonAccountAuthInfo,
    .base.getAuthParamsVecForServer = GetAuthParamsVecForServer,
    .base.combineServerConfirmParams = CombineDasServerConfirmParams,
    .base.authType = ACCOUNT_UNRELATED_GROUP_AUTH_TYPE,
};

static int32_t ReturnSessionKey(int64_t requestId, const CJson *out, const DeviceAuthCallback *callback)
{
    const char *returnSessionKeyStr = GetStringFromJson(out, FIELD_SESSION_KEY);
    if (returnSessionKeyStr == NULL) {
        LOGE("Failed to get sessionKey!");
        return HC_ERR_JSON_GET;
    }
    uint32_t keyLen = (strlen(returnSessionKeyStr) / BYTE_TO_HEX_OPER_LENGTH);
    uint8_t *sessionKey = (uint8_t *)HcMalloc(keyLen, 0);
    if (sessionKey == NULL) {
        LOGE("Failed to allocate memory for sessionKey!");
        return HC_ERR_ALLOC_MEMORY;
    }

    int32_t res = HC_SUCCESS;
    do {
        if (GetByteFromJson(out, FIELD_SESSION_KEY, sessionKey, keyLen) != HC_SUCCESS) {
            LOGE("Failed to get sessionKey!");
            res = HC_ERR_JSON_GET;
            break;
        }
        if ((callback == NULL) || (callback->onSessionKeyReturned == NULL)) {
            LOGE("The callback of onSessionKeyReturned is null!");
            res = HC_ERR_INVALID_PARAMS;
            break;
        }
        LOGI("Begin invoke onSessionKeyReturned.");
        UPDATE_PERFORM_DATA_BY_INPUT_INDEX(requestId, ON_SESSION_KEY_RETURN_TIME, HcGetCurTimeInMillis());
        callback->onSessionKeyReturned(requestId, sessionKey, keyLen);
        LOGI("End invoke onSessionKeyReturned, res = %d.", res);
    } while (0);
    (void)memset_s(sessionKey, keyLen, 0, keyLen);
    HcFree(sessionKey);
    sessionKey = NULL;
    return res;
}

static int32_t AddGroupIdToSelfData(const CJson *authParam, CJson *returnToSelf)
{
    const char *groupId = GetStringFromJson(authParam, FIELD_SERVICE_TYPE);
    if (groupId == NULL) {
        LOGE("Failed to get groupId from authParam!");
        return HC_ERR_JSON_GET;
    }
    if (AddStringToJson(returnToSelf, FIELD_GROUP_ID, groupId) != HC_SUCCESS) {
        LOGE("Failed to add group id!");
        return HC_ERR_JSON_FAIL;
    }
    return HC_SUCCESS;
}

static int32_t AddPeerUdidToSelfData(const CJson *authParam, CJson *returnToSelf)
{
    const char *peerUdid = GetStringFromJson(authParam, FIELD_PEER_CONN_DEVICE_ID);
    if (peerUdid == NULL) {
        LOGD("The input has no peerUdid in authParam!");
        return HC_SUCCESS;
    }
    if (AddStringToJson(returnToSelf, FIELD_PEER_CONN_DEVICE_ID, peerUdid) != HC_SUCCESS) {
        LOGE("Failed to add peer udid!");
        return HC_ERR_JSON_FAIL;
    }
    return HC_SUCCESS;
}

static int32_t AddPeerAuthIdToSelfData(const CJson *authParam, CJson *returnToSelf)
{
    const char *peerAuthId = GetStringFromJson(authParam, FIELD_PEER_AUTH_ID);
    if (peerAuthId == NULL) {
        LOGD("No peerAuthId in auth session cached params!");
        return HC_SUCCESS;
    }

    if (AddStringToJson(returnToSelf, FIELD_PEER_AUTH_ID, peerAuthId) != HC_SUCCESS) {
        LOGE("Failed to add peerAuthId!");
        return HC_ERR_JSON_FAIL;
    }
    return HC_SUCCESS;
}

static int32_t AddSelfTypeToSelfData(const CJson *authParam, CJson *returnToSelf)
{
    int32_t userType = 0;
    if (GetIntFromJson(authParam, FIELD_SELF_TYPE, &userType) != HC_SUCCESS) {
        LOGE("Failed to get self userType from authParam!");
        return HC_ERR_JSON_GET;
    }
    if (AddIntToJson(returnToSelf, FIELD_USER_TYPE, userType) != HC_SUCCESS) {
        LOGE("Failed to add self userType for onFinish!");
        return HC_ERR_JSON_FAIL;
    }
    return HC_SUCCESS;
}

static int32_t AddPeerTypeToSelfData(const CJson *authParam, CJson *returnToSelf)
{
    int32_t peerUserType = 0;
    if (GetIntFromJson(authParam, FIELD_PEER_USER_TYPE, &peerUserType) != HC_SUCCESS) {
        LOGE("Failed to get peerUserType from authParam!");
        return HC_ERR_JSON_GET;
    }
    if (AddIntToJson(returnToSelf, FIELD_PEER_USER_TYPE, peerUserType) != HC_SUCCESS) {
        LOGE("Failed to add peer peerUserType for onFinish!");
        return HC_ERR_JSON_FAIL;
    }
    return HC_SUCCESS;
}

static int32_t AddSessionKeyToSelfData(const CJson *authParam, const CJson *sendToSelf, CJson *returnToSelf)
{
    int32_t keyLen = DEFAULT_RETURN_KEY_LENGTH;
    (void)GetIntFromJson(authParam, FIELD_KEY_LENGTH, &keyLen);
    uint8_t *sessionKey = (uint8_t *)HcMalloc(keyLen, 0);
    if (sessionKey == NULL) {
        LOGE("Failed to allocate memory for sessionKey!");
        return HC_ERR_ALLOC_MEMORY;
    }
    int32_t res = HC_SUCCESS;
    do {
        if (GetByteFromJson(sendToSelf, FIELD_SESSION_KEY, sessionKey, keyLen) != HC_SUCCESS) {
            LOGE("Failed to get sessionKey!");
            res = HC_ERR_JSON_GET;
            break;
        }
        if (AddByteToJson(returnToSelf, FIELD_SESSION_KEY, (const uint8_t *)sessionKey, keyLen) != HC_SUCCESS) {
            LOGE("Failed to add sessionKey for onFinish!");
            res = HC_ERR_JSON_FAIL;
            break;
        }
    } while (0);
    (void)memset_s(sessionKey, keyLen, 0, keyLen);
    HcFree(sessionKey);
    sessionKey = NULL;
    return res;
}

static int32_t PrepareDasReturnToSelfData(const CJson *authParam, const CJson *sendToSelf, CJson *returnToSelf)
{
    int32_t res = AddGroupIdToSelfData(authParam, returnToSelf);
    if (res != HC_SUCCESS) {
        return res;
    }
    res = AddPeerUdidToSelfData(authParam, returnToSelf);
    if (res != HC_SUCCESS) {
        return res;
    }
    res = AddPeerAuthIdToSelfData(authParam, returnToSelf);
    if (res != HC_SUCCESS) {
        return res;
    }
    res = AddSelfTypeToSelfData(authParam, returnToSelf);
    if (res != HC_SUCCESS) {
        return res;
    }
    res = AddPeerTypeToSelfData(authParam, returnToSelf);
    if (res != HC_SUCCESS) {
        return res;
    }
    res = AddSessionKeyToSelfData(authParam, sendToSelf, returnToSelf);
    if (res != HC_SUCCESS) {
        return res;
    }
    return HC_SUCCESS;
}

static int32_t DasOnFinishToPeer(int64_t requestId, const CJson *out, const DeviceAuthCallback *callback)
{
    int32_t res = HC_SUCCESS;
    const CJson *sendToPeer = GetObjFromJson(out, FIELD_SEND_TO_PEER);
    if (sendToPeer == NULL) {
        LOGI("No need to transmit data to peer.");
        return res;
    }
    char *sendToPeerStr = PackJsonToString(sendToPeer);
    if (sendToPeerStr == NULL) {
        LOGE("Failed to pack sendToPeerStr for onTransmit!");
        return HC_ERR_ALLOC_MEMORY;
    }
    if ((callback != NULL) && (callback->onTransmit != NULL)) {
        LOGD("Begin to transmit data to peer for auth in DasOnFinishToPeer.");
        UPDATE_PERFORM_DATA_BY_SELF_INDEX(requestId, HcGetCurTimeInMillis());
        if (!callback->onTransmit(requestId, (uint8_t *)sendToPeerStr, (uint32_t)strlen(sendToPeerStr) + 1)) {
            LOGE("Failed to transmit data to peer!");
            res = HC_ERR_TRANSMIT_FAIL;
        }
        LOGD("End to transmit data to peer for auth in DasOnFinishToPeer.");
    }
    FreeJsonString(sendToPeerStr);
    return res;
}

static int32_t DasOnFinishToSelf(int64_t requestId, const CJson *authParam, const CJson *out,
    const DeviceAuthCallback *callback)
{
    const CJson *sendToSelf = GetObjFromJson(out, FIELD_SEND_TO_SELF);
    if (sendToSelf == NULL) {
        LOGE("No data to send to self for onFinish.");
        return HC_ERR_LOST_DATA;
    }
    CJson *returnToSelf = CreateJson();
    if (returnToSelf == NULL) {
        LOGE("Create json failed!");
        return HC_ERR_ALLOC_MEMORY;
    }
    int32_t res = PrepareDasReturnToSelfData(authParam, sendToSelf, returnToSelf);
    if (res != HC_SUCCESS) {
        LOGE("Failed to add das returnToSelf data!");
        ClearSensitiveStringInJson(returnToSelf, FIELD_SESSION_KEY);
        FreeJson(returnToSelf);
        return res;
    }
    char *returnStr = PackJsonToString(returnToSelf);
    ClearSensitiveStringInJson(returnToSelf, FIELD_SESSION_KEY);
    FreeJson(returnToSelf);
    if (returnStr == NULL) {
        LOGE("Failed to pack returnToSelf for onFinish!");
        return HC_ERR_ALLOC_MEMORY;
    }
    if ((callback != NULL) && (callback->onFinish != NULL)) {
        LOGD("Group auth call onFinish for account unrelated auth.");
        UPDATE_PERFORM_DATA_BY_INPUT_INDEX(requestId, ON_FINISH_TIME, HcGetCurTimeInMillis());
        callback->onFinish(requestId, AUTH_FORM_ACCOUNT_UNRELATED, returnStr);
    }
    ClearAndFreeJsonString(returnStr);
    return res;
}

static int32_t AddNonAccountPkgName(const TrustedGroupEntry *entry, CJson *paramsData)
{
    int32_t groupType = entry->type;
    if (groupType == COMPATIBLE_GROUP) {
        if ((entry->managers).size(&(entry->managers)) == 0) {
            LOGE("The manager size is 0!");
            return HC_ERR_DB;
        }
        HcString ownerName = (entry->managers).get(&(entry->managers), 0);
        const char *ownerNameStr = StringGet(&ownerName);
        if (ownerNameStr == NULL) {
            LOGE("Failed to get ownerName!");
            return HC_ERR_DB;
        }
        if (AddStringToJson(paramsData, FIELD_SERVICE_PKG_NAME, ownerNameStr) != HC_SUCCESS) {
            LOGE("Failed to add ownerName to json!");
            return HC_ERR_JSON_FAIL;
        }
    } else {
        if (AddStringToJson(paramsData, FIELD_SERVICE_PKG_NAME, GROUP_MANAGER_PACKAGE_NAME) != HC_SUCCESS) {
            LOGE("Failed to add group manager name to json!");
            return HC_ERR_JSON_FAIL;
        }
    }
    return HC_SUCCESS;
}

static int32_t AddNonAccountAuthInfo(const TrustedDeviceEntry *localAuthInfo, const TrustedDeviceEntry *peerAuthInfo,
    CJson *paramsData)
{
    int32_t keyLen = DEFAULT_RETURN_KEY_LENGTH;
    (void)GetIntFromJson(paramsData, FIELD_KEY_LENGTH, &keyLen);
    if (AddIntToJson(paramsData, FIELD_KEY_LENGTH, keyLen) != HC_SUCCESS) {
        LOGE("Failed to add keyLen for auth!");
        return HC_ERR_JSON_FAIL;
    }
    if (AddStringToJson(paramsData, FIELD_SELF_AUTH_ID, StringGet(&localAuthInfo->authId))
        != HC_SUCCESS) {
        LOGE("Failed to add self authId to paramsData from db!");
        return HC_ERR_JSON_FAIL;
    }
    if (AddIntToJson(paramsData, FIELD_SELF_TYPE, localAuthInfo->devType) != HC_SUCCESS) {
        LOGE("Failed to add self devType to paramsData from db!");
        return HC_ERR_JSON_FAIL;
    }
    const char *peerAuthId = GetStringFromJson(paramsData, FIELD_PEER_ID_FROM_REQUEST);
    if (peerAuthId == NULL) {
        peerAuthId = StringGet(&peerAuthInfo->authId);
    }
    if (AddStringToJson(paramsData, FIELD_PEER_AUTH_ID, peerAuthId) != HC_SUCCESS) {
        LOGE("Failed to add peer authId to paramsData!");
        return HC_ERR_JSON_FAIL;
    }
    if (AddIntToJson(paramsData, FIELD_PEER_USER_TYPE, peerAuthInfo->devType) != HC_SUCCESS) {
        LOGE("Failed to add peer devType to paramsData from db!");
        return HC_ERR_JSON_FAIL;
    }
    return HC_SUCCESS;
}

static int32_t FillNonAccountAuthInfo(int32_t osAccountId, const TrustedGroupEntry *entry,
    const TrustedDeviceEntry *localAuthInfo, CJson *paramsData)
{
    int32_t res;
    const char *groupId = StringGet(&entry->id);
    TrustedDeviceEntry *peerAuthInfo = CreateDeviceEntry();
    if (peerAuthInfo == NULL) {
        LOGE("Failed to allocate devEntry memory for peerAuthInfo!");
        return HC_ERR_ALLOC_MEMORY;
    }
    const char *peerUdid = GetStringFromJson(paramsData, FIELD_PEER_CONN_DEVICE_ID);
    const char *peerAuthId = GetStringFromJson(paramsData, FIELD_PEER_ID_FROM_REQUEST);
    if (peerAuthId == NULL) {
        peerAuthId = GetStringFromJson(paramsData, FIELD_PEER_AUTH_ID);
    }
    if (peerUdid != NULL) {
        res = GaGetTrustedDeviceEntryById(osAccountId, peerUdid, true, groupId, peerAuthInfo);
    } else if (peerAuthId != NULL) {
        res = GaGetTrustedDeviceEntryById(osAccountId, peerAuthId, false, groupId, peerAuthInfo);
    } else {
        LOGE("Invalid input, both peer udid and peer authId are null!");
        res = HC_ERR_NULL_PTR;
    }
    do {
        if (res != HC_SUCCESS) {
            LOGE("Failed to get peer device info from database!");
            break;
        }
        res = AddNonAccountPkgName(entry, paramsData);
        if (res != HC_SUCCESS) {
            LOGE("Failed to add pkg name to paramsData!");
            break;
        }
        res = AddNonAccountAuthInfo(localAuthInfo, peerAuthInfo, paramsData);
        if (res != HC_SUCCESS) {
            LOGE("Failed to add device auth info for non-account group!");
            break;
        }
    } while (0);
    DestroyDeviceEntry(peerAuthInfo);
    return res;
}

static int32_t CombineDasServerConfirmParams(const CJson *confirmationJson, CJson *dataFromClient)
{
    bool isClient = false;
    if (AddBoolToJson(dataFromClient, FIELD_IS_CLIENT, isClient) != HC_SUCCESS) {
        LOGE("Failed to combine server param for isClient!");
        return HC_ERR_JSON_FAIL;
    }
    const char *pkgName = GetStringFromJson(confirmationJson, FIELD_SERVICE_PKG_NAME);
    if (pkgName != NULL) {
        if (AddStringToJson(dataFromClient, FIELD_SERVICE_PKG_NAME, pkgName) != HC_SUCCESS) {
            LOGE("Failed to combine server param for pkgName!");
            return HC_ERR_JSON_FAIL;
        }
    }

    const char *peerUdid = GetStringFromJson(confirmationJson, FIELD_PEER_CONN_DEVICE_ID);
    if (peerUdid != NULL) {
        if (AddStringToJson(dataFromClient, FIELD_PEER_CONN_DEVICE_ID, peerUdid) != HC_SUCCESS) {
            LOGE("Failed to combine server param for peerUdid!");
            return HC_ERR_JSON_FAIL;
        }
    }
    const char *peerAuthId = GetStringFromJson(confirmationJson, FIELD_PEER_AUTH_ID);
    if (peerAuthId != NULL) {
        if (AddStringToJson(dataFromClient, FIELD_PEER_ID_FROM_REQUEST, peerAuthId) != HC_SUCCESS) {
            LOGE("Failed to combine server param for peerAuthId!");
            return HC_ERR_JSON_FAIL;
        }
    }
    return HC_SUCCESS;
}

static int32_t GetAuthParamsVecForServer(const CJson *dataFromClient, ParamsVecForAuth *authParamsVec)
{
    LOGI("Begin get non-account auth params for server.");
    int32_t osAccountId = ANY_OS_ACCOUNT;
    if (GetIntFromJson(dataFromClient, FIELD_OS_ACCOUNT_ID, &osAccountId) != HC_SUCCESS) {
        LOGE("Failed to get os accountId from dataFromClient!");
        return HC_ERR_JSON_GET;
    }
    int32_t res = GetAuthParamsVec(osAccountId, dataFromClient, authParamsVec);
    if (res != HC_SUCCESS) {
        LOGE("Failed to get non-account auth params!");
    }
    return res;
}

static void OnDasFinish(int64_t requestId, const CJson *authParam, const CJson *out,
    const DeviceAuthCallback *callback)
{
    LOGI("Begin call onFinish for non-account auth.");
    if (DasOnFinishToPeer(requestId, out, callback) != HC_SUCCESS) {
        LOGE("Failed to send data to peer when auth finished!");
        return;
    }
    if (ReturnSessionKey(requestId, out, callback) != HC_SUCCESS) {
        LOGE("Failed to return session key when auth finished!");
        return;
    }
    if (DasOnFinishToSelf(requestId, authParam, out, callback) != HC_SUCCESS) {
        LOGE("Failed to send data to self when auth finished!");
        return;
    }
    LOGI("Call onFinish for non-account auth successfully.");
}

BaseGroupAuth *GetAccountUnrelatedGroupAuth(void)
{
    return (BaseGroupAuth *)&g_nonAccountGroupAuth;
}
