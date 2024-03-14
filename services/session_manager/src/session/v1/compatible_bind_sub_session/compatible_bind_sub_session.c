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

#include "compatible_bind_sub_session.h"

#include "callback_manager.h"
#include "channel_manager.h"
#include "compatible_bind_sub_session_common.h"
#include "compatible_bind_sub_session_util.h"
#include "das_module_defines.h"
#include "dev_auth_module_manager.h"
#include "group_operation_common.h"
#include "hc_dev_info.h"
#include "hc_log.h"
#include "hc_time.h"
#include "hc_types.h"
#include "hitrace_adapter.h"
#include "performance_dumper.h"

static int32_t CheckInvitePeer(const CJson *jsonParams)
{
    const char *groupId = GetStringFromJson(jsonParams, FIELD_GROUP_ID);
    if (groupId == NULL) {
        LOGE("Failed to get groupId from jsonParams!");
        return HC_ERR_JSON_GET;
    }
    const char *appId = GetStringFromJson(jsonParams, FIELD_APP_ID);
    if (appId == NULL) {
        LOGE("Failed to get appId from jsonParams!");
        return HC_ERR_JSON_GET;
    }
    int32_t osAccountId;
    if (GetIntFromJson(jsonParams, FIELD_OS_ACCOUNT_ID, &osAccountId) != HC_SUCCESS) {
        LOGE("Failed to get osAccountId from jsonParams!");
        return HC_ERR_JSON_GET;
    }

    int32_t groupType = PEER_TO_PEER_GROUP;
    int32_t result;
    if (((result = CheckGroupExist(osAccountId, groupId)) != HC_SUCCESS) ||
        ((result = GetGroupTypeFromDb(osAccountId, groupId, &groupType)) != HC_SUCCESS) ||
        ((result = AssertGroupTypeMatch(groupType, PEER_TO_PEER_GROUP)) != HC_SUCCESS) ||
        ((result = CheckPermForGroup(osAccountId, MEMBER_INVITE, appId, groupId)) != HC_SUCCESS) ||
        ((result = CheckDeviceNumLimit(osAccountId, groupId, NULL)) != HC_SUCCESS)) {
        return result;
    }
    return HC_SUCCESS;
}

static int32_t CheckJoinPeer(const CJson *jsonParams)
{
    int32_t groupType = PEER_TO_PEER_GROUP;
    if (GetIntFromJson(jsonParams, FIELD_GROUP_TYPE, &groupType) != HC_SUCCESS) {
        LOGE("Failed to get groupType from jsonParams!");
        return HC_ERR_JSON_GET;
    }
    return AssertGroupTypeMatch(groupType, PEER_TO_PEER_GROUP);
}

static int32_t CheckClientStatus(int operationCode, const CJson *jsonParams)
{
    switch (operationCode) {
        case MEMBER_INVITE:
            return CheckInvitePeer(jsonParams);
        case MEMBER_JOIN:
            return CheckJoinPeer(jsonParams);
        default:
            LOGE("Invalid operation!");
            return HC_ERR_CASE;
    }
}

static int32_t GetDuplicateAppId(const CJson *params, char **returnAppId)
{
    const char *appId = GetStringFromJson(params, FIELD_APP_ID);
    if (appId == NULL) {
        LOGE("Failed to get appId from json!");
        return HC_ERR_JSON_GET;
    }
    uint32_t appIdLen = HcStrlen(appId);
    *returnAppId = (char *)HcMalloc(appIdLen + 1, 0);
    if (*returnAppId == NULL) {
        LOGE("Failed to allocate return appId memory!");
        return HC_ERR_ALLOC_MEMORY;
    }
    if (memcpy_s(*returnAppId, appIdLen + 1, appId, appIdLen) != EOK) {
        LOGE("Failed to copy appId!");
        HcFree(*returnAppId);
        *returnAppId = NULL;
        return HC_ERR_MEMORY_COPY;
    }
    return HC_SUCCESS;
}

static int32_t CreateBaseBindSubSession(int32_t sessionType, int32_t opCode, const CJson *params,
    const DeviceAuthCallback *callback, CompatibleBaseSubSession **session)
{
    int64_t reqId = DEFAULT_REQUEST_ID;
    if (GetInt64FromJson(params, FIELD_REQUEST_ID, &reqId) != HC_SUCCESS) {
        LOGE("Failed to get requestId from params!");
        return HC_ERR_JSON_GET;
    }

    int32_t osAccountId = 0;
    if (GetIntFromJson(params, FIELD_OS_ACCOUNT_ID, &osAccountId) != HC_SUCCESS) {
        LOGE("Failed to get osAccountId from params!");
        return HC_ERR_JSON_GET;
    }

    CompatibleBindSubSession *subSession = (CompatibleBindSubSession *)HcMalloc(sizeof(CompatibleBindSubSession), 0);
    if (subSession == NULL) {
        LOGE("Failed to allocate session memory!");
        return HC_ERR_ALLOC_MEMORY;
    }

    int32_t result = GetDuplicateAppId(params, &(subSession->base.appId));
    if (result != HC_SUCCESS) {
        LOGE("Failed to get appId!");
        HcFree(subSession);
        return result;
    }
    subSession->base.type = sessionType;
    subSession->base.callback = callback;
    subSession->base.curTaskId = 0;
    subSession->base.status = STATUS_INITIAL;
    subSession->params = NULL;
    subSession->osAccountId = osAccountId;
    subSession->opCode = opCode;
    subSession->moduleType = DAS_MODULE;
    subSession->reqId = reqId;
    subSession->channelType = NO_CHANNEL;
    subSession->channelId = DEFAULT_CHANNEL_ID;
    *session = (CompatibleBaseSubSession *)subSession;
    return HC_SUCCESS;
}

static int32_t GenerateKeyPairIfNeeded(int isClient, int32_t opCode, CJson *jsonParams)
{
    if (!IsCreateGroupNeeded(isClient, opCode)) {
        LOGI("no need to generate local keypair.");
        return HC_SUCCESS;
    }
    const char *groupId = GetStringFromJson(jsonParams, FIELD_GROUP_ID);
    if (groupId == NULL) {
        LOGE("Failed to get groupId from jsonParams!");
        return HC_ERR_JSON_GET;
    }
    DEV_AUTH_START_TRACE(TRACE_TAG_CREATE_KEY_PAIR);
    int32_t result = ProcessKeyPair(CREATE_KEY_PAIR, jsonParams, groupId);
    DEV_AUTH_FINISH_TRACE();
    if (result != HC_SUCCESS) {
        LOGE("Failed to create keypair!");
    }
    return result;
}

static int32_t CheckServerStatusIfNotInvite(int32_t osAccountId, int operationCode, const CJson *jsonParams)
{
    if (operationCode == MEMBER_INVITE) {
        return HC_SUCCESS;
    }
    const char *groupId = GetStringFromJson(jsonParams, FIELD_GROUP_ID);
    if (groupId == NULL) {
        LOGE("Failed to get groupId from jsonParams!");
        return HC_ERR_JSON_GET;
    }
    const char *appId = GetStringFromJson(jsonParams, FIELD_APP_ID);
    if (appId == NULL) {
        LOGE("Failed to get appId from jsonParams!");
        return HC_ERR_JSON_GET;
    }
    const char *peerUdid = GetStringFromJson(jsonParams, FIELD_CONN_DEVICE_ID);
    if (peerUdid == NULL) {
        LOGE("Failed to get peerUdid from jsonParams!");
        return HC_ERR_JSON_GET;
    }
    int32_t result = CheckGroupExist(osAccountId, groupId);
    if (result != HC_SUCCESS) {
        return result;
    }
    if (operationCode == MEMBER_JOIN) {
        /* The client sends a join request, which is equivalent to the server performing an invitation operation. */
        result = CheckPermForGroup(osAccountId, MEMBER_INVITE, appId, groupId);
        if (result != HC_SUCCESS) {
            return result;
        }
        result = CheckDeviceNumLimit(osAccountId, groupId, peerUdid);
    }
    return result;
}

static int32_t GenerateServerBindParams(CompatibleBindSubSession *session, CJson *jsonParams)
{
    int32_t result = CheckServerStatusIfNotInvite(session->osAccountId, session->opCode, jsonParams);
    if (result != HC_SUCCESS) {
        return result;
    }
    result = GenerateBaseBindParams(session->osAccountId, SERVER, jsonParams, session);
    if (result != HC_SUCCESS) {
        return result;
    }

    return GenerateKeyPairIfNeeded(SERVER, session->opCode, jsonParams);
}

static int32_t CheckPeerStatus(const CJson *params, bool *isNeedInform)
{
    int32_t errorCode = HC_SUCCESS;
    if (GetIntFromJson(params, FIELD_GROUP_ERROR_MSG, &errorCode) == HC_SUCCESS) {
        LOGE("An error occurs in the peer device! [ErrorCode]: %d", errorCode);
        *isNeedInform = false;
        return errorCode;
    }
    return HC_SUCCESS;
}

static int32_t TryAddPeerUserTypeToParams(const CJson *jsonParams, CompatibleBindSubSession *session)
{
    int32_t peerUserType = DEVICE_TYPE_ACCESSORY;
    int32_t res = GetIntFromJson(jsonParams, FIELD_PEER_USER_TYPE, &peerUserType);
    if (res == HC_SUCCESS && AddIntToJson(session->params, FIELD_PEER_USER_TYPE, peerUserType) != HC_SUCCESS) {
        LOGE("Failed to add peerUserType to params!");
        return HC_ERR_JSON_ADD;
    }
    return HC_SUCCESS;
}

static int32_t InteractWithPeer(const CompatibleBindSubSession *session, CJson *sendData)
{
    int32_t res = AddInfoToBindData(false, session, sendData);
    if (res != HC_SUCCESS) {
        LOGE("Failed to generate sendData!");
        return res;
    }
    return TransmitBindSessionData(session, sendData);
}

static int32_t SendBindDataToPeer(CompatibleBindSubSession *session, CJson *out)
{
    CJson *sendData = DetachItemFromJson(out, FIELD_SEND_TO_PEER);
    if (sendData == NULL) {
        LOGE("Failed to get sendToPeer from out!");
        return HC_ERR_JSON_GET;
    }
    int32_t result = InteractWithPeer(session, sendData);
    FreeJson(sendData);
    return result;
}

static int32_t InformSelfBindSuccess(const char *peerAuthId, const char *peerUdid, const char *groupId,
    const CompatibleBindSubSession *session, CJson *out)
{
    uint8_t sessionKey[DEFAULT_RETURN_KEY_LENGTH] = { 0 };
    if (GetByteFromJson(out, FIELD_SESSION_KEY, sessionKey, DEFAULT_RETURN_KEY_LENGTH) == HC_SUCCESS) {
        UPDATE_PERFORM_DATA_BY_INPUT_INDEX(session->reqId, ON_SESSION_KEY_RETURN_TIME, HcGetCurTimeInMillis());
        ProcessSessionKeyCallback(session->reqId, sessionKey, DEFAULT_RETURN_KEY_LENGTH, session->base.callback);
        (void)memset_s(sessionKey, DEFAULT_RETURN_KEY_LENGTH, 0, DEFAULT_RETURN_KEY_LENGTH);
        ClearSensitiveStringInJson(out, FIELD_SESSION_KEY);
    }

    char *jsonDataStr = NULL;
    int32_t result = GenerateBindSuccessData(peerAuthId, peerUdid, groupId, &jsonDataStr);
    if (result != HC_SUCCESS) {
        LOGE("Failed to generate the data to be sent to the service!");
        return result;
    }
    UPDATE_PERFORM_DATA_BY_INPUT_INDEX(session->reqId, ON_FINISH_TIME, HcGetCurTimeInMillis());
    ProcessFinishCallback(session->reqId, session->opCode, jsonDataStr, session->base.callback);
    FreeJsonString(jsonDataStr);
    return HC_SUCCESS;
}

static int32_t SetGroupId(const CJson *params, TrustedGroupEntry *groupParams)
{
    const char *groupId = GetStringFromJson(params, FIELD_GROUP_ID);
    if (groupId == NULL) {
        LOGE("Failed to get groupId from params!");
        return HC_ERR_JSON_GET;
    }
    if (!StringSetPointer(&groupParams->id, groupId)) {
        LOGE("Failed to copy groupId!");
        return HC_ERR_MEMORY_COPY;
    }
    return HC_SUCCESS;
}

static int32_t SetGroupName(const CJson *params, TrustedGroupEntry *groupParams)
{
    const char *groupName = GetStringFromJson(params, FIELD_GROUP_NAME);
    if (groupName == NULL) {
        LOGE("Failed to get groupName from params!");
        return HC_ERR_JSON_GET;
    }
    if (!StringSetPointer(&groupParams->name, groupName)) {
        LOGE("Failed to copy groupName!");
        return HC_ERR_MEMORY_COPY;
    }
    return HC_SUCCESS;
}

static int32_t SetGroupOwner(const char *ownerAppId, TrustedGroupEntry *groupParams)
{
    HcString ownerName = CreateString();
    if (!StringSetPointer(&ownerName, ownerAppId)) {
        LOGE("Failed to copy groupOwner!");
        DeleteString(&ownerName);
        return HC_ERR_MEMORY_COPY;
    }
    if (groupParams->managers.pushBackT(&groupParams->managers, ownerName) == NULL) {
        LOGE("Failed to push owner to vec!");
        DeleteString(&ownerName);
        return HC_ERR_MEMORY_COPY;
    }
    return HC_SUCCESS;
}

static int32_t SetGroupType(TrustedGroupEntry *groupParams)
{
    groupParams->type = PEER_TO_PEER_GROUP;
    return HC_SUCCESS;
}

static int32_t SetGroupVisibility(const CJson *params, TrustedGroupEntry *groupParams)
{
    int32_t groupVisibility = GROUP_VISIBILITY_PUBLIC;
    (void)GetIntFromJson(params, FIELD_GROUP_VISIBILITY, &groupVisibility);
    groupParams->visibility = groupVisibility;
    return HC_SUCCESS;
}

static int32_t SetGroupExpireTime(const CJson *params, TrustedGroupEntry *groupParams)
{
    int32_t expireTime = DEFAULT_EXPIRE_TIME;
    (void)GetIntFromJson(params, FIELD_EXPIRE_TIME, &expireTime);
    groupParams->expireTime = expireTime;
    return HC_SUCCESS;
}

static int32_t GenerateGroupParams(const CompatibleBindSubSession *session, TrustedGroupEntry *groupParams)
{
    int32_t result;
    if (((result = SetGroupId(session->params, groupParams)) != HC_SUCCESS) ||
        ((result = SetGroupName(session->params, groupParams)) != HC_SUCCESS) ||
        ((result = SetGroupOwner(session->base.appId, groupParams)) != HC_SUCCESS) ||
        ((result = SetGroupType(groupParams)) != HC_SUCCESS) ||
        ((result = SetGroupVisibility(session->params, groupParams)) != HC_SUCCESS) ||
        ((result = SetGroupExpireTime(session->params, groupParams)) != HC_SUCCESS)) {
        return result;
    }
    return HC_SUCCESS;
}

static int32_t AddGroupToDatabase(const CompatibleBindSubSession *session)
{
    TrustedGroupEntry *groupParams = CreateGroupEntry();
    if (groupParams == NULL) {
        LOGE("Failed to allocate groupParams memory!");
        return HC_ERR_ALLOC_MEMORY;
    }
    int32_t result = GenerateGroupParams(session, groupParams);
    if (result != HC_SUCCESS) {
        LOGE("Failed to generate groupParams!");
        DestroyGroupEntry(groupParams);
        return result;
    }
    result = AddGroup(session->osAccountId, groupParams);
    DestroyGroupEntry(groupParams);
    if (result != HC_SUCCESS) {
        LOGE("Failed to add the group to the database!");
        return result;
    }
    return HC_SUCCESS;
}

static void GenerateDevAuthParams(const char *authId, const char *udid, const char *groupId,
    int userType, TrustedDeviceEntry *devAuthParams)
{
    devAuthParams->devType = userType;
    devAuthParams->source = SELF_CREATED;
    StringSetPointer(&(devAuthParams->authId), authId);
    StringSetPointer(&(devAuthParams->udid), udid);
    StringSetPointer(&(devAuthParams->groupId), groupId);
    StringSetPointer(&(devAuthParams->serviceType), groupId);
}

static int32_t AddTrustDevToDatabase(int32_t osAccountId, const char *authId, const char *udid, const char *groupId,
    int userType)
{
    TrustedDeviceEntry *devAuthParams = CreateDeviceEntry();
    if (devAuthParams == NULL) {
        LOGE("Failed to allocate devAuthParams memory!");
        return HC_ERR_ALLOC_MEMORY;
    }
    GenerateDevAuthParams(authId, udid, groupId, userType, devAuthParams);
    int32_t result = AddTrustedDevice(osAccountId, devAuthParams);
    DestroyDeviceEntry(devAuthParams);
    if (result != HC_SUCCESS) {
        LOGE("Failed to add the trusted devices to the database!");
        return result;
    }
    return HC_SUCCESS;
}

static int32_t AddGroupAndLocalDevIfNotExist(const char *groupId, const CompatibleBindSubSession *session)
{
    if (IsGroupExistByGroupId(session->osAccountId, groupId)) {
        return HC_SUCCESS;
    }
    char udid[INPUT_UDID_LEN] = { 0 };
    int32_t result = HcGetUdid((uint8_t *)udid, INPUT_UDID_LEN);
    if (result != HC_SUCCESS) {
        LOGE("Failed to get local udid! res: %d", result);
        return result;
    }
    result = AddGroupToDatabase(session);
    if (result != HC_SUCCESS) {
        return result;
    }
    const char *authId = GetStringFromJson(session->params, FIELD_AUTH_ID);
    if (authId == NULL) {
        LOGI("No authId is found. The default value is udid!");
        authId = udid;
    }
    int32_t userType = DEVICE_TYPE_ACCESSORY;
    (void)GetIntFromJson(session->params, FIELD_USER_TYPE, &userType);
    return AddTrustDevToDatabase(session->osAccountId, authId, udid, groupId, userType);
}

static int32_t AddPeerDevToGroup(const char *peerAuthId, const char *peerUdid,
    const char *groupId, const CompatibleBindSubSession *session)
{
    int32_t peerUserType = DEVICE_TYPE_ACCESSORY;
    (void)GetIntFromJson(session->params, FIELD_PEER_USER_TYPE, &peerUserType);
    int32_t result = AddTrustDevToDatabase(session->osAccountId, peerAuthId, peerUdid, groupId, peerUserType);
    if (result != HC_SUCCESS) {
        LOGE("Failed to add the peer trusted device information! RequestId: %" PRId64, session->reqId);
        return result;
    }
    LOGI("The peer trusted device is added to the database successfully! RequestId: %" PRId64, session->reqId);
    return HC_SUCCESS;
}

static int32_t AddGroupAndDev(const char *peerAuthId, const char *peerUdid, const char *groupId,
    const CompatibleBindSubSession *session)
{
    int32_t result = AddGroupAndLocalDevIfNotExist(groupId, session);
    if (result != HC_SUCCESS) {
        return result;
    }
    result = AddPeerDevToGroup(peerAuthId, peerUdid, groupId, session);
    if (result != HC_SUCCESS) {
        return result;
    }
    return SaveOsAccountDb(session->osAccountId);
}

static int32_t HandleBindSuccess(const char *peerAuthId, const char *peerUdid, const char *groupId,
    const CompatibleBindSubSession *session, CJson *out)
{
    DEV_AUTH_START_TRACE(TRACE_TAG_ADD_TRUSTED_DEVICE);
    int32_t result = AddGroupAndDev(peerAuthId, peerUdid, groupId, session);
    DEV_AUTH_FINISH_TRACE();
    if (result != HC_SUCCESS) {
        return result;
    }
    return InformSelfBindSuccess(peerAuthId, peerUdid, groupId, session, out);
}

static int32_t OnBindFinish(const CompatibleBindSubSession *session, const CJson *jsonParams, CJson *out)
{
    const char *peerAuthId = GetStringFromJson(jsonParams, FIELD_PEER_DEVICE_ID);
    if (peerAuthId == NULL) {
        peerAuthId = GetStringFromJson(session->params, FIELD_PEER_AUTH_ID);
        if (peerAuthId == NULL) {
            LOGE("Failed to get peerAuthId from jsonParams and params!");
            return HC_ERR_JSON_GET;
        }
    }
    const char *peerUdid = GetStringFromJson(jsonParams, FIELD_CONN_DEVICE_ID);
    if (peerUdid == NULL) {
        peerUdid = GetStringFromJson(session->params, FIELD_PEER_UDID);
        if (peerUdid == NULL) {
            LOGE("Failed to get peerUdid from jsonParams and params!");
            return HC_ERR_JSON_GET;
        }
    }
    const char *groupId = GetStringFromJson(session->params, FIELD_GROUP_ID);
    if (groupId == NULL) {
        LOGE("Failed to get groupId from session params!");
        return HC_ERR_JSON_GET;
    }
    return HandleBindSuccess(peerAuthId, peerUdid, groupId, session, out);
}

static int32_t OnSessionFinish(const CompatibleBindSubSession *session, CJson *jsonParams, CJson *out)
{
    int32_t result;
    CJson *sendData = GetObjFromJson(out, FIELD_SEND_TO_PEER);
    /* The last packet may need to be sent. */
    if (sendData != NULL) {
        result = InteractWithPeer(session, sendData);
        if (result != HC_SUCCESS) {
            return result;
        }
    }
    result = OnBindFinish(session, jsonParams, out);
    if (result != HC_SUCCESS) {
        LOGE("An error occurred when processing different end operations!");
        return result;
    }
    LOGI("The session completed successfully! [ReqId]: %" PRId64, session->reqId);
    NotifyBindResult((ChannelType)session->channelType, session->channelId);
    CloseChannel((ChannelType)session->channelType, session->channelId);
    return HC_SUCCESS;
}

static void InformPeerModuleError(CJson *out, const CompatibleBindSubSession *session)
{
    CJson *errorData = GetObjFromJson(out, FIELD_SEND_TO_PEER);
    if (errorData == NULL) {
        return;
    }
    if (AddStringToJson(errorData, FIELD_APP_ID, session->base.appId) != HC_SUCCESS) {
        LOGE("Failed to add appId to errorData!");
        return;
    }
    if (AddInt64StringToJson(errorData, FIELD_REQUEST_ID, session->reqId) != HC_SUCCESS) {
        LOGE("Failed to add requestId to errorData!");
        return;
    }
    if (AddInfoToBindData(false, session, errorData) != HC_SUCCESS) {
        LOGE("Failed to add info to error data!");
        return;
    }
    if (TransmitBindSessionData(session, errorData) != HC_SUCCESS) {
        LOGE("An error occurred when notifying the peer service!");
    } else {
        LOGI("Succeeded in notifying the peer device that an error occurred at the local end!");
    }
}

static int32_t ProcessModule(const CompatibleBindSubSession *session, const CJson *in, CJson *out, int32_t *status)
{
    LOGI("Start to process module task! [ModuleType]: %d", session->moduleType);
    DEV_AUTH_START_TRACE(TRACE_TAG_PROCESS_AUTH_TASK);
    int32_t res = ProcessTask(session->base.curTaskId, in, out, status, session->moduleType);
    DEV_AUTH_FINISH_TRACE();
    if (res != HC_SUCCESS) {
        LOGE("Failed to process module task! res: %d", res);
        return res;
    }
    LOGI("Process module task successfully!");
    return HC_SUCCESS;
}

static int32_t ProcessBindTaskInner(CompatibleBindSubSession *session, CJson *in, int32_t *status, bool *isNeedInform)
{
    int32_t result;
    if (((result = CheckPeerStatus(in, isNeedInform)) != HC_SUCCESS) ||
        ((result = TryAddPeerUserTypeToParams(in, session))) != HC_SUCCESS) {
        return result;
    }

    CJson *out = CreateJson();
    if (out == NULL) {
        LOGE("Failed to allocate out memory!");
        return HC_ERR_JSON_CREATE;
    }
    result = ProcessModule(session, in, out, status);
    if (result != HC_SUCCESS) {
        *isNeedInform = false;
        InformPeerModuleError(out, session);
        FreeJson(out);
        return result;
    }
    if (*status == IGNORE_MSG) {
        LOGI("The msg is ignored!");
    } else if (*status == CONTINUE) {
        DeleteAllItem(in);
        result = SendBindDataToPeer(session, out);
    } else {
        DEV_AUTH_START_TRACE(TRACE_TAG_ON_SESSION_FINISH);
        result = OnSessionFinish(session, in, out);
        DEV_AUTH_FINISH_TRACE();
    }
    FreeJson(out);
    return result;
}

static int32_t ProcessBindTask(CompatibleBindSubSession *session, CJson *in, int32_t *status)
{
    bool isNeedInform = true;
    int32_t result = ProcessBindTaskInner(session, in, status, &isNeedInform);
    if (result != HC_SUCCESS) {
        LOGE("Failed to process bind task!");
        InformPeerGroupErrorIfNeeded(isNeedInform, result, session);
        return result;
    }
    LOGI("Process bind session successfully! [ReqId]: %" PRId64, session->reqId);
    if (*status == FINISH) {
        return FINISH;
    }
    return HC_SUCCESS;
}

static int32_t GenerateClientModuleParams(CompatibleBindSubSession *session, CJson *moduleParams)
{
    if (AddIntToJson(moduleParams, FIELD_OPERATION_CODE, OP_BIND) != HC_SUCCESS) {
        LOGE("Failed to add operationCode to moduleParams!");
        return HC_ERR_JSON_ADD;
    }
    return GenerateBaseModuleParams(true, session, moduleParams);
}

static int32_t GetClientModuleReturnData(CompatibleBindSubSession *session, CJson *out, int32_t *status)
{
    CJson *moduleParams = CreateJson();
    if (moduleParams == NULL) {
        LOGE("Failed to allocate moduleParams memory!");
        return HC_ERR_JSON_CREATE;
    }

    int32_t result = GenerateClientModuleParams(session, moduleParams);
    if (result != HC_SUCCESS) {
        LOGE("Failed to generate all params sent to the module!");
        FreeJson(moduleParams);
        return result;
    }

    result = CreateAndProcessBindTask(session, moduleParams, out, status);
    FreeJson(moduleParams);
    return result;
}

static int32_t CreateAndProcessClientBindTask(CompatibleBindSubSession *session, CJson **sendData, int32_t *status)
{
    CJson *out = CreateJson();
    if (out == NULL) {
        LOGE("Failed to allocate out memory!");
        return HC_ERR_JSON_CREATE;
    }
    int32_t result = GetClientModuleReturnData(session, out, status);
    if (result != HC_SUCCESS) {
        FreeJson(out);
        return result;
    }

    *sendData = DetachItemFromJson(out, FIELD_SEND_TO_PEER);
    FreeJson(out);
    if (*sendData == NULL) {
        LOGE("Failed to get sendToPeer from out!");
        return HC_ERR_JSON_GET;
    }

    result = AddInfoToBindData(false, session, *sendData);
    if (result != HC_SUCCESS) {
        LOGE("Failed to add information to sendData!");
        FreeJson(*sendData);
        *sendData = NULL;
    }
    return result;
}

static int32_t AddConfirmationToParams(CJson *moduleParams)
{
    if (AddIntToJson(moduleParams, FIELD_CONFIRMATION, REQUEST_ACCEPTED) != HC_SUCCESS) {
        LOGE("Failed to add confirmation to moduleParams!");
        return HC_ERR_JSON_ADD;
    }
    return HC_SUCCESS;
}

static int32_t AddRecvModuleDataToParams(CJson *jsonParams, CJson *moduleParams)
{
    int32_t message = ERR_MESSAGE;
    if (GetIntFromJson(jsonParams, FIELD_MESSAGE, &message) != HC_SUCCESS) {
        LOGE("Failed to get message from in!");
        return HC_ERR_JSON_GET;
    }
    int32_t authForm = AUTH_FORM_INVALID_TYPE;
    (void)GetIntFromJson(jsonParams, FIELD_AUTH_FORM, &authForm);
    CJson *payload = GetObjFromJson(jsonParams, FIELD_PAYLOAD);
    if (payload == NULL) {
        LOGE("Failed to get payload from in!");
        return HC_ERR_JSON_GET;
    }
    if (AddIntToJson(moduleParams, FIELD_MESSAGE, message) != HC_SUCCESS) {
        LOGE("Failed to add message to moduleParams!");
        return HC_ERR_JSON_ADD;
    }
    if (AddIntToJson(moduleParams, FIELD_AUTH_FORM, authForm) != HC_SUCCESS) {
        LOGE("Failed to add authForm to moduleParams!");
        return HC_ERR_JSON_ADD;
    }
    if (AddObjToJson(moduleParams, FIELD_PAYLOAD, payload) != HC_SUCCESS) {
        LOGE("Failed to add payload to moduleParams!");
        return HC_ERR_JSON_ADD;
    }
    return HC_SUCCESS;
}

static int32_t GenerateServerModuleParams(CompatibleBindSubSession *session, CJson *jsonParams, CJson *moduleParams)
{
    int32_t result;
    if (((result = GenerateBaseModuleParams(false, session, moduleParams)) != HC_SUCCESS) ||
        ((result = AddConfirmationToParams(moduleParams)) != HC_SUCCESS) ||
        ((result = AddRecvModuleDataToParams(jsonParams, moduleParams)) != HC_SUCCESS)) {
        return result;
    }
    return HC_SUCCESS;
}

static int32_t GetServerModuleReturnData(CompatibleBindSubSession *session, CJson *jsonParams, CJson *out,
    bool *isNeedInform, int32_t *status)
{
    CJson *moduleParams = CreateJson();
    if (moduleParams == NULL) {
        LOGE("Failed to allocate moduleParams memory!");
        return HC_ERR_JSON_CREATE;
    }

    int32_t result = GenerateServerModuleParams(session, jsonParams, moduleParams);
    if (result != HC_SUCCESS) {
        LOGE("Failed to generate all params sent to the module!");
        FreeJson(moduleParams);
        return result;
    }
    /* Release the memory in advance to reduce the memory usage. */
    DeleteAllItem(jsonParams);

    result = CreateAndProcessBindTask(session, moduleParams, out, status);
    FreeJson(moduleParams);
    if (result != HC_SUCCESS) {
        *isNeedInform = false;
        InformPeerModuleError(out, session);
    }
    return result;
}

static int32_t PrepareServerData(CompatibleBindSubSession *session, CJson *jsonParams, CJson **sendData,
    bool *isNeedInform, int32_t *status)
{
    CJson *out = CreateJson();
    if (out == NULL) {
        LOGE("Failed to allocate out memory!");
        return HC_ERR_JSON_CREATE;
    }

    int32_t result = GetServerModuleReturnData(session, jsonParams, out, isNeedInform, status);
    if (result != HC_SUCCESS) {
        FreeJson(out);
        return result;
    }

    *sendData = DetachItemFromJson(out, FIELD_SEND_TO_PEER);
    FreeJson(out);
    if (*sendData == NULL) {
        LOGE("Failed to get sendToPeer from out!");
        return HC_ERR_JSON_GET;
    }

    result = AddInfoToBindData((session->opCode == MEMBER_JOIN), session, *sendData);
    if (result != HC_SUCCESS) {
        LOGE("Failed to add information to sendData!");
        FreeJson(*sendData);
        *sendData = NULL;
    }
    return result;
}

static int32_t PrepareAndSendServerData(CompatibleBindSubSession *session, CJson *jsonParams,
    bool *isNeedInform, int32_t *status)
{
    CJson *sendData = NULL;
    int32_t result = PrepareServerData(session, jsonParams, &sendData, isNeedInform, status);
    if (result != HC_SUCCESS) {
        return result;
    }

    result = TransmitBindSessionData(session, sendData);
    FreeJson(sendData);
    return result;
}

static int32_t InitChannel(const CJson *params, CompatibleBindSubSession *session)
{
    if (GetByteFromJson(params, FIELD_CHANNEL_ID, (uint8_t *)&session->channelId, sizeof(int64_t)) != HC_SUCCESS) {
        LOGE("Failed to get channelId!");
        return HC_ERR_JSON_GET;
    }
    if (GetIntFromJson(params, FIELD_CHANNEL_TYPE, &session->channelType) != HC_SUCCESS) {
        LOGE("Failed to get channel type!");
        return HC_ERR_JSON_GET;
    }
    return HC_SUCCESS;
}

int32_t CreateClientBindSubSession(CJson *jsonParams, const DeviceAuthCallback *callback,
    CompatibleBaseSubSession **session)
{
    int64_t requestId = DEFAULT_REQUEST_ID;
    if (GetInt64FromJson(jsonParams, FIELD_REQUEST_ID, &requestId) != HC_SUCCESS) {
        LOGE("Failed to get requestId from params!");
        return HC_ERR_JSON_GET;
    }

    int32_t opCode = MEMBER_INVITE;
    if (GetIntFromJson(jsonParams, FIELD_OPERATION_CODE, &opCode) != HC_SUCCESS) {
        LOGE("Failed to get opCode from params!");
        return HC_ERR_JSON_GET;
    }

    int32_t result = CheckClientStatus(opCode, jsonParams);
    if (result != HC_SUCCESS) {
        LOGE("Failed to check client status!");
        return result;
    }

    result = GenerateKeyPairIfNeeded(CLIENT, opCode, jsonParams);
    if (result != HC_SUCCESS) {
        return result;
    }

    result = CreateBaseBindSubSession(TYPE_CLIENT_BIND_SUB_SESSION, opCode, jsonParams, callback, session);
    if (result != HC_SUCCESS) {
        return result;
    }

    CompatibleBindSubSession *subSession = (CompatibleBindSubSession *)(*session);
    result = InitChannel(jsonParams, subSession);
    if (result != HC_SUCCESS) {
        DestroyCompatibleBindSubSession(*session);
        *session = NULL;
        return result;
    }
    result = GenerateBaseBindParams(subSession->osAccountId, CLIENT, jsonParams, subSession);
    if (result != HC_SUCCESS) {
        DestroyCompatibleBindSubSession(*session);
        *session = NULL;
    }
    return result;
}

int32_t CreateServerBindSubSession(CJson *jsonParams, const DeviceAuthCallback *callback,
    CompatibleBaseSubSession **session)
{
    int64_t reqId = DEFAULT_REQUEST_ID;
    if (GetInt64FromJson(jsonParams, FIELD_REQUEST_ID, &reqId) != HC_SUCCESS) {
        LOGE("Failed to get requestId from params!");
        return HC_ERR_JSON_GET;
    }
    int32_t opCode = MEMBER_INVITE;
    if (GetIntFromJson(jsonParams, FIELD_GROUP_OP, &opCode) != HC_SUCCESS) {
        LOGE("Failed to get operation code from params!");
        return HC_ERR_JSON_GET;
    }
    int32_t result = CreateBaseBindSubSession(TYPE_SERVER_BIND_SUB_SESSION, opCode, jsonParams, callback, session);
    if (result != HC_SUCCESS) {
        InformPeerProcessError(reqId, jsonParams, callback, result);
        return result;
    }
    CompatibleBindSubSession *subSession = (CompatibleBindSubSession *)(*session);
    result = InitChannel(jsonParams, subSession);
    if (result != HC_SUCCESS) {
        InformPeerGroupErrorIfNeeded(true, result, subSession);
        DestroyCompatibleBindSubSession(*session);
        *session = NULL;
        return result;
    }
    result = GenerateServerBindParams(subSession, jsonParams);
    if (result != HC_SUCCESS) {
        InformPeerGroupErrorIfNeeded(true, result, subSession);
        DestroyCompatibleBindSubSession(*session);
        *session = NULL;
    }
    return result;
}

int32_t ProcessClientBindSubSession(CompatibleBaseSubSession *session, CJson *in, CJson **out, int32_t *status)
{
    CompatibleBindSubSession *subSession = (CompatibleBindSubSession *)session;
    if (session->status == STATUS_PROCESSING) {
        return ProcessBindTask(subSession, in, status);
    } else {
        session->status = STATUS_PROCESSING;
        return CreateAndProcessClientBindTask(subSession, out, status);
    }
}

int32_t ProcessServerBindSubSession(CompatibleBaseSubSession *session, CJson *in, int32_t *status)
{
    CompatibleBindSubSession *subSession = (CompatibleBindSubSession *)session;
    if (session->status == STATUS_PROCESSING) {
        return ProcessBindTask(subSession, in, status);
    } else {
        session->status = STATUS_PROCESSING;
        bool isNeedInform = true;
        int32_t result = PrepareAndSendServerData(subSession, in, &isNeedInform, status);
        if (result != HC_SUCCESS) {
            InformPeerGroupErrorIfNeeded(isNeedInform, result, subSession);
        }
        return result;
    }
}

void DestroyCompatibleBindSubSession(CompatibleBaseSubSession *session)
{
    if (session == NULL) {
        return;
    }
    CompatibleBindSubSession *realSession = (CompatibleBindSubSession *)session;
    DestroyTask(realSession->base.curTaskId, realSession->moduleType);
    HcFree(realSession->base.appId);
    realSession->base.appId = NULL;
    FreeJson(realSession->params);
    realSession->params = NULL;
    HcFree(realSession);
}