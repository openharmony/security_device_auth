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

#include "compatible_auth_sub_session_common.h"

#include "account_auth_plugin_proxy.h"
#include "account_module_defines.h"
#include "account_related_group_auth.h"
#include "compatible_auth_sub_session_util.h"
#include "data_manager.h"
#include "dev_auth_module_manager.h"
#include "group_auth_data_operation.h"
#include "hc_log.h"
#include "hc_time.h"
#include "hc_types.h"
#include "hitrace_adapter.h"
#include "performance_dumper.h"

#define MIN_PROTOCOL_VERSION "1.0.0"
IMPLEMENT_HC_VECTOR(ParamsVecForAuth, void *, 1)

static void GetAccountRelatedCandidateGroups(int32_t osAccountId, const CJson *param, bool isDeviceLevel, bool isClient,
    GroupEntryVec *vec)
{
    QueryGroupParams queryParams = InitQueryGroupParams();
    if (!isDeviceLevel || !isClient) {
        queryParams.groupVisibility = GROUP_VISIBILITY_PUBLIC;
    }
    BaseGroupAuth *groupAuth = GetGroupAuth(ACCOUNT_RELATED_GROUP_AUTH_TYPE);
    if (groupAuth == NULL) {
        LOGE("Account related group auth object is null!");
        return;
    }
    ((AccountRelatedGroupAuth *)groupAuth)->getAccountCandidateGroup(osAccountId, param, &queryParams, vec);
    if (vec->size(vec) != 0) {
        return;
    }
    LOGI("Account related groups not found!");
    if (HasAccountAuthPlugin() != HC_SUCCESS) {
        return;
    }
    CJson *input = CreateJson();
    if (input == NULL) {
        return;
    }
    CJson *output = CreateJson();
    if (output == NULL) {
        FreeJson(input);
        return;
    }
    int32_t ret = ExcuteCredMgrCmd(osAccountId, QUERY_SELF_CREDENTIAL_INFO, input, output);
    if (ret != HC_SUCCESS) {
        LOGE("Account cred is empty.");
    }
    FreeJson(input);
    FreeJson(output);
}

static void GetAccountUnrelatedCandidateGroups(int32_t osAccountId, bool isDeviceLevel, bool isClient,
    GroupEntryVec *vec)
{
    QueryGroupParams queryParams = InitQueryGroupParams();
    if (!isDeviceLevel || !isClient) {
        queryParams.groupVisibility = GROUP_VISIBILITY_PUBLIC;
    }
    queryParams.groupType = PEER_TO_PEER_GROUP;
    if (QueryGroups(osAccountId, &queryParams, vec) != HC_SUCCESS) {
        LOGE("Failed to query p2p groups!");
        return;
    }
    if (vec->size(vec) == 0) {
        LOGI("p2p groups not found!");
    }
}

static void GetCandidateGroups(int32_t osAccountId, const CJson *param, GroupEntryVec *vec)
{
    bool isDeviceLevel = false;
    bool isClient = true;
    (void)GetBoolFromJson(param, FIELD_IS_DEVICE_LEVEL, &isDeviceLevel);
    if (GetBoolFromJson(param, FIELD_IS_CLIENT, &isClient) != HC_SUCCESS) {
        LOGE("Failed to get isClient!");
        return;
    }
    if (isDeviceLevel && isClient) {
        LOGI("Try to get device-level candidate groups for auth.");
    }
    GetAccountRelatedCandidateGroups(osAccountId, param, isDeviceLevel, isClient, vec);
    GetAccountUnrelatedCandidateGroups(osAccountId, isDeviceLevel, isClient, vec);
}

static void GetGroupInfoByGroupId(int32_t osAccountId, const char *groupId,
    GroupEntryVec *groupEntryVec)
{
    QueryGroupParams queryParams = InitQueryGroupParams();
    queryParams.groupId = groupId;
    if (QueryGroups(osAccountId, &queryParams, groupEntryVec) != HC_SUCCESS) {
        LOGE("Failed to query groups for groupId: %s!", groupId);
    }
}

static int32_t AddGeneralParams(const char *groupId, int32_t groupType, const TrustedDeviceEntry *localAuthInfo,
    CJson *paramsData)
{
    if (AddStringToJson(paramsData, FIELD_GROUP_ID, groupId) != HC_SUCCESS) {
        LOGE("Failed to add groupId for client auth!");
        return HC_ERR_JSON_ADD;
    }
    int32_t authForm = GroupTypeToAuthForm(groupType);
    if (AddIntToJson(paramsData, FIELD_AUTH_FORM, authForm) != HC_SUCCESS) {
        LOGE("Failed to add authFrom for client auth!");
        return HC_ERR_JSON_ADD;
    }
    const char *serviceType = StringGet(&(localAuthInfo->serviceType));
    if ((groupType == COMPATIBLE_GROUP) && (serviceType != NULL)) {
        if (AddStringToJson(paramsData, FIELD_SERVICE_TYPE, serviceType) != HC_SUCCESS) {
            LOGE("Failed to add serviceType for client compatible group auth!");
            return HC_ERR_JSON_ADD;
        }
    } else {
        if (AddStringToJson(paramsData, FIELD_SERVICE_TYPE, groupId) != HC_SUCCESS) {
            LOGE("Failed to add serviceType with groupId for client auth!");
            return HC_ERR_JSON_ADD;
        }
    }
    return HC_SUCCESS;
}

static int32_t ExtractAndAddParams(int32_t osAccountId, const char *groupId,
    const TrustedGroupEntry *groupInfo, CJson *paramsData)
{
    TrustedDeviceEntry *localAuthInfo = CreateDeviceEntry();
    if (localAuthInfo == NULL) {
        LOGE("Failed to allocate memory for localAuthInfo!");
        return HC_ERR_ALLOC_MEMORY;
    }
    int32_t groupType = groupInfo->type;
    int32_t authForm = GroupTypeToAuthForm(groupType);
    int32_t res = GaGetLocalDeviceInfo(osAccountId, groupId, localAuthInfo);
    if (res != HC_SUCCESS) {
        DestroyDeviceEntry(localAuthInfo);
        return res;
    }
    res = AddGeneralParams(groupId, groupType, localAuthInfo, paramsData);
    if (res != HC_SUCCESS) {
        DestroyDeviceEntry(localAuthInfo);
        return res;
    }
    BaseGroupAuth *groupAuth = GetGroupAuth(GetAuthType(authForm));
    if (groupAuth == NULL) {
        LOGE("Failed to get group auth handle!");
        DestroyDeviceEntry(localAuthInfo);
        return HC_ERR_NULL_PTR;
    }
    res = groupAuth->fillDeviceAuthInfo(osAccountId, groupInfo, localAuthInfo, paramsData);
    DestroyDeviceEntry(localAuthInfo);
    if (res != HC_SUCCESS) {
        LOGE("Failed to fill device auth info!");
    }
    return res;
}

static int32_t FillAuthParams(int32_t osAccountId, const CJson *param,
    const GroupEntryVec *vec, ParamsVecForAuth *paramsVec)
{
    const char *pkgName = GetStringFromJson(param, FIELD_SERVICE_PKG_NAME);
    if (pkgName == NULL) {
        LOGE("Pkg name is null, can't extract params from db!");
        return HC_ERR_NULL_PTR;
    }
    const char *peerUdid = GetStringFromJson(param, FIELD_PEER_CONN_DEVICE_ID);
    const char *peerAuthId = GetStringFromJson(param, FIELD_PEER_ID_FROM_REQUEST);
    if (peerAuthId == NULL) {
        peerAuthId = GetStringFromJson(param, FIELD_PEER_AUTH_ID);
    }
    uint32_t index;
    TrustedGroupEntry **ptr = NULL;
    FOR_EACH_HC_VECTOR(*vec, index, ptr) {
        const TrustedGroupEntry *groupInfo = (TrustedGroupEntry *)(*ptr);
        const char *groupId = StringGet(&(groupInfo->id));
        if (groupId == NULL) {
            continue;
        }
        if (!GaIsGroupAccessible(osAccountId, groupId, pkgName)) {
            continue;
        }
        if (!GaIsDeviceInGroup(groupInfo->type, osAccountId, peerUdid, peerAuthId, groupId)) {
            continue;
        }
        CJson *paramsData = DuplicateJson(param);
        if (paramsData == NULL) {
            LOGE("Failed to duplicate auth param data!");
            return HC_ERR_JSON_FAIL;
        }
        if (ExtractAndAddParams(osAccountId, groupId, groupInfo, paramsData) != HC_SUCCESS) {
            LOGE("Failed to extract and add param!");
            FreeJson(paramsData);
            continue;
        }
        paramsVec->pushBack(paramsVec, (const void **)&paramsData);
    }
    LOGI("The candidate group size is: %u", paramsVec->size(paramsVec));
    return HC_SUCCESS;
}

static int32_t GetCandidateAuthInfo(int32_t osAccountId, const char *groupId,
    const CJson *param, ParamsVecForAuth *authParamsVec)
{
    GroupEntryVec vec = CreateGroupEntryVec();
    if (groupId == NULL) {
        LOGI("No groupId specified, extract group info without groupId.");
        GetCandidateGroups(osAccountId, param, &vec);
    } else {
        LOGI("GroupId specified, extract group info with the groupId.");
        GetGroupInfoByGroupId(osAccountId, groupId, &vec);
    }
    if (vec.size(&vec) == 0) {
        LOGW("No satisfied candidate group!");
        ClearGroupEntryVec(&vec);
        return HC_ERR_NO_CANDIDATE_GROUP;
    }
    int32_t res = FillAuthParams(osAccountId, param, &vec, authParamsVec);
    ClearGroupEntryVec(&vec);
    return res;
}

static int32_t AddInfoToErrorData(CJson *sendToPeer, const CJson *authParam)
{
    int32_t authForm = AUTH_FORM_INVALID_TYPE;
    if (GetIntFromJson(authParam, FIELD_AUTH_FORM, &authForm) != HC_SUCCESS) {
        LOGE("Failed to get authForm from authParam!");
        return HC_ERR_JSON_GET;
    }
    if (AddIntToJson(sendToPeer, FIELD_AUTH_FORM, authForm) != HC_SUCCESS) {
        LOGE("Failed to add authForm for peer!");
        return HC_ERR_JSON_ADD;
    }
    if ((authForm == AUTH_FORM_IDENTICAL_ACCOUNT) && (AddIntToJson(sendToPeer, FIELD_STEP, ERR_MSG) != HC_SUCCESS)) {
        LOGE("Failed to add step for peer!");
        return HC_ERR_JSON_ADD;
    }
    return HC_SUCCESS;
}

static int32_t AddVersionMsgToError(CJson *errorToPeer)
{
    CJson *version = CreateJson();
    if (version == NULL) {
        LOGE("Failed to create json for version!");
        return HC_ERR_JSON_CREATE;
    }
    CJson *payload = CreateJson();
    if (payload == NULL) {
        LOGE("Failed to create json for payload!");
        FreeJson(version);
        return HC_ERR_JSON_CREATE;
    }
    int32_t res = HC_SUCCESS;
    do {
        if (AddStringToJson(version, FIELD_MIN_VERSION, MIN_PROTOCOL_VERSION) != HC_SUCCESS) {
            LOGE("Failed to add min version to json!");
            res = HC_ERR_JSON_ADD;
            break;
        }
        if (AddStringToJson(version, FIELD_CURRENT_VERSION, MIN_PROTOCOL_VERSION) != HC_SUCCESS) {
            LOGE("Failed to add max version to json!");
            res = HC_ERR_JSON_ADD;
            break;
        }
        if (AddObjToJson(payload, FIELD_VERSION, version) != HC_SUCCESS) {
            LOGE("Add version object to errorToPeer failed.");
            res = HC_ERR_JSON_ADD;
            break;
        }
        if (AddIntToJson(payload, FIELD_ERROR_CODE, -1) != HC_SUCCESS) {
            LOGE("Failed to add errorCode for peer!");
            res = HC_ERR_JSON_ADD;
            break;
        }
        if (AddObjToJson(errorToPeer, FIELD_PAYLOAD, payload) != HC_SUCCESS) {
            LOGE("Failed to add error data!");
            res = HC_ERR_JSON_ADD;
            break;
        }
    } while (0);
    FreeJson(version);
    FreeJson(payload);
    return res;
}

static int32_t PrepareErrorMsgToPeer(const CJson *authParam, CJson *errorToPeer)
{
    int32_t res = AddInfoToErrorData(errorToPeer, authParam);
    if (res != HC_SUCCESS) {
        LOGE("Failed to add info to error data!");
        return res;
    }
    if (AddIntToJson(errorToPeer, FIELD_GROUP_ERROR_MSG, GROUP_ERR_MSG) != HC_SUCCESS) {
        LOGE("Failed to add groupErrorMsg for peer!");
        return HC_ERR_JSON_ADD;
    }
    if (AddIntToJson(errorToPeer, FIELD_MESSAGE, GROUP_ERR_MSG) != HC_SUCCESS) {
        LOGE("Failed to add message for peer!");
        return HC_ERR_JSON_ADD;
    }
    return AddVersionMsgToError(errorToPeer);
}

static int32_t ReturnErrorToPeerBySession(const CJson *authParam, const DeviceAuthCallback *callback)
{
    int64_t requestId = 0;
    if (GetInt64FromJson(authParam, FIELD_REQUEST_ID, &requestId) != HC_SUCCESS) {
        LOGE("Failed to get request ID!");
        return HC_ERR_JSON_GET;
    }
    CJson *errorToPeer = CreateJson();
    if (errorToPeer == NULL) {
        LOGE("Failed to allocate memory for errorToPeer!");
        return HC_ERR_ALLOC_MEMORY;
    }
    int32_t res = PrepareErrorMsgToPeer(authParam, errorToPeer);
    if (res != HC_SUCCESS) {
        FreeJson(errorToPeer);
        return res;
    }
    char *errorToPeerStr = PackJsonToString(errorToPeer);
    FreeJson(errorToPeer);
    if (errorToPeerStr == NULL) {
        LOGE("Failed to pack errorToPeer to string!");
        return HC_ERR_ALLOC_MEMORY;
    }
    if ((callback == NULL) || (callback->onTransmit == NULL)) {
        LOGE("The callback of onTransmit is null!");
        FreeJsonString(errorToPeerStr);
        return HC_ERR_NULL_PTR;
    }
    LOGD("Begin transmit error msg to peer by session!");
    if (!callback->onTransmit(requestId, (uint8_t *)errorToPeerStr, HcStrlen(errorToPeerStr) + 1)) {
        LOGE("Failed to transmit error msg by session!");
        FreeJsonString(errorToPeerStr);
        return HC_ERR_TRANSMIT_FAIL;
    }
    LOGD("End transmit error msg to peer by session!");
    FreeJsonString(errorToPeerStr);
    return HC_SUCCESS;
}

static int32_t ReturnErrorToPeerByTask(CJson *sendToPeer, const CJson *authParam,
    const DeviceAuthCallback *callback)
{
    int64_t requestId = 0;
    if (GetInt64FromJson(authParam, FIELD_REQUEST_ID, &requestId) != HC_SUCCESS) {
        LOGE("Failed to get request id!");
        return HC_ERR_JSON_GET;
    }
    int32_t res = AddInfoToErrorData(sendToPeer, authParam);
    if (res != HC_SUCCESS) {
        LOGE("Failed to add info to error data!");
        return res;
    }
    char *sendToPeerStr = PackJsonToString(sendToPeer);
    if (sendToPeerStr == NULL) {
        LOGE("Failed to pack json to string!");
        return HC_ERR_ALLOC_MEMORY;
    }
    if ((callback == NULL) || (callback->onTransmit == NULL)) {
        LOGE("The callback of onTransmit is null!");
        FreeJsonString(sendToPeerStr);
        return HC_ERR_NULL_PTR;
    }
    LOGD("Begin transmit error msg to peer by task!");
    if (!callback->onTransmit(requestId, (uint8_t *)sendToPeerStr, HcStrlen(sendToPeerStr) + 1)) {
        LOGE("Failed to transmit error msg by task!");
        FreeJsonString(sendToPeerStr);
        return HC_ERR_TRANSMIT_FAIL;
    }
    LOGD("End transmit error msg to peer by task!");
    FreeJsonString(sendToPeerStr);
    return HC_SUCCESS;
}

static int32_t ReturnTransmitData(const CompatibleAuthSubSession *session, CJson *out)
{
    CJson *sendToPeer = GetObjFromJson(out, FIELD_SEND_TO_PEER);
    if (sendToPeer == NULL) {
        LOGI("The transmit data to peer is null!");
        return HC_ERR_JSON_GET;
    }
    CJson *authParam = (session->paramsList).get(&(session->paramsList), session->currentIndex);
    if (authParam == NULL) {
        LOGE("The json data in session is null!");
        return HC_ERR_NULL_PTR;
    }
    int64_t requestId = 0;
    if (GetInt64FromJson(authParam, FIELD_REQUEST_ID, &requestId) != HC_SUCCESS) {
        LOGE("Failed to get request id!");
        return HC_ERR_JSON_GET;
    }

    int32_t ret = AddGroupAuthTransmitData(session, false, sendToPeer);
    if (ret != HC_SUCCESS) {
        LOGE("Failed to add extra data!");
        return ret;
    }
    char *outStr = PackJsonToString(sendToPeer);
    if (outStr == NULL) {
        LOGE("Failed to pack outStr for onTransmit!");
        return HC_ERR_ALLOC_MEMORY;
    }

    const DeviceAuthCallback *callback = session->base.callback;
    if ((callback == NULL) || (callback->onTransmit == NULL)) {
        LOGE("The callback for transmit is null!");
        FreeJsonString(outStr);
        return HC_ERR_NULL_PTR;
    }
    LOGI("Start to transmit data to peer for auth!");
    DEV_AUTH_START_TRACE(TRACE_TAG_SEND_DATA);
    UPDATE_PERFORM_DATA_BY_SELF_INDEX(requestId, HcGetCurTimeInMillis());
    if (!callback->onTransmit(requestId, (uint8_t *)outStr, HcStrlen(outStr) + 1)) {
        LOGE("Failed to transmit data to peer!");
        FreeJsonString(outStr);
        return HC_ERR_TRANSMIT_FAIL;
    }
    DEV_AUTH_FINISH_TRACE();
    LOGI("End transmit data to peer for auth!");
    FreeJsonString(outStr);
    return HC_SUCCESS;
}

static void ReturnFinishData(const CompatibleAuthSubSession *session, const CJson *out)
{
    ParamsVecForAuth list = session->paramsList;
    const CJson *authParam = list.get(&list, session->currentIndex);
    if (authParam == NULL) {
        LOGE("The json data in session is null!");
        return;
    }
    int64_t requestId = 0;
    if (GetInt64FromJson(authParam, FIELD_REQUEST_ID, &requestId) != HC_SUCCESS) {
        LOGE("Failed to get request id!");
        return;
    }
    int32_t authForm = AUTH_FORM_INVALID_TYPE;
    if (GetIntFromJson(authParam, FIELD_AUTH_FORM, &authForm) != HC_SUCCESS) {
        LOGE("Failed to get auth type!");
        return;
    }
    BaseGroupAuth *groupAuth = GetGroupAuth(GetAuthType(authForm));
    if (groupAuth != NULL) {
        DEV_AUTH_START_TRACE(TRACE_TAG_ON_SESSION_FINISH);
        groupAuth->onFinish(requestId, authParam, out, session->base.callback);
        DEV_AUTH_FINISH_TRACE();
    }
}

int32_t AuthOnNextGroupIfExist(CompatibleAuthSubSession *session)
{
    if (session->currentIndex >= session->paramsList.size(&session->paramsList) - 1) {
        LOGD("There is no alternative auth group.");
        return HC_ERR_NO_CANDIDATE_GROUP;
    }
    session->currentIndex++;
    CJson *paramInNextSession = (session->paramsList).get(&(session->paramsList), session->currentIndex);
    if (paramInNextSession == NULL) {
        LOGE("The json data in session is null!");
        return HC_ERR_NULL_PTR;
    }
    int64_t requestId = 0;
    if (GetInt64FromJson(paramInNextSession, FIELD_REQUEST_ID, &requestId) != HC_SUCCESS) {
        LOGE("Failed to get request id!");
        return HC_ERR_JSON_GET;
    }
    RESET_PERFORM_DATA(requestId);
    CJson *outNext = CreateJson();
    if (outNext == NULL) {
        LOGE("Failed to create json for outNext!");
        return HC_ERR_ALLOC_MEMORY;
    }
    int32_t res;
    do {
        int32_t status = 0;
        res = CreateAndProcessAuthTask(session, paramInNextSession, outNext, &status);
        if (res != HC_SUCCESS) {
            break;
        }
        res = HandleAuthTaskStatus(session, outNext, status);
    } while (0);
    if (res != HC_SUCCESS) {
        LOGW("Failed to auth on current group, try to auth on next group!");
        DestroyTask(session->base.curTaskId, GetAuthModuleType(paramInNextSession));
        res = ProcessClientAuthError(session, outNext);
    }
    FreeJson(outNext);
    return res;
}

void CreateAuthParamsList(ParamsVecForAuth *vec)
{
    *vec = CREATE_HC_VECTOR(ParamsVecForAuth);
}

void DestroyAuthParamsList(ParamsVecForAuth *vec)
{
    DESTROY_HC_VECTOR(ParamsVecForAuth, vec);
}

int32_t GetAuthParamsVec(int32_t osAccountId, const CJson *param, ParamsVecForAuth *authParamsVec)
{
    const char *groupId = GetStringFromJson(param, FIELD_GROUP_ID);
    if (groupId == NULL) {
        groupId = GetStringFromJson(param, FIELD_SERVICE_TYPE);
    }
    return GetCandidateAuthInfo(osAccountId, groupId, param, authParamsVec);
}

int32_t CreateAndProcessAuthTask(CompatibleAuthSubSession *session, CJson *paramInSession, CJson *out, int32_t *status)
{
    int32_t moduleType = GetAuthModuleType(paramInSession);
    if (moduleType == DAS_MODULE) {
        const char *servicePkgName = GetStringFromJson(paramInSession, FIELD_SERVICE_PKG_NAME);
        if (servicePkgName == NULL) {
            LOGE("servicePkgName is null!");
            return HC_ERR_JSON_GET;
        }
        if (AddStringToJson(paramInSession, FIELD_PKG_NAME, servicePkgName) != HC_SUCCESS) {
            LOGE("Failed to add pkg name to json!");
            return HC_ERR_JSON_ADD;
        }
    }
    session->base.curTaskId = 0;
    DEV_AUTH_START_TRACE(TRACE_TAG_CREATE_AUTH_TASK);
    int32_t res = CreateTask(&(session->base.curTaskId), paramInSession, out, moduleType);
    DEV_AUTH_FINISH_TRACE();
    if (res != HC_SUCCESS) {
        LOGE("Failed to create task for auth!");
        return res;
    }
    DEV_AUTH_START_TRACE(TRACE_TAG_PROCESS_AUTH_TASK);
    res = ProcessTask(session->base.curTaskId, paramInSession, out, status, moduleType);
    DEV_AUTH_FINISH_TRACE();
    ClearCachedData(paramInSession);
    if (res != HC_SUCCESS) {
        DestroyTask(session->base.curTaskId, GetAuthModuleType(paramInSession));
        LOGE("Failed to process task for auth!");
    }
    return res;
}

void ClearCachedData(CJson *paramInSession)
{
    DeleteItemFromJson(paramInSession, FIELD_PAYLOAD);
    DeleteItemFromJson(paramInSession, FIELD_SELF_AUTH_ID);
    DeleteItemFromJson(paramInSession, FIELD_OPERATION_CODE);
}

int32_t ProcessClientAuthError(CompatibleAuthSubSession *session, const CJson *out)
{
    ParamsVecForAuth list = session->paramsList;
    CJson *paramInSession = list.get(&list, session->currentIndex);
    if (paramInSession == NULL) {
        LOGE("The json data in session is null!");
        return HC_ERR_NULL_PTR;
    }
    CJson *sendToPeer = GetObjFromJson(out, FIELD_SEND_TO_PEER);
    if (sendToPeer != NULL && ReturnErrorToPeerByTask(sendToPeer, paramInSession,
        session->base.callback) != HC_SUCCESS) {
        LOGE("Failed to return task's error msg to peer!");
        return HC_ERR_INFORM_ERR;
    }
    int32_t res = AuthOnNextGroupIfExist(session);
    if (res != HC_SUCCESS) {
        LOGE("Failed to auth on next group!");
    }
    return res;
}

void ProcessServerAuthError(CompatibleAuthSubSession *session, const CJson *out)
{
    ParamsVecForAuth list = session->paramsList;
    CJson *paramInSession = list.get(&list, session->currentIndex);
    if (paramInSession == NULL) {
        LOGE("The json data in session is null!");
        return;
    }
    CJson *sendToPeer = GetObjFromJson(out, FIELD_SEND_TO_PEER);
    if (sendToPeer != NULL && ReturnErrorToPeerByTask(sendToPeer, paramInSession,
        session->base.callback) != HC_SUCCESS) {
        LOGE("Failed to return task's error msg to peer!");
    }
}

int32_t AddGroupAuthTransmitData(const CompatibleAuthSubSession *session, bool isClientFirst, CJson *sendToPeer)
{
    ParamsVecForAuth list = session->paramsList;
    CJson *authParam = list.get(&list, session->currentIndex);
    if (authParam == NULL) {
        LOGE("The json data in session is null!");
        return HC_ERR_NULL_PTR;
    }
    bool isDeviceLevel = false;
    int32_t authForm = AUTH_FORM_INVALID_TYPE;
    (void)GetIntFromJson(authParam, FIELD_AUTH_FORM, &authForm);
    if (isClientFirst && (authForm == AUTH_FORM_IDENTICAL_ACCOUNT || authForm == AUTH_FORM_ACROSS_ACCOUNT)) {
        (void)GetBoolFromJson(authParam, FIELD_IS_DEVICE_LEVEL, &isDeviceLevel);
    }
    /* Disable device-level auth. */
    if (AddBoolToJson(sendToPeer, FIELD_IS_DEVICE_LEVEL, isDeviceLevel) != HC_SUCCESS) {
        LOGE("Failed to add device level!");
        return HC_ERR_JSON_ADD;
    }
    bool isClient = true;
    if (GetBoolFromJson(authParam, FIELD_IS_CLIENT, &isClient)) {
        LOGE("Failed to get isClient!");
        return HC_ERR_JSON_GET;
    }
    if (isClient && (session->currentIndex < (list.size(&list) - 1))) {
        CJson *nextParam = list.get(&list, session->currentIndex + 1);
        if (nextParam == NULL) {
            LOGE("Failed to get next auth params!");
            return HC_ERR_NULL_PTR;
        }
        const char *altGroup = GetStringFromJson(nextParam, FIELD_SERVICE_TYPE);
        if ((altGroup != NULL) && (AddStringToJson(sendToPeer, FIELD_ALTERNATIVE, altGroup) != HC_SUCCESS)) {
            LOGE("Failed to add alternative group!");
            return HC_ERR_JSON_ADD;
        }
    }
    return HC_SUCCESS;
}

int32_t HandleAuthTaskStatus(const CompatibleAuthSubSession *session, CJson *out, int32_t status)
{
    int32_t res = HC_SUCCESS;
    switch (status) {
        case IGNORE_MSG:
            LOGI("Ignore this msg.");
            break;
        case CONTINUE:
            res = ReturnTransmitData(session, out);
            if (res != HC_SUCCESS) {
                LOGE("Failed to transmit data to peer!");
            }
            break;
        case FINISH:
            ReturnFinishData(session, out);
            ClearSensitiveStringInJson(out, FIELD_SESSION_KEY);
            res = FINISH;
            break;
        default:
            LOGE("Invalid status after process task!");
            res = HC_ERR_INVALID_PARAMS;
            break;
    }
    return res;
}

void NotifyPeerAuthError(const CJson *authParam, const DeviceAuthCallback *callback)
{
    if (ReturnErrorToPeerBySession(authParam, callback) != HC_SUCCESS) {
        LOGE("Failed to return error to peer by session!");
    }
}