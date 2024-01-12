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

#include "compatible_auth_sub_session.h"

#include "compatible_auth_sub_session_common.h"
#include "compatible_auth_sub_session_util.h"
#include "dev_auth_module_manager.h"
#include "hc_log.h"
#include "hc_types.h"
#include "hitrace_adapter.h"

static int32_t CheckInputAuthParams(const CJson *authParam)
{
    int32_t keyLen = DEFAULT_RETURN_KEY_LENGTH;
    (void)GetIntFromJson(authParam, FIELD_KEY_LENGTH, &keyLen);
    if ((keyLen < MIN_KEY_LENGTH) || (keyLen > MAX_KEY_LENGTH)) {
        LOGE("The key length is invalid!");
        return HC_ERR_INVALID_PARAMS;
    }
    if (GetStringFromJson(authParam, FIELD_SERVICE_PKG_NAME) == NULL) {
        LOGE("Failed to get servicePkgName!");
        return HC_ERR_JSON_GET;
    }
    return HC_SUCCESS;
}

static int32_t CreateClientAuthSubSessionInner(int32_t osAccountId, CJson *jsonParams,
    const DeviceAuthCallback *callback, CompatibleBaseSubSession **session)
{
    ParamsVecForAuth authParamsVec;
    CreateAuthParamsList(&authParamsVec);
    int32_t res = GetAuthParamsVec(osAccountId, jsonParams, &authParamsVec);
    if (res != HC_SUCCESS) {
        LOGW("Failed to get auth param list!");
        DestroyAuthParamsList(&authParamsVec);
        return res;
    }
    if (authParamsVec.size(&authParamsVec) == 0) {
        LOGE("Empty auth params list!");
        DestroyAuthParamsList(&authParamsVec);
        return HC_ERR_NO_CANDIDATE_GROUP;
    }
    CompatibleAuthSubSession *subSession = (CompatibleAuthSubSession *)HcMalloc(sizeof(CompatibleAuthSubSession), 0);
    if (subSession == NULL) {
        LOGE("Failed to allocate memory for session!");
        DestroyAuthParamsList(&authParamsVec);
        return HC_ERR_ALLOC_MEMORY;
    }
    subSession->base.type = TYPE_CLIENT_AUTH_SUB_SESSION;
    subSession->base.callback = callback;
    subSession->base.appId = GetDuplicatePkgName(jsonParams);
    subSession->currentIndex = 0;
    subSession->paramsList = authParamsVec;
    subSession->base.status = STATUS_INITIAL;
    *session = (CompatibleBaseSubSession *)subSession;

    return HC_SUCCESS;
}

static int32_t GetAuthInfoForServer(CJson *dataFromClient, ParamsVecForAuth *authParamsVec)
{
    int32_t authForm = AUTH_FORM_INVALID_TYPE;
    if (GetIntFromJson(dataFromClient, FIELD_AUTH_FORM, &authForm) != HC_SUCCESS) {
        LOGE("Failed to get auth form!");
        return HC_ERR_JSON_GET;
    }
    int32_t groupAuthType = GetAuthType(authForm);
    BaseGroupAuth *groupAuthHandle = GetGroupAuth(groupAuthType);
    if (groupAuthHandle == NULL) {
        LOGE("Failed to get group auth handle!");
        return HC_ERR_NOT_SUPPORT;
    }
    return groupAuthHandle->getAuthParamsVecForServer(dataFromClient, authParamsVec);
}

static bool IsPeerGroupAuthError(const CJson *in)
{
    int32_t groupErrMsg = 0;
    if (GetIntFromJson(in, FIELD_GROUP_ERROR_MSG, &groupErrMsg) != HC_SUCCESS) {
        return false;
    }
    return true;
}

static int32_t HandlePeerAuthError(CompatibleAuthSubSession *session)
{
    if (AuthOnNextGroupIfExist(session) != HC_SUCCESS) {
        LOGE("Failed to auth on next group!");
        return HC_ERR_PEER_ERROR;
    }
    return HC_SUCCESS;
}

static int32_t ProcessClientAuthTaskInner(CompatibleAuthSubSession *session, int32_t moduleType, CJson *in,
    CJson *out, int32_t *status)
{
    CJson *paramInSession = (session->paramsList).get(&(session->paramsList), session->currentIndex);
    if (paramInSession == NULL) {
        LOGE("Failed to get param in session!");
        return HC_ERR_NULL_PTR;
    }
    DEV_AUTH_START_TRACE(TRACE_TAG_PROCESS_AUTH_TASK);
    int32_t res = ProcessTask(session->base.curTaskId, in, out, status, moduleType);
    DEV_AUTH_FINISH_TRACE();
    DeleteItemFromJson(in, FIELD_PAYLOAD);
    if (res != HC_SUCCESS) {
        LOGW("Failed to process client auth task, try to auth on next group!");
        DestroyTask(session->base.curTaskId, moduleType);
        return ProcessClientAuthError(session, out);
    }
    return HandleAuthTaskStatus(session, out, *status);
}

static void ProcessDeviceLevel(const CJson *receiveData, CJson *authParam)
{
    bool receiveLevel = false;
    bool authLevel = false;
    (void)GetBoolFromJson(receiveData, FIELD_IS_DEVICE_LEVEL, &receiveLevel);
    (void)GetBoolFromJson(authParam, FIELD_IS_DEVICE_LEVEL, &authLevel);
    if (AddBoolToJson(authParam, FIELD_IS_DEVICE_LEVEL, receiveLevel && authLevel) != HC_SUCCESS) {
        LOGE("Failed to add device level to auth param!");
    }
}

static int32_t ProcessClientAuthTask(CompatibleAuthSubSession *session, CJson *receivedData, int32_t *status)
{
    CJson *paramInSession = (session->paramsList).get(&(session->paramsList), session->currentIndex);
    if (paramInSession == NULL) {
        LOGE("Failed to get param in session!");
        return HC_ERR_NULL_PTR;
    }
    ProcessDeviceLevel(receivedData, paramInSession);

    if (IsPeerGroupAuthError(receivedData)) {
        return HandlePeerAuthError(session);
    }

    CJson *out = CreateJson();
    if (out == NULL) {
        LOGE("Failed to create json for out!");
        NotifyPeerAuthError(paramInSession, session->base.callback);
        return HC_ERR_JSON_CREATE;
    }
    int32_t res = ProcessClientAuthTaskInner(session, GetAuthModuleType(paramInSession), receivedData, out, status);
    ClearSensitiveStringInJson(out, FIELD_SESSION_KEY);
    FreeJson(out);
    if (res == FINISH) {
        LOGI("End process client authSession.");
    }
    return res;
}

static int32_t GenerateClientFirstMsg(CompatibleAuthSubSession *session, CJson *out, CJson **sendData)
{
    *sendData = DetachItemFromJson(out, FIELD_SEND_TO_PEER);
    if (*sendData == NULL) {
        LOGE("The transmit data to peer is null!");
        return HC_ERR_JSON_GET;
    }
    int32_t res = AddGroupAuthTransmitData(session, true, *sendData);
    if (res != HC_SUCCESS) {
        FreeJson(*sendData);
        *sendData = NULL;
    }
    return res;
}

static int32_t CreateAndProcessClientAuthTask(CompatibleAuthSubSession *session, CJson **sendData, int32_t *status)
{
    CJson *paramInSession = (session->paramsList).get(&(session->paramsList), session->currentIndex);
    if (paramInSession == NULL) {
        LOGE("Failed to get param in session!");
        return HC_ERR_NULL_PTR;
    }
    CJson *out = CreateJson();
    if (out == NULL) {
        LOGE("Failed to create json!");
        return HC_ERR_JSON_CREATE;
    }
    int32_t res = CreateAndProcessAuthTask(session, paramInSession, out, status);
    if (res != HC_SUCCESS) {
        LOGW("Failed to create and process client auth task, try to auth on next group!");
        res = ProcessClientAuthError(session, out);
        FreeJson(out);
        return res;
    }
    res = GenerateClientFirstMsg(session, out, sendData);
    FreeJson(out);
    return res;
}

static int32_t ProcessServerAuthTaskInner(CompatibleAuthSubSession *session, int32_t moduleType,
    CJson *in, CJson *out, int32_t *status)
{
    CJson *paramInSession = (session->paramsList).get(&(session->paramsList), session->currentIndex);
    if (paramInSession == NULL) {
        LOGE("The json data in session is null!");
        return HC_ERR_NULL_PTR;
    }
    DEV_AUTH_START_TRACE(TRACE_TAG_PROCESS_AUTH_TASK);
    int32_t res = ProcessTask(session->base.curTaskId, in, out, status, moduleType);
    DEV_AUTH_FINISH_TRACE();
    DeleteItemFromJson(in, FIELD_PAYLOAD);
    if (res != HC_SUCCESS) {
        ProcessServerAuthError(session, out);
        return res;
    }
    return HandleAuthTaskStatus(session, out, *status);
}

static int32_t ProcessServerAuthTask(CompatibleAuthSubSession *session, CJson *receivedData, int32_t *status)
{
    CJson *paramInSession = (session->paramsList).get(&(session->paramsList), session->currentIndex);
    if (paramInSession == NULL) {
        LOGE("Failed to get param in session!");
        return HC_ERR_NULL_PTR;
    }
    if (IsPeerGroupAuthError(receivedData)) {
        LOGE("Peer group auth error happened, stop the server auth session!");
        return HC_ERR_PEER_ERROR;
    }
    CJson *out = CreateJson();
    if (out == NULL) {
        LOGE("Failed to create json for out!");
        NotifyPeerAuthError(paramInSession, session->base.callback);
        return HC_ERR_JSON_CREATE;
    }
    int32_t moduleType = GetAuthModuleType(paramInSession);
    int32_t res = ProcessServerAuthTaskInner(session, moduleType, receivedData, out, status);
    FreeJson(out);
    if (res == FINISH) {
        LOGI("finish process server authSession.");
    }
    return res;
}

static int32_t CreateAndProcessServerAuthTask(CompatibleAuthSubSession *session, CJson *receivedData, int32_t *status)
{
    CJson *paramInSession = (session->paramsList).get(&(session->paramsList), session->currentIndex);
    if (paramInSession == NULL) {
        LOGE("The json data in session is null!");
        return HC_ERR_NULL_PTR;
    }
    ProcessDeviceLevel(receivedData, paramInSession);
    CJson *out = CreateJson();
    if (out == NULL) {
        LOGE("Failed to create json!");
        NotifyPeerAuthError(receivedData, session->base.callback);
        return HC_ERR_JSON_CREATE;
    }
    int32_t res = CreateAndProcessAuthTask(session, paramInSession, out, status);
    if (res != HC_SUCCESS) {
        ProcessServerAuthError(session, out);
        FreeJson(out);
        return res;
    }
    res = HandleAuthTaskStatus(session, out, *status);
    FreeJson(out);
    return res;
}

int32_t CreateClientAuthSubSession(CJson *jsonParams, const DeviceAuthCallback *callback,
    CompatibleBaseSubSession **session)
{
    int32_t res = CheckInputAuthParams(jsonParams);
    if (res != HC_SUCCESS) {
        LOGE("Invalid input params!");
        return res;
    }
    if (AddIntToJson(jsonParams, FIELD_OPERATION_CODE, AUTHENTICATE) != HC_SUCCESS) {
        LOGE("Failed to add operation code to json!");
        return HC_ERR_JSON_ADD;
    }
    int32_t osAccountId = INVALID_OS_ACCOUNT;
    if (GetIntFromJson(jsonParams, FIELD_OS_ACCOUNT_ID, &osAccountId) != HC_SUCCESS) {
        LOGE("Failed to get osAccountId from params!");
        return HC_ERR_JSON_GET;
    }
    return CreateClientAuthSubSessionInner(osAccountId, jsonParams, callback, session);
}

int32_t CreateServerAuthSubSession(CJson *jsonParams, const DeviceAuthCallback *callback,
    CompatibleBaseSubSession **session)
{
    ParamsVecForAuth authVec;
    CreateAuthParamsList(&authVec);
    int32_t res = GetAuthInfoForServer(jsonParams, &authVec);
    ClearCachedData(jsonParams);
    if (res != HC_SUCCESS) {
        LOGE("Failed to add auth param for server!");
        DestroyAuthParamsList(&authVec);
        NotifyPeerAuthError(jsonParams, callback);
        return res;
    }
    if (authVec.size(&authVec) == 0) {
        LOGE("Empty auth params list!");
        DestroyAuthParamsList(&authVec);
        NotifyPeerAuthError(jsonParams, callback);
        return HC_ERR_NO_CANDIDATE_GROUP;
    }
    CompatibleAuthSubSession *subSession = (CompatibleAuthSubSession *)HcMalloc(sizeof(CompatibleAuthSubSession), 0);
    if (subSession == NULL) {
        LOGE("Failed to malloc memory for session!");
        DestroyAuthParamsList(&authVec);
        NotifyPeerAuthError(jsonParams, callback);
        return HC_ERR_ALLOC_MEMORY;
    }

    subSession->base.type = TYPE_SERVER_AUTH_SUB_SESSION;
    subSession->base.callback = callback;
    subSession->base.appId = GetDuplicatePkgName(jsonParams);
    subSession->currentIndex = 0;
    subSession->paramsList = authVec;
    subSession->base.status = STATUS_INITIAL;
    *session = (CompatibleBaseSubSession *)subSession;

    return HC_SUCCESS;
}

int32_t ProcessClientAuthSubSession(CompatibleBaseSubSession *session, CJson *in, CJson **out, int32_t *status)
{
    CompatibleAuthSubSession *subSession = (CompatibleAuthSubSession *)session;
    if (session->status == STATUS_PROCESSING) {
        return ProcessClientAuthTask(subSession, in, status);
    } else {
        session->status = STATUS_PROCESSING;
        return CreateAndProcessClientAuthTask(subSession, out, status);
    }
}

int32_t ProcessServerAuthSubSession(CompatibleBaseSubSession *session, CJson *in, int32_t *status)
{
    CompatibleAuthSubSession *subSession = (CompatibleAuthSubSession *)session;
    if (session->status == STATUS_PROCESSING) {
        return ProcessServerAuthTask(subSession, in, status);
    } else {
        session->status = STATUS_PROCESSING;
        return CreateAndProcessServerAuthTask(subSession, in, status);
    }
}

void DestroyCompatibleAuthSubSession(CompatibleBaseSubSession *session)
{
    if (session == NULL) {
        return;
    }
    CompatibleAuthSubSession *realSession = (CompatibleAuthSubSession *)session;
    HcFree(realSession->base.appId);
    realSession->base.appId = NULL;
    CJson *paramInSession = (realSession->paramsList).get(&(realSession->paramsList), realSession->currentIndex);
    if (paramInSession == NULL) {
        LOGE("The json param in session is null!");
        return;
    }
    DestroyTask(realSession->base.curTaskId, GetAuthModuleType(paramInSession));

    uint32_t index;
    void **paramsData = NULL;
    FOR_EACH_HC_VECTOR(realSession->paramsList, index, paramsData) {
        FreeJson((CJson *)*paramsData);
    }
    DestroyAuthParamsList(&(realSession->paramsList));
    HcFree(realSession);
}