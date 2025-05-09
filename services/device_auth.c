/*
 * Copyright (C) 2021-2025 Huawei Device Co., Ltd.
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

#include "device_auth.h"

#include "alg_loader.h"
#include "callback_manager.h"
#include "channel_manager.h"
#include "common_defs.h"
#include "ext_plugin_manager.h"
#include "group_data_manager.h"
#include "dev_auth_module_manager.h"
#include "dev_session_mgr.h"
#include "group_manager.h"
#include "group_operation_common.h"
#include "hc_dev_info.h"
#include "hc_init_protection.h"
#include "hc_log.h"
#include "hc_time.h"
#include "hisysevent_common.h"
#include "hitrace_adapter.h"
#include "json_utils.h"
#include "key_manager.h"
#include "os_account_adapter.h"
#include "plugin_adapter.h"
#include "pseudonym_manager.h"
#include "task_manager.h"
#include "performance_dumper.h"
#include "identity_manager.h"
#include "group_auth_manager.h"
#include "account_task_manager.h"
#include "device_auth_common.h"

#include "identity_service.h"
#include "cred_session_util.h"
#include "credential_data_manager.h"
#include "identity_service_defines.h"

static GroupAuthManager *g_groupAuthManager =  NULL;
static DeviceGroupManager *g_groupManagerInstance = NULL;
static AccountVerifier *g_accountVerifierInstance = NULL;

static CredManager *g_credManager = NULL;
static CredAuthManager *g_credAuthManager = NULL;

#define CLEAN_CRED 1
#define CLEAN_MODULE 2
#define CLEAN_CALLBACK 3
#define CLEAN_GROUP_MANAGER 4
#define CLEAN_IDENTITY_SERVICE 5
#define CLEAN_ALL 6

static int32_t AddOriginDataForPlugin(CJson *receivedMsg, const uint8_t *data)
{
    if ((receivedMsg == NULL) || (data == NULL)) {
        LOGE("Invalid params");
        return HC_ERR_INVALID_PARAMS;
    }
    return AddStringToJson(receivedMsg, FIELD_PLUGIN_EXT_DATA, (const char *)data);
}

static int32_t BuildClientAuthContext(int32_t osAccountId, int64_t requestId, const char *appId, CJson *context,
    char **returnPeerUdid)
{
    const char *peerUdid = GetPeerUdidFromJson(osAccountId, context);
    if (peerUdid != NULL) {
        (void)DeepCopyString(peerUdid, returnPeerUdid);
        char *deviceId = NULL;
        if (DeepCopyString(peerUdid, &deviceId) != HC_SUCCESS) {
            LOGE("Failed to copy peerUdid!");
            return HC_ERR_ALLOC_MEMORY;
        }
        if (AddStringToJson(context, FIELD_PEER_UDID, deviceId) != HC_SUCCESS) {
            LOGE("add peerUdid to context fail.");
            HcFree(deviceId);
            return HC_ERR_JSON_ADD;
        }
        if (AddStringToJson(context, FIELD_PEER_CONN_DEVICE_ID, deviceId) != HC_SUCCESS) {
            LOGE("add peerConnDeviceId to context fail.");
            HcFree(deviceId);
            return HC_ERR_JSON_ADD;
        }
        PRINT_SENSITIVE_DATA("PeerUdid", deviceId);
        HcFree(deviceId);
    }
    if (AddBoolToJson(context, FIELD_IS_BIND, false) != HC_SUCCESS) {
        LOGE("add isBind to context fail.");
        return HC_ERR_JSON_ADD;
    }
    if (AddBoolToJson(context, FIELD_IS_CLIENT, true) != HC_SUCCESS) {
        LOGE("add isClient to context fail.");
        return HC_ERR_JSON_ADD;
    }
    if (AddIntToJson(context, FIELD_OS_ACCOUNT_ID, osAccountId) != HC_SUCCESS) {
        LOGE("add osAccountId to context fail.");
        return HC_ERR_JSON_ADD;
    }
    if (AddInt64StringToJson(context, FIELD_REQUEST_ID, requestId) != HC_SUCCESS) {
        LOGE("add request id to context fail.");
        return HC_ERR_JSON_ADD;
    }
    if (AddStringToJson(context, FIELD_APP_ID, appId) != HC_SUCCESS) {
        LOGE("add app id to context fail.");
        return HC_ERR_JSON_ADD;
    }
    if (AddIntToJson(context, FIELD_OPERATION_CODE, AUTH_FORM_ACCOUNT_UNRELATED) != HC_SUCCESS) {
        LOGE("add operation code to context fail.");
        return HC_ERR_JSON_ADD;
    }
    return AddChannelInfoToContext(SERVICE_CHANNEL, DEFAULT_CHANNEL_ID, context);
}

static int32_t BuildP2PBindContext(CJson *context)
{
    int32_t acquireType = -1;
    if (GetIntFromJson(context, FIELD_ACQURIED_TYPE, &acquireType) != HC_SUCCESS) {
        LOGE("Failed to get acquireType from reqJsonStr!");
        return HC_ERR_JSON_FAIL;
    }
    if ((acquireType == P2P_BIND) && AddBoolToJson(context, FIELD_IS_DIRECT_AUTH, true) != HC_SUCCESS) {
        LOGE("add isDirectAuth to context fail.");
        return HC_ERR_JSON_ADD;
    }
    if (AddIntToJson(context, FIELD_OPERATION_CODE, acquireType) != HC_SUCCESS) {
        LOGE("add opCode to context fail.");
        return HC_ERR_JSON_ADD;
    }
    const char *serviceType = GetStringFromJson(context, FIELD_SERVICE_TYPE);
    if (serviceType == NULL) {
        if ((acquireType == P2P_BIND) &&
            AddStringToJson(context, FIELD_SERVICE_TYPE, DEFAULT_SERVICE_TYPE) != HC_SUCCESS) {
            LOGE("add serviceType to context fail.");
            return HC_ERR_JSON_ADD;
        }
    }
    return HC_SUCCESS;
}

static int32_t AuthDeviceInner(int32_t osAccountId, int64_t authReqId, const char *authParams,
    const DeviceAuthCallback *gaCallback, char **returnPeerUdid)
{
    SET_LOG_MODE(TRACE_MODE);
    SET_TRACE_ID(authReqId);
    ADD_PERFORM_DATA(authReqId, false, true, HcGetCurTimeInMillis());
    osAccountId = DevAuthGetRealOsAccountLocalId(osAccountId);
    LOGI("Begin AuthDevice. [ReqId]: %" LOG_PUB PRId64 ", [OsAccountId]: %" LOG_PUB "d", authReqId, osAccountId);
    if ((authParams == NULL) || (osAccountId == INVALID_OS_ACCOUNT) || (gaCallback == NULL)) {
        LOGE("The input auth params is invalid!");
        return HC_ERR_INVALID_PARAMS;
    }
    if (!CheckIsForegroundOsAccountId(osAccountId)) {
        LOGE("This access is not from the foreground user, rejected it.");
        return HC_ERR_CROSS_USER_ACCESS;
    }
    if (!IsOsAccountUnlocked(osAccountId)) {
        LOGE("Os account is not unlocked!");
        return HC_ERR_OS_ACCOUNT_NOT_UNLOCKED;
    }
    CJson *context = CreateJsonFromString(authParams);
    if (context == NULL) {
        LOGE("Failed to create json from string!");
        return HC_ERR_JSON_FAIL;
    }
    const char *appId = GetStringFromJson(context, FIELD_SERVICE_PKG_NAME);
    if (appId == NULL) {
        LOGE("get servicePkgName from json fail.");
        FreeJson(context);
        return HC_ERR_JSON_GET;
    }
    int32_t res = BuildClientAuthContext(osAccountId, authReqId, appId, context, returnPeerUdid);
    if (res != HC_SUCCESS) {
        FreeJson(context);
        return res;
    }
    DEV_AUTH_REPORT_UE_CALL_EVENT_BY_PARAMS(osAccountId, authParams, appId, AUTH_DEV_EVENT);
    SessionInitParams params = { context, *gaCallback };
    res = OpenDevSession(authReqId, appId, &params);
    FreeJson(context);
    if (res != HC_SUCCESS) {
        LOGE("OpenDevSession fail. [Res]: %" LOG_PUB "d", res);
        return res;
    }
    return PushStartSessionTask(authReqId);
}

static int32_t AuthDevice(int32_t osAccountId, int64_t authReqId, const char *authParams,
    const DeviceAuthCallback *gaCallback)
{
    ReportBehaviorBeginEvent(false, true, authReqId);
    char *peerUdid = NULL;
    int32_t res = AuthDeviceInner(osAccountId, authReqId, authParams, gaCallback, &peerUdid);
    ReportBehaviorBeginResultEvent(false, true, authReqId, peerUdid, res);
    if (peerUdid != NULL) {
        HcFree(peerUdid);
    }
    return res;
}

static int32_t AddDeviceIdToJson(CJson *context, const char *peerUdid)
{
    char *deviceId = NULL;
    if (DeepCopyString(peerUdid, &deviceId) != HC_SUCCESS) {
        LOGE("Failed to copy peerUdid!");
        return HC_ERR_ALLOC_MEMORY;
    }
    if (AddStringToJson(context, FIELD_PEER_UDID, deviceId) != HC_SUCCESS) {
        LOGE("add peerUdid to context fail.");
        HcFree(deviceId);
        return HC_ERR_JSON_ADD;
    }
    if (AddStringToJson(context, FIELD_PEER_CONN_DEVICE_ID, deviceId) != HC_SUCCESS) {
        LOGE("add peerConnDeviceId to context fail.");
        HcFree(deviceId);
        return HC_ERR_JSON_ADD;
    }
    HcFree(deviceId);
    return HC_SUCCESS;
}

static int32_t BuildServerAuthContext(int64_t requestId, int32_t opCode, const char *appId, CJson *context,
    char **returnPeerUdid)
{
    int32_t res = CheckConfirmationExist(context);
    if (res != HC_SUCCESS) {
        return res;
    }
    res = AddOsAccountIdToContextIfValid(context);
    if (res != HC_SUCCESS) {
        return res;
    }
    int32_t osAccountId = ANY_OS_ACCOUNT;
    (void)GetIntFromJson(context, FIELD_OS_ACCOUNT_ID, &osAccountId);
    const char *peerUdid = GetPeerUdidFromJson(osAccountId, context);
    if (peerUdid == NULL) {
        return HC_ERR_JSON_GET;
    }
    (void)DeepCopyString(peerUdid, returnPeerUdid);
    PRINT_SENSITIVE_DATA("PeerUdid", peerUdid);
    if (AddDeviceIdToJson(context, peerUdid) != HC_SUCCESS) {
        LOGE("add deviceId to context failed.");
        return HC_ERR_JSON_ADD;
    }
    if (AddBoolToJson(context, FIELD_IS_BIND, false) != HC_SUCCESS) {
        LOGE("add isBind to context failed.");
        return HC_ERR_JSON_ADD;
    }
    if (AddBoolToJson(context, FIELD_IS_CLIENT, false) != HC_SUCCESS) {
        LOGE("add isClient to context failed.");
        return HC_ERR_JSON_ADD;
    }
    if (AddInt64StringToJson(context, FIELD_REQUEST_ID, requestId) != HC_SUCCESS) {
        LOGE("add requestId to context failed.");
        return HC_ERR_JSON_ADD;
    }
    if (AddStringToJson(context, FIELD_APP_ID, appId) != HC_SUCCESS) {
        LOGE("add appId to context failed.");
        return HC_ERR_JSON_ADD;
    }
    if (AddIntToJson(context, FIELD_OPERATION_CODE, opCode) != HC_SUCCESS) {
        LOGE("add opCode to context failed.");
        return HC_ERR_JSON_ADD;
    }
    return AddChannelInfoToContext(SERVICE_CHANNEL, DEFAULT_CHANNEL_ID, context);
}

static int32_t BuildServerP2PAuthContext(int64_t requestId, int32_t opCode, const char *appId, CJson *context)
{
    int32_t res = CheckConfirmationExist(context);
    if (res != HC_SUCCESS) {
        return res;
    }
    res = AddOsAccountIdToContextIfValid(context);
    if (res != HC_SUCCESS) {
        return res;
    }
    const char *peerUdid = GetStringFromJson(context, FIELD_PEER_CONN_DEVICE_ID);
    const char *pinCode = GetStringFromJson(context, FIELD_PIN_CODE);
    if (peerUdid == NULL && pinCode == NULL) {
        LOGE("need peerConnDeviceId or pinCode!");
        return HC_ERR_JSON_GET;
    }
    if (peerUdid != NULL) {
        PRINT_SENSITIVE_DATA("PeerUdid", peerUdid);
        if (AddDeviceIdToJson(context, peerUdid) != HC_SUCCESS) {
            LOGE("add deviceId to context fail.");
            return HC_ERR_JSON_ADD;
        }
    }
    if (AddBoolToJson(context, FIELD_IS_SINGLE_CRED, true) != HC_SUCCESS) {
        LOGE("add isSingleCred to context fail.");
        return HC_ERR_JSON_ADD;
    }
    if (AddBoolToJson(context, FIELD_IS_BIND, false) != HC_SUCCESS) {
        LOGE("add isBind to context fail.");
        return HC_ERR_JSON_ADD;
    }
    if (AddBoolToJson(context, FIELD_IS_CLIENT, false) != HC_SUCCESS) {
        LOGE("add isClient to context fail.");
        return HC_ERR_JSON_ADD;
    }
    if (AddInt64StringToJson(context, FIELD_REQUEST_ID, requestId) != HC_SUCCESS) {
        LOGE("add requestId to context fail.");
        return HC_ERR_JSON_ADD;
    }
    if (AddStringToJson(context, FIELD_APP_ID, appId) != HC_SUCCESS) {
        LOGE("add appId to context fail.");
        return HC_ERR_JSON_ADD;
    }
    if (AddIntToJson(context, FIELD_OPERATION_CODE, opCode) != HC_SUCCESS) {
        LOGE("add opCode to context fail.");
        return HC_ERR_JSON_ADD;
    }
    return AddChannelInfoToContext(SERVICE_CHANNEL, DEFAULT_CHANNEL_ID, context);
}

static int32_t OpenServerAuthSession(int64_t requestId, const CJson *receivedMsg, const DeviceAuthCallback *callback,
    char **returnPeerUdid)
{
    int32_t opCode = AUTH_FORM_ACCOUNT_UNRELATED;
    if (GetIntFromJson(receivedMsg, FIELD_AUTH_FORM, &opCode) != HC_SUCCESS) {
        if (GetIntFromJson(receivedMsg, FIELD_OP_CODE, &opCode) != HC_SUCCESS) {
            opCode = AUTH_FORM_INVALID_TYPE;
            LOGW("use default opCode.");
        }
    }
    char *returnDataStr = ProcessRequestCallback(requestId, opCode, NULL, callback);
    if (returnDataStr == NULL) {
        LOGE("The OnRequest callback failed!");
        return HC_ERR_REQ_REJECTED;
    }
    CJson *context = CreateJsonFromString(returnDataStr);
    FreeJsonString(returnDataStr);
    if (context == NULL) {
        LOGE("Failed to create context json from returnDataStr!");
        return HC_ERR_JSON_FAIL;
    }
    const char *appId = GetStringFromJson(context, FIELD_SERVICE_PKG_NAME);
    if (appId == NULL) {
        LOGE("get appId from json fail.");
        FreeJson(context);
        return HC_ERR_JSON_GET;
    }
    int32_t res = BuildServerAuthContext(requestId, opCode, appId, context, returnPeerUdid);
    if (res != HC_SUCCESS) {
        FreeJson(context);
        return res;
    }
    SessionInitParams params = { context, *callback };
    res = OpenDevSession(requestId, appId, &params);
    FreeJson(context);
    return res;
}

static int32_t OpenServerAuthSessionForP2P(
    int64_t requestId, const CJson *receivedMsg, const DeviceAuthCallback *callback)
{
    int32_t opCode = P2P_BIND;
    if (GetIntFromJson(receivedMsg, FIELD_OP_CODE, &opCode) != HC_SUCCESS) {
        opCode = P2P_BIND;
        LOGW("use default opCode.");
    }
    char *returnDataStr = ProcessRequestCallback(requestId, opCode, NULL, callback);
    if (returnDataStr == NULL) {
        LOGE("The OnRequest callback is fail!");
        return HC_ERR_REQ_REJECTED;
    }
    CJson *context = CreateJsonFromString(returnDataStr);
    FreeJsonString(returnDataStr);
    if (context == NULL) {
        LOGE("Failed to create context from string!");
        return HC_ERR_JSON_FAIL;
    }
    if (AddBoolToJson(context, FIELD_IS_DIRECT_AUTH, true) != HC_SUCCESS) {
        LOGE("Failed to add isDirectAuth to context!");
        FreeJson(context);
        return HC_ERR_JSON_ADD;
    }
    const char *pkgName = GetStringFromJson(context, FIELD_SERVICE_PKG_NAME);
    if (pkgName == NULL && AddStringToJson(context, FIELD_SERVICE_PKG_NAME, DEFAULT_PACKAGE_NAME) != HC_SUCCESS) {
        LOGE("Failed to add default package name to context!");
        FreeJson(context);
        return HC_ERR_JSON_ADD;
    }
    const char *serviceType = GetStringFromJson(context, FIELD_SERVICE_TYPE);
    if (serviceType == NULL && AddStringToJson(context, FIELD_SERVICE_TYPE, DEFAULT_SERVICE_TYPE) != HC_SUCCESS) {
        LOGE("Failed to add default package name to context!");
        FreeJson(context);
        return HC_ERR_JSON_ADD;
    }
    const char *appId = pkgName != NULL ? pkgName : DEFAULT_PACKAGE_NAME;
    int32_t res = BuildServerP2PAuthContext(requestId, opCode, appId, context);
    if (res != HC_SUCCESS) {
        FreeJson(context);
        return res;
    }
    SessionInitParams params = { context, *callback };
    res = OpenDevSession(requestId, appId, &params);
    FreeJson(context);
    return res;
}

static int32_t ProcessDataInner(int64_t authReqId, const uint8_t *data, uint32_t dataLen,
    const DeviceAuthCallback *gaCallback, char **returnPeerUdid)
{
    SET_LOG_MODE(TRACE_MODE);
    SET_TRACE_ID(authReqId);
    if (!IsSessionExist(authReqId)) {
        ADD_PERFORM_DATA(authReqId, false, false, HcGetCurTimeInMillis());
    } else {
        UPDATE_PERFORM_DATA_BY_SELF_INDEX(authReqId, HcGetCurTimeInMillis());
    }
    LOGI("[GA] Begin ProcessData. [DataLen]: %" LOG_PUB "u, [ReqId]: %" LOG_PUB PRId64, dataLen, authReqId);
    if ((data == NULL) || (dataLen > MAX_DATA_BUFFER_SIZE)) {
        LOGE("Invalid input for ProcessData!");
        return HC_ERR_INVALID_PARAMS;
    }
    CJson *receivedMsg = CreateJsonFromString((const char *)data);
    if (receivedMsg == NULL) {
        LOGE("Failed to create json from string!");
        return HC_ERR_JSON_FAIL;
    }
    int32_t res;
    if (!IsSessionExist(authReqId)) {
        res = OpenServerAuthSession(authReqId, receivedMsg, gaCallback, returnPeerUdid);
        if (res != HC_SUCCESS) {
            FreeJson(receivedMsg);
            return res;
        }
    }
    if (HasAccountPlugin()) {
        res = AddOriginDataForPlugin(receivedMsg, data);
        if (res != HC_SUCCESS) {
            FreeJson(receivedMsg);
            return res;
        }
    }
    res = PushProcSessionTask(authReqId, receivedMsg);
    if (res != HC_SUCCESS) {
        FreeJson(receivedMsg);
        return res;
    }
    return HC_SUCCESS;
}

static int32_t ProcessData(int64_t authReqId, const uint8_t *data, uint32_t dataLen,
    const DeviceAuthCallback *gaCallback)
{
    bool isSessionExist = IsSessionExist(authReqId);
    if (!isSessionExist) {
        ReportBehaviorBeginEvent(false, false, authReqId);
    }
    char *peerUdid = NULL;
    int32_t res = ProcessDataInner(authReqId, data, dataLen, gaCallback, &peerUdid);
    if (!isSessionExist) {
        ReportBehaviorBeginResultEvent(false, false, authReqId, peerUdid, res);
    }
    if (peerUdid != NULL) {
        HcFree(peerUdid);
    }
    return res;
}

static int32_t OpenServerCredSession(int64_t requestId, const CJson *receivedMsg, const DeviceAuthCallback *callback,
    char **returnPeerUdid)
{
    int32_t opCode = AUTH_FORM_ACCOUNT_UNRELATED;
    if (GetIntFromJson(receivedMsg, FIELD_AUTH_FORM, &opCode) != HC_SUCCESS) {
        if (GetIntFromJson(receivedMsg, FIELD_OP_CODE, &opCode) != HC_SUCCESS) {
            opCode = AUTH_FORM_INVALID_TYPE;
            LOGW("use default opCode.");
        }
    }
    char *returnDataStr = ProcessRequestCallback(requestId, opCode, NULL, callback);
    if (returnDataStr == NULL) {
        LOGE("The OnRequest callback is fail!");
        return HC_ERR_REQ_REJECTED;
    }
    CJson *context = CreateJsonFromString(returnDataStr);
    FreeJsonString(returnDataStr);
    if (context == NULL) {
        LOGE("Failed to create context from string!");
        return HC_ERR_JSON_FAIL;
    }
    if (AddIntToJson(context, FIELD_OPERATION_CODE, opCode) != HC_SUCCESS) {
        LOGE("add opCode to context fail.");
        FreeJson(context);
        return HC_ERR_JSON_ADD;
    }
    const char *appId = NULL;
    int32_t res = BuildServerCredContext(requestId, context, returnPeerUdid, &appId);
    if (res != HC_SUCCESS) {
        FreeJson(context);
        return res;
    }
    SessionInitParams params = { context, *callback };
    res = OpenDevSession(requestId, appId, &params);
    FreeJson(context);
    return res;
}

static int32_t AuthCredentialInner(int32_t osAccountId, int64_t authReqId, const char *authParams,
    const DeviceAuthCallback *caCallback, char **returnPeerUdid)
{
    SET_LOG_MODE(TRACE_MODE);
    SET_TRACE_ID(authReqId);
    ADD_PERFORM_DATA(authReqId, false, true, HcGetCurTimeInMillis());
    LOGI("Begin AuthCredential. [ReqId]: %" LOG_PUB PRId64 ", [OsAccountId]: %" LOG_PUB "d", authReqId, osAccountId);
    if (authParams == NULL || osAccountId == INVALID_OS_ACCOUNT || caCallback == NULL ||
        returnPeerUdid == NULL) {
        LOGE("The input auth cred params is invalid!");
        return HC_ERR_INVALID_PARAMS;
    }
    if (!CheckIsForegroundOsAccountId(osAccountId)) {
        LOGE("This access is not from the foreground user, rejected it.");
        return HC_ERR_CROSS_USER_ACCESS;
    }
    if (!IsOsAccountUnlocked(osAccountId)) {
        LOGE("Os account is not unlocked! Please unlock it first.");
        return HC_ERR_OS_ACCOUNT_NOT_UNLOCKED;
    }
    CJson *context = CreateJsonFromString(authParams);
    if (context == NULL) {
        LOGE("Failed to create json from string!");
        return HC_ERR_JSON_FAIL;
    }
    const char *appId = NULL;
    int32_t res = BuildClientCredContext(osAccountId, authReqId, context, &appId);
    if (res != HC_SUCCESS) {
        FreeJson(context);
        return res;
    }
    SessionInitParams params = { context, *caCallback };
    res = OpenDevSession(authReqId, appId, &params);
    FreeJson(context);
    if (res != HC_SUCCESS) {
        LOGE("OpenDevSession fail. [Res]: %" LOG_PUB "d", res);
        return res;
    }
    return PushStartSessionTask(authReqId);
}

int32_t AuthCredential(int32_t osAccountId, int64_t authReqId, const char *authParams,
    const DeviceAuthCallback *caCallback)
{
    char *peerUdid = NULL;
    int32_t res = AuthCredentialInner(osAccountId, authReqId, authParams, caCallback, &peerUdid);
    if (peerUdid != NULL) {
        HcFree(peerUdid);
    }
    return res;
}

static int32_t ProcessCredDataInner(int64_t authReqId, const uint8_t *data, uint32_t dataLen,
    const DeviceAuthCallback *caCallback, char **returnPeerUdid)
{
    SET_LOG_MODE(TRACE_MODE);
    SET_TRACE_ID(authReqId);
    if (!IsSessionExist(authReqId)) {
        ADD_PERFORM_DATA(authReqId, false, false, HcGetCurTimeInMillis());
    } else {
        UPDATE_PERFORM_DATA_BY_SELF_INDEX(authReqId, HcGetCurTimeInMillis());
    }
    LOGI("[GA] Begin ProcessCredData. [DataLen]: %" LOG_PUB "u, [ReqId]: %" LOG_PUB PRId64, dataLen, authReqId);
    if ((data == NULL) || (dataLen > MAX_DATA_BUFFER_SIZE)) {
        LOGE("Invalid input for ProcessCredData!");
        return HC_ERR_INVALID_PARAMS;
    }
    CJson *receivedMsg = CreateJsonFromString((const char *)data);
    if (receivedMsg == NULL) {
        LOGE("Failed to create json from string!");
        return HC_ERR_JSON_CREATE;
    }
    int32_t res;
    if (!IsSessionExist(authReqId)) {
        res = OpenServerCredSession(authReqId, receivedMsg, caCallback, returnPeerUdid);
        if (res != HC_SUCCESS) {
            FreeJson(receivedMsg);
            return res;
        }
    }
    if (HasAccountPlugin()) {
        res = AddOriginDataForPlugin(receivedMsg, data);
        if (res != HC_SUCCESS) {
            FreeJson(receivedMsg);
            return res;
        }
    }
    res = PushProcSessionTask(authReqId, receivedMsg);
    if (res != HC_SUCCESS) {
        FreeJson(receivedMsg);
        return res;
    }
    return HC_SUCCESS;
}

static int32_t ProcessCredData(int64_t authReqId, const uint8_t *data, uint32_t dataLen,
    const DeviceAuthCallback *caCallback)
{
    char *peerUdid = NULL;
    int32_t res = ProcessCredDataInner(authReqId, data, dataLen, caCallback, &peerUdid);
    if (peerUdid != NULL) {
        HcFree(peerUdid);
    }
    return res;
}

static void CancelRequest(int64_t requestId, const char *appId)
{
    SET_LOG_MODE(TRACE_MODE);
    SET_TRACE_ID(requestId);
    DEV_AUTH_REPORT_UE_CALL_EVENT_BY_PARAMS(DEFAULT_OS_ACCOUNT, NULL, appId, CANCEL_REQUEST_EVENT);
    if (appId == NULL) {
        LOGE("Invalid app id!");
        return;
    }
    LOGI("cancel request. [AppId]: %" LOG_PUB "s, [ReqId]: %" LOG_PUB PRId64, appId, requestId);
    CancelDevSession(requestId, appId);
}

static int32_t GetRealInfo(int32_t osAccountId, const char *pseudonymId, char **realInfo)
{
    if (pseudonymId == NULL || realInfo == NULL) {
        LOGE("Invalid params!");
        return HC_ERR_INVALID_PARAMS;
    }
    PseudonymManager *pseudonymInstance = GetPseudonymInstance();
    if (pseudonymInstance == NULL) {
        LOGE("not support privacy enhancement!");
        return HC_ERR_NOT_SUPPORT;
    }
    return pseudonymInstance->getRealInfo(osAccountId, pseudonymId, realInfo);
}

static int32_t GetPseudonymId(int32_t osAccountId, const char *indexKey, char **pseudonymId)
{
    if (indexKey == NULL || pseudonymId == NULL) {
        LOGE("Invalid params!");
        return HC_ERR_INVALID_PARAMS;
    }
    PseudonymManager *pseudonymInstance = GetPseudonymInstance();
    if (pseudonymInstance == NULL) {
        LOGE("not support privacy enhancement!");
        return HC_ERR_NOT_SUPPORT;
    }
    return pseudonymInstance->getPseudonymId(osAccountId, indexKey, pseudonymId);
}

DEVICE_AUTH_API_PUBLIC int32_t ProcessCredential(int32_t operationCode, const char *reqJsonStr, char **returnData)
{
    if (reqJsonStr == NULL || returnData == NULL) {
        LOGE("Invalid params!");
        return HC_ERR_INVALID_PARAMS;
    }

    const CredentialOperator *credOperator = GetCredentialOperator();
    if (credOperator == NULL) {
        LOGE("credOperator is null!");
        return HC_ERR_NOT_SUPPORT;
    }

    int32_t res = HC_ERR_UNSUPPORTED_OPCODE;
    switch (operationCode) {
        case CRED_OP_QUERY:
            res = credOperator->queryCredential(reqJsonStr, returnData);
            break;
        case CRED_OP_CREATE:
            res = credOperator->genarateCredential(reqJsonStr, returnData);
            break;
        case CRED_OP_IMPORT:
            res = credOperator->importCredential(reqJsonStr, returnData);
            break;
        case CRED_OP_DELETE:
            res = credOperator->deleteCredential(reqJsonStr, returnData);
            break;
        default:
            LOGE("invalid opCode: %" LOG_PUB "d", operationCode);
            break;
    }

    return res;
}

DEVICE_AUTH_API_PUBLIC int32_t ProcessAuthDevice(
    int64_t authReqId, const char *authParams, const DeviceAuthCallback *callback)
{
    SET_LOG_MODE(TRACE_MODE);
    SET_TRACE_ID(authReqId);
    LOGI("[DA] Begin ProcessAuthDevice [ReqId]: %" LOG_PUB PRId64, authReqId);
    if (authParams == NULL || HcStrlen(authParams) > MAX_DATA_BUFFER_SIZE) {
        LOGE("Invalid input for ProcessData!");
        return HC_ERR_INVALID_PARAMS;
    }
    CJson *json = CreateJsonFromString(authParams);
    if (json == NULL) {
        LOGE("Failed to create json from string!");
        return HC_ERR_JSON_FAIL;
    }
    const char *data = GetStringFromJson(json, "data");
    if (data == NULL) {
        LOGE("Failed to get received data from parameter!");
        FreeJson(json);
        return HC_ERR_INVALID_PARAMS;
    }
    CJson *receivedMsg = CreateJsonFromString(data);
    FreeJson(json);
    if (receivedMsg == NULL) {
        LOGE("Failed to create json from string!");
        return HC_ERR_JSON_FAIL;
    }
    int32_t res;
    if (!IsSessionExist(authReqId)) {
        res = OpenServerAuthSessionForP2P(authReqId, receivedMsg, callback);
        if (res != HC_SUCCESS) {
            FreeJson(receivedMsg);
            return res;
        }
    }
    res = PushProcSessionTask(authReqId, receivedMsg);
    if (res != HC_SUCCESS) {
        FreeJson(receivedMsg);
        return res;
    }
    return HC_SUCCESS;
}

DEVICE_AUTH_API_PUBLIC int32_t StartAuthDevice(
    int64_t authReqId, const char *authParams, const DeviceAuthCallback *callback)
{
    SET_LOG_MODE(TRACE_MODE);
    SET_TRACE_ID(authReqId);
    LOGI("StartAuthDevice. [ReqId]:%" LOG_PUB PRId64, authReqId);

    if ((authParams == NULL) || (callback == NULL) || HcStrlen(authParams) > MAX_DATA_BUFFER_SIZE) {
        LOGE("The input auth params is invalid!");
        return HC_ERR_INVALID_PARAMS;
    }
    CJson *context = CreateJsonFromString(authParams);
    if (context == NULL) {
        LOGE("Failed to create json from string!");
        return HC_ERR_JSON_FAIL;
    }
    int32_t osAccountId = INVALID_OS_ACCOUNT;
    if (GetIntFromJson(context, FIELD_OS_ACCOUNT_ID, &osAccountId) != HC_SUCCESS) {
        LOGE("Failed to get osAccountId from json!");
        FreeJson(context);
        return HC_ERR_JSON_FAIL;
    }
    osAccountId = DevAuthGetRealOsAccountLocalId(osAccountId);
    if (osAccountId == INVALID_OS_ACCOUNT) {
        FreeJson(context);
        return HC_ERR_INVALID_PARAMS;
    }
    if (!CheckIsForegroundOsAccountId(osAccountId)) {
        LOGE("This access is not from the foreground user, rejected it.");
        return HC_ERR_CROSS_USER_ACCESS;
    }
    int32_t res = BuildClientAuthContext(osAccountId, authReqId, DEFAULT_PACKAGE_NAME, context, NULL);
    if (res != HC_SUCCESS) {
        FreeJson(context);
        return res;
    }
    res = BuildP2PBindContext(context);
    if (res != HC_SUCCESS) {
        FreeJson(context);
        return res;
    }
    SessionInitParams params = { context, *callback };
    res = OpenDevSession(authReqId, DEFAULT_PACKAGE_NAME, &params);
    FreeJson(context);
    if (res != HC_SUCCESS) {
        LOGE("OpenDevSession fail. [Res]: %" LOG_PUB "d", res);
        return res;
    }
    return PushStartSessionTask(authReqId);
}

DEVICE_AUTH_API_PUBLIC int32_t CancelAuthRequest(int64_t requestId, const char *authParams)
{
    SET_LOG_MODE(TRACE_MODE);
    SET_TRACE_ID(requestId);
    if (authParams == NULL || HcStrlen(authParams) > MAX_DATA_BUFFER_SIZE) {
        LOGE("Invalid authParams!");
        return HC_ERR_INVALID_PARAMS;
    }
    LOGI("cancel request. [ReqId]: %" LOG_PUB PRId64, requestId);
    CancelDevSession(requestId, DEFAULT_PACKAGE_NAME);
    return HC_SUCCESS;
}

static int32_t AllocGmAndGa(void)
{
    if (g_groupManagerInstance == NULL) {
        g_groupManagerInstance = (DeviceGroupManager *)HcMalloc(sizeof(DeviceGroupManager), 0);
        if (g_groupManagerInstance == NULL) {
            LOGE("Failed to allocate groupManager Instance memory!");
            return HC_ERR_ALLOC_MEMORY;
        }
    }
    if (g_groupAuthManager == NULL) {
        g_groupAuthManager = (GroupAuthManager *)HcMalloc(sizeof(GroupAuthManager), 0);
        if (g_groupAuthManager == NULL) {
            LOGE("Failed to allocate groupAuth Instance memory!");
            HcFree(g_groupManagerInstance);
            g_groupManagerInstance = NULL;
            return HC_ERR_ALLOC_MEMORY;
        }
    }
    if (g_accountVerifierInstance == NULL) {
        g_accountVerifierInstance = (AccountVerifier *)HcMalloc(sizeof(AccountVerifier), 0);
        if (g_accountVerifierInstance == NULL) {
            LOGE("Failed to allocate accountVerifier Instance memory!");
            HcFree(g_groupManagerInstance);
            g_groupManagerInstance = NULL;
            HcFree(g_groupAuthManager);
            g_groupAuthManager = NULL;
            return HC_ERR_ALLOC_MEMORY;
        }
    }
    return HC_SUCCESS;
}

static void DestroyGmAndGa(void)
{
    if (g_groupAuthManager != NULL) {
        HcFree(g_groupAuthManager);
        g_groupAuthManager = NULL;
    }
    if (g_groupManagerInstance != NULL) {
        HcFree(g_groupManagerInstance);
        g_groupManagerInstance = NULL;
    }
    if (g_accountVerifierInstance != NULL) {
        HcFree(g_accountVerifierInstance);
        g_accountVerifierInstance = NULL;
    }
}

static int32_t AllocCredentialMgr(void)
{
    if (g_credManager == NULL) {
        g_credManager = (CredManager *)HcMalloc(sizeof(CredManager), 0);
        if (g_credManager == NULL) {
            LOGE("Failed to allocate g_credManager Instance memory!");
            return HC_ERR_ALLOC_MEMORY;
        }
    }
    return HC_SUCCESS;
}

static void DestroyCredentialMgr(void)
{
    if (g_credManager != NULL) {
        HcFree(g_credManager);
        g_credManager = NULL;
    }
}

static int32_t AllocCa(void)
{
    if (g_credAuthManager == NULL) {
        g_credAuthManager = (CredAuthManager *)HcMalloc(sizeof(CredAuthManager), 0);
        if (g_credAuthManager == NULL) {
            LOGE("Failed to allocate groupManager Instance memory!");
            return HC_ERR_ALLOC_MEMORY;
        }
    }
    return HC_SUCCESS;
}

static void DestroyCa(void)
{
    if (g_credAuthManager != NULL) {
        HcFree(g_credAuthManager);
        g_credAuthManager = NULL;
    }
}

static void CleanAllModules(int32_t type)
{
    switch (type) {
        case CLEAN_ALL:
            DestroyDevSessionManager();
        // fallthrough
        case CLEAN_IDENTITY_SERVICE:
            DestroyIdentityService();
        // fallthrough
        case CLEAN_GROUP_MANAGER:
            DestroyGroupManager();
        // fallthrough
        case CLEAN_CALLBACK:
            DestroyCallbackManager();
        // fallthrough
        case CLEAN_MODULE:
            DestroyModules();
        // fallthrough
        case CLEAN_CRED:
            DestroyCredMgr();
        // fallthrough
        default:
            break;
    }
}

static int32_t InitAllModules(void)
{
    int32_t res = GetLoaderInstance()->initAlg();
    if (res != HC_SUCCESS) {
        LOGE("[End]: [Service]: Failed to init algorithm module!");
        return res;
    }
    do {
        if ((res = InitCredMgr()) != HC_SUCCESS) {
            LOGE("[End]: [Service]: Failed to init cred mgr!");
            break;
        }
        if ((res = InitModules()) != HC_SUCCESS) {
            LOGE("[End]: [Service]: Failed to init all authenticator modules!");
            CleanAllModules(CLEAN_CRED);
            break;
        }
        if ((res = InitCallbackManager()) != HC_SUCCESS) {
            LOGE("[End]: [Service]: Failed to init callback manage module!");
            CleanAllModules(CLEAN_MODULE);
            break;
        }
        if ((res = InitGroupManager()) != HC_SUCCESS) {
            LOGE("[End]: [Service]: Failed to init group manage module!");
            CleanAllModules(CLEAN_CALLBACK);
            break;
        }
        if ((res = InitIdentityService()) != HC_SUCCESS) {
            LOGE("[End]: [Service]: Failed to init IS module!");
            CleanAllModules(CLEAN_GROUP_MANAGER);
            break;
        }
        if ((res = InitDevSessionManager()) != HC_SUCCESS) {
            LOGE("[End]: [Service]: Failed to init dev session manager module!");
            CleanAllModules(CLEAN_IDENTITY_SERVICE);
            break;
        }
        (void)InitGroupAuthManager();
        if ((res = InitTaskManager()) != HC_SUCCESS) {
            LOGE("[End]: [Service]: Failed to init worker thread!");
            CleanAllModules(CLEAN_ALL);
            break;
        }
    } while (0);
    return res;
}

static void InitPseudonymModule(void)
{
    PseudonymManager *manager = GetPseudonymInstance();
    if (manager == NULL) {
        LOGE("Pseudonym manager is null!");
        return;
    }
    manager->loadPseudonymData();
}

DEVICE_AUTH_API_PUBLIC int InitDeviceAuthService(void)
{
    LOGI("[Service]: Start to init device auth service!");
    if (CheckInit() == FINISH_INIT) {
        LOGI("[End]: [Service]: Device auth service is running!");
        return HC_SUCCESS;
    }
    int32_t res = AllocGmAndGa();
    if (res != HC_SUCCESS) {
        return res;
    }
    res = AllocCa();
    if (res != HC_SUCCESS) {
        DestroyGmAndGa();
        return res;
    }
    res = AllocCredentialMgr();
    if (res != HC_SUCCESS) {
        DestroyGmAndGa();
        DestroyCa();
        return res;
    }
    InitOsAccountAdapter();
    res = InitAllModules();
    if (res != HC_SUCCESS) {
        DestroyGmAndGa();
        DestroyCa();
        DestroyCredentialMgr();
        return res;
    }
    INIT_PERFORMANCE_DUMPER();
    InitPseudonymModule();
    InitAccountTaskManager();
    SetInitStatus();
    LOGI("[End]: [Service]: Init device auth service successfully!");
    return HC_SUCCESS;
}

DEVICE_AUTH_API_PUBLIC void DestroyDeviceAuthService(void)
{
    LOGI("[Service]: Start to destroy device auth service!");
    if (CheckDestroy() == FINISH_DESTROY) {
        LOGI("[End]: [Service]: The service has not been initialized!");
        return;
    }
    DestroyTaskManager();
    DestroyDevSessionManager();
    DestroyIdentityService();
    DestroyGroupManager();
    DestroyGmAndGa();
    DestroyAccountTaskManager();
    DestroyCa();
    DestroyCredentialMgr();
    DestroyModules();
    DestroyCredMgr();
    DestroyChannelManager();
    DestroyCallbackManager();
    DESTROY_PERFORMANCE_DUMPER();
    DestroyPseudonymManager();
    DestroyOsAccountAdapter();
    SetDeInitStatus();
    LOGI("[End]: [Service]: Destroy device auth service successfully!");
}

DEVICE_AUTH_API_PUBLIC const DeviceGroupManager *GetGmInstance(void)
{
    if (g_groupManagerInstance == NULL) {
        LOGE("Service not init.");
        return NULL;
    }

    g_groupManagerInstance->regCallback = RegCallbackImpl;
    g_groupManagerInstance->unRegCallback = UnRegCallbackImpl;
    g_groupManagerInstance->regDataChangeListener = RegListenerImpl;
    g_groupManagerInstance->unRegDataChangeListener = UnRegListenerImpl;
    g_groupManagerInstance->createGroup = CreateGroupImpl;
    g_groupManagerInstance->deleteGroup = DeleteGroupImpl;
    g_groupManagerInstance->addMemberToGroup = AddMemberToGroupImpl;
    g_groupManagerInstance->deleteMemberFromGroup = DeleteMemberFromGroupImpl;
    g_groupManagerInstance->addMultiMembersToGroup = AddMultiMembersToGroupImpl;
    g_groupManagerInstance->delMultiMembersFromGroup = DelMultiMembersFromGroupImpl;
    g_groupManagerInstance->processData = ProcessBindDataImpl;
    g_groupManagerInstance->getRegisterInfo = GetRegisterInfoImpl;
    g_groupManagerInstance->checkAccessToGroup = CheckAccessToGroupImpl;
    g_groupManagerInstance->getPkInfoList = GetPkInfoListImpl;
    g_groupManagerInstance->getGroupInfoById = GetGroupInfoByIdImpl;
    g_groupManagerInstance->getGroupInfo = GetGroupInfoImpl;
    g_groupManagerInstance->getJoinedGroups = GetJoinedGroupsImpl;
    g_groupManagerInstance->getRelatedGroups = GetRelatedGroupsImpl;
    g_groupManagerInstance->getDeviceInfoById = GetDeviceInfoByIdImpl;
    g_groupManagerInstance->getTrustedDevices = GetTrustedDevicesImpl;
    g_groupManagerInstance->isDeviceInGroup = IsDeviceInGroupImpl;
    g_groupManagerInstance->cancelRequest = CancelRequest;
    g_groupManagerInstance->destroyInfo = DestroyInfoImpl;
    return g_groupManagerInstance;
}

DEVICE_AUTH_API_PUBLIC const GroupAuthManager *GetGaInstance(void)
{
    if (g_groupAuthManager == NULL) {
        LOGE("Service not init.");
        return NULL;
    }

    g_groupAuthManager->processData = ProcessData;
    g_groupAuthManager->authDevice = AuthDevice;
    g_groupAuthManager->cancelRequest = CancelRequest;
    g_groupAuthManager->getRealInfo = GetRealInfo;
    g_groupAuthManager->getPseudonymId = GetPseudonymId;
    return g_groupAuthManager;
}

static int32_t GetSharedKeyFromOutJson(const CJson *out, DataBuff *returnSharedKey)
{
    int sharedKeyLen = 0;
    if (GetIntFromJson(out, FIELD_ACCOUNT_SHARED_KEY_LEN, &sharedKeyLen) != HC_SUCCESS) {
        LOGE("Failed to get shared key len!");
        return HC_ERR_JSON_GET;
    }
    uint8_t *sharedKeyVal = (uint8_t *)HcMalloc(sharedKeyLen, 0);
    if (sharedKeyVal == NULL) {
        LOGE("Failed to alloc shared key!");
        return HC_ERR_ALLOC_MEMORY;
    }
    if (GetByteFromJson(out, FIELD_ACCOUNT_SHARED_KEY_VAL, sharedKeyVal, sharedKeyLen) != HC_SUCCESS) {
        LOGE("Failed to get shared key val!");
        HcFree(sharedKeyVal);
        return HC_ERR_JSON_GET;
    }
    returnSharedKey->data = sharedKeyVal;
    returnSharedKey->length = sharedKeyLen;
    return HC_SUCCESS;
}

static int32_t GetRandomFromOutJson(const CJson *out, DataBuff *returnRandom)
{
    int randomLen = 0;
    if (GetIntFromJson(out, FIELD_ACCOUNT_RANDOM_LEN, &randomLen) != HC_SUCCESS) {
        LOGE("Failed to get random len!");
        return HC_ERR_JSON_GET;
    }
    uint8_t *randomVal = (uint8_t *)HcMalloc(randomLen, 0);
    if (randomVal == NULL) {
        LOGE("Failed to alloc random!");
        return HC_ERR_ALLOC_MEMORY;
    }
    if (GetByteFromJson(out, FIELD_ACCOUNT_RANDOM_VAL, randomVal, randomLen) != HC_SUCCESS) {
        LOGE("Failed to get random val!");
        HcFree(randomVal);
        return HC_ERR_JSON_GET;
    }
    returnRandom->data = randomVal;
    returnRandom->length = randomLen;
    return HC_SUCCESS;
}

static void DestroyDataBuff(DataBuff *data)
{
    if (data == NULL || data->data == NULL) {
        return;
    }
    HcFree(data->data);
    data->data = NULL;
    data->length = 0;
}

static int32_t ConstructClientInJson(CJson *in, const char *peerPkWithSig, const char *serviceId)
{
    if (AddStringToJson(in, FIELD_ACCOUNT_PEER_PK_WITH_SIG, peerPkWithSig) != HC_SUCCESS) {
        LOGE("Failed to add peer pk to json!");
        return HC_ERR_JSON_ADD;
    }
    if (AddStringToJson(in, FIELD_ACCOUNT_SERVICE_ID, serviceId) != HC_SUCCESS) {
        LOGE("Failed to add serviceId to json!");
        return HC_ERR_JSON_ADD;
    }
    return HC_SUCCESS;
}

static int32_t GetClientSharedKey(const char *peerPkWithSig, const char *serviceId, DataBuff *returnSharedKey,
    DataBuff *returnRandom)
{
    if (peerPkWithSig == NULL || serviceId == NULL || returnSharedKey == NULL || returnRandom == NULL) {
        LOGE("Invalid params!");
        return HC_ERR_INVALID_PARAMS;
    }
    CJson *in = CreateJson();
    if (in == NULL) {
        LOGE("Failed to create in json!");
        return HC_ERR_JSON_CREATE;
    }
    int32_t res = ConstructClientInJson(in, peerPkWithSig, serviceId);
    if (res != HC_SUCCESS) {
        FreeJson(in);
        return res;
    }
    CJson *out = CreateJson();
    if (out == NULL) {
        LOGE("Failed to create out json!");
        FreeJson(in);
        return HC_ERR_JSON_CREATE;
    }
    res = ExecuteAccountAuthCmd(DEFAULT_OS_ACCOUNT, ACCOUNT_GET_CLIENT_SHARED_KEY, in, out);
    FreeJson(in);
    if (res != HC_SUCCESS) {
        LOGE("Failed to get client shared key!");
        FreeJson(out);
        return res;
    }
    res = GetSharedKeyFromOutJson(out, returnSharedKey);
    if (res != HC_SUCCESS) {
        LOGE("Failed to get shared key from out json!");
        FreeJson(out);
        return res;
    }

    res = GetRandomFromOutJson(out, returnRandom);
    FreeJson(out);
    if (res != HC_SUCCESS) {
        LOGE("Failed to get random from out json!");
        DestroyDataBuff(returnSharedKey);
    }
    return res;
}

static int32_t ConstructServerInJson(CJson *in, const char *peerPkWithSig, const char *serviceId,
    const DataBuff *random)
{
    if (AddStringToJson(in, FIELD_ACCOUNT_PEER_PK_WITH_SIG, peerPkWithSig) != HC_SUCCESS) {
        LOGE("Failed to add peer pk to json!");
        return HC_ERR_JSON_ADD;
    }
    if (AddStringToJson(in, FIELD_ACCOUNT_SERVICE_ID, serviceId) != HC_SUCCESS) {
        LOGE("Failed to add serviceId to json!");
        return HC_ERR_JSON_ADD;
    }
    if (AddByteToJson(in, FIELD_ACCOUNT_RANDOM_VAL, random->data, random->length) != HC_SUCCESS) {
        LOGE("Failed to add random val to json!");
        return HC_ERR_JSON_ADD;
    }
    if (AddIntToJson(in, FIELD_ACCOUNT_RANDOM_LEN, random->length) != HC_SUCCESS) {
        LOGE("Failed to add random len to json!");
        return HC_ERR_JSON_ADD;
    }
    return HC_SUCCESS;
}

static int32_t GetServerSharedKey(const char *peerPkWithSig, const char *serviceId, const DataBuff *random,
    DataBuff *returnSharedKey)
{
    if (peerPkWithSig == NULL || serviceId == NULL || random == NULL || random->data == NULL ||
        returnSharedKey == NULL) {
        LOGE("Invalid params!");
        return HC_ERR_INVALID_PARAMS;
    }
    CJson *in = CreateJson();
    if (in == NULL) {
        LOGE("Failed to create in json!");
        return HC_ERR_JSON_CREATE;
    }
    int32_t res = ConstructServerInJson(in, peerPkWithSig, serviceId, random);
    if (res != HC_SUCCESS) {
        FreeJson(in);
        return res;
    }
    CJson *out = CreateJson();
    if (out == NULL) {
        LOGE("Failed to create out json!");
        FreeJson(in);
        return HC_ERR_JSON_CREATE;
    }
    res = ExecuteAccountAuthCmd(DEFAULT_OS_ACCOUNT, ACCOUNT_GET_SERVER_SHARED_KEY, in, out);
    FreeJson(in);
    if (res != HC_SUCCESS) {
        LOGE("Failed to get server shared key!");
        FreeJson(out);
        return res;
    }

    res = GetSharedKeyFromOutJson(out, returnSharedKey);
    FreeJson(out);
    if (res != HC_SUCCESS) {
        LOGE("Failed to get shared key from out json!");
    }
    return res;
}

DEVICE_AUTH_API_PUBLIC const AccountVerifier *GetAccountVerifierInstance(void)
{
    if (g_accountVerifierInstance == NULL) {
        LOGE("Account verifier instance not init!");
        return NULL;
    }
    g_accountVerifierInstance->getClientSharedKey = GetClientSharedKey;
    g_accountVerifierInstance->getServerSharedKey = GetServerSharedKey;
    g_accountVerifierInstance->destroyDataBuff = DestroyDataBuff;
    return g_accountVerifierInstance;
}

DEVICE_AUTH_API_PUBLIC const CredManager *GetCredMgrInstance(void)
{
    if (g_credManager == NULL) {
        LOGE("Service not init");
        return NULL;
    }

    g_credManager->addCredential = AddCredential;
    g_credManager->exportCredential = ExportCredential;
    g_credManager->queryCredentialByParams = QueryCredentialByParams;
    g_credManager->queryCredInfoByCredId = QueryCredInfoByCredId;
    g_credManager->deleteCredential = DeleteCredential;
    g_credManager->updateCredInfo = UpdateCredInfo;
    g_credManager->agreeCredential = AgreeCredential;
    g_credManager->registerChangeListener = RegisterChangeListener;
    g_credManager->unregisterChangeListener = UnregisterChangeListener;
    g_credManager->deleteCredByParams = DeleteCredByParams;
    g_credManager->batchUpdateCredentials = BatchUpdateCredentials;
    g_credManager->destroyInfo = DestroyInfo;

    return g_credManager;
}

DEVICE_AUTH_API_PUBLIC const CredAuthManager *GetCredAuthInstance(void)
{
    if (g_credAuthManager == NULL) {
        LOGE("Service not init.");
        return NULL;
    }

    g_credAuthManager->processCredData = ProcessCredData;
    g_credAuthManager->authCredential = AuthCredential;
    return g_credAuthManager;
}