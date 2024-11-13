/*
 * Copyright (C) 2024-2024 Huawei Device Co., Ltd.
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

#include <ipc_skeleton.h>
#include <system_ability_definition.h>

#include "hc_log.h"
#include "device_auth.h"
#include "device_auth_defines.h"
#include "ipc_adapt.h"
#include "ipc_dev_auth_stub.h"
#include "ipc_sdk.h"
#include "common_defs.h"
#include "hc_thread.h"
#include "securec.h"
#include "hc_string_vector.h"
#include "hidump_adapter.h"
#include "string_ex.h"

#include "deviceauth_sa.h"

namespace OHOS {

static const int32_t IPC_RESULT_NUM_1 = 1;
static const int32_t IPC_RESULT_NUM_2 = 2;
static const char *SERVICE_APP_ID = "deviceauth_service";
static DeviceGroupManager g_devGroupMgrMethod = {nullptr};
static GroupAuthManager g_groupAuthMgrMethod = {nullptr};
static DeviceAuthCallback g_bindCbAdt = {nullptr};
static DeviceAuthCallback g_authCbAdt = {nullptr};
static DataChangeListener g_listenCbAdt = {nullptr};
static const uint32_t RESTORE_CODE = 14701;

REGISTER_SYSTEM_ABILITY_BY_ID(DeviceAuthAbility, SA_ID_DEVAUTH_SERVICE, true);

std::mutex DeviceAuthAbility::g_instanceLock;
sptr<DeviceAuthAbility> DeviceAuthAbility::g_instance;

DeviceAuthAbility::DeviceAuthAbility(int saId, bool runOnCreate = true) : SystemAbility(saId, runOnCreate)
{
    LOGI("DeviceAuthAbility");
}

DeviceAuthAbility::~DeviceAuthAbility()
{
    LOGI("~DeviceAuthAbility");
}

static inline int32_t GetAndValSize32Param(const IpcDataInfo *ipcParams,
    int32_t paramNum, int32_t paramType, uint8_t *param, int32_t *paramSize)
{
    int32_t ret = GetIpcRequestParamByType(ipcParams, paramNum, paramType, param, paramSize);
    if ((*paramSize) != sizeof(int32_t) || ret != HC_SUCCESS) {
        LOGE("get param error, type %d", paramType);
        return HC_ERR_IPC_BAD_PARAM;
    }
    return HC_SUCCESS;
}

static inline int32_t GetAndValSize64Param(const IpcDataInfo *ipcParams,
    int32_t paramNum, int32_t paramType, uint8_t *param, int32_t *paramSize)
{
    int32_t ret = GetIpcRequestParamByType(ipcParams, paramNum, paramType, param, paramSize);
    if ((*paramSize) != sizeof(int64_t) || ret != HC_SUCCESS) {
        LOGE("get param error, type %d", paramType);
        return HC_ERR_IPC_BAD_PARAM;
    }
    return HC_SUCCESS;
}

static inline int32_t GetAndValSizeCbParam(const IpcDataInfo *ipcParams,
    int32_t paramNum, int32_t paramType, uint8_t *param, int32_t *paramSize)
{
    int32_t ret = GetIpcRequestParamByType(ipcParams, paramNum, paramType, param, paramSize);
    if ((*paramSize) != sizeof(DeviceAuthCallback) || ret != HC_SUCCESS) {
        LOGE("get param error, type %d", paramType);
        return HC_ERR_IPC_BAD_PARAM;
    }
    return HC_SUCCESS;
}

static inline int32_t GetAndValNullParam(const IpcDataInfo *ipcParams,
    int32_t paramNum, int32_t paramType, uint8_t *param, int32_t *paramSize)
{
    int32_t ret = GetIpcRequestParamByType(ipcParams, paramNum, paramType, param, nullptr);
    if (param == nullptr || ret != HC_SUCCESS) {
        LOGE("get param error, type %d", paramType);
        return HC_ERR_IPC_BAD_PARAM;
    }
    return HC_SUCCESS;
}

static int32_t BindRequestIdWithAppId(const char *data)
{
    const char *appId = nullptr;
    int32_t ret;
    int64_t requestId = -1;
    CJson *dataJson = CreateJsonFromString(data);
    if (dataJson == nullptr) {
        LOGE("failed to create json from string!");
        return HC_ERR_JSON_CREATE;
    }

    appId = GetStringFromJson(dataJson, FIELD_APP_ID);
    if (appId == nullptr) {
        LOGE("failed to get appId from json object!");
        FreeJson(dataJson);
        return HC_ERROR;
    }
    (void)GetInt64FromJson(dataJson, FIELD_REQUEST_ID, &requestId);
    ret = AddReqIdByAppId(appId, requestId);
    FreeJson(dataJson);
    return ret;
}

static int32_t IpcServiceGmRegCallback(const IpcDataInfo *ipcParams, int32_t paramNum, uintptr_t outCache)
{
    int32_t callRet;
    int32_t ret;
    const char *appId = nullptr;
    const DeviceAuthCallback *callback = nullptr;
    int32_t cbObjIdx = -1;
    int32_t inOutLen;

    LOGI("starting ...");
    ret = GetIpcRequestParamByType(ipcParams, paramNum, PARAM_TYPE_APPID, (uint8_t *)&appId, nullptr);
    if (ret != HC_SUCCESS) {
        LOGE("get param error, type %d", PARAM_TYPE_APPID);
        return HC_ERR_IPC_BAD_PARAM;
    }

    inOutLen = sizeof(DeviceAuthCallback);
    ret = GetAndValSizeCbParam(ipcParams, paramNum, PARAM_TYPE_DEV_AUTH_CB, (uint8_t *)&callback, &inOutLen);
    if (ret != HC_SUCCESS) {
        return ret;
    }
    ret = AddIpcCallBackByAppId(appId, (const uint8_t *)callback, sizeof(DeviceAuthCallback), CB_TYPE_DEV_AUTH);
    if (ret != HC_SUCCESS) {
        LOGE("add ipc callback failed");
        return HC_ERROR;
    }

    inOutLen = sizeof(int32_t);
    ret = GetIpcRequestParamByType(ipcParams, paramNum, PARAM_TYPE_CB_OBJECT, (uint8_t *)&cbObjIdx, &inOutLen);
    if (ret != HC_SUCCESS) {
        LOGE("get param error, type %d", PARAM_TYPE_CB_OBJECT);
        DelIpcCallBackByAppId(appId, CB_TYPE_DEV_AUTH);
        return HC_ERR_IPC_BAD_PARAM;
    }
    AddIpcCbObjByAppId(appId, cbObjIdx, CB_TYPE_DEV_AUTH);
    InitDeviceAuthCbCtx(&g_bindCbAdt, CB_TYPE_DEV_AUTH);
    callRet = g_devGroupMgrMethod.regCallback(appId, &g_bindCbAdt);
    if (callRet != HC_SUCCESS) {
        DelIpcCallBackByAppId(appId, CB_TYPE_DEV_AUTH);
    }
    ret = IpcEncodeCallReply(outCache, PARAM_TYPE_IPC_RESULT,
        reinterpret_cast<const uint8_t *>(&callRet), sizeof(int32_t));
    LOGI("process done, call ret %d, ipc ret %d", callRet, ret);
    return ret;
}

static int32_t IpcServiceGmUnRegCallback(const IpcDataInfo *ipcParams, int32_t paramNum, uintptr_t outCache)
{
    int32_t callRet = HC_SUCCESS;
    int32_t ret;
    const char *appId = nullptr;

    LOGI("starting ...");
    ret = GetIpcRequestParamByType(ipcParams, paramNum, PARAM_TYPE_APPID, (uint8_t *)&appId, nullptr);
    if (ret != HC_SUCCESS) {
        LOGE("get param error, type %d", PARAM_TYPE_APPID);
        return HC_ERR_IPC_BAD_PARAM;
    }

    DelIpcCallBackByAppId(appId, CB_TYPE_DEV_AUTH);
    ret = IpcEncodeCallReply(outCache, PARAM_TYPE_IPC_RESULT,
        reinterpret_cast<const uint8_t *>(&callRet), sizeof(int32_t));
    LOGI("process done, call ret %d, ipc ret %d", callRet, ret);
    return ret;
}

static int32_t IpcServiceGmRegDataChangeListener(const IpcDataInfo *ipcParams, int32_t paramNum, uintptr_t outCache)
{
    int32_t callRet;
    int32_t ret;
    const char *appId = nullptr;
    const DataChangeListener *callback = nullptr;
    static int32_t registered = 0;
    int32_t cbObjIdx = -1;
    int32_t inOutLen;

    ret = GetIpcRequestParamByType(ipcParams, paramNum, PARAM_TYPE_APPID, (uint8_t *)&appId, nullptr);
    if (ret != HC_SUCCESS) {
        LOGE("get param error, type %d", PARAM_TYPE_APPID);
        return HC_ERR_IPC_BAD_PARAM;
    }

    inOutLen = sizeof(DataChangeListener);
    ret = GetIpcRequestParamByType(ipcParams, paramNum, PARAM_TYPE_LISTERNER, (uint8_t *)&callback, &inOutLen);
    if ((ret != HC_SUCCESS) || (inOutLen != sizeof(DataChangeListener))) {
        LOGE("get param error, type %d", PARAM_TYPE_LISTERNER);
        return HC_ERR_IPC_BAD_PARAM;
    }

    ret = AddIpcCallBackByAppId(appId, (const uint8_t *)callback, sizeof(DataChangeListener), CB_TYPE_LISTENER);
    if (ret != HC_SUCCESS) {
        LOGE("add ipc callback failed");
        return HC_ERROR;
    }

    inOutLen = sizeof(int32_t);
    ret = GetIpcRequestParamByType(ipcParams, paramNum, PARAM_TYPE_CB_OBJECT, (uint8_t *)&cbObjIdx, &inOutLen);
    if (ret != HC_SUCCESS) {
        LOGE("get param error, type %d", PARAM_TYPE_CB_OBJECT);
        DelIpcCallBackByAppId(appId, CB_TYPE_DEV_AUTH);
        return HC_ERR_IPC_BAD_PARAM;
    }
    AddIpcCbObjByAppId(appId, cbObjIdx, CB_TYPE_LISTENER);

    callRet = HC_SUCCESS;
    if (registered == 0) {
        InitDevAuthListenerCbCtx(&g_listenCbAdt);
        callRet = g_devGroupMgrMethod.regDataChangeListener(SERVICE_APP_ID, &g_listenCbAdt);
        if (callRet == HC_SUCCESS) {
            registered = 1;
        } else {
            DelIpcCallBackByAppId(appId, CB_TYPE_LISTENER);
        }
    }
    ret = IpcEncodeCallReply(outCache, PARAM_TYPE_IPC_RESULT,
        reinterpret_cast<const uint8_t *>(&callRet), sizeof(int32_t));
    LOGI("process done, call ret %d, ipc ret %d", callRet, ret);
    return ret;
}

static int32_t IpcServiceGmUnRegDataChangeListener(const IpcDataInfo *ipcParams, int32_t paramNum, uintptr_t outCache)
{
    int32_t callRet = HC_SUCCESS;
    int32_t ret;
    const char *appId = nullptr;

    LOGI("starting ...");
    ret = GetIpcRequestParamByType(ipcParams, paramNum, PARAM_TYPE_APPID, (uint8_t *)&appId, nullptr);
    if (ret != HC_SUCCESS) {
        LOGE("get param error, type %d", PARAM_TYPE_APPID);
        return HC_ERR_IPC_BAD_PARAM;
    }
    DelIpcCallBackByAppId(appId, CB_TYPE_LISTENER);
    ret = IpcEncodeCallReply(outCache, PARAM_TYPE_IPC_RESULT,
        reinterpret_cast<const uint8_t *>(&callRet), sizeof(int32_t));
    LOGI("process done, call ret %d, ipc ret %d", callRet, ret);
    return ret;
}

static int32_t IpcServiceGmCreateGroup(const IpcDataInfo *ipcParams, int32_t paramNum, uintptr_t outCache)
{
    int32_t callRet;
    int32_t ret;
    int32_t osAccountId;
    int64_t requestId = 0;
    int32_t inOutLen;
    const char *createParams = nullptr;
    const char *appId = nullptr;

    LOGI("starting ...");
    inOutLen = sizeof(int32_t);
    ret = GetAndValSize32Param(ipcParams, paramNum, PARAM_TYPE_OS_ACCOUNT_ID, (uint8_t *)&osAccountId, &inOutLen);
    if (ret != HC_SUCCESS) {
        return ret;
    }
    inOutLen = sizeof(int64_t);
    ret = GetAndValSize64Param(ipcParams, paramNum, PARAM_TYPE_REQID, (uint8_t *)&requestId, &inOutLen);
    if (ret != HC_SUCCESS) {
        return ret;
    }
    ret = GetIpcRequestParamByType(ipcParams, paramNum, PARAM_TYPE_APPID, (uint8_t *)&appId, nullptr);
    if (ret != HC_SUCCESS) {
        LOGE("get param error, type %d", PARAM_TYPE_APPID);
        return HC_ERR_IPC_BAD_PARAM;
    }
    ret = GetIpcRequestParamByType(ipcParams, paramNum, PARAM_TYPE_CREATE_PARAMS, (uint8_t *)&createParams, nullptr);
    if (ret != HC_SUCCESS) {
        LOGE("get param error, type %d", PARAM_TYPE_CREATE_PARAMS);
        return HC_ERR_IPC_BAD_PARAM;
    }
    ret = AddReqIdByAppId(appId, requestId);
    if (ret != 0) {
        LOGE("bind request id by app id failed");
        return ret;
    }
    callRet = g_devGroupMgrMethod.createGroup(osAccountId, requestId, appId, createParams);
    ret = IpcEncodeCallReply(outCache, PARAM_TYPE_IPC_RESULT,
        reinterpret_cast<const uint8_t *>(&callRet), sizeof(int32_t));
    LOGI("process done, call ret %d, ipc ret %d", callRet, ret);
    return ret;
}

static int32_t IpcServiceGmDelGroup(const IpcDataInfo *ipcParams, int32_t paramNum, uintptr_t outCache)
{
    int32_t callRet;
    int32_t ret;
    int32_t osAccountId;
    int64_t requestId = 0;
    int32_t inOutLen;
    const char *appId = nullptr;
    const char *delParams = nullptr;

    LOGI("starting ...");
    inOutLen = sizeof(int32_t);
    ret = GetAndValSize32Param(ipcParams, paramNum, PARAM_TYPE_OS_ACCOUNT_ID, (uint8_t *)&osAccountId, &inOutLen);
    if (ret != HC_SUCCESS) {
        return ret;
    }
    inOutLen = sizeof(int64_t);
    ret = GetAndValSize64Param(ipcParams, paramNum, PARAM_TYPE_REQID, (uint8_t *)&requestId, &inOutLen);
    if (ret != HC_SUCCESS) {
        return ret;
    }
    ret = GetIpcRequestParamByType(ipcParams, paramNum, PARAM_TYPE_APPID, (uint8_t *)&appId, nullptr);
    if (ret != HC_SUCCESS) {
        LOGE("get param error, type %d", PARAM_TYPE_APPID);
        return HC_ERR_IPC_BAD_PARAM;
    }
    ret = GetIpcRequestParamByType(ipcParams, paramNum, PARAM_TYPE_DEL_PARAMS, (uint8_t *)&delParams, nullptr);
    if (ret != HC_SUCCESS) {
        LOGE("get param error, type %d", PARAM_TYPE_DEL_PARAMS);
        return HC_ERR_IPC_BAD_PARAM;
    }
    ret = AddReqIdByAppId(appId, requestId);
    if (ret != 0) {
        LOGE("bind request id by app id failed");
        return ret;
    }
    callRet = g_devGroupMgrMethod.deleteGroup(osAccountId, requestId, appId, delParams);
    ret = IpcEncodeCallReply(outCache, PARAM_TYPE_IPC_RESULT,
        reinterpret_cast<const uint8_t *>(&callRet), sizeof(int32_t));
    LOGI("process done, call ret %d, ipc ret %d", callRet, ret);
    return ret;
}

static int32_t IpcServiceGmAddMemberToGroup(const IpcDataInfo *ipcParams, int32_t paramNum, uintptr_t outCache)
{
    int32_t callRet;
    int32_t ret;
    int32_t inOutLen;
    int32_t osAccountId;
    int64_t requestId = 0;
    const char *addParams = nullptr;
    const char *appId = nullptr;

    LOGI("starting ...");
    inOutLen = sizeof(int32_t);
    ret = GetAndValSize32Param(ipcParams, paramNum, PARAM_TYPE_OS_ACCOUNT_ID, (uint8_t *)&osAccountId, &inOutLen);
    if (ret != HC_SUCCESS) {
        return ret;
    }
    inOutLen = sizeof(int64_t);
    ret = GetAndValSize64Param(ipcParams, paramNum, PARAM_TYPE_REQID, (uint8_t *)&requestId, &inOutLen);
    if (ret != HC_SUCCESS) {
        return ret;
    }
    ret = GetIpcRequestParamByType(ipcParams, paramNum, PARAM_TYPE_ADD_PARAMS, (uint8_t *)&addParams, nullptr);
    if (ret != HC_SUCCESS) {
        LOGE("get param error, type %d", PARAM_TYPE_ADD_PARAMS);
        return HC_ERR_IPC_BAD_PARAM;
    }
    ret = GetIpcRequestParamByType(ipcParams, paramNum, PARAM_TYPE_APPID, (uint8_t *)&appId, nullptr);
    if (ret != HC_SUCCESS) {
        LOGE("get param error, type %d", PARAM_TYPE_APPID);
        return HC_ERR_IPC_BAD_PARAM;
    }
    ret = AddReqIdByAppId(appId, requestId);
    if (ret != HC_SUCCESS) {
        return ret;
    }
    callRet = g_devGroupMgrMethod.addMemberToGroup(osAccountId, requestId, appId, addParams);
    ret = IpcEncodeCallReply(outCache, PARAM_TYPE_IPC_RESULT,
        reinterpret_cast<const uint8_t *>(&callRet), sizeof(int32_t));
    LOGI("process done, call ret %d, ipc ret %d", callRet, ret);
    return ret;
}

static int32_t IpcServiceGmDelMemberFromGroup(const IpcDataInfo *ipcParams, int32_t paramNum, uintptr_t outCache)
{
    int32_t callRet;
    int32_t ret;
    int32_t inOutLen;
    int32_t osAccountId;
    int64_t requestId = 0;
    const char *delParams = nullptr;
    const char *appId = nullptr;

    LOGI("starting ...");
    inOutLen = sizeof(int32_t);
    ret = GetAndValSize32Param(ipcParams, paramNum, PARAM_TYPE_OS_ACCOUNT_ID, (uint8_t *)&osAccountId, &inOutLen);
    if (ret != HC_SUCCESS) {
        return ret;
    }
    inOutLen = sizeof(int64_t);
    ret = GetAndValSize64Param(ipcParams, paramNum, PARAM_TYPE_REQID, (uint8_t *)&requestId, &inOutLen);
    if (ret != HC_SUCCESS) {
        return ret;
    }
    ret = GetIpcRequestParamByType(ipcParams, paramNum, PARAM_TYPE_APPID, (uint8_t *)&appId, nullptr);
    if (ret != HC_SUCCESS) {
        LOGE("get param error, type %d", PARAM_TYPE_APPID);
        return HC_ERR_IPC_BAD_PARAM;
    }
    ret = GetIpcRequestParamByType(ipcParams, paramNum, PARAM_TYPE_DEL_PARAMS, (uint8_t *)&delParams, nullptr);
    if (ret != HC_SUCCESS) {
        LOGE("get param error, type %d", PARAM_TYPE_DEL_PARAMS);
        return HC_ERR_IPC_BAD_PARAM;
    }
    ret = AddReqIdByAppId(appId, requestId);
    if (ret != 0) {
        LOGE("bind request id by app id failed");
        return ret;
    }
    callRet = g_devGroupMgrMethod.deleteMemberFromGroup(osAccountId, requestId, appId, delParams);
    ret = IpcEncodeCallReply(outCache, PARAM_TYPE_IPC_RESULT,
        reinterpret_cast<const uint8_t *>(&callRet), sizeof(int32_t));
    LOGI("process done, call ret %d, ipc ret %d", callRet, ret);
    return ret;
}

static int32_t IpcServiceGmAddMultiMembersToGroup(const IpcDataInfo *ipcParams, int32_t paramNum, uintptr_t outCache)
{
    int32_t callRet;
    int32_t ret;
    int32_t inOutLen;
    int32_t osAccountId;
    const char *addParams = nullptr;
    const char *appId = nullptr;

    LOGI("starting ...");
    inOutLen = sizeof(int32_t);
    ret = GetAndValSize32Param(ipcParams, paramNum, PARAM_TYPE_OS_ACCOUNT_ID, (uint8_t *)&osAccountId, &inOutLen);
    if (ret != HC_SUCCESS) {
        return ret;
    }
    ret = GetIpcRequestParamByType(ipcParams, paramNum, PARAM_TYPE_ADD_PARAMS, (uint8_t *)&addParams, nullptr);
    if (ret != HC_SUCCESS) {
        LOGE("get param error, type %d", PARAM_TYPE_ADD_PARAMS);
        return HC_ERR_IPC_BAD_PARAM;
    }
    ret = GetIpcRequestParamByType(ipcParams, paramNum, PARAM_TYPE_APPID, (uint8_t *)&appId, nullptr);
    if (ret != HC_SUCCESS) {
        LOGE("get param error, type %d", PARAM_TYPE_APPID);
        return HC_ERR_IPC_BAD_PARAM;
    }
    callRet = g_devGroupMgrMethod.addMultiMembersToGroup(osAccountId, appId, addParams);
    ret = IpcEncodeCallReply(outCache, PARAM_TYPE_IPC_RESULT,
        reinterpret_cast<const uint8_t *>(&callRet), sizeof(int32_t));
    LOGI("process done, call ret %d, ipc ret %d", callRet, ret);
    return ret;
}

static int32_t IpcServiceGmDelMultiMembersFromGroup(const IpcDataInfo *ipcParams, int32_t paramNum, uintptr_t outCache)
{
    int32_t callRet;
    int32_t ret;
    int32_t inOutLen;
    int32_t osAccountId;
    const char *delParams = nullptr;
    const char *appId = nullptr;

    LOGI("starting ...");
    inOutLen = sizeof(int32_t);
    ret = GetAndValSize32Param(ipcParams, paramNum, PARAM_TYPE_OS_ACCOUNT_ID, (uint8_t *)&osAccountId, &inOutLen);
    if (ret != HC_SUCCESS) {
        return ret;
    }
    ret = GetIpcRequestParamByType(ipcParams, paramNum, PARAM_TYPE_APPID, (uint8_t *)&appId, nullptr);
    if (ret != HC_SUCCESS) {
        LOGE("get param error, type %d", PARAM_TYPE_APPID);
        return ret;
    }
    ret = GetIpcRequestParamByType(ipcParams, paramNum, PARAM_TYPE_DEL_PARAMS, (uint8_t *)&delParams, nullptr);
    if (ret != HC_SUCCESS) {
        LOGE("get param error, type %d", PARAM_TYPE_DEL_PARAMS);
        return HC_ERR_IPC_BAD_PARAM;
    }
    callRet = g_devGroupMgrMethod.delMultiMembersFromGroup(osAccountId, appId, delParams);
    ret = IpcEncodeCallReply(outCache, PARAM_TYPE_IPC_RESULT,
        reinterpret_cast<const uint8_t *>(&callRet), sizeof(int32_t));
    LOGI("process done, call ret %d, ipc ret %d", callRet, ret);
    return ret;
}

static int32_t IpcServiceGmProcessData(const IpcDataInfo *ipcParams, int32_t paramNum, uintptr_t outCache)
{
    int32_t callRet;
    int32_t ret;
    int32_t dataLen;
    int32_t inOutLen;
    int64_t requestId = 0;
    const uint8_t *data = nullptr;

    LOGI("starting ...");
    inOutLen = sizeof(int64_t);
    ret = GetAndValSize64Param(ipcParams, paramNum, PARAM_TYPE_REQID, (uint8_t *)&requestId, &inOutLen);
    if (ret != HC_SUCCESS) {
        return ret;
    }

    dataLen = 0;
    ret = GetIpcRequestParamByType(ipcParams, paramNum, PARAM_TYPE_COMM_DATA, (uint8_t *)&data, &dataLen);
    if ((dataLen <= 0) || (ret != HC_SUCCESS)) {
        LOGE("get param error, type %d, data length %d", PARAM_TYPE_COMM_DATA, dataLen);
        return HC_ERR_IPC_BAD_PARAM;
    }
    ret = BindRequestIdWithAppId(reinterpret_cast<const char *>(data));
    if (ret != HC_SUCCESS) {
        return ret;
    }
    callRet = g_devGroupMgrMethod.processData(requestId, data, dataLen);
    ret = IpcEncodeCallReply(outCache, PARAM_TYPE_IPC_RESULT,
        reinterpret_cast<const uint8_t *>(&callRet), sizeof(int32_t));
    LOGI("process done, call ret %d, ipc ret %d", callRet, ret);
    return ret;
}

static int32_t IpcServiceGmApplyRegisterInfo(const IpcDataInfo *ipcParams, int32_t paramNum, uintptr_t outCache)
{
    int32_t callRet;
    int32_t ret;
    const char *reqJsonStr = nullptr;
    char *registerInfo = nullptr;

    LOGI("starting ...");
    ret = GetAndValNullParam(ipcParams, paramNum, PARAM_TYPE_REQ_JSON, (uint8_t *)&reqJsonStr, nullptr);
    if (ret != HC_SUCCESS) {
        return ret;
    }
    callRet = g_devGroupMgrMethod.getRegisterInfo(reqJsonStr, &registerInfo);
    ret = IpcEncodeCallReply(outCache, PARAM_TYPE_IPC_RESULT,
        reinterpret_cast<const uint8_t *>(&callRet), sizeof(int32_t));
    ret += IpcEncodeCallReply(outCache, PARAM_TYPE_IPC_RESULT_NUM,
        reinterpret_cast<const uint8_t *>(&IPC_RESULT_NUM_1), sizeof(int32_t));
    if (registerInfo != nullptr) {
        ret += IpcEncodeCallReply(outCache, PARAM_TYPE_REG_INFO,
            (const uint8_t *)registerInfo, HcStrlen(registerInfo) + 1);
        g_devGroupMgrMethod.destroyInfo(&registerInfo);
    } else {
        ret += IpcEncodeCallReply(outCache, PARAM_TYPE_REG_INFO, nullptr, 0);
    }
    LOGI("process done, call ret %d, ipc ret %d", callRet, ret);
    return (ret == HC_SUCCESS) ? ret : HC_ERROR;
}

static int32_t IpcServiceGmCheckAccessToGroup(const IpcDataInfo *ipcParams, int32_t paramNum, uintptr_t outCache)
{
    int32_t callRet;
    int32_t ret;
    int32_t inOutLen;
    int32_t osAccountId;
    const char *appId = nullptr;
    const char *groupId = nullptr;

    LOGI("starting ...");
    inOutLen = sizeof(int32_t);
    ret = GetAndValSize32Param(ipcParams, paramNum, PARAM_TYPE_OS_ACCOUNT_ID, (uint8_t *)&osAccountId, &inOutLen);
    if (ret != HC_SUCCESS) {
        return ret;
    }
    ret = GetAndValNullParam(ipcParams, paramNum, PARAM_TYPE_APPID, (uint8_t *)&appId, nullptr);
    if (ret != HC_SUCCESS) {
        return ret;
    }
    ret = GetAndValNullParam(ipcParams, paramNum, PARAM_TYPE_GROUPID, (uint8_t *)&groupId, nullptr);
    if (ret != HC_SUCCESS) {
        return ret;
    }

    callRet = g_devGroupMgrMethod.checkAccessToGroup(osAccountId, appId, groupId);
    ret = IpcEncodeCallReply(outCache, PARAM_TYPE_IPC_RESULT,
        reinterpret_cast<const uint8_t *>(&callRet), sizeof(int32_t));
    LOGI("process done, call ret %d, ipc ret %d", callRet, ret);
    return ret;
}

static int32_t IpcServiceGmGetPkInfoList(const IpcDataInfo *ipcParams, int32_t paramNum, uintptr_t outCache)
{
    int32_t callRet;
    int32_t ret;
    int32_t inOutLen;
    int32_t osAccountId;
    const char *appId = nullptr;
    const char *queryParams = nullptr;
    char *returnInfoList = nullptr;
    uint32_t returnInfoNum = 0;

    inOutLen = sizeof(int32_t);
    ret = GetAndValSize32Param(ipcParams, paramNum, PARAM_TYPE_OS_ACCOUNT_ID, (uint8_t *)&osAccountId, &inOutLen);
    if (ret != HC_SUCCESS) {
        return ret;
    }
    ret = GetAndValNullParam(ipcParams, paramNum, PARAM_TYPE_APPID, (uint8_t *)&appId, nullptr);
    if (ret != HC_SUCCESS) {
        return ret;
    }
    ret = GetAndValNullParam(ipcParams, paramNum, PARAM_TYPE_QUERY_PARAMS, (uint8_t *)&queryParams, nullptr);
    if (ret != HC_SUCCESS) {
        return ret;
    }

    callRet = g_devGroupMgrMethod.getPkInfoList(osAccountId, appId, queryParams, &returnInfoList, &returnInfoNum);
    ret = IpcEncodeCallReply(outCache, PARAM_TYPE_IPC_RESULT,
        reinterpret_cast<const uint8_t *>(&callRet), sizeof(int32_t));
    ret += IpcEncodeCallReply(outCache, PARAM_TYPE_IPC_RESULT_NUM,
        reinterpret_cast<const uint8_t *>(&IPC_RESULT_NUM_2), sizeof(int32_t));
    if (returnInfoList != nullptr) {
        ret += IpcEncodeCallReply(outCache, PARAM_TYPE_RETURN_DATA, (const uint8_t *)returnInfoList,
                                  HcStrlen(returnInfoList) + 1);
    } else {
        ret += IpcEncodeCallReply(outCache, PARAM_TYPE_RETURN_DATA, nullptr, 0);
    }
    ret += IpcEncodeCallReply(outCache, PARAM_TYPE_DATA_NUM, (const uint8_t *)&returnInfoNum, sizeof(int32_t));
    LOGI("process done, call ret %d, ipc ret %d", callRet, ret);
    g_devGroupMgrMethod.destroyInfo(&returnInfoList);
    return (ret == HC_SUCCESS) ? ret : HC_ERROR;
}

static int32_t IpcServiceGmGetGroupInfoById(const IpcDataInfo *ipcParams, int32_t paramNum, uintptr_t outCache)
{
    int32_t callRet;
    int32_t ret;
    int32_t inOutLen;
    int32_t osAccountId;
    const char *appId = nullptr;
    const char *groupId = nullptr;
    char *groupInfo = nullptr;

    LOGI("starting ...");
    inOutLen = sizeof(int32_t);
    ret = GetAndValSize32Param(ipcParams, paramNum, PARAM_TYPE_OS_ACCOUNT_ID, (uint8_t *)&osAccountId, &inOutLen);
    if (ret != HC_SUCCESS) {
        return ret;
    }
    ret = GetAndValNullParam(ipcParams, paramNum, PARAM_TYPE_APPID, (uint8_t *)&appId, nullptr);
    if (ret != HC_SUCCESS) {
        return ret;
    }
    ret = GetAndValNullParam(ipcParams, paramNum, PARAM_TYPE_GROUPID, (uint8_t *)&groupId, nullptr);
    if (ret != HC_SUCCESS) {
        return ret;
    }

    callRet = g_devGroupMgrMethod.getGroupInfoById(osAccountId, appId, groupId, &groupInfo);
    ret = IpcEncodeCallReply(outCache, PARAM_TYPE_IPC_RESULT,
        reinterpret_cast<const uint8_t *>(&callRet), sizeof(int32_t));
    ret += IpcEncodeCallReply(outCache, PARAM_TYPE_IPC_RESULT_NUM,
        reinterpret_cast<const uint8_t *>(&IPC_RESULT_NUM_1), sizeof(int32_t));
    if (groupInfo != nullptr) {
        ret += IpcEncodeCallReply(outCache, PARAM_TYPE_GROUP_INFO, (const uint8_t *)groupInfo, HcStrlen(groupInfo) + 1);
        g_devGroupMgrMethod.destroyInfo(&groupInfo);
    } else {
        ret += IpcEncodeCallReply(outCache, PARAM_TYPE_GROUP_INFO, nullptr, 0);
    }
    LOGI("process done, call ret %d, ipc ret %d", callRet, ret);
    return (ret == HC_SUCCESS) ? ret : HC_ERROR;
}

static int32_t IpcServiceGmGetGroupInfo(const IpcDataInfo *ipcParams, int32_t paramNum, uintptr_t outCache)
{
    int32_t callRet;
    int32_t ret;
    int32_t inOutLen;
    int32_t osAccountId;
    const char *appId = nullptr;
    const char *queryParams = nullptr;
    char *outGroups = nullptr;
    uint32_t groupNum = 0;

    LOGI("starting ...");
    inOutLen = sizeof(int32_t);
    ret = GetAndValSize32Param(ipcParams, paramNum, PARAM_TYPE_OS_ACCOUNT_ID, (uint8_t *)&osAccountId, &inOutLen);
    if (ret != HC_SUCCESS) {
        return ret;
    }
    ret = GetAndValNullParam(ipcParams, paramNum, PARAM_TYPE_APPID, (uint8_t *)&appId, nullptr);
    if (ret != HC_SUCCESS) {
        return ret;
    }
    ret = GetAndValNullParam(ipcParams, paramNum, PARAM_TYPE_QUERY_PARAMS, (uint8_t *)&queryParams, nullptr);
    if (ret != HC_SUCCESS) {
        return ret;
    }

    callRet = g_devGroupMgrMethod.getGroupInfo(osAccountId, appId, queryParams, &outGroups, &groupNum);
    ret = IpcEncodeCallReply(outCache, PARAM_TYPE_IPC_RESULT,
        reinterpret_cast<const uint8_t *>(&callRet), sizeof(int32_t));
    ret += IpcEncodeCallReply(outCache, PARAM_TYPE_IPC_RESULT_NUM,
        reinterpret_cast<const uint8_t *>(&IPC_RESULT_NUM_2), sizeof(int32_t));
    if (outGroups != nullptr) {
        ret += IpcEncodeCallReply(outCache, PARAM_TYPE_GROUP_INFO, (const uint8_t *)outGroups, HcStrlen(outGroups) + 1);
    } else {
        ret += IpcEncodeCallReply(outCache, PARAM_TYPE_GROUP_INFO, nullptr, 0);
    }
    ret += IpcEncodeCallReply(outCache, PARAM_TYPE_DATA_NUM, (const uint8_t *)&groupNum, sizeof(int32_t));
    LOGI("process done, call ret %d, ipc ret %d", callRet, ret);
    g_devGroupMgrMethod.destroyInfo(&outGroups);
    return (ret == HC_SUCCESS) ? ret : HC_ERROR;
}

static int32_t IpcServiceGmGetJoinedGroups(const IpcDataInfo *ipcParams, int32_t paramNum, uintptr_t outCache)
{
    int32_t callRet;
    int32_t ret;
    int32_t groupType = 0;
    int32_t inOutLen;
    int32_t osAccountId;
    const char *appId = nullptr;
    char *outGroups = nullptr;
    uint32_t groupNum = 0;

    LOGI("starting ...");
    inOutLen = sizeof(int32_t);
    ret = GetAndValSize32Param(ipcParams, paramNum, PARAM_TYPE_OS_ACCOUNT_ID, (uint8_t *)&osAccountId, &inOutLen);
    if (ret != HC_SUCCESS) {
        return ret;
    }
    ret = GetAndValNullParam(ipcParams, paramNum, PARAM_TYPE_APPID, (uint8_t *)&appId, nullptr);
    if (ret != HC_SUCCESS) {
        return ret;
    }
    inOutLen = sizeof(groupType);
    ret = GetIpcRequestParamByType(ipcParams, paramNum, PARAM_TYPE_GROUP_TYPE, (uint8_t *)&groupType, &inOutLen);
    if ((inOutLen != sizeof(groupType)) || (ret != HC_SUCCESS)) {
        LOGE("get param error, type %d", PARAM_TYPE_GROUP_TYPE);
        return HC_ERR_IPC_BAD_PARAM;
    }

    callRet = g_devGroupMgrMethod.getJoinedGroups(osAccountId, appId, groupType, &outGroups, &groupNum);
    ret = IpcEncodeCallReply(outCache, PARAM_TYPE_IPC_RESULT,
        reinterpret_cast<const uint8_t *>(&callRet), sizeof(int32_t));
    ret += IpcEncodeCallReply(outCache, PARAM_TYPE_IPC_RESULT_NUM,
        reinterpret_cast<const uint8_t *>(&IPC_RESULT_NUM_2), sizeof(int32_t));
    if (outGroups != nullptr) {
        ret += IpcEncodeCallReply(outCache, PARAM_TYPE_GROUP_INFO, (const uint8_t *)outGroups, HcStrlen(outGroups) + 1);
        g_devGroupMgrMethod.destroyInfo(&outGroups);
    } else {
        ret += IpcEncodeCallReply(outCache, PARAM_TYPE_GROUP_INFO, nullptr, 0);
    }
    ret += IpcEncodeCallReply(outCache, PARAM_TYPE_DATA_NUM, (const uint8_t *)&groupNum, sizeof(int32_t));
    LOGI("process done, call ret %d, ipc ret %d", callRet, ret);
    return (ret == HC_SUCCESS) ? ret : HC_ERROR;
}

static int32_t IpcServiceGmGetRelatedGroups(const IpcDataInfo *ipcParams, int32_t paramNum, uintptr_t outCache)
{
    int32_t callRet;
    int32_t ret;
    int32_t inOutLen;
    int32_t osAccountId;
    const char *appId = nullptr;
    const char *peerUdid = nullptr;
    char *outGroups = nullptr;
    uint32_t groupNum = 0;

    inOutLen = sizeof(int32_t);
    ret = GetAndValSize32Param(ipcParams, paramNum, PARAM_TYPE_OS_ACCOUNT_ID, (uint8_t *)&osAccountId, &inOutLen);
    if (ret != HC_SUCCESS) {
        return ret;
    }
    ret = GetAndValNullParam(ipcParams, paramNum, PARAM_TYPE_APPID, (uint8_t *)&appId, nullptr);
    if (ret != HC_SUCCESS) {
        return ret;
    }
    ret = GetAndValNullParam(ipcParams, paramNum, PARAM_TYPE_UDID, (uint8_t *)&peerUdid, nullptr);
    if (ret != HC_SUCCESS) {
        return ret;
    }

    callRet = g_devGroupMgrMethod.getRelatedGroups(osAccountId, appId, peerUdid, &outGroups, &groupNum);
    ret = IpcEncodeCallReply(outCache, PARAM_TYPE_IPC_RESULT,
        reinterpret_cast<const uint8_t *>(&callRet), sizeof(int32_t));
    ret += IpcEncodeCallReply(outCache, PARAM_TYPE_IPC_RESULT_NUM,
        reinterpret_cast<const uint8_t *>(&IPC_RESULT_NUM_2), sizeof(int32_t));
    if (outGroups != nullptr) {
        ret += IpcEncodeCallReply(outCache, PARAM_TYPE_GROUP_INFO, (const uint8_t *)outGroups, HcStrlen(outGroups) + 1);
    } else {
        ret += IpcEncodeCallReply(outCache, PARAM_TYPE_GROUP_INFO, nullptr, 0);
    }
    ret += IpcEncodeCallReply(outCache, PARAM_TYPE_DATA_NUM, (const uint8_t *)&groupNum, sizeof(int32_t));
    g_devGroupMgrMethod.destroyInfo(&outGroups);
    return (ret == HC_SUCCESS) ? ret : HC_ERROR;
}

static int32_t IpcServiceGmGetDeviceInfoById(const IpcDataInfo *ipcParams, int32_t paramNum, uintptr_t outCache)
{
    int32_t callRet;
    int32_t ret;
    int32_t inOutLen;
    int32_t osAccountId;
    const char *appId = nullptr;
    const char *peerUdid = nullptr;
    const char *groupId = nullptr;
    char *outDevInfo = nullptr;

    LOGI("starting ...");
    inOutLen = sizeof(int32_t);
    ret = GetAndValSize32Param(ipcParams, paramNum, PARAM_TYPE_OS_ACCOUNT_ID, (uint8_t *)&osAccountId, &inOutLen);
    if (ret != HC_SUCCESS) {
        return ret;
    }
    ret = GetAndValNullParam(ipcParams, paramNum, PARAM_TYPE_APPID, (uint8_t *)&appId, nullptr);
    if (ret != HC_SUCCESS) {
        return ret;
    }
    ret = GetAndValNullParam(ipcParams, paramNum, PARAM_TYPE_UDID, (uint8_t *)&peerUdid, nullptr);
    if (ret != HC_SUCCESS) {
        return ret;
    }
    ret = GetAndValNullParam(ipcParams, paramNum, PARAM_TYPE_GROUPID, (uint8_t *)&groupId, nullptr);
    if (ret != HC_SUCCESS) {
        return ret;
    }

    callRet = g_devGroupMgrMethod.getDeviceInfoById(osAccountId, appId, peerUdid, groupId, &outDevInfo);
    ret = IpcEncodeCallReply(outCache, PARAM_TYPE_IPC_RESULT,
        reinterpret_cast<const uint8_t *>(&callRet), sizeof(int32_t));
    ret += IpcEncodeCallReply(outCache, PARAM_TYPE_IPC_RESULT_NUM,
        reinterpret_cast<const uint8_t *>(&IPC_RESULT_NUM_1), sizeof(int32_t));
    if (outDevInfo != nullptr) {
        ret += IpcEncodeCallReply(outCache, PARAM_TYPE_DEVICE_INFO,
            (const uint8_t *)outDevInfo, HcStrlen(outDevInfo) + 1);
        g_devGroupMgrMethod.destroyInfo(&outDevInfo);
    } else {
        ret += IpcEncodeCallReply(outCache, PARAM_TYPE_DEVICE_INFO, nullptr, 0);
    }
    LOGI("process done, call ret %d, ipc ret %d", callRet, ret);
    return (ret == HC_SUCCESS) ? ret : HC_ERROR;
}

static int32_t IpcServiceGmGetTrustedDevices(const IpcDataInfo *ipcParams, int32_t paramNum, uintptr_t outCache)
{
    int32_t callRet;
    int32_t ret;
    int32_t inOutLen;
    int32_t osAccountId;
    const char *appId = nullptr;
    const char *groupId = nullptr;
    char *outDevInfo = nullptr;
    uint32_t outDevNum = 0;

    inOutLen = sizeof(int32_t);
    ret = GetAndValSize32Param(ipcParams, paramNum, PARAM_TYPE_OS_ACCOUNT_ID, (uint8_t *)&osAccountId, &inOutLen);
    if (ret != HC_SUCCESS) {
        return ret;
    }
    ret = GetAndValNullParam(ipcParams, paramNum, PARAM_TYPE_APPID, (uint8_t *)&appId, nullptr);
    if (ret != HC_SUCCESS) {
        return ret;
    }
    ret = GetAndValNullParam(ipcParams, paramNum, PARAM_TYPE_GROUPID, (uint8_t *)&groupId, nullptr);
    if (ret != HC_SUCCESS) {
        return ret;
    }

    callRet = g_devGroupMgrMethod.getTrustedDevices(osAccountId, appId, groupId, &outDevInfo, &outDevNum);
    ret = IpcEncodeCallReply(outCache, PARAM_TYPE_IPC_RESULT,
        reinterpret_cast<const uint8_t *>(&callRet), sizeof(int32_t));
    ret += IpcEncodeCallReply(outCache, PARAM_TYPE_IPC_RESULT_NUM,
        reinterpret_cast<const uint8_t *>(&IPC_RESULT_NUM_2), sizeof(int32_t));
    if (outDevInfo != nullptr) {
        ret += IpcEncodeCallReply(outCache, PARAM_TYPE_DEVICE_INFO,
            (const uint8_t *)outDevInfo, HcStrlen(outDevInfo) + 1);
    } else {
        ret += IpcEncodeCallReply(outCache, PARAM_TYPE_DEVICE_INFO, nullptr, 0);
    }
    ret += IpcEncodeCallReply(outCache, PARAM_TYPE_DATA_NUM, (const uint8_t *)&outDevNum, sizeof(int32_t));
    g_devGroupMgrMethod.destroyInfo(&outDevInfo);
    return (ret == HC_SUCCESS) ? ret : HC_ERROR;
}

static int32_t IpcServiceGmIsDeviceInGroup(const IpcDataInfo *ipcParams, int32_t paramNum, uintptr_t outCache)
{
    int32_t callRet;
    int32_t ret;
    int32_t inOutLen;
    int32_t osAccountId;
    bool bRet = false;
    const char *appId = nullptr;
    const char *udid = nullptr;
    const char *groupId = nullptr;

    LOGI("starting ...");
    inOutLen = sizeof(int32_t);
    ret = GetAndValSize32Param(ipcParams, paramNum, PARAM_TYPE_OS_ACCOUNT_ID, (uint8_t *)&osAccountId, &inOutLen);
    if (ret != HC_SUCCESS) {
        return ret;
    }
    ret = GetAndValNullParam(ipcParams, paramNum, PARAM_TYPE_APPID, (uint8_t *)&appId, nullptr);
    if (ret != HC_SUCCESS) {
        return ret;
    }
    ret = GetAndValNullParam(ipcParams, paramNum, PARAM_TYPE_UDID, (uint8_t *)&udid, nullptr);
    if (ret != HC_SUCCESS) {
        return ret;
    }
    ret = GetAndValNullParam(ipcParams, paramNum, PARAM_TYPE_GROUPID, (uint8_t *)&groupId, nullptr);
    if (ret != HC_SUCCESS) {
        return ret;
    }

    bRet = g_devGroupMgrMethod.isDeviceInGroup(osAccountId, appId, groupId, udid);
    callRet = ((bRet == true) ? HC_SUCCESS : HC_ERROR);
    ret = IpcEncodeCallReply(outCache, PARAM_TYPE_IPC_RESULT,
        reinterpret_cast<const uint8_t *>(&callRet), sizeof(int32_t));
    LOGI("process done, call ret %d, ipc ret %d", callRet, ret);
    return ret;
}

static int32_t IpcServiceGmCancelRequest(const IpcDataInfo *ipcParams, int32_t paramNum, uintptr_t outCache)
{
    int32_t ret;
    int64_t requestId = 0;
    const char *appId = nullptr;

    LOGI("starting ...");
    int32_t inOutLen = sizeof(int64_t);
    ret = GetIpcRequestParamByType(ipcParams, paramNum, PARAM_TYPE_REQID, (uint8_t *)&requestId, &inOutLen);
    if ((inOutLen != sizeof(requestId)) || (ret != HC_SUCCESS)) {
        LOGE("get param error, type %d", PARAM_TYPE_REQID);
        return HC_ERR_IPC_BAD_PARAM;
    }
    ret = GetAndValNullParam(ipcParams, paramNum, PARAM_TYPE_APPID, (uint8_t *)&appId, nullptr);
    if (ret != HC_SUCCESS) {
        return ret;
    }

    g_devGroupMgrMethod.cancelRequest(requestId, appId);
    LOGI("process done, ipc ret %d", ret);
    return ret;
}

static int32_t IpcServiceGaProcessData(const IpcDataInfo *ipcParams, int32_t paramNum, uintptr_t outCache)
{
    int32_t callRet;
    int32_t ret;
    const DeviceAuthCallback *gaCallback = nullptr;
    int64_t reqId = 0;
    uint8_t *data = nullptr;
    uint32_t dataLen = 0;
    int32_t inOutLen;
    int32_t cbObjIdx = -1;

    LOGI("starting ...");
    inOutLen = sizeof(int64_t);
    ret = GetAndValSize64Param(ipcParams, paramNum, PARAM_TYPE_REQID, (uint8_t *)&reqId, &inOutLen);
    if (ret != HC_SUCCESS) {
        return ret;
    }
    ret = GetIpcRequestParamByType(ipcParams, paramNum, PARAM_TYPE_COMM_DATA, (uint8_t *)&data, (int32_t *)&dataLen);
    if ((data == nullptr) || (dataLen == 0) || (ret != HC_SUCCESS)) {
        LOGE("get param error, type %d", PARAM_TYPE_COMM_DATA);
        return HC_ERR_IPC_BAD_PARAM;
    }
    inOutLen = sizeof(DeviceAuthCallback);
    ret = GetAndValSizeCbParam(ipcParams, paramNum, PARAM_TYPE_DEV_AUTH_CB, (uint8_t *)&gaCallback, &inOutLen);
    if (ret != HC_SUCCESS) {
        return ret;
    }
    /* add call back */
    ret = AddIpcCallBackByReqId(reqId, (const uint8_t *)gaCallback, sizeof(DeviceAuthCallback), CB_TYPE_TMP_DEV_AUTH);
    if (ret != HC_SUCCESS) {
        LOGE("add ipc callback failed");
        return ret;
    }
    inOutLen = sizeof(int32_t);
    ret = GetIpcRequestParamByType(ipcParams, paramNum, PARAM_TYPE_CB_OBJECT, (uint8_t *)&cbObjIdx, &inOutLen);
    if (ret != HC_SUCCESS) {
        LOGE("get param error, type %d", PARAM_TYPE_CB_OBJECT);
        DelIpcCallBackByReqId(reqId, CB_TYPE_TMP_DEV_AUTH, true);
        return HC_ERR_IPC_BAD_PARAM;
    }
    AddIpcCbObjByReqId(reqId, cbObjIdx, CB_TYPE_TMP_DEV_AUTH);
    InitDeviceAuthCbCtx(&g_authCbAdt, CB_TYPE_TMP_DEV_AUTH);
    callRet = g_groupAuthMgrMethod.processData(reqId, data, dataLen, &g_authCbAdt);
    if (callRet != HC_SUCCESS) {
        DelIpcCallBackByReqId(reqId, CB_TYPE_TMP_DEV_AUTH, true);
    }
    return IpcEncodeCallReply(outCache, PARAM_TYPE_IPC_RESULT,
        reinterpret_cast<const uint8_t *>(&callRet), sizeof(int32_t));
}

static int32_t IpcServiceGaAuthDevice(const IpcDataInfo *ipcParams, int32_t paramNum, uintptr_t outCache)
{
    int32_t ret;
    DeviceAuthCallback *gaCallback = nullptr;
    int32_t osAccountId;
    int64_t reqId = 0;
    const char *authParams = nullptr;
    int32_t cbObjIdx = -1;

    int32_t inOutLen = sizeof(int32_t);
    ret = GetAndValSize32Param(ipcParams, paramNum, PARAM_TYPE_OS_ACCOUNT_ID, (uint8_t *)&osAccountId, &inOutLen);
    if (ret != HC_SUCCESS) {
        return ret;
    }

    inOutLen = sizeof(int64_t);
    ret = GetAndValSize64Param(ipcParams, paramNum, PARAM_TYPE_REQID, (uint8_t *)&reqId, &inOutLen);
    if (ret != HC_SUCCESS) {
        return ret;
    }

    ret = GetAndValNullParam(ipcParams, paramNum, PARAM_TYPE_AUTH_PARAMS, (uint8_t *)&authParams, nullptr);
    if (ret != HC_SUCCESS) {
        return ret;
    }

    inOutLen = sizeof(DeviceAuthCallback);
    ret = GetAndValSizeCbParam(ipcParams, paramNum, PARAM_TYPE_DEV_AUTH_CB, (uint8_t *)&gaCallback, &inOutLen);
    if (ret != HC_SUCCESS) {
        return ret;
    }

    ret = AddIpcCallBackByReqId(reqId, (const uint8_t *)gaCallback, sizeof(DeviceAuthCallback), CB_TYPE_TMP_DEV_AUTH);
    if (ret != HC_SUCCESS) {
        return ret;
    }

    inOutLen = sizeof(int32_t);
    ret = GetIpcRequestParamByType(ipcParams, paramNum, PARAM_TYPE_CB_OBJECT, (uint8_t *)&cbObjIdx, &inOutLen);
    if (ret != HC_SUCCESS) {
        LOGE("get param error, type %d", PARAM_TYPE_CB_OBJECT);
        DelIpcCallBackByReqId(reqId, CB_TYPE_TMP_DEV_AUTH, true);
        return ret;
    }

    AddIpcCbObjByReqId(reqId, cbObjIdx, CB_TYPE_TMP_DEV_AUTH);
    InitDeviceAuthCbCtx(&g_authCbAdt, CB_TYPE_TMP_DEV_AUTH);
    ret = g_groupAuthMgrMethod.authDevice(osAccountId, reqId, authParams, &g_authCbAdt);
    if (ret != HC_SUCCESS) {
        DelIpcCallBackByReqId(reqId, CB_TYPE_TMP_DEV_AUTH, true);
    }

    return IpcEncodeCallReply(outCache, PARAM_TYPE_IPC_RESULT,
        reinterpret_cast<const uint8_t *>(&ret), sizeof(int32_t));
}

static int32_t IpcServiceGaCancelRequest(const IpcDataInfo *ipcParams, int32_t paramNum, uintptr_t outCache)
{
    int32_t ret;
    int64_t requestId = 0;
    const char *appId = nullptr;

    LOGI("starting ...");
    int32_t inOutLen = sizeof(int64_t);
    ret = GetIpcRequestParamByType(ipcParams, paramNum, PARAM_TYPE_REQID, (uint8_t *)&requestId, &inOutLen);
    if ((inOutLen != sizeof(requestId)) || (ret != HC_SUCCESS)) {
        LOGE("get param error, type %d", PARAM_TYPE_REQID);
        return HC_ERR_IPC_BAD_PARAM;
    }
    ret = GetAndValNullParam(ipcParams, paramNum, PARAM_TYPE_APPID, (uint8_t *)&appId, nullptr);
    if (ret != HC_SUCCESS) {
        return ret;
    }

    g_groupAuthMgrMethod.cancelRequest(requestId, appId);
    DelIpcCallBackByReqId(requestId, CB_TYPE_TMP_DEV_AUTH, true);
    LOGI("process done, ipc ret %d", ret);
    return ret;
}

static int32_t IpcServiceGaGetRealInfo(const IpcDataInfo *ipcParams, int32_t paramNum, uintptr_t outCache)
{
    int32_t ret;
    int32_t osAccountId;
    const char *pseudonymId = nullptr;

    LOGI("starting ...");
    int32_t inOutLen = sizeof(int64_t);
    ret = GetAndValSize32Param(ipcParams, paramNum, PARAM_TYPE_OS_ACCOUNT_ID, (uint8_t *)&osAccountId, &inOutLen);
    if (ret != HC_SUCCESS) {
        return ret;
    }
    ret = GetAndValNullParam(ipcParams, paramNum, PARAM_TYPE_PSEUDONYM_ID, (uint8_t *)&pseudonymId, nullptr);
    if (ret != HC_SUCCESS) {
        return ret;
    }

    char *realInfo = nullptr;
    ret = g_groupAuthMgrMethod.getRealInfo(osAccountId, pseudonymId, &realInfo);
    if ((realInfo != nullptr) && (ret == HC_SUCCESS)) {
        ret = IpcEncodeCallReply(outCache, PARAM_TYPE_RETURN_DATA, (const uint8_t *)realInfo,
            HcStrlen(realInfo) + 1);
        HcFree(realInfo);
    } else {
        ret = IpcEncodeCallReply(outCache, PARAM_TYPE_RETURN_DATA, nullptr, 0);
    }
    LOGI("process done, ipc ret %d", ret);
    return ret;
}

static int32_t IpcServiceGaGetPseudonymId(const IpcDataInfo *ipcParams, int32_t paramNum, uintptr_t outCache)
{
    int32_t ret;
    int32_t osAccountId;
    const char *indexKey = nullptr;

    LOGI("starting ...");
    int32_t inOutLen = sizeof(int64_t);
    ret = GetAndValSize32Param(ipcParams, paramNum, PARAM_TYPE_OS_ACCOUNT_ID, (uint8_t *)&osAccountId, &inOutLen);
    if (ret != HC_SUCCESS) {
        return ret;
    }
    ret = GetAndValNullParam(ipcParams, paramNum, PARAM_TYPE_INDEX_KEY, (uint8_t *)&indexKey, nullptr);
    if (ret != HC_SUCCESS) {
        return ret;
    }

    char *pseudonymId = nullptr;
    ret = g_groupAuthMgrMethod.getPseudonymId(osAccountId, indexKey, &pseudonymId);
    if ((pseudonymId != nullptr) && (ret == HC_SUCCESS)) {
        ret = IpcEncodeCallReply(outCache, PARAM_TYPE_RETURN_DATA, (const uint8_t *)pseudonymId,
            HcStrlen(pseudonymId) + 1);
        HcFree(pseudonymId);
    } else {
        ret = IpcEncodeCallReply(outCache, PARAM_TYPE_RETURN_DATA, nullptr, 0);
    }
    LOGI("process done, ipc ret %d", ret);
    return ret;
}

static int32_t IpcServiceDaProcessCredential(const IpcDataInfo *ipcParams, int32_t paramNum, uintptr_t outCache)
{
    int32_t ret;
    int32_t operationCode = 0;
    const char *reqJsonStr = nullptr;
    char *returnData = nullptr;

    LOGI("starting ...");
    int32_t inOutLen = sizeof(int32_t);
    ret = GetAndValSize32Param(ipcParams, paramNum, PARAM_TYPE_OPCODE, (uint8_t *)&operationCode, &inOutLen);
    if (ret != HC_SUCCESS) {
        return ret;
    }
    ret = GetAndValNullParam(ipcParams, paramNum, PARAM_TYPE_REQ_JSON, (uint8_t *)&reqJsonStr, nullptr);
    if (ret != HC_SUCCESS) {
        return ret;
    }
    ret = ProcessCredential(operationCode, reqJsonStr, &returnData);
    if (ret != HC_SUCCESS) {
        LOGI("call ProcessCredential failed %d", ret);
    }
    if (returnData != nullptr) {
        ret = IpcEncodeCallReply(
            outCache, PARAM_TYPE_RETURN_DATA, (const uint8_t *)returnData, HcStrlen(returnData) + 1);
        HcFree(returnData);
    } else {
        ret = IpcEncodeCallReply(outCache, PARAM_TYPE_RETURN_DATA, nullptr, 0);
    }
    LOGI("process done, ipc ret %d", ret);
    return ret;
}

static int32_t IpcServiceDaProcessData(const IpcDataInfo *ipcParams, int32_t paramNum, uintptr_t outCache)
{
    int32_t callRet;
    int32_t ret;
    const DeviceAuthCallback *callback = nullptr;
    int64_t authReqId = 0;
    const char *authParams = nullptr;
    int32_t inOutLen;
    int32_t cbObjIdx = -1;

    LOGI("starting ...");
    inOutLen = sizeof(int64_t);
    ret = GetIpcRequestParamByType(ipcParams, paramNum, PARAM_TYPE_REQID, (uint8_t *)&authReqId, &inOutLen);
    if ((ret != HC_SUCCESS) || (inOutLen != sizeof(authReqId))) {
        LOGE("get param error, type %d", PARAM_TYPE_REQID);
        return HC_ERR_IPC_BAD_PARAM;
    }
    ret = GetAndValNullParam(ipcParams, paramNum, PARAM_TYPE_AUTH_PARAMS, (uint8_t *)&authParams, nullptr);
    if (ret != HC_SUCCESS) {
        return ret;
    }
    inOutLen = sizeof(DeviceAuthCallback);
    ret = GetAndValSizeCbParam(ipcParams, paramNum, PARAM_TYPE_DEV_AUTH_CB, (uint8_t *)&callback, &inOutLen);
    if (ret != HC_SUCCESS) {
        return ret;
    }
    ret = AddIpcCallBackByReqId(
        authReqId, (const uint8_t *)callback, sizeof(DeviceAuthCallback), CB_TYPE_TMP_DEV_AUTH);
    if (ret != HC_SUCCESS) {
        return ret;
    }
    inOutLen = sizeof(int32_t);
    ret = GetIpcRequestParamByType(ipcParams, paramNum, PARAM_TYPE_CB_OBJECT, (uint8_t *)&cbObjIdx, &inOutLen);
    if (ret != HC_SUCCESS) {
        LOGE("get param error, type %d", PARAM_TYPE_CB_OBJECT);
        DelIpcCallBackByReqId(authReqId, CB_TYPE_TMP_DEV_AUTH, true);
        return HC_ERR_IPC_BAD_PARAM;
    }
    AddIpcCbObjByReqId(authReqId, cbObjIdx, CB_TYPE_TMP_DEV_AUTH);
    InitDeviceAuthCbCtx(&g_authCbAdt, CB_TYPE_TMP_DEV_AUTH);
    callRet = ProcessAuthDevice(authReqId, authParams, &g_authCbAdt);
    if (callRet != HC_SUCCESS) {
        DelIpcCallBackByReqId(authReqId, CB_TYPE_TMP_DEV_AUTH, true);
    }
    ret = IpcEncodeCallReply(outCache, PARAM_TYPE_IPC_RESULT,
        reinterpret_cast<const uint8_t *>(&callRet), sizeof(int32_t));
    LOGI("process done, call ret %d, ipc ret %d", callRet, ret);
    return ret;
}

static int32_t IpcServiceDaAuthDevice(const IpcDataInfo *ipcParams, int32_t paramNum, uintptr_t outCache)
{
    int32_t callRet;
    int32_t ret;
    DeviceAuthCallback *callback = nullptr;
    int64_t authReqId = 0;
    const char *authParams = nullptr;
    int32_t inOutLen;
    int32_t cbObjIdx = -1;

    LOGI("starting ...");
    inOutLen = sizeof(int64_t);
    ret = GetAndValSize64Param(ipcParams, paramNum, PARAM_TYPE_REQID, (uint8_t *)&authReqId, &inOutLen);
    if (ret != HC_SUCCESS) {
        return ret;
    }
    ret = GetAndValNullParam(ipcParams, paramNum, PARAM_TYPE_AUTH_PARAMS, (uint8_t *)&authParams, nullptr);
    if (ret != HC_SUCCESS) {
        return ret;
    }
    inOutLen = sizeof(DeviceAuthCallback);
    ret = GetAndValSizeCbParam(ipcParams, paramNum, PARAM_TYPE_DEV_AUTH_CB, (uint8_t *)&callback, &inOutLen);
    if (ret != HC_SUCCESS) {
        return ret;
    }
    ret = AddIpcCallBackByReqId(
        authReqId, (const uint8_t *)callback, sizeof(DeviceAuthCallback), CB_TYPE_TMP_DEV_AUTH);
    if (ret != HC_SUCCESS) {
        LOGE("add ipc callback failed");
        return ret;
    }
    inOutLen = sizeof(int32_t);
    ret = GetIpcRequestParamByType(ipcParams, paramNum, PARAM_TYPE_CB_OBJECT, (uint8_t *)&cbObjIdx, &inOutLen);
    if (ret != HC_SUCCESS) {
        LOGE("get param error, type %d", PARAM_TYPE_CB_OBJECT);
        DelIpcCallBackByReqId(authReqId, CB_TYPE_TMP_DEV_AUTH, true);
        return HC_ERR_IPC_BAD_PARAM;
    }
    AddIpcCbObjByReqId(authReqId, cbObjIdx, CB_TYPE_TMP_DEV_AUTH);
    InitDeviceAuthCbCtx(&g_authCbAdt, CB_TYPE_TMP_DEV_AUTH);
    callRet = StartAuthDevice(authReqId, authParams, &g_authCbAdt);
    if (callRet != HC_SUCCESS) {
        DelIpcCallBackByReqId(authReqId, CB_TYPE_TMP_DEV_AUTH, true);
    }
    ret = IpcEncodeCallReply(outCache, PARAM_TYPE_IPC_RESULT,
        reinterpret_cast<const uint8_t *>(&callRet), sizeof(int32_t));
    LOGI("process done, call ret %d, ipc ret %d", callRet, ret);
    return ret;
}

static int32_t IpcServiceDaCancelRequest(const IpcDataInfo *ipcParams, int32_t paramNum, uintptr_t outCache)
{
    int32_t ret;
    int64_t requestId = 0;
    const char *authParams = nullptr;

    LOGI("starting ...");
    int32_t inOutLen = sizeof(int64_t);
    ret = GetIpcRequestParamByType(ipcParams, paramNum, PARAM_TYPE_REQID, (uint8_t *)&requestId, &inOutLen);
    if ((inOutLen != sizeof(requestId)) || (ret != HC_SUCCESS)) {
        LOGE("get param error, type %d", PARAM_TYPE_REQID);
        return HC_ERR_IPC_BAD_PARAM;
    }
    ret = GetAndValNullParam(ipcParams, paramNum, PARAM_TYPE_AUTH_PARAMS, (uint8_t *)&authParams, nullptr);
    if (ret != HC_SUCCESS) {
        return ret;
    }
    ret = CancelAuthRequest(requestId, authParams);
    DelIpcCallBackByReqId(requestId, CB_TYPE_TMP_DEV_AUTH, true);
    ret = IpcEncodeCallReply(outCache, PARAM_TYPE_IPC_RESULT, reinterpret_cast<const uint8_t *>(&ret), sizeof(int32_t));
    LOGI("process done, ipc ret %d", ret);
    return ret;
}

static int32_t MainRescInit(void)
{
    int32_t ret;

    LOGI("DeviceAuthAbility MainRescInit starting ...");
    ret = InitIpcCallBackList();
    if (ret != HC_SUCCESS) {
        return ret;
    }
    const DeviceGroupManager *gmInst = GetGmInstance();
    const GroupAuthManager *gaInst = GetGaInstance();
    if ((gmInst == nullptr) || (gaInst == nullptr)) {
        DeInitIpcCallBackList();
        LOGE("DeviceAuthAbility MainInit GetGmInstance or GetGaInstance failed");
        return HC_ERROR;
    }
    g_devGroupMgrMethod = (DeviceGroupManager)(*gmInst);
    g_groupAuthMgrMethod = (GroupAuthManager)(*gaInst);
    InitDevAuthListenerCbCtx(&g_listenCbAdt);
    ret = gmInst->regDataChangeListener(SERVICE_APP_ID, &g_listenCbAdt);
    if (ret != HC_SUCCESS) {
        DeInitIpcCallBackList();
        LOGE("DeviceAuthAbility MainInit, register ipc listener failed, ret %d", ret);
        return HC_ERROR;
    }

    LOGI("DeviceAuthAbility MainRescInit process done");
    return HC_SUCCESS;
}

#ifndef DEV_AUTH_FUZZ_TEST
static void DeMainRescInit(void)
{
    if (g_devGroupMgrMethod.unRegDataChangeListener != nullptr) {
        (void)g_devGroupMgrMethod.unRegDataChangeListener(SERVICE_APP_ID);
    }
    DeInitIpcCallBackList();
}
#endif

__attribute__((no_sanitize("cfi"))) static uint32_t SaSetIpcCallMap(
    uintptr_t ipcInstance, IpcServiceCall method, int32_t methodId)
{
    if ((method == nullptr) || (methodId <= 0)) {
        return static_cast<uint32_t>(HC_ERR_INVALID_PARAMS);
    }

    DeviceAuthAbility *service = reinterpret_cast<DeviceAuthAbility *>(ipcInstance);
    return static_cast<uint32_t>(service->SetCallMap(method, methodId));
}

int32_t SaAddMethodMap(uintptr_t ipcInstance)
{
    uint32_t ret = 0;
    using IpcCallMap = struct {
        int32_t (*func)(const IpcDataInfo*, int32_t, uintptr_t);
        uint32_t id;
    };

    IpcCallMap ipcCallMaps[] = {
        {IpcServiceGmRegCallback, IPC_CALL_ID_REG_CB},
        {IpcServiceGmUnRegCallback, IPC_CALL_ID_UNREG_CB},
        {IpcServiceGmRegDataChangeListener, IPC_CALL_ID_REG_LISTENER},
        {IpcServiceGmUnRegDataChangeListener, IPC_CALL_ID_UNREG_LISTENER},
        {IpcServiceGmCreateGroup, IPC_CALL_ID_CREATE_GROUP},
        {IpcServiceGmDelGroup, IPC_CALL_ID_DEL_GROUP},
        {IpcServiceGmAddMemberToGroup, IPC_CALL_ID_ADD_GROUP_MEMBER},
        {IpcServiceGmDelMemberFromGroup, IPC_CALL_ID_DEL_GROUP_MEMBER},
        {IpcServiceGmAddMultiMembersToGroup, IPC_CALL_ID_ADD_MULTI_GROUP_MEMBERS},
        {IpcServiceGmDelMultiMembersFromGroup, IPC_CALL_ID_DEL_MULTI_GROUP_MEMBERS},
        {IpcServiceGmProcessData, IPC_CALL_ID_GM_PROC_DATA},
        {IpcServiceGmApplyRegisterInfo, IPC_CALL_ID_APPLY_REG_INFO},
        {IpcServiceGmCheckAccessToGroup, IPC_CALL_ID_CHECK_ACCESS_TO_GROUP},
        {IpcServiceGmGetPkInfoList, IPC_CALL_ID_GET_PK_INFO_LIST},
        {IpcServiceGmGetGroupInfoById, IPC_CALL_ID_GET_GROUP_INFO},
        {IpcServiceGmGetGroupInfo, IPC_CALL_ID_SEARCH_GROUPS},
        {IpcServiceGmGetJoinedGroups, IPC_CALL_ID_GET_JOINED_GROUPS},
        {IpcServiceGmGetRelatedGroups, IPC_CALL_ID_GET_RELATED_GROUPS},
        {IpcServiceGmGetDeviceInfoById, IPC_CALL_ID_GET_DEV_INFO_BY_ID},
        {IpcServiceGmGetTrustedDevices, IPC_CALL_ID_GET_TRUST_DEVICES},
        {IpcServiceGmIsDeviceInGroup, IPC_CALL_ID_IS_DEV_IN_GROUP},
        {IpcServiceGmCancelRequest, IPC_CALL_GM_CANCEL_REQUEST},
        {IpcServiceGaProcessData, IPC_CALL_ID_GA_PROC_DATA},
        {IpcServiceGaAuthDevice, IPC_CALL_ID_AUTH_DEVICE},
        {IpcServiceGaCancelRequest, IPC_CALL_GA_CANCEL_REQUEST},
        {IpcServiceGaGetRealInfo, IPC_CALL_ID_GET_REAL_INFO},
        {IpcServiceGaGetPseudonymId, IPC_CALL_ID_GET_PSEUDONYM_ID},
        {IpcServiceDaProcessCredential, IPC_CALL_ID_PROCESS_CREDENTIAL},
        {IpcServiceDaAuthDevice, IPC_CALL_ID_DA_AUTH_DEVICE},
        {IpcServiceDaProcessData, IPC_CALL_ID_DA_PROC_DATA},
        {IpcServiceDaCancelRequest, IPC_CALL_ID_DA_CANCEL_REQUEST},
    };

    for (uint32_t i = 0; i < sizeof(ipcCallMaps)/sizeof(ipcCallMaps[0]); i++) {
        ret &= SaSetIpcCallMap(ipcInstance, ipcCallMaps[i].func, ipcCallMaps[i].id);
    }

    return ret;
}

sptr<DeviceAuthAbility> DeviceAuthAbility::GetInstance()
{
    std::lock_guard<std::mutex> autoLock(g_instanceLock);
    if (g_instance == nullptr) {
        g_instance = new (std::nothrow) DeviceAuthAbility(SA_ID_DEVAUTH_SERVICE, true);
    }
    return g_instance;
}

void DeviceAuthAbility::DestroyInstance()
{
    std::lock_guard<std::mutex> autoLock(g_instanceLock);
    if (g_instance != nullptr) {
        delete g_instance;
        g_instance = nullptr;
    }
    LOGI("DeviceAuthAbility DestroyInstance done");
}

int32_t DeviceAuthAbility::Dump(int32_t fd, const std::vector<std::u16string> &args)
{
    std::vector<std::string> strArgs;
    for (auto arg : args) {
        strArgs.emplace_back(Str16ToStr8(arg));
    }
    uint32_t argc = strArgs.size();
    StringVector strArgVec = CreateStrVector();
    for (uint32_t i = 0; i < argc; i++) {
        HcString strArg = CreateString();
        if (!StringSetPointer(&strArg, strArgs[i].c_str())) {
            LOGE("Failed to set strArg!");
            DeleteString(&strArg);
            continue;
        }
        if (strArgVec.pushBackT(&strArgVec, strArg) == nullptr) {
            LOGE("Failed to push strArg to strArgVec!");
            DeleteString(&strArg);
        }
    }
    DEV_AUTH_DUMP(fd, &strArgVec);
    DestroyStrVector(&strArgVec);
    return 0;
}

void DeviceAuthAbility::OnStart()
{
    LOGI("DeviceAuthAbility starting ...");
    int32_t ret = InitDeviceAuthService();
    if (ret != HC_SUCCESS) {
        LOGE("DeviceAuthAbility InitDeviceAuthService failed, ret %d", ret);
        return;
    }

    ret = MainRescInit();
    if (ret != HC_SUCCESS) {
        DestroyDeviceAuthService();
        LOGE("device auth service main, init work failed");
        return;
    }

    sptr<DeviceAuthAbility> serviceInstance = DeviceAuthAbility::GetInstance();
    if (serviceInstance == nullptr) {
        LOGE("DeviceAuthAbility GetInstance Failed");
        DeMainRescInit();
        DestroyDeviceAuthService();
        return;
    }

    uintptr_t serviceInstanceAddress = reinterpret_cast<uintptr_t>(serviceInstance.GetRefPtr());
    ret = SaAddMethodMap(serviceInstanceAddress);
    if (ret != HC_SUCCESS) {
        LOGW("DeviceAuthAbility SaAddMethodMap failed at least once.");
    }
    
    if (!Publish(serviceInstance)) {
        LOGE("DeviceAuthAbility Publish failed");
        DeviceAuthAbility::DestroyInstance();
        DeMainRescInit();
        DestroyDeviceAuthService();
        return;
    }
    LOGI("DeviceAuthAbility start success.");
}

int32_t DeviceAuthAbility::OnRemoteRequest(uint32_t code, MessageParcel &data, MessageParcel &reply,
    MessageOption &option)
{
    std::u16string readToken = data.ReadInterfaceToken();

    bool isRestoreCall = ((code == RESTORE_CODE) && (readToken == std::u16string(u"OHOS.Updater.RestoreData")));
    if (readToken != GetDescriptor() && !isRestoreCall) {
        LOGE("DeviceAuthAbility [IPC][C->S]: The proxy interface token is invalid!");
        return -1;
    }
    if (isRestoreCall) {
        return HandleRestoreCall(data, reply);
    } else {
        return HandleDeviceAuthCall(code, data, reply, option);
    }
}

void DeviceAuthAbility::OnStop()
{
    LOGI("DeviceAuthAbility OnStop");
    DeviceAuthAbility::DestroyInstance();
    DeMainRescInit();
    DestroyDeviceAuthService();
}

} // namespace OHOS