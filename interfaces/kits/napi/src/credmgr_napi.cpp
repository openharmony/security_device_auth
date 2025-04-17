/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "credmgr_napi.h"

#include "device_auth_defines.h"
#include "hc_log.h"
#include "hc_types.h"
#include "ipc_sdk.h"
#include "identity_service_ipc_sdk.h"
#include "napi/native_api.h"
#include "napi/native_node_api.h"
#include "string_util.h"

namespace OHOS {
namespace CredMgrNapi {
thread_local napi_ref NapiCredManager::classRef_ = nullptr;
std::mutex NapiCredManager::g_instanceLock;

struct BatchUpdateCredsCtx {
    napi_value env = nullptr;
    AsyncType asyncType = ASYNC_CALLBACK;
    napi_ref callback = nullptr;
    napi_deferred deferred = nullptr;
    napi_value promise = nullptr;
    napi_async_work asyncWork = nullptr;
    napi_ref credManagerRef = nullptr;

    int32_t errCode = 0;
    int32_t osAccountId = 0;
    char *requestParams = nullptr;
    char *returnData = nullptr;
    const char *errMsg = nullptr;
    
    CredManager *credManager = nullptr;
};

static void FreeBatchUpdateCredsCtx(napi_env env, BatchUpdateCredsCtx *ctx)
{
    if (ctx == nullptr) {
        return;
    }
    if (ctx->asyncWork != nullptr) {
        napi_delete_async_work(env, ctx->asyncWork);
        ctx->asyncWork = nullptr;
    }
    if (ctx->callback != nullptr) {
        napi_delete_reference(env, ctx->callback);
        ctx->callback = nullptr;
    }
    if (ctx->credManagerRef != nullptr) {
        napi_delete_reference(env, ctx->credManagerRef);
        ctx->credManagerRef = nullptr;
    }
    if (ctx->requestParams != nullptr) {
        HcFree(ctx->requestParams);
        ctx->requestParams = nullptr;
    }
    if (ctx->returnData != nullptr) {
        HcFree(ctx->returnData);
        ctx->returnData = nullptr;
    }
    ctx->errMsg = nullptr;
    HcFree(ctx);
    ctx = nullptr;
}

napi_value GenerateErrorMsg(napi_env env, int32_t errorCode, const char *errMsg)
{
    std::string errCodeField = "code";
    napi_value errorRes = nullptr;
    napi_value code = nullptr;
    napi_create_int32(env, errorCode, &code);
    napi_value msg = nullptr;
    napi_create_string_utf8(env, errMsg, NAPI_AUTO_LENGTH, &msg);

    napi_create_error(env, nullptr, msg, &errorRes);
    napi_set_named_property(env, errorRes, errCodeField.c_str(), code);
    return errorRes;
}

NapiCredManager::NapiCredManager(CredManager *credManager)
{
    this->credManager_ = credManager;
}

NapiCredManager::~NapiCredManager()
{
    std::lock_guard<std::mutex> autoLock(g_instanceLock);
    if (this->credManager_ != nullptr) {
        DestroyDeviceAuthService();
        this->credManager_ = nullptr;
    }
}

CredManager *NapiCredManager::GetCurrentCredMgr()
{
    std::lock_guard<std::mutex> autoLock(g_instanceLock);
    return this->credManager_;
}

napi_value NapiCredManager::NapiCredMgrConstructor(napi_env env, napi_callback_info info)
{
    napi_value thisVar = nullptr;
    napi_get_cb_info(env, info, nullptr, nullptr, &thisVar, nullptr);
    return thisVar;
}

napi_value NapiCredManager::NapiGetCredMgrInstance(napi_env env, napi_callback_info info)
{
    LOGI("start...");
    int32_t ret = InitDeviceAuthService();
    if (ret != IS_SUCCESS) {
        LOGE("InitDeviceAuthService failed");
        napi_throw(env, GenerateErrorMsg(env, ret, "InitDeviceAuthService failed"));
        return nullptr;
    }

    napi_value instance;
    napi_value constructor = nullptr;
    napi_get_reference_value(env, classRef_, &constructor);
    napi_new_instance(env, constructor, 0, nullptr, &instance);

    CredManager *credManager = (CredManager *)GetCredMgrInstance();
    if (credManager == nullptr) {
        LOGE("GetCredMgrInstance failed");
        napi_throw(env, GenerateErrorMsg(env, IS_ERR_NULL_PTR, "GetCredMgrInstance failed"));
        return nullptr;
    }
    NapiCredManager *napiCredManager = new (std::nothrow) NapiCredManager(credManager);
    if (napiCredManager == nullptr) {
        LOGE("new NapiCredManager failed");
        napi_throw(env, GenerateErrorMsg(env, IS_ERR_ALLOC_MEMORY, "new NapiCredManager failed"));
        return nullptr;
    }
    napi_status status = napi_wrap(env, instance, napiCredManager,
        [](napi_env env, void *data, void *hint) {
            NapiCredManager *napiCredManager = static_cast<NapiCredManager *>(data);
            delete napiCredManager;
            return;
        }, nullptr, nullptr);
    if (status != napi_ok) {
        LOGE("napi_wrap failed");
        napi_throw(env, GenerateErrorMsg(env, IS_ERROR, "napi_wrap failed"));
        delete napiCredManager;
        return nullptr;
    }
    return instance;
}

static bool GetParamsFromNapiValue(napi_env env, napi_value osAccountIdVal, napi_value reqParamsVal,
    int32_t &osAccountId, std::string &reqParams)
{
    size_t length = 0;
    napi_valuetype osAccountIdType;
    napi_valuetype reqParamsType;
    napi_typeof(env, osAccountIdVal, &osAccountIdType);
    napi_typeof(env, reqParamsVal, &reqParamsType);
    if (osAccountIdType == napi_null || reqParamsType == napi_null) {
        LOGE("osAccountId or reqParams is null");
        return false;
    }
    if (osAccountIdType != napi_number || reqParamsType != napi_string) {
        LOGE("osAccountId is not number or reqParams is not string");
        return false;
    }
    if (napi_get_value_int32(env, osAccountIdVal, &osAccountId) != napi_ok) {
        LOGE("can not get osAccountId");
        return false;
    }
    if (napi_get_value_string_utf8(env, reqParamsVal, nullptr, 0, &length) != napi_ok) {
        LOGE("can not get length of reqParams");
        return false;
    }
    reqParams.reserve(length + 1);
    reqParams.resize(length);
    if (napi_get_value_string_utf8(env, reqParamsVal, reqParams.data(), length + 1, &length) != napi_ok) {
        LOGE("can not get reqParams");
        return false;
    }
    return true;
}

static bool IsCallback(napi_env env, napi_value argv, size_t argc, size_t expectedArgc)
{
    if (argc == expectedArgc - 1) {
        return false;
    }
    napi_valuetype valueType = napi_undefined;
    napi_typeof(env, argv, &valueType);
    if (valueType == napi_undefined || valueType == napi_null) {
        return false;
    }
    return true;
}

static bool GetCallbackFromJsParams(napi_env env, napi_value arg, napi_ref *returnCb)
{
    napi_valuetype valueType = napi_undefined;
    napi_typeof(env, arg, &valueType);
    if (valueType != napi_function) {
        LOGE("wrong arg type. expect callback function. [Type]: %" LOG_PUB "d", valueType);
        return false;
    }
    napi_create_reference(env, arg, 1, returnCb);
    return true;
}

static bool BuildCtxForBatchUpdateCreds(napi_env env, napi_callback_info info, BatchUpdateCredsCtx *ctx)
{
    napi_value thisVar = nullptr;
    size_t expectedArgc = ARGS_SIZE_THREE;
    size_t argc = expectedArgc;
    napi_value argv[ARGS_SIZE_THREE] = { nullptr };
    napi_get_cb_info(env, info, &argc, argv, &thisVar, nullptr);

    if (argc != expectedArgc - 1 && argc != expectedArgc) {
        LOGE("wrong arg count, required: %" LOG_PUB "zu or %" LOG_PUB "zu, but got: %" LOG_PUB "zu",
            expectedArgc - 1, expectedArgc, argc);
        return false;
    }
    int32_t osAccountId = 0;
    std::string requestParams;
    if (!GetParamsFromNapiValue(env, argv[PARAM0], argv[PARAM1], osAccountId, requestParams)) {
        LOGE("get params failed");
        return false;
    }
    ctx->osAccountId = osAccountId;
    if (DeepCopyString(requestParams.c_str(), &ctx->requestParams) != HC_SUCCESS) {
        LOGE("copy requestParams failed");
        return false;
    }
    ctx->asyncType = IsCallback(env, argv[expectedArgc - 1], argc, expectedArgc) ? ASYNC_CALLBACK : ASYNC_PROMISE;
    NapiCredManager *napiCredManager = nullptr;
    napi_status status = napi_unwrap(env, thisVar, reinterpret_cast<void **>(&napiCredManager));
    if (status != napi_ok || napiCredManager == nullptr) {
        LOGE("napiCredManager unwrap failed");
        return false;
    }
    ctx->credManager = napiCredManager->GetCurrentCredMgr();
    if (ctx->credManager == nullptr) {
        LOGE("failed to get credManager obj");
        return false;
    }
    if (napi_create_reference(env, thisVar, 1, &ctx->credManagerRef) != napi_ok) {
        LOGE("failed to create credManager reference");
        return false;
    }
    if (ctx->asyncType == ASYNC_PROMISE) {
        napi_create_promise(env, &ctx->deferred, &ctx->promise);
        return true;
    }
    return GetCallbackFromJsParams(env, argv[expectedArgc - 1], &ctx->callback);
}

static napi_value NapiGetNull(napi_env env)
{
    napi_value result = nullptr;
    napi_get_null(env, &result);
    return result;
}

static void AsyncBatchUpdateCredsProcess(napi_env env, void *data)
{
    BatchUpdateCredsCtx *ctx = static_cast<BatchUpdateCredsCtx *>(data);
    CredManager *credManager = ctx->credManager;

    ctx->errCode = credManager->batchUpdateCredentials(ctx->osAccountId, ctx->requestParams, &(ctx->returnData));
    if (ctx->errCode != IS_SUCCESS) {
        LOGE("batchUpdateCredentials failed, errCode: %" LOG_PUB "d", ctx->errCode);
        ctx->errMsg = "batchUpdateCredentials failed";
        return;
    }
}

static void CredMgrCallbackResult(napi_env env, BatchUpdateCredsCtx *ctx, napi_value result)
{
    napi_value errorReturn = nullptr;
    if (ctx->errCode != IS_SUCCESS) {
        errorReturn = GenerateErrorMsg(env, ctx->errCode, ctx->errMsg);
    }
    napi_value param[ARGS_SIZE_TWO] = { errorReturn, result };

    napi_value func = nullptr;
    napi_get_reference_value(env, ctx->callback, &func);

    napi_value recv = nullptr;
    napi_value callFuncRet = nullptr;
    napi_get_undefined(env, &recv);
    napi_call_function(env, recv, func, ARGS_SIZE_TWO, param, &callFuncRet);
}

static void CredMgrPromiseResult(napi_env env, BatchUpdateCredsCtx *ctx, napi_value result)
{
    if (ctx->errCode == IS_SUCCESS) {
        napi_resolve_deferred(env, ctx->deferred, result);
    } else {
        napi_reject_deferred(env, ctx->deferred, GenerateErrorMsg(env, ctx->errCode, ctx->errMsg));
    }
}

static void CredMgrAsyncWorkReturn(napi_env env, napi_status status, void *data)
{
    BatchUpdateCredsCtx *ctx = static_cast<BatchUpdateCredsCtx *>(data);
    napi_value result = nullptr;
    napi_create_string_utf8(env, ctx->returnData, NAPI_AUTO_LENGTH, &result);
    if (ctx->asyncType == ASYNC_CALLBACK) {
        CredMgrCallbackResult(env, ctx, result);
    } else {
        CredMgrPromiseResult(env, ctx, result);
    }
    FreeBatchUpdateCredsCtx(env, ctx); // only free here, normal no need free
}

static napi_value BatchUpdateCredsAsyncWork(napi_env env, BatchUpdateCredsCtx *ctx)
{
    napi_value resourceName = nullptr;
    napi_create_string_utf8(env, "batchUpdateCredentials", NAPI_AUTO_LENGTH, &resourceName);

    napi_create_async_work(
        env,
        nullptr,
        resourceName,
        [](napi_env env, void *data) {
            AsyncBatchUpdateCredsProcess(env, data);
            return;
        },
        [](napi_env env, napi_status status, void *data) {
            CredMgrAsyncWorkReturn(env, status, data);
            return;
        },
        static_cast<void *>(ctx),
        &ctx->asyncWork);
    napi_queue_async_work(env, ctx->asyncWork);
    if (ctx->asyncType == ASYNC_PROMISE) {
        return ctx->promise;
    }
    return NapiGetNull(env);
}

napi_value NapiCredManager::NapiBatchUpdateCreds(napi_env env, napi_callback_info info)
{
    BatchUpdateCredsCtx *ctx =
        static_cast<BatchUpdateCredsCtx *>(HcMalloc(sizeof(BatchUpdateCredsCtx), 0));
    if (ctx == nullptr) {
        LOGE("HcMalloc BatchUpdateCredsCtx failed");
        napi_throw(env, GenerateErrorMsg(env, IS_ERR_ALLOC_MEMORY, "HcMalloc BatchUpdateCredsCtx failed"));
        return nullptr;
    }
    if (!BuildCtxForBatchUpdateCreds(env, info, ctx)) {
        LOGE("BuildCtxForBatchUpdateCreds failed");
        napi_throw(env, GenerateErrorMsg(env, IS_ERR_INVALID_PARAMS, "BuildCtxForBatchUpdateCreds failed"));
        FreeBatchUpdateCredsCtx(env, ctx);
        return nullptr;
    }
    napi_value result = BatchUpdateCredsAsyncWork(env, ctx);
    if (result == nullptr) {
        LOGE("BatchUpdateCredsAsyncWork failed");
        napi_throw(env, GenerateErrorMsg(env, IS_ERR_INVALID_PARAMS, "BatchUpdateCredsAsyncWork failed"));
        FreeBatchUpdateCredsCtx(env, ctx);
        return nullptr;
    }
    return result;
}

void NapiCredManager::CredMgrNapiRegister(napi_env env, napi_value exports)
{
    napi_property_descriptor desc[] = {
        DECLARE_NAPI_FUNCTION("getCredMgrInstance", NapiCredManager::NapiGetCredMgrInstance),
    };
    napi_define_properties(env, exports, sizeof(desc) / sizeof(desc[0]), desc);

    napi_property_descriptor funcDesc[] = {
        DECLARE_NAPI_FUNCTION("batchUpdateCredentials", NapiCredManager::NapiBatchUpdateCreds),
    };

    napi_value constructor = nullptr;
    napi_define_class(env, "CredManager", NAPI_AUTO_LENGTH, NapiCredManager::NapiCredMgrConstructor,
        nullptr, sizeof(funcDesc) / sizeof(funcDesc[0]), funcDesc, &constructor);
    napi_create_reference(env, constructor, 1, &classRef_);
}

static napi_value ModuleExport(napi_env env, napi_value exports)
{
    LOGI("device auth napi module export start");
    NapiCredManager::CredMgrNapiRegister(env, exports);
    LOGI("device auth napi module export end");
    return exports;
}

extern "C" __attribute__((constructor)) void RegisterModule(void)
{
    static napi_module credMgrModule = {
        .nm_version = 1,
        .nm_flags = 0,
        .nm_filename = nullptr,
        .nm_register_func = ModuleExport,
        .nm_modname = "security.deviceauth",
        .nm_priv = nullptr,
        .reserved = { nullptr },
    };
    napi_module_register(&credMgrModule);
}

}
}
