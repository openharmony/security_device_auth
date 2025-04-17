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

#ifndef CREDMGR_NAPI_H
#define CREDMGR_NAPI_H

#include "device_auth.h"
#include "napi/native_api.h"
#include "napi/native_node_api.h"

namespace OHOS {
namespace CredMgrNapi {

enum AsyncType {
    ASYNC_CALLBACK = 1,
    ASYNC_PROMISE = 2,
};

constexpr size_t ARGS_SIZE_TWO = 2;
constexpr size_t ARGS_SIZE_THREE = 3;
constexpr int32_t PARAM0 = 0;
constexpr int32_t PARAM1 = 1;

class NapiCredManager {
public:
    explicit NapiCredManager(CredManager *manager);
    ~NapiCredManager();

    CredManager *GetCurrentCredMgr();

    static napi_value NapiCredMgrConstructor(napi_env env, napi_callback_info info);
    static napi_value NapiGetCredMgrInstance(napi_env env, napi_callback_info info);
    static napi_value NapiBatchUpdateCreds(napi_env env, napi_callback_info info);

    static void CredMgrNapiRegister(napi_env env, napi_value exports);
    static thread_local napi_ref classRef_;

private:
    CredManager *credManager_ = nullptr;
    static std::mutex g_instanceLock;
};

} // namespace CredMgrNapi
}  // namespace OHOS

#endif