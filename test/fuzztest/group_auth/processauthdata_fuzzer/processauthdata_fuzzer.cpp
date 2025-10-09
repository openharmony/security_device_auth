/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#include "processauthdata_fuzzer.h"
#include <fuzzer/FuzzedDataProvider.h>

namespace OHOS {
    void OnError(int64_t requestId, int operationCode, int errorCode, const char *errorReturn)
    {
        (void)requestId;
        (void)operationCode;
        (void)errorCode;
        (void)errorReturn;
    }

    void OnFinish(int64_t requestId, int operationCode, const char *authReturn)
    {
        (void)requestId;
        (void)operationCode;
        (void)authReturn;
    }

    void OnSessionKeyReturned(int64_t requestId, const uint8_t *sessionKey, uint32_t sessionKeyLen)
    {
        (void)requestId;
        (void)sessionKey;
        (void)sessionKeyLen;
    }

    bool OnTransmit(int64_t requestId, const uint8_t *data, uint32_t dataLen)
    {
        (void)requestId;
        (void)data;
        (void)dataLen;
        return true;
    }

    char *OnRequest(int64_t requestId, int operationCode, const char* reqParam)
    {
        (void)requestId;
        (void)operationCode;
        (void)reqParam;
        return nullptr;
    }

    bool FuzzDoProcessData(const uint8_t* data, size_t size)
    {
        const GroupAuthManager *gaInstance = GetGaInstance();
        if (gaInstance == nullptr) {
            return false;
        }
        if (data == nullptr) {
            return false;
        }
        if (size < sizeof(int64_t)) {
            return false;
        }
        FuzzedDataProvider fdp(data, size);
        const int64_t authReqId = fdp.ConsumeIntegral<int64_t>();
        DeviceAuthCallback gaCallback;
        gaCallback.onError = OnError;
        gaCallback.onFinish = OnFinish;
        gaCallback.onSessionKeyReturned = OnSessionKeyReturned;
        gaCallback.onTransmit = OnTransmit;
        gaCallback.onRequest = OnRequest;
        gaInstance->processData(authReqId, data, (uint32_t)size, &gaCallback);
        return true;
    }
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    OHOS::FuzzDoProcessData(data, size);
    return 0;
}

