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

#include "deletegroup_fuzzer.h"
#include <fuzzer/FuzzedDataProvider.h>

namespace OHOS {
    bool FuzzDoDeleteGroup(const uint8_t* data, size_t size)
    {
        const DeviceGroupManager *gmInstance = GetGmInstance();
        if (gmInstance == nullptr) {
            return false;
        }
        if (data == nullptr) {
            return false;
        }
        if (size < sizeof(int64_t)) {
            return false;
        }
        FuzzedDataProvider fdp(data, size);
        const int32_t osAccountId = fdp.ConsumeIntegral<int32_t>();
        const int64_t requestId = fdp.ConsumeIntegral<int64_t>();
        const int32_t appIdLen = fdp.ConsumeIntegral<int32_t>();
        const int32_t createParamsLen = fdp.ConsumeIntegral<int32_t>();
        std::string appId(fdp.ConsumeBytesAsString(appIdLen));
        std::string deleteParams(fdp.ConsumeBytesAsString(createParamsLen));
        gmInstance->deleteGroup(osAccountId, requestId, appId.c_str(), deleteParams.c_str());
        return true;
    }
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    OHOS::FuzzDoDeleteGroup(data, size);
    return 0;
}

