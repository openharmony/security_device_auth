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

#include "getrelatedgroups_fuzzer.h"
#include <fuzzer/FuzzedDataProvider.h>

namespace OHOS {
    bool FuzzDoGetRelatedGroups(const uint8_t* data, size_t size)
    {
        const DeviceGroupManager *gmInstance = GetGmInstance();
        if (gmInstance == nullptr) {
            return false;
        }
        if (data == nullptr) {
            return false;
        }
        if (size < sizeof(int32_t)) {
            return false;
        }
        FuzzedDataProvider fdp(data, size);
        const int32_t osAccountId = fdp.ConsumeIntegral<int32_t>();
        std::string appId(fdp.ConsumeBytesAsString(size));
        std::string peerDeviceId(fdp.ConsumeBytesAsString(size));
        char *outGroups = nullptr;
        uint32_t groupNum = 0;
        gmInstance->getRelatedGroups(osAccountId, appId.c_str(), peerDeviceId.c_str(), &outGroups, &groupNum);
        return true;
    }
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    OHOS::FuzzDoGetRelatedGroups(data, size);
    return 0;
}

