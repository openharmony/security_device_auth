/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#include "getpseudonymid_fuzzer.h"
#include <fuzzer/FuzzedDataProvider.h>

namespace OHOS {
    bool FuzzDoGetPseudonymId(const uint8_t* data, size_t size)
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
        const int32_t osAccountId = fdp.ConsumeIntegral<int32_t>();
        std::string indexKey(fdp.ConsumeBytesAsString(size));
        char *pseudonymId = nullptr;
        gaInstance->getPseudonymId(osAccountId, indexKey.c_str(), &pseudonymId);
        if (pseudonymId != nullptr) {
            free(pseudonymId);
        }
        return true;
    }
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    OHOS::FuzzDoGetPseudonymId(data, size);
    return 0;
}

