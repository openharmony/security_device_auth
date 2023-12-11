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

#include "registelog_fuzzer.h"

#include "hichain.h"
#include "distribution.h"
#include "securec.h"
#include "log.h"

namespace OHOS {
    const int32_t MAX_LOG_BUFF_LENGTH = 1024;
    void TestLogd(const char *tag, const char *funcName, const char *format, ...)
    {
        va_list ap;
        char logBuff[MAX_LOG_BUFF_LENGTH];
        va_start(ap, format);
        if (vsnprintf_s(logBuff, MAX_LOG_BUFF_LENGTH, MAX_LOG_BUFF_LENGTH - 1, format, ap) == -1) {
            va_end(ap);
            return;
        }
    }

    bool RegisteLogFuzz(const uint8_t *data, size_t size)
    {
        struct log_func_group logFunc = {
            TestLogd,
            TestLogd,
            TestLogd,
            TestLogd,
        };
        registe_log(&logFunc);
        return true;
    }
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    OHOS::RegisteLogFuzz(data, size);
    return 0;
}
