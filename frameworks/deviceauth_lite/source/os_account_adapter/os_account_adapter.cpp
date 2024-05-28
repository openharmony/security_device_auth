/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#ifdef HAS_OS_ACCOUNT_PART
#include "os_account_manager.h"
#endif

#include "log.h"
#include "hichain.h"
#include "os_account_adapter.h"

#define DEFAULT_USER

int32_t GetFrontUserId(int32_t *userId)
{
#ifdef HAS_OS_ACCOUNT_PART
    std::vector<int32_t> ids;
    int32_t errCode = OHOS::AccountSA::OsAccountManager::QueryActiveOsAccountIds(ids);
    if (!errCode || ids.empty()) {
    LOGE("QueryActiveOsAccountIds failed");
        return HC_INNER_ERROR;
    }
    LOGI("QueryActiveOsAccountIds success");
    *userId = ids[0];
#else
    LOGI("no os account part, set default user");
    *userId = DEFAULT_USER;
#endif
    return errCode;
}