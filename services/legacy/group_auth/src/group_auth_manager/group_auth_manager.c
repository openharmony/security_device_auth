/*
 * Copyright (C) 2022-2023 Huawei Device Co., Ltd.
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

#include "group_auth_manager.h"
#include "common_defs.h"
#include "hc_dev_info.h"
#include "hc_log.h"
#include "hc_string.h"
#include "hc_types.h"
#include "compatible_auth_sub_session_util.h"
#include "account_related_group_auth.h"
#include "account_unrelated_group_auth.h"

static BaseGroupAuth *GetAccountGroupAuth(int32_t groupAuthType)
{
    switch (groupAuthType) {
        case ACCOUNT_UNRELATED_GROUP_AUTH_TYPE:
            LOGI("Non-account auth type.");
            return GetAccountUnrelatedGroupAuth();
        case ACCOUNT_RELATED_GROUP_AUTH_TYPE:
            LOGI("Account-related auth type.");
            return GetAccountRelatedGroupAuth();
        default:
            LOGE("Invalid auth type!");
    }
    return NULL;
}

int32_t InitGroupAuthManager(void)
{
    RegisterGroupAuth(GetAccountGroupAuth);
    LOGI("[GroupAuthManager]: Init success!");
    return HC_SUCCESS;
}
