/*
 * Copyright (C) 2025 Huawei Device Co., Ltd.
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

#include "cache_common_event_handler.h"
#include "iservice_registry.h"
#include "system_ability_definition.h"
#include "matching_skills.h"
#include "common_event_manager.h"
#include "common_event_support.h"
#include "hc_log.h"
#include <vector>
#include "system_ability_ondemand_reason.h"
#include "os_account_adapter.h"
#include "account_task_manager.h"
#include "json_utils.h"
#include "string_util.h"
#include "common_defs.h"

static const std::string COMMON_EVENT_ACTION_NAME = "common_event_action_name";

static void HandleCacheCommonEventInner(const char *eventName, int32_t eventCode)
{
    CJson *cmdParamJson = CreateJson();
    if (cmdParamJson == nullptr) {
        LOGE("[CacheCommonEvent]: Failed to create cmd params json.");
        return;
    }
    if (AddStringToJson(cmdParamJson, FIELD_COMMON_EVENT_NAME, eventName)
        != HC_SUCCESS) {
        LOGE("[CacheCommonEvent]: Failed to add common event name to json.");
        FreeJson(cmdParamJson);
        return;
    }
    if (AddIntToJson(cmdParamJson, FIELD_COMMON_EVENT_CODE, eventCode) != HC_SUCCESS) {
        LOGE("[CacheCommonEvent]: Failed to add common event code to json.");
        FreeJson(cmdParamJson);
        return;
    }
    LOGI("[CacheCommonEvent]: start handle common event.");
    int32_t res = ExecuteAccountAuthCmd(DEFAULT_OS_ACCOUNT, HANDLE_COMMON_EVENT, cmdParamJson, nullptr);
    FreeJson(cmdParamJson);
    LOGI("[CacheCommonEvent]: handle common event res: %" LOG_PUB "d.", res);
}

static int32_t GetOsAccountFromExtraData(const OHOS::OnDemandReasonExtraData* extraData, const std::string& eventType,
    const std::map<std::string, std::string>& want)
{
    if ((eventType != OHOS::EventFwk::CommonEventSupport::COMMON_EVENT_DISTRIBUTED_ACCOUNT_LOGIN) &&
        (eventType != OHOS::EventFwk::CommonEventSupport::COMMON_EVENT_DISTRIBUTED_ACCOUNT_LOGOUT)) {
        return extraData->GetCode();
    }
    auto it = want.find(FIELD_USER_ID);
    if (it == want.end()) {
        LOGE("extract userId failed!");
        return DEFAULT_OS_ACCOUNT;
    }
    int32_t osAccountId = static_cast<int32_t>(StringToInt64(it->second.c_str()));
    LOGI("[CacheCommonEvent]: OsAccountId:%" LOG_PUB "d", osAccountId);
    return osAccountId;
}

void HandleCacheCommonEvent(void)
{
    auto saMgr = OHOS::SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (saMgr == nullptr) {
        LOGE("[CacheCommonEvent]: system ability manager is null!");
        return;
    }
    std::vector<int64_t> extraDataIdList;
    int32_t ret = saMgr->GetCommonEventExtraDataIdlist(OHOS::DEVICE_AUTH_SERVICE_ID, extraDataIdList);
    if (ret != OHOS::ERR_OK) {
        LOGE("GetCommonEventExtraDataIdlist failed ret is %" LOG_PUB "d.", ret);
        return;
    }
    for (auto &item : extraDataIdList) {
        OHOS::MessageParcel extraDataParcel;
        ret = saMgr->GetOnDemandReasonExtraData(item, extraDataParcel);
        if (ret != OHOS::ERR_OK) {
            LOGE("get extra data failed.");
            continue;
        }
        auto extraData = extraDataParcel.ReadParcelable<OHOS::OnDemandReasonExtraData>();
        if (extraData == nullptr) {
            LOGE("get extra data read parcel failed.");
            continue;
        }
        LOGI("code: %" LOG_PUB "d, data: %" LOG_PUB "s", extraData->GetCode(), extraData->GetData().c_str());
        auto want = extraData->GetWant();
        auto it = want.find(COMMON_EVENT_ACTION_NAME);
        if (it == want.end()) {
            LOGW("common event not found.");
            delete extraData;
            continue;
        }
        int32_t osAccountId = GetOsAccountFromExtraData(extraData, it->second, want);
        LOGI("common event name: %" LOG_PUB "s.", it->second.c_str());
        if (it->second == OHOS::EventFwk::CommonEventSupport::COMMON_EVENT_USER_UNLOCKED) {
            LOGI("[CacheCommonEvent]: user unlocked, userId %" LOG_PUB "d.", osAccountId);
            NotifyOsAccountUnlocked(osAccountId);
        } else if (it->second == OHOS::EventFwk::CommonEventSupport::COMMON_EVENT_USER_REMOVED) {
            LOGI("[CacheCommonEvent]: user removed, userId %" LOG_PUB "d.", osAccountId);
            NotifyOsAccountRemoved(osAccountId);
        } else {
            LOGI("[CacheCommonEvent]: receive other event.");
        }
        HandleCacheCommonEventInner(it->second.c_str(), osAccountId);
        delete extraData;
    }
}