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

#include "account_subscriber.h"

#include "account_task_manager.h"
#include "common_defs.h"
#include "common_event_support.h"
#include "device_auth.h"
#include "hc_log.h"
#include "json_utils.h"
#include "want.h"

namespace OHOS {
namespace DevAuth {
AccountSubscriber::AccountSubscriber(const EventFwk::CommonEventSubscribeInfo &subscriberInfo,
    const OsAccountEventNotifier &notifier)
    : EventFwk::CommonEventSubscriber(subscriberInfo), notifier_(notifier)
{}

void AccountSubscriber::OnReceiveEvent(const EventFwk::CommonEventData &eventData)
{
    const OHOS::AAFwk::Want& want = eventData.GetWant();
    std::string action = want.GetAction();
    LOGI("[AccountSubscriber]: OnReceiveEvent action: %" LOG_PUB "s.", action.c_str());

    if (action == EventFwk::CommonEventSupport::COMMON_EVENT_USER_UNLOCKED) {
        LOGI("[AccountSubscriber]: user unlocked, userId: %" LOG_PUB "d.", eventData.GetCode());
        notifier_.notifyOsAccountUnlocked(eventData.GetCode());
    } else if (action == EventFwk::CommonEventSupport::COMMON_EVENT_USER_REMOVED) {
        LOGI("[AccountSubscriber]: user removed, userId: %" LOG_PUB "d.", eventData.GetCode());
        notifier_.notifyOsAccountRemoved(eventData.GetCode());
    } else {
        LOGI("[AccountSubscriber]: receive other event.");
    }
    CJson *cmdParamJson = CreateJson();
    if (cmdParamJson == nullptr) {
        LOGE("[AccountSubscriber]: Failed to create cmd params json!");
        return;
    }
    if (AddStringToJson(cmdParamJson, FIELD_COMMON_EVENT_NAME, action.c_str()) != HC_SUCCESS) {
        LOGE("[AccountSubscriber]: Failed to add common event name to json!");
        FreeJson(cmdParamJson);
        return;
    }
    if (AddIntToJson(cmdParamJson, FIELD_COMMON_EVENT_CODE, eventData.GetCode()) != HC_SUCCESS) {
        LOGE("[AccountSubscriber]: Failed to add common event code to json!");
        FreeJson(cmdParamJson);
        return;
    }
    int32_t res = ExecuteAccountAuthCmd(DEFAULT_OS_ACCOUNT, HANDLE_COMMON_EVENT, cmdParamJson, nullptr);
    FreeJson(cmdParamJson);
    LOGI("[AccountSubscriber]: handle common event res: %" LOG_PUB "d", res);
}
}  // namespace DevAuth
}  // namespace OHOS
