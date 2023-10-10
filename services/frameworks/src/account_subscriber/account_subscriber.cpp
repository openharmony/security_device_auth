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

#include "common_event_support.h"
#include "hc_log.h"
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
    int32_t userId = eventData.GetCode();
    LOGI("[AccountSubscriber]: OnReceiveEvent action: %s, userId: %d.", action.c_str(), userId);

    if (action == EventFwk::CommonEventSupport::COMMON_EVENT_USER_UNLOCKED) {
        notifier_.notifyOsAccountUnlocked(userId);
    } else if (action == EventFwk::CommonEventSupport::COMMON_EVENT_USER_REMOVED) {
        notifier_.notifyOsAccountRemoved(userId);
    } else {
        LOGE("[AccountSubscriber]: OnReceiveEvent invalid action!");
    }
}
}  // namespace DevAuth
}  // namespace OHOS
