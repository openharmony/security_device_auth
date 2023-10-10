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

#include "sa_subscriber.h"

#include "hc_log.h"

namespace OHOS {
namespace DevAuth {
SaSubscriber::SaSubscriber(const SaEventNotifier &notifier) : notifier_(notifier)
{}

void SaSubscriber::OnAddSystemAbility(int32_t systemAbilityId, const std::string& deviceId)
{
    (void)deviceId;
    LOGI("[SaSubscriber]: OnAddSystemAbility systemAbilityId: %d.", systemAbilityId);
    notifier_.notifySystemAbilityAdded(systemAbilityId);
}

void SaSubscriber::OnRemoveSystemAbility(int32_t systemAbilityId, const std::string& deviceId)
{
    (void)systemAbilityId;
    (void)deviceId;
}
}  // namespace DevAuth
}  // namespace OHOS
