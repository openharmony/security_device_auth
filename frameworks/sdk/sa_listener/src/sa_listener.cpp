/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include "sa_listener.h"

#include "hc_log.h"

namespace OHOS {
namespace DevAuth {
SaListener::SaListener(SaStatusChangeCallback act) : act_(act)
{}

void SaListener::OnAddSystemAbility(int32_t systemAbilityId, const std::string &deviceId)
{
    (void)deviceId;
    LOGI("[SystemAbilityStatusChangeListener]: OnAddSystemAbility systemAbilityId: %" LOG_PUB "d.", systemAbilityId);
    act_.onReceivedSaAdd();
}

void SaListener::OnRemoveSystemAbility(int32_t systemAbilityId, const std::string &deviceId)
{
    (void)deviceId;
    LOGI("[SystemAbilityStatusChangeListener]: OnRemoveSystemAbility systemAbilityId: %" LOG_PUB "d.", systemAbilityId);
    act_.onReceivedSaRemoved();
}
}  // namespace DevAuth
}  // namespace OHOS
