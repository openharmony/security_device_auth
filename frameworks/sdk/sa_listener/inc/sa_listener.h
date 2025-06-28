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
#ifndef SA_LISTENER_H
#define SA_LISTENER_H

#include "system_ability_status_change_stub.h"
#include "ipc_sdk_defines.h"

namespace OHOS {
namespace DevAuth {

class SaListener : public SystemAbilityStatusChangeStub {
public:
    SaListener(SaStatusChangeCallback act);
    ~SaListener() = default;
    void OnAddSystemAbility(int32_t systemAbilityId, const std::string &deviceId) override;
    void OnRemoveSystemAbility(int32_t systemAbilityId, const std::string &deviceId) override;

private:
    SaStatusChangeCallback act_;
};

}  // namespace DevAuth
}  // namespace OHOS
#endif // SA_LISTENER_H