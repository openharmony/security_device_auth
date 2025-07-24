/*
 * Copyright (C) 2024-2024 Huawei Device Co., Ltd.
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

#ifndef DEVICE_AUTH_SA_H
#define DEVICE_AUTH_SA_H

#include <atomic>
#include "system_ability.h"
#include "iremote_broker.h"
#include "iremote_stub.h"
#include "nocopyable.h"

#include "ipc_dev_auth_stub.h"

namespace OHOS {

constexpr int SA_ID_DEVAUTH_SERVICE = 4701;

class DeviceAuthAbility : public SystemAbility, public ServiceDevAuth {
    DECLARE_SYSTEM_ABILITY(DeviceAuthAbility);

public:
    DISALLOW_COPY_AND_MOVE(DeviceAuthAbility);
    DeviceAuthAbility(int saId, bool runOnCreate);
    virtual ~DeviceAuthAbility();

    int32_t Dump(int32_t fd, const std::vector<std::u16string> &args) override;
    int32_t OnRemoteRequest(uint32_t code, MessageParcel &data,
        MessageParcel &reply, MessageOption &option) override;

    static sptr<DeviceAuthAbility> GetInstance();
    static void DestroyInstance();

protected:
    void OnStart() override;
    void OnStop() override;
    void OnActive(const SystemAbilityOnDemandReason &activeReason) override;
    int32_t OnIdle(const SystemAbilityOnDemandReason &idleReason) override;
    void OnAddSystemAbility(int32_t systemAbilityId, const std::string &deviceId) override;
    void OnRemoveSystemAbility(int32_t systemAbilityId, const std::string &deviceId) override;

private:
    DeviceAuthAbility();
    std::mutex instanceMutex_;
    bool isUnloading_{false};
};

} // namespace OHOS

#endif