/*
 * Copyright (C) 2024-2025 Huawei Device Co., Ltd.
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

#ifndef NET_OBSERVER_H
#define NET_OBSERVER_H

#include "net_all_capabilities.h"
#include "net_conn_callback_stub.h"
#include "net_specifier.h"

class NetObserver final : public OHOS::NetManagerStandard::NetConnCallbackStub {
public:
    void StartObserver();
    void StopObserver();
    int32_t NetCapabilitiesChange(OHOS::sptr<OHOS::NetManagerStandard::NetHandle> &netHandle,
        const OHOS::sptr<OHOS::NetManagerStandard::NetAllCapabilities> &netAllCap) final;
    int32_t NetLost(OHOS::sptr<OHOS::NetManagerStandard::NetHandle> &netHandle) final;
    int32_t NetAvailable(OHOS::sptr<OHOS::NetManagerStandard::NetHandle> &netHandle) final;

private:
    OHOS::sptr<INetConnCallback> netConnCallback_;
    int32_t HandleNetAllCap(const OHOS::NetManagerStandard::NetAllCapabilities &netAllCap);
};

#endif // NET_OBSERVER_H