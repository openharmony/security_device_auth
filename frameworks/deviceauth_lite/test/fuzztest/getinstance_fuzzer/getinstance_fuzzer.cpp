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

#include "getinstance_fuzzer.h"

#include <cstddef>

#include "hichain.h"
#include "distribution.h"
#include "securec.h"

namespace OHOS {
    static void TransmitCb(const struct session_identity *identity, const void *data, uint32_t length)
    {
        return;
    }

    static int32_t ConfirmReceiveRequestFunc(const struct session_identity *identity, int32_t operationCode)
    {
        return HC_OK;
    }

    static void GetProtocolParamsCb(const struct session_identity *identity, int32_t operationCode,
                                    struct hc_pin *pin, struct operation_parameter *para)
    {
        return;
    }

    static void SetSessionKeyFunc(const struct session_identity *identity, const struct hc_session_key *sessionKey)
    {
        return;
    }

    static void SetServiceResultFunc(const struct session_identity *identity, int32_t result)
    {
        return;
    }

    static hc_call_back callback = {
        .transmit = TransmitCb,
        .get_protocol_params = GetProtocolParamsCb,
        .set_session_key = SetSessionKeyFunc,
        .set_service_result = SetServiceResultFunc,
        .confirm_receive_request = ConfirmReceiveRequestFunc,
    };

    bool GetInstanceFuzz(const uint8_t *data, size_t size)
    {
        if ((data == nullptr) || (size < sizeof(int32_t))) {
            return false;
        }
        int32_t sessionId = *reinterpret_cast<const int *>(data);
        hc_package_name package_name = {sizeof("hicar"), "hicar"};
        hc_service_type service_type = {sizeof("CarDevice"), "CarDevice"};
        struct session_identity identity;
        if (memset_s(&identity, sizeof(identity), 0, sizeof(identity)) != EOK) {
            return false;
        }
        identity.session_id = sessionId;
        identity.package_name = package_name;
        identity.service_type = service_type;
        identity.context = 0;
        hc_handle demo = get_instance(&identity, HC_CENTRE, &callback);
        destroy(&demo);
        return true;
    }
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    OHOS::GetInstanceFuzz(data, size);
    return 0;
}
