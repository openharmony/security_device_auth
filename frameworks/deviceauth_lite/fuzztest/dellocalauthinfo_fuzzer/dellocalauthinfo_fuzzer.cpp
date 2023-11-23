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

#include "dellocalauthinfo_fuzzer.h"

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

    static struct session_identity identity = {
        1,
        {sizeof("hicar"), "hicar"},
        {sizeof("CarDevice"), "CarDevice"},
        0
    };

    bool DelLocalaAuthInfoFuzz(const uint8_t *data, size_t size)
    {
        if ((data == nullptr) || (size < sizeof(uint8_t))) {
            return false;
        }
        hc_handle handle = get_instance(&identity, HC_CENTRE, &callback);
        hc_auth_id authId;
        if (memset_s(&authId, sizeof(authId), 0, sizeof(authId)) != EOK) {
            return false;
        }
        authId.length = size > HC_AUTH_ID_BUFF_LEN ? HC_AUTH_ID_BUFF_LEN : size;
        if (memcpy_s(authId.auth_id, HC_AUTH_ID_BUFF_LEN, data, authId.length) != EOK) {
            return false;
        }
        hc_user_info userInfo = {authId, 1};
        delete_local_auth_info(handle, &userInfo);
        destroy(&handle);
        return true;
    }
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    OHOS::DelLocalaAuthInfoFuzz(data, size);
    return 0;
}
