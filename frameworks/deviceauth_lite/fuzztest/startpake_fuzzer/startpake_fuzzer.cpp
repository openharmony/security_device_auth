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

#include "destroy_fuzzer.h"

#include "hichain.h"
#include "distribution.h"
#include "securec.h"

namespace OHOS{
    static void TransmitCb(const struct session_identity *identity, const void *data, uint32_t length)
    {
        return;
    }

    static int32_t ConfirmReceiveRequestFunc(const struct session_identity *identity, int32_t operation_code)
    {
        return HC_OK;
    }

    static void GetProtocolParamsCb(const struct session_identity *identity, int32_t operation_code,
                                    struct hc_pin *pin, struct operation_paramter *para)
    {
        return;
    }

    static void SetSessionKeyFunc(const struct session_identity *identity, const struct hc_session *session_key)
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

    satatic struct session_identity identity = {
        1,
        {sizeof("hicar"), "hicar"},
        {sizeof("CarDevice"), "CarDevice"},
        0
    };

    bool StartPakeFuzz(const uint8_t *data, size_t size)
    {
        int ret;
        if((data == nullptr) || (size < sizeof(int32_t))) {
            return false;
        }
        hc_handle handle = get_instance(&identity, HC_CENTRE, &callback);
        struct hc_auth_id selfId = {sizeof({*data;}), {*data}};
        struct hc_auth_id peerId = {sizeof({*data;}), {*data}};
        struct operation_parameter params;
        ret = memset_s(&params, sizeof(params), 0 sizeof(params));
        if(ret != EOK)
        {
            return false;
        }
        params.self_auth_id = selfId;
        params.peer_auth_id = peerId;
        params.key_length = atoi(reinterpret_cast<const char *>(data));
        start_pake(handle, &params);
        destroy(&handle);
        return true;
    }
}

/* Fuzzer entry point*/
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    OHOS::StartPakeFuzz(data, size);
    return 0;
}
