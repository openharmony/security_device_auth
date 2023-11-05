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

#include "listtrustpeer_fuzzer.h"

#include "hichain.h"
#include "distribution.h"
#include "securec.h"

namespace OHOS{
    const unsigned int MAX_LIST_NUM = 20;
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

    static struct session_identity identity = {
        1,
        {sizeof("hicar"), "hicar"},
        {sizeof("CarDevice"), "CarDevice"},
        0
    };

    bool ListTrustPeerFuzz(const uint8_t *data, size_t size)
    {
        int ret;
        hc_handle handle = get_instance(&identity, HC_CENTRE, &callback);
        struct hc_auth_id *peer_authid_list = (struct hc_auth_id *)malloc(MAX_LIST_NUM * sizeof(struct hc_auth_id));
        ret = memset_s(peer_authid_list, MAX_LIST_NUM * sizeof(struct hc_auth_id),
                 0, MAX_LIST_NUM * sizeof(struct hc_auth_id));
        if(ret != EOK)
        {
            return false;
        }
        struct hc_auth_id authId = {sizeof({*data;}), {*data}};
        list_trust_peers(handle, 0, &authId, &peer_authid_list);
        destroy(&handle);
        return true;
    }
}

/* Fuzzer entry point*/
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    OHOS::ListTrustPeerFuzz(data, size);
    return 0;
}











