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

#include "receivedata_fuzzer.h"

#include "hichain.h"
#include "distribution.h"
#include "securec.h"
#include "parsedata.h"
#include "key_agreement_version.h"

using namespace std;

namespace OHOS {
enum Branch {
    PAKE_REQUEST = 1,
    PAKE_CLIENT_CONFIRM = 2,
    AUTH_START_REQUEST = 3,
    PAKE_ACK_REQUEST = 4,
    EXCHANGE_REQUEST = 5,
};

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

static void SetSessionKeyFunc(const struct session_identity *identity,
                              const struct hc_session_key *sessionKey)
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

uint8_t g_retStr1[] = "{\"message\":1,\"payload\":{\"version\":{\"currentVersion\":\"1.0.0\","
    "\"minVersion\":\"1.0.0\"},\"support256mod\":\"true\","
    "\"operationCode\":\"1\",}}";

uint8_t g_retStr2[] = "{\"message\":3,\"payload\":{\"kcfData\":\"463853720FFFC312084B9FF288E17C3F3D8B9D8F2A"
    "609D349CAA712AAD926C26\",\"challenge\":\"76539E5634EDA735A94845C3A4F356D6\","
    "\"epk\":\"24EBF8D727B19E8A43B20D22F744113CB49B226D834B2E3C9CB5B0378732D6CF7C658BFB468682A6762"
    "2D5FE061F4D8102E4D8912377AA785919C529F0C1289F2100E641C6DC626054FC30304DC804FD9F059F5F5D8CEAA29"
    "A44814F10CC2A770C5BEB0BE86559E4FA85AD6E480DC2A627F5B28626E23B613EAC21101FF1C1DDA76E35A67A5A70B\"}}";


uint8_t g_retStr3[] = "{\"authForm\":0,\"message\":17,\"payload\":{\"authData\":\"4A4EB66225"
    "24CBBF7DC96412A82BF4CB6022F50226A201DB3B3C55\",\"challenge\":\"A1714848785F27C22B31\","
    "\"epk\":\"493CB95DB80320360BE5A3E3000E3E8E67371D6DCC"
    "57D1F97937ABABC219\",\"operationCode\":\"1\",\"version\":{\"currentVersion\":"
    "\"1.0.0\",\"minVersion\":\"1.0.0\"},\"peerAuthId\":\"6B5A16BFA24C941F4C1B094D"
    "6F2FA8DC8A45\",\"peerUserType\":\"0\"}}";

uint8_t g_retStr4[] = "{\"authForm\":0,\"message\":18,\"payload\":{\"authData\":\"4A4EB6622524CBBF7DC96412A82BF4CB6022"
    "F50226A201DB3B3C55\"}}";

uint8_t g_retStr5[] = "{\"message\":3,\"payload\":{\"exAuthInfo\":}}";

uint8_t g_retStr6[] = "{\"message\":32786,\"payload\":{\"errorCode\":17}}";

bool ReceiveDataFuzz(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size < sizeof(int32_t))) {
        return false;
    }
    hc_handle handle = get_instance(&identity, HC_CENTRE, &callback);
    int ver = *reinterpret_cast<const int *>(data);
    int temp = ver % 6; /* 6 : total branch */
    struct uint8_buff buff;
    switch (temp) {
        case PAKE_REQUEST:
            buff.val = g_retStr1;
            buff.size = sizeof(g_retStr1);
            buff.length = sizeof(g_retStr1);
            break;
        case PAKE_CLIENT_CONFIRM:
            buff.val = g_retStr2;
            buff.size = sizeof(g_retStr2);
            buff.length = sizeof(g_retStr2);
            break;
        case AUTH_START_REQUEST:
            buff.val = g_retStr3;
            buff.size = sizeof(g_retStr3);
            buff.length = sizeof(g_retStr3);
            break;
        case PAKE_ACK_REQUEST:
            buff.val = g_retStr4;
            buff.size = sizeof(g_retStr4);
            buff.length = sizeof(g_retStr4);
            break;
        case EXCHANGE_REQUEST:
            buff.val = g_retStr5;
            buff.size = sizeof(g_retStr5);
            buff.length = sizeof(g_retStr5);
            break;
        default:
            buff.val = g_retStr6;
            buff.size = sizeof(g_retStr6);
            buff.length = sizeof(g_retStr6);
            break;
    };
    receive_data(handle, &buff);
    destroy(&handle);
    return true;
}
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    OHOS::ReceiveDataFuzz(data, size);
    return 0;
}

