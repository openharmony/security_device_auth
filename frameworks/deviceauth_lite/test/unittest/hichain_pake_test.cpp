/*
 * Copyright (C) 2021 Huawei Device Co., Ltd.
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
#include <cstdint>
#include <cstdlib>
#include "gtest/gtest.h"
#include "gmock/gmock.h"
#include "securec.h"
#include "hichain.h"
#include "huks_adapter.h"
#include "distribution.h"
#include "auth_info.h"


#define LOG(format, ...) (printf(format"\n", ##__VA_ARGS__))

using namespace std;
using namespace testing::ext;

namespace {
const int KEY_LEN = 16;
const int AUTH_ID_LENGTH = 64;

static struct session_identity g_server_identity = {
    153666603,
    {strlen("aaa.bbbb.ccc"), "aaa.bbbb.ccc"},
    {strlen("CarDevice"), "CarDevice"},
    0
};


static struct hc_pin g_test_pin = {strlen("123456"), "123456"};

static struct hc_auth_id g_test_client_auth_id;
static struct hc_auth_id g_test_server_auth_id;

static int32_t g_result;

uint8_t g_testPhoneId[65] = {"14bb6543b893a3250f5793fbbbd48be56641505dc6514be1bb37b032903ebc67"};
uint8_t g_testCarId[65] = {"d37cd7ceb894f4393a299ef852b4fc35a1a0d77c48a5b3e0b2599ab1d69b23a6"};

void InitHcAuthId()
{
    memcpy_s(g_test_client_auth_id.auth_id, AUTH_ID_LENGTH, g_testPhoneId, AUTH_ID_LENGTH);
    g_test_client_auth_id.length = AUTH_ID_LENGTH;

    memcpy_s(g_test_server_auth_id.auth_id, AUTH_ID_LENGTH, g_testCarId, AUTH_ID_LENGTH);
    g_test_server_auth_id.length = AUTH_ID_LENGTH;
    return ;
}

static void Transmit(const struct session_identity *identity, const void *data, uint32_t length)
{
    LOG("--------Transmit--------");
    LOG("identity session_id[%d] package_name[%s]", identity->session_id, identity->package_name.name);
    LOG("length[%u]", length);
    LOG("--------Transmit--------");
}

static void GetProtocolParams(const struct session_identity *identity, int32_t operationCode,
    struct hc_pin *pin, struct operation_parameter *para)
{
    LOG("--------GetProtocolParams--------");
    LOG("identity session_id[%d] package_name[%s]", identity->session_id, identity->package_name.name);
    LOG("operationCode[%d]", operationCode);
    pin->length = g_test_pin.length;
    memcpy_s(pin->pin, pin->length, g_test_pin.pin, pin->length);
    para->self_auth_id = g_test_server_auth_id;
    para->peer_auth_id = g_test_client_auth_id;
    para->key_length = KEY_LEN;
    LOG("--------GetProtocolParams--------");
}

static void SetSessionKey(const struct session_identity *identity, const struct hc_session_key *sessionKey)
{
    LOG("--------SetSessionKey--------");
    LOG("identity session_id[%d] package_name[%s]", identity->session_id, identity->package_name.name);
    LOG("sessionKey[%s]", sessionKey->session_key);
    LOG("--------SetSessionKey--------");
}

static void SetServiceResult(const struct session_identity *identity, int32_t result)
{
    LOG("--------SetServiceResult--------");
    LOG("identity session_id[%d] package_name[%s]", identity->session_id, identity->package_name.name);
    LOG("result[%d]", result);
    LOG("--------SetServiceResult--------");
    g_result = result;
}

static int32_t ConfirmReceiveRequest(const struct session_identity *identity, int32_t operationCode)
{
    LOG("--------ConfirmReceiveRequest--------");
    LOG("identity session_id[%d] package_name[%s]", identity->session_id, identity->package_name.name);
    LOG("operationCode[%d]", operationCode);
    LOG("--------ConfirmReceiveRequest--------");
    return HC_OK;
}

class HichainPakeTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void HichainPakeTest::SetUpTestCase(void) {}
void HichainPakeTest::TearDownTestCase(void) {}
void HichainPakeTest::SetUp()
{
    InitHcAuthId();
}
void HichainPakeTest::TearDown() {}

uint8_t g_dataStr011[] = {"{\"message\":32769,\"payload\":{\"version\":"
    "{\"currentVersion\":\"1.0.0\",\"minVersion\":\"1.0.0\"},"
	"\"challenge\":\"76539E5634EDA735A94845C3A4F356D6\","
	"\"salt\":\"025E4B3B2DD3B0E67395C760008A9154\","
	"\"epk\":\"24EBF8D727B19E8A43B20D22F744113C8B49B226D834B2E3C9CB5B0378732D6CF7C658BFB468682A6762"
    "2D5FE061F4D8102E4D8912377AA785919C529F0C1289F2188E641C6DC626054FC30304DC804FD9F059F5F5D8CEAA29"
    "A44814F10CC2A770C5BEB0BE86559E4FA85AD6E480DC2A627F5B28626E23B613EAC21101FF1C1DDA76E35A67A5A70B"
    "C24ECFD0C92F4F69A5B73FD67BE3EFC0904709BEC26490E21A4A04E29211DF393559B4A71F7368B68F529806DB90C5"
    "8315EDFF0A1738E26E82A54D2030A5B9B270DCF01A2377300135C55B3F6B273CF157246D0DF928D6E3E2886E79ECEB"
    "F69F98806C37A6128E4E93C9C43DD01B53963458AF60FA1C0E497F5FD4E807DA4F804EE145967D74792AD9B135C2F3"
    "A25FAA3427B3666C9D30539F008915A53D1FE2E2DDDCFCFD0815976332575F9EDBC9F4946A83116C7A29C38AC1A5FD"
    "8E5B894DCB4A1A29672D2647D6C734D4EA74E4A077D3403CAD0CA15318D9560FFF163D71B2991D70148F97CD524244"
    "7DF2B23C856D734CDD39220EC0\"}}"};

uint8_t g_dataStr012[] = {"{\"message\":32770,\"payload\":{"
    "\"kcfData\":\"463853720FFFC312084B9FF288E17"
    "C3F3D8B9D8F2A609D349CAA712AAD926C26\"}}"};

uint8_t g_dataStr013[] = {"{\"message\":32771,\"payload\":{\"exAuthInfo\":\"63B2AC76C0645224DA7E395DBCC29D9F"
                        "9AF5E0ABEEC94048962F838D12C501B22193E1B2AD43A7D9443A80EA92C4BD4F53B14C867DD00308167CB2803754"
                        "D4A909C0666B231C17736E0C5BE5A21746BE53AF0E72BE30DC56D56752823D9453F025DD3A56904EDBF54FB16667"
                        "82623DDF7BA29A1FA3CFE34864D4AF958EA616785AB7F06DBC01675ADB19EB12D8CA5CF312AEECE9016CA92BC9A2"
                        "69FE9BA2C579C7EA69F34855FDF689B3153BBFF618464612C6CC8984167842316A7E6E38813CC901DFBE4BA0767C"
                        "914B03AD0CF221BC319860A018078F74454DE18B0A144F812A3560D1A3223084A0BE48F737B49840A331B037CC13"
                        "DF82BFC85C1B95890907972897B827C237071A8D706CE41F9E8B045E3FDD9850BEBB50BFA84721B6E64A23557D0F"
                        "572B33D18FD8DE25C0B6C57F35AB9931EE02\"}}"};

static HWTEST_F(HichainPakeTest, ReceiveDataTest001, TestSize.Level2)
{
    struct hc_call_back callBack = {
        Transmit,
        GetProtocolParams,
        SetSessionKey,
        SetServiceResult,
        ConfirmReceiveRequest
    };

    const struct operation_parameter params = {g_test_server_auth_id, g_test_client_auth_id, KEY_LEN};
    hc_handle server = get_instance(&g_server_identity, HC_CENTRE, &callBack);
    ASSERT_TRUE(server != nullptr);
    int32_t ret = start_pake(server, &params);
    EXPECT_EQ(ret, HC_OK);
    struct uint8_buff data001 = {
        g_dataStr011,
        sizeof(g_dataStr011),
        strlen(reinterpret_cast<char *>(g_dataStr011))
    };
    ret = receive_data(server, &data001);
    EXPECT_EQ(ret, HC_OK);
    EXPECT_EQ(g_result, KEY_AGREEMENT_PROCESSING);
    struct uint8_buff data002 = {
        g_dataStr012,
        sizeof(g_dataStr012),
        strlen(reinterpret_cast<char *>(g_dataStr012))
    };
    ret = receive_data(server, &data002);
    EXPECT_EQ(ret, HC_OK);
    struct uint8_buff data003 = {
        g_dataStr013,
        sizeof(g_dataStr013),
        strlen(reinterpret_cast<char *>(g_dataStr013))
    };
    ret = receive_data(server, &data003);
    EXPECT_EQ(ret, HC_OK);
    EXPECT_EQ(g_result, END_SUCCESS);
    destroy(&server);
}

class HichainStructTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void HichainStructTest::SetUpTestCase(void) {}
void HichainStructTest::TearDownTestCase(void) {}
void HichainStructTest::SetUp() {}
void HichainStructTest::TearDown() {}

static HWTEST_F(HichainStructTest, free_auth_start_request_test001, TestSize.Level2)
{
    void *obj = nullptr;
    free_auth_start_request(obj);
    obj = static_cast<void*>(MALLOC(sizeof(char)));
    free_auth_start_request(obj);
    obj = nullptr;
    EXPECT_EQ(obj, nullptr);
}


static HWTEST_F(HichainStructTest, free_exchange_request_test001, TestSize.Level2)
{
    void *obj = nullptr;
    free_exchange_request(obj);
    exchange_request_data *data = static_cast<exchange_request_data *>(MALLOC(sizeof(exchange_request_data)));
    (void)memset_s(data, sizeof(*data), 0, sizeof(*data));
    free_exchange_request(data);
    data = nullptr;
    EXPECT_EQ(data, nullptr);
}


static HWTEST_F(HichainStructTest, parse_header_test001, TestSize.Level2)
{
    std::string data_str = "{\"message\":1,\"payload\":{\"version\":{\"currentVersion\":\"1.0.0\","
        "\"minVersion\":\"1.0.0\"},\"support256mod\":true,\"operationCode\":1}}";
    int32_t ret = parse_header(data_str.c_str());
    EXPECT_EQ(ret, 1);
}

static HWTEST_F(HichainStructTest, parse_header_test002, TestSize.Level2)
{
    int32_t ret = parse_header(nullptr);
    EXPECT_EQ(ret, -1);
}


static HWTEST_F(HichainStructTest, parse_payload_test001, TestSize.Level2)
{
    std::string data_str = "{\"payload\":{\"support256mod\":true,\"operationCode\":1}}";
    void *ret = parse_payload(data_str.c_str(), JSON_OBJECT_DATA);
    EXPECT_NE(ret, nullptr);
}
}