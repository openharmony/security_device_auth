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
#include "distribution.h"
#include "huks_adapter.h"
#include "log.h"
#include "auth_info_test.h"
#include "commonutil_test.h"
#include "jsonutil_test.h"
#include "cJSON.h"
#include "deviceauth_test.h"

#define LOG(format, ...) (printf(format"\n", ##__VA_ARGS__))

using namespace std;
using namespace testing::ext;
using ::testing::Return;

namespace {
const int KEY_LEN = 16;
const int AUTH_ID_LENGTH = 64;

static struct session_identity g_server_identity = {
    153666603,
    {strlen("aaa.bbbb.ccc"), "aaa.bbbb.ccc"},
    {strlen("CarDevice"), "CarDevice"},
    0
};

static struct hc_pin g_testPin = {strlen("123456"), "123456"};

static struct hc_auth_id g_testClientAuthId;
static struct hc_auth_id g_testServerAuthId;

static int32_t g_result;

uint8_t g_testPhoneId[65] = {"14bb6543b893a3250f5793fbbbd48be56641505dc6514be1bb37b032903ebc67"};
uint8_t g_testCarId[65] = {"14bb6543b893a3250f5793fbbbd48be56641505dc6514be1bb37b032903abcde"};

void InitHcAuthId()
{
    memcpy_s(g_testClientAuthId.auth_id, AUTH_ID_LENGTH, g_testPhoneId, AUTH_ID_LENGTH);
    g_testClientAuthId.length = AUTH_ID_LENGTH;

    memcpy_s(g_testServerAuthId.auth_id, AUTH_ID_LENGTH, g_testCarId, AUTH_ID_LENGTH);
    g_testServerAuthId.length = AUTH_ID_LENGTH;

    return;
}

enum HksErrorCode {
    HKS_SUCCESS = 0,
    HKS_FAILURE = -1,
    HKS_ERROR_INVALID_KEY_FILE = -27,
    HKS_ERROR_UPDATE_ROOT_KEY_MATERIAL_FAIL = -37,
    HKS_ERROR_CRYPTO_ENGINE_ERROR = -31,
};

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
    pin->length = g_testPin.length;
    memcpy_s(pin->pin, pin->length, g_testPin.pin, pin->length);
    para->self_auth_id = g_testServerAuthId;
    para->peer_auth_id = g_testClientAuthId;
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

/*--------------------------receive_data------------------------*/
class ReceiveDataTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void ReceiveDataTest::SetUpTestCase(void) {}
void ReceiveDataTest::TearDownTestCase(void) {}
void ReceiveDataTest::SetUp()
{
    InitHcAuthId();
}
void ReceiveDataTest::TearDown() {}

static HWTEST_F(ReceiveDataTest, ReceiveDataTest001_empty, TestSize.Level2)
{
    LOG("--------ReceiveDataTest001--------");
    struct hc_call_back callBack = {
        Transmit,
        GetProtocolParams,
        SetSessionKey,
        SetServiceResult,
        ConfirmReceiveRequest
    };

    const struct operation_parameter params = {g_testServerAuthId, g_testClientAuthId, KEY_LEN};
    hc_handle server = get_instance(&g_server_identity, HC_CENTRE, &callBack);
    ASSERT_TRUE(server != nullptr);
    int32_t ret = start_pake(server, &params);
    EXPECT_EQ(ret, HC_OK);
    uint8_t dataStr[] = {""};
    uint8_buff data = {
        dataStr,
        sizeof(dataStr),
        strlen(reinterpret_cast<char *>(dataStr))
    };
    ret = receive_data(server, &data);
    EXPECT_EQ(ret, HC_OK);
    EXPECT_EQ(g_result, END_FAILED);
    destroy(&server);
    LOG("--------ReceiveDataTest001--------");
}

static HWTEST_F(ReceiveDataTest, ReceiveDataTest002_msg0, TestSize.Level2)
{
    LOG("--------ReceiveDataTest002--------");
    struct hc_call_back callBack = {
        Transmit,
        GetProtocolParams,
        SetSessionKey,
        SetServiceResult,
        ConfirmReceiveRequest
    };

    hc_handle server = get_instance(&g_server_identity, HC_CENTRE, &callBack);
    ASSERT_TRUE(server != nullptr);

    uint8_t dataStr[] = "{\"message\":0}";
    uint8_buff data = {
        dataStr,
        sizeof(dataStr),
        strlen(reinterpret_cast<char *>(dataStr))
    };
    receive_data(server, &data);
    EXPECT_EQ(g_result, END_FAILED);

    destroy(&server);
    LOG("--------ReceiveDataTest002--------");
}

uint8_t g_dataStr031[] = {"{\"message\":32769,\"payload\":{\"version\":{\"currentVersion\":\"1.0.0\","
                        "\"minVersion\":\"1.0.0\"},\"challenge\":\"76539E5634EDA735A94845C3A4F356D6\","
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

uint8_t g_dataStr032[] = {"{\"message\":32770,\"payload\":{\"kcfData\":\"463853720FFFC312084B9FF288E17"
                        "C3F3D8B9D8F2A609D349CAA712AAD926C26\"}}"};

uint8_t g_dataStr033[] = {"{\"message\":32771,\"payload\":{\"exAuthInfo\":\"63B2AC76C0645224DA7E395DBCC29D9F"
                        "9AF5E0ABEEC94048962F838D12C501B22193E1B2AD43A7D9443A80EA92C4BD4F53B14C867DD00308167CB2803754"
                        "D4A909C0666B231C17736E0C5BE5A21746BE53AF0E72BE30DC56D56752823D9453F025DD3A56904EDBF54FB16667"
                        "82623DDF7BA29A1FA3CFE34864D4AF958EA616785AB7F06DBC01675ADB19EB12D8CA5CF312AEECE9016CA92BC9A2"
                        "69FE9BA2C579C7EA69F34855FDF689B3153BBFF618464612C6CC8984167842316A7E6E38813CC901DFBE4BA0767C"
                        "914B03AD0CF221BC319860A018078F74454DE18B0A144F812A3560D1A3223084A0BE48F737B49840A331B037CC13"
                        "DF82BFC85C1B95890907972897B827C237071A8D706CE41F9E8B045E3FDD9850BEBB50BFA84721B6E64A23557D0F"
                        "572B33D18FD8DE25C0B6C57F35AB9931EE02\"}}"};

static HWTEST_F(ReceiveDataTest, ReceiveDataTest003_pake_client, TestSize.Level2)
{
    LOG("--------ReceiveDataTest003--------");

    struct hc_call_back callBack = {
        Transmit,
        GetProtocolParams,
        SetSessionKey,
        SetServiceResult,
        ConfirmReceiveRequest
    };

    const struct operation_parameter params = {g_testServerAuthId, g_testClientAuthId, KEY_LEN};
    hc_handle server = get_instance(&g_server_identity, HC_CENTRE, &callBack);
    ASSERT_TRUE(server != nullptr);
    int32_t ret = start_pake(server, &params);
    EXPECT_EQ(ret, HC_OK);
    uint8_buff data001 = {
        g_dataStr031,
        sizeof(g_dataStr031),
        strlen(reinterpret_cast<char *>(g_dataStr031))
    };
    ret = receive_data(server, &data001);
    EXPECT_EQ(ret, HC_OK);
    EXPECT_EQ(g_result, KEY_AGREEMENT_PROCESSING);
    uint8_buff data002 = {
        g_dataStr032,
        sizeof(g_dataStr032),
        strlen(reinterpret_cast<char *>(g_dataStr032))
    };
    ret = receive_data(server, &data002);
    EXPECT_EQ(ret, HC_OK);
    EXPECT_EQ(g_result, KEY_AGREEMENT_END);
    uint8_buff data003 = {
        g_dataStr033,
        sizeof(g_dataStr033),
        strlen(reinterpret_cast<char *>(g_dataStr033))
    };
    ret = receive_data(server, &data003);
    EXPECT_EQ(ret, HC_OK);
    EXPECT_EQ(g_result, END_SUCCESS);
    destroy(&server);
    LOG("--------ReceiveDataTest003--------");
}

static HWTEST_F(ReceiveDataTest, ReceiveDataTest004_pake_client, TestSize.Level2)
{
    LOG("--------ReceiveDataTest004--------");
    struct hc_call_back callBack = {
        Transmit,
        GetProtocolParams,
        SetSessionKey,
        SetServiceResult,
        ConfirmReceiveRequest
    };

    const struct operation_parameter params = {g_testServerAuthId, g_testClientAuthId, KEY_LEN};
    hc_handle server = get_instance(&g_server_identity, HC_CENTRE, &callBack);
    ASSERT_TRUE(server != nullptr);
    int32_t ret = start_pake(server, &params);
    EXPECT_EQ(ret, HC_OK);
    uint8_t dataStr001[] = {"{\"message\":32769,\"payload\":{\"version\":{\"currentVersion\":\"1.0.0\","
                        "\"minVersion\":\"1.0.0\"},\"challenge\":\"76539E5634EDA735A94845C3A4F356D6\","
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
    uint8_buff data001 = {
        dataStr001,
        sizeof(dataStr001),
        strlen(reinterpret_cast<char *>(dataStr001))
    };
    ret = receive_data(server, &data001);
    EXPECT_EQ(ret, HC_OK);
    EXPECT_EQ(g_result, KEY_AGREEMENT_PROCESSING);
    destroy(&server);
    LOG("--------ReceiveDataTest004--------");
}

static HWTEST_F(ReceiveDataTest, ReceiveDataTest005_pake_client, TestSize.Level2)
{
    LOG("--------ReceiveDataTest005--------");
    struct hc_call_back callBack = {
        Transmit,
        GetProtocolParams,
        SetSessionKey,
        SetServiceResult,
        ConfirmReceiveRequest
    };

    const struct operation_parameter params = {g_testServerAuthId, g_testClientAuthId, KEY_LEN};
    hc_handle server = get_instance(&g_server_identity, HC_CENTRE, &callBack);
    ASSERT_TRUE(server != nullptr);
    int32_t ret = start_pake(server, &params);
    EXPECT_EQ(ret, HC_OK);
    uint8_t dataStr001[] = {"{\"message\":32769,\"payload\":{\"version\":{\"currentVersion\":\"1.0.0\","
                        "\"minVersion\":\"1.0.0\"},\"challenge\":\"76539E5634EDA735A94845C3A4F356D6\","
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
    uint8_buff data001 = {
        dataStr001,
        sizeof(dataStr001),
        strlen(reinterpret_cast<char *>(dataStr001))
    };
    ret = receive_data(server, &data001);
    EXPECT_EQ(ret, HC_OK);
    EXPECT_EQ(g_result, KEY_AGREEMENT_PROCESSING);

    uint8_t dataStr002[] = {"{\"message\":32770,\"payload\":{\"kcfData\":\"463853720FFFC312084B9FF288E17"
                          "C3F3D8B9D8F2A609D349CAA712AAD926C26\"}}"};
    uint8_buff data002 = {
        dataStr002,
        sizeof(dataStr002),
        strlen(reinterpret_cast<char *>(dataStr002))
    };
    ret = receive_data(server, &data002);
    EXPECT_EQ(ret, HC_OK);
    destroy(&server);
    LOG("--------ReceiveDataTest005--------");
}

uint8_t g_dataStr061[] = {"{\"message\":32769,\"payload\":{\"version\":{\"currentVersion\":\"1.0.0\","
                        "\"minVersion\":\"1.0.0\"},\"challenge\":\"76539E5634EDA735A94845C3A4F356D6\","
                        "\"salt\":\"025E4B3B2DD3B0E67395C760008A9154\","
                        "\"epk\":""}}"};

uint8_t g_dataStr062[] = {"{\"message\":32770,\"payload\":{\"kcfData\":\"463853720FFFC312084B9FF288E17"
                          "C3F3D8B9D8F2A609D349CAA712AAD926C26\"}}"};

uint8_t g_dataStr063[] = {"{\"message\":32771,\"payload\":{\"exAuthInfo\":\"63B2AC76C0645224DA7E395DBCC29D9F"
                        "9AF5E0ABEEC94048962F838D12C501B22193E1B2AD43A7D9443A80EA92C4BD4F53B14C867DD00308167CB2803754"
                        "D4A909C0666B231C17736E0C5BE5A21746BE53AF0E72BE30DC56D56752823D9453F025DD3A56904EDBF54FB16667"
                        "82623DDF7BA29A1FA3CFE34864D4AF958EA616785AB7F06DBC01675ADB19EB12D8CA5CF312AEECE9016CA92BC9A2"
                        "69FE9BA2C579C7EA69F34855FDF689B3153BBFF618464612C6CC8984167842316A7E6E38813CC901DFBE4BA0767C"
                        "914B03AD0CF221BC319860A018078F74454DE18B0A144F812A3560D1A3223084A0BE48F737B49840A331B037CC13"
                        "DF82BFC85C1B95890907972897B827C237071A8D706CE41F9E8B045E3FDD9850BEBB50BFA84721B6E64A23557D0F"
                        "572B33D18FD8DE25C0B6C57F35AB9931EE02\"}}"};
static HWTEST_F(ReceiveDataTest, ReceiveDataTest006_pake_client_error1, TestSize.Level2)
{
    LOG("--------ReceiveDataTest006--------");
    struct hc_call_back callBack = {
        Transmit,
        GetProtocolParams,
        SetSessionKey,
        SetServiceResult,
        ConfirmReceiveRequest
    };

    const struct operation_parameter params = {g_testServerAuthId, g_testClientAuthId, KEY_LEN};
    hc_handle server = get_instance(&g_server_identity, HC_CENTRE, &callBack);
    ASSERT_TRUE(server != nullptr);
    int32_t ret = start_pake(server, &params);
    EXPECT_EQ(ret, HC_OK);
    uint8_buff data001 = {
        g_dataStr061,
        sizeof(g_dataStr061),
        strlen(reinterpret_cast<char *>(g_dataStr061))
    };
    ret = receive_data(server, &data001);
    EXPECT_EQ(ret, HC_OK);
    uint8_buff data002 = {
        g_dataStr062,
        sizeof(g_dataStr062),
        strlen(reinterpret_cast<char *>(g_dataStr062))
    };
    ret = receive_data(server, &data002);
    EXPECT_EQ(ret, HC_OK);
    uint8_buff data003 = {
        g_dataStr063,
        sizeof(g_dataStr063),
        strlen(reinterpret_cast<char *>(g_dataStr063))
    };
    ret = receive_data(server, &data003);
    EXPECT_EQ(ret, HC_OK);
    EXPECT_EQ(g_result, END_FAILED);
    destroy(&server);
    LOG("--------ReceiveDataTest006--------");
}

static HWTEST_F(ReceiveDataTest, ReceiveDataTest007_pake_client_error2, TestSize.Level2)
{
    LOG("--------ReceiveDataTest007--------");
    struct hc_call_back callBack = {
        Transmit,
        GetProtocolParams,
        SetSessionKey,
        SetServiceResult,
        ConfirmReceiveRequest
    };

    const struct operation_parameter params = {g_testServerAuthId, g_testClientAuthId, KEY_LEN};
    hc_handle server = get_instance(&g_server_identity, HC_CENTRE, &callBack);
    ASSERT_TRUE(server != nullptr);
    int32_t ret = start_pake(server, &params);
    EXPECT_EQ(ret, HC_OK);
    uint8_t dataStr001[] = {"{\"message\":32769}"};
    uint8_buff data001 = {
        dataStr001,
        sizeof(dataStr001),
        strlen(reinterpret_cast<char *>(dataStr001))
    };
    ret = receive_data(server, &data001);
    EXPECT_EQ(ret, HC_OK);
    EXPECT_EQ(g_result, END_FAILED);

    uint8_t dataStr002[] = {"{\"message\":32770,\"payload\":{\"kcfData\":\"463853720FFFC312084B9FF288E17"
                          "C3F3D8B9D8F2A609D349CAA712AAD926C26\"}}"};
    uint8_buff data002 = {
        dataStr002,
        sizeof(dataStr002),
        strlen(reinterpret_cast<char *>(dataStr002))
    };
    ret = receive_data(server, &data002);
    EXPECT_EQ(ret, HC_OK);

    uint8_t dataStr003[] = {"{\"message\":32771,\"payload\":{\"exAuthInfo\":\"63B2AC76C0645224DA7E395DBCC29D9F"
                        "9AF5E0ABEEC94048962F838D12C501B22193E1B2AD43A7D9443A80EA92C4BD4F53B14C867DD00308167CB2803754"
                        "D4A909C0666B231C17736E0C5BE5A21746BE53AF0E72BE30DC56D56752823D9453F025DD3A56904EDBF54FB16667"
                        "82623DDF7BA29A1FA3CFE34864D4AF958EA616785AB7F06DBC01675ADB19EB12D8CA5CF312AEECE9016CA92BC9A2"
                        "69FE9BA2C579C7EA69F34855FDF689B3153BBFF618464612C6CC8984167842316A7E6E38813CC901DFBE4BA0767C"
                        "914B03AD0CF221BC319860A018078F74454DE18B0A144F812A3560D1A3223084A0BE48F737B49840A331B037CC13"
                        "DF82BFC85C1B95890907972897B827C237071A8D706CE41F9E8B045E3FDD9850BEBB50BFA84721B6E64A23557D0F"
                        "572B33D18FD8DE25C0B6C57F35AB9931EE02\"}}"};
    uint8_buff data003 = {
        dataStr003,
        sizeof(dataStr003),
        strlen(reinterpret_cast<char *>(dataStr003))
    };
    ret = receive_data(server, &data003);
    EXPECT_EQ(ret, HC_OK);
    destroy(&server);
    LOG("--------ReceiveDataTest007--------");
}

uint8_t g_dataStr081[] = {"{\"message\":32769,\"payload\":{\"version\":{\"currentVersion\":\"1.0.0\","
                        "\"minVersion\":\"1.0.0\"},\"challenge\":\"76539E5634EDA735A94845C3A4F356D6\","
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

uint8_t g_dataStr082[] = {"{\"message\":0,\"payload\":{\"kcfData\":\"463853720FFFC312084B9FF288E17"
                        "C3F3D8B9D8F2A609D349CAA712AAD926C26\"}}"};

uint8_t g_dataStr083[] = {"{\"message\":32771,\"payload\":{\"exAuthInfo\":\"63B2AC76C0645224DA7E395DBCC29D9F"
                        "9AF5E0ABEEC94048962F838D12C501B22193E1B2AD43A7D9443A80EA92C4BD4F53B14C867DD00308167CB2803754"
                        "D4A909C0666B231C17736E0C5BE5A21746BE53AF0E72BE30DC56D56752823D9453F025DD3A56904EDBF54FB16667"
                        "82623DDF7BA29A1FA3CFE34864D4AF958EA616785AB7F06DBC01675ADB19EB12D8CA5CF312AEECE9016CA92BC9A2"
                        "69FE9BA2C579C7EA69F34855FDF689B3153BBFF618464612C6CC8984167842316A7E6E38813CC901DFBE4BA0767C"
                        "914B03AD0CF221BC319860A018078F74454DE18B0A144F812A3560D1A3223084A0BE48F737B49840A331B037CC13"
                        "DF82BFC85C1B95890907972897B827C237071A8D706CE41F9E8B045E3FDD9850BEBB50BFA84721B6E64A23557D0F"
                        "572B33D18FD8DE25C0B6C57F35AB9931EE02\"}}"};

static HWTEST_F(ReceiveDataTest, ReceiveDataTest008_pake_client_error3, TestSize.Level2)
{
    LOG("--------ReceiveDataTest008--------");
    struct hc_call_back callBack = {
        Transmit,
        GetProtocolParams,
        SetSessionKey,
        SetServiceResult,
        ConfirmReceiveRequest
    };

    const struct operation_parameter params = {g_testServerAuthId, g_testClientAuthId, KEY_LEN};
    hc_handle server = get_instance(&g_server_identity, HC_CENTRE, &callBack);
    ASSERT_TRUE(server != nullptr);
    int32_t ret = start_pake(server, &params);
    EXPECT_EQ(ret, HC_OK);
    uint8_buff data001 = {
        g_dataStr081,
        sizeof(g_dataStr081),
        strlen(reinterpret_cast<char *>(g_dataStr081))
    };
    ret = receive_data(server, &data001);
    EXPECT_EQ(ret, HC_OK);
    uint8_buff data002 = {
        g_dataStr082,
        sizeof(g_dataStr082),
        strlen(reinterpret_cast<char *>(g_dataStr082))
    };
    ret = receive_data(server, &data002);
    EXPECT_EQ(ret, HC_OK);
    uint8_buff data003 = {
        g_dataStr083,
        sizeof(g_dataStr083),
        strlen(reinterpret_cast<char *>(g_dataStr083))
    };
    ret = receive_data(server, &data003);
    EXPECT_EQ(ret, HC_OK);
    destroy(&server);
    LOG("--------ReceiveDataTest008--------");
}

static HWTEST_F(ReceiveDataTest, ReceiveDataTest010_pake_client2error, TestSize.Level2)
{
    LOG("--------ReceiveDataTest010--------");
    struct hc_call_back callBack = {
        Transmit,
        GetProtocolParams,
        SetSessionKey,
        SetServiceResult,
        ConfirmReceiveRequest
    };
    hc_handle server = get_instance(&g_server_identity, HC_CENTRE, &callBack);
    ASSERT_TRUE(server != nullptr);
    struct hichain *hcServer = static_cast<struct hichain *>(server);
    hcServer->operation_code = BIND;
    hcServer->last_state = KEY_AGREEMENT_STATE;
    hcServer->state = OPERATION_STATE;
    struct operation_parameter params = {g_testServerAuthId, g_testClientAuthId, KEY_LEN};
    build_object(hcServer, PAKE_MODULAR, true, &params);
    hcServer->pake_client->client_info.protocol_base_info.state = START_REQUEST;
    hcServer->pake_client->client_info.protocol_base_info.last_state = PROTOCOL_INIT;
    uint8_t dataStr[] = "{\"message\":32770,\"payload\":{}}";
    uint8_buff data = {
        dataStr,
        sizeof(dataStr),
        strlen(reinterpret_cast<char *>(dataStr))
    };
    receive_data(server, &data);
    EXPECT_EQ(g_result, END_FAILED);

    destroy(&server);
    LOG("--------ReceiveDataTest010--------");
}

static HWTEST_F(ReceiveDataTest, ReceiveDataTest014_pake_client3error, TestSize.Level2)
{
    LOG("--------ReceiveDataTest014--------");
    struct hc_call_back callBack = {
        Transmit,
        GetProtocolParams,
        SetSessionKey,
        SetServiceResult,
        ConfirmReceiveRequest
    };

    hc_handle server = get_instance(&g_server_identity, HC_CENTRE, &callBack);
    ASSERT_TRUE(server != nullptr);
    struct hichain *hcServer = static_cast<struct hichain *>(server);
    hcServer->operation_code = BIND;
    hcServer->last_state = OPERATION_STATE;
    hcServer->state = OVER_STATE;
    struct operation_parameter params = {g_testServerAuthId, g_testClientAuthId, KEY_LEN};
    build_object(hcServer, PAKE_MODULAR, true, &params);
    hcServer->pake_client->client_info.protocol_base_info.state = END_REQUEST;
    hcServer->pake_client->client_info.protocol_base_info.last_state = START_REQUEST;
    uint8_t dataStr[] = {"{\"message\":32771,\"payload\":{}}"};
    uint8_buff data = {
        dataStr,
        sizeof(dataStr),
        strlen(reinterpret_cast<char *>(dataStr))
    };
    receive_data(server, &data);
    EXPECT_EQ(g_result, END_FAILED);

    destroy(&server);
    LOG("--------ReceiveDataTest014--------");
}

uint8_t g_dataStr0151[] = "{\"message\":32769,\"payload\":{\"version\":{\"currentVersion\":"
                            "\"1.0.0\",\"minVersion\":\"1.0.0\"},"
                           "\"challenge\":\"EF6768B27F8BB03128195903788D415A\",\"salt\":"
                           "\"41F4D7096B21DA799A722DA00EB8B030\",\"epk\":\"5F990513D00D2"
                           "206A5AA4AAF7659A066236DDCD3CB806EE6373B8FA2F15AA72274A20709B"
                           "350D8CD17358FD123E7393FE12B5CE4D0CAE62854DBC33425"
                           "F7B49E727F029C5AA724962E221E6095C8ACC6C8AABA5F4A9"
                           "DCCB8AF1BD6CEA09B6AEBD2058C1BD1572005FE5096F1D840F7C78E83D89"
                           "A803C6FF49BF98C03FCEA32247816DF3EB39A52BCCB215747E91B9831BDB"
                           "5E3349C7AA8FCCF121B1CFD2E5CC1861CD85D47AC698E9933"
                           "30110889C2221D45ECA9515956FEA641B64C5EC81F449DF74D863539AF49"
                           "23E13220A513E473352CC532F4710DFB199A5C520D19D14C7"
                           "4EA425721E8EDAFD655E024C99DA1C130EAFB4B420A0B0A85FEB9030546B"
                           "8B3FC9F307F50ABEDC249AB69BA3442D8A567D2D2F2A001AF"
                           "A21D6A9F6FD0D4AB2153EB737094692318FC0C4FCD8026D73585FFD2D411"
                           "CD7703FF9B7B981C42FF4C969E75D846CDFAC54E122A1B073"
                           "CAD7123E8B06C7B51FFC832942001FA33E3E85BB3DE306BB2AE2BEC7D1AB"
                           "BD3D466FFD87FCA3CE65254E4D5A97AD29DFAB4F0\"}}";
static HWTEST_F(ReceiveDataTest, ReceiveDataTest015_pake_client_all, TestSize.Level2)
{
    LOG("--------ReceiveDataTest015--------");
    struct hc_call_back callBack = {
        Transmit,
        GetProtocolParams,
        SetSessionKey,
        SetServiceResult,
        ConfirmReceiveRequest
    };

    hc_handle server = get_instance(&g_server_identity, HC_CENTRE, &callBack);
    ASSERT_TRUE(server != nullptr);
    uint8_buff data001 = {
        g_dataStr0151,
        sizeof(g_dataStr0151),
        strlen(reinterpret_cast<char *>(g_dataStr0151))
    };
    receive_data(server, &data001);
    EXPECT_EQ(g_result, END_FAILED);

    uint8_t dataStr002[] = "{\"message\":32770,\"payload\":{"\
                           "\"kcfData\":\"BFA2C2B30CF314401AB067D42655B199824AAF3F3D57926FA903C584BA12A8CB\"}}";

    uint8_buff data002 = {
        dataStr002,
        sizeof(dataStr002),
        strlen(reinterpret_cast<char *>(dataStr002))
    };
    receive_data(server, &data002);
    EXPECT_EQ(g_result, END_FAILED);

    uint8_t dataStr003[] = "{\"message\":32771,\"payload\":{"\
                           "\"exAuthInfo\":\"93E41C6E20911B9B36BC7CE94EDC677E32D83BB6F3AD985FD4BC655B3D9ACBE2\"}}";
    uint8_buff data003 = {
        dataStr003,
        sizeof(dataStr003),
        strlen(reinterpret_cast<char *>(dataStr003))
    };
    receive_data(server, &data003);
    EXPECT_EQ(g_result, END_FAILED);
    destroy(&server);
    LOG("--------ReceiveDataTest015--------");
}

static HWTEST_F(ReceiveDataTest, ReceiveDataTest016_sts_response1_Ok, TestSize.Level2)
{
    LOG("--------ReceiveDataTest016--------");
    struct hc_call_back callBack = {
        Transmit,
        GetProtocolParams,
        SetSessionKey,
        SetServiceResult,
        ConfirmReceiveRequest
    };

    hc_handle server = get_instance(&g_server_identity, HC_CENTRE, &callBack);
    ASSERT_TRUE(server != nullptr);
    struct hichain *hcServer = static_cast<struct hichain *>(server);
    hcServer->operation_code = AUTHENTICATE;
    struct operation_parameter params = {g_testServerAuthId, g_testClientAuthId, KEY_LEN};
    build_object(hcServer, STS_MODULAR, true, &params);
    hcServer->sts_client->client_info.protocol_base_info.state = END_REQUEST;
    hcServer->sts_client->client_info.protocol_base_info.last_state = PROTOCOL_INIT;
    uint8_t dataStr[] = "{\"authForm\":0,\"message\":32785,\"payload\":{\"authData\":\"4A4EB6622524C"
                        "BBF7DC96412A82BF4CB6022F50226A201DB3B3C55\",\"challenge\":\"A1714848785F27C22B31\","\
                        "\"epk\":\"493CB95DB80320360BE5A3E3000E3E8E67371D6DCC57D1F97937ABABC219\","\
                        "\"salt\":\"93E69DC0D48479316984\",\"version\":{\"currentVersion\":"\
                        "\"1.0.0\",\"minVersion\":\"1.0.0\"},\"peerAuthId\":\"6B5A16BFA24C941F4C1B094D"\
                        "6F2FA8DC8A45\",\"peerUserType\":\"0\"}}";
    uint8_buff data = {
        dataStr,
        sizeof(dataStr),
        strlen(reinterpret_cast<char *>(dataStr))
    };
    receive_data(server, &data);
    EXPECT_EQ(g_result, END_FAILED);

    destroy(&server);
    LOG("--------ReceiveDataTest016--------");
}

uint8_t g_dataStr0171[] = "{\"authForm\":0,\"message\":32785,\"payload\":"
                           "{\"authData\":\"0CE64CAFFA6AD1146EDB618E6F"
                           "1DA15183EFDCAE08F909A6ABA7B9F2676F4E4C2A280A72"
                           "0C3EBB069858DB473191ED51237E201CC697D3E10130CE"
                           "8FB86FD57F66214643874AD17FE91EC3ACBC446CA666CD"
                           "C5BDFB0EB5BE76DF673C\",\"challenge\":\"C591479"
                           "0E4A81F59F286F2F31415A590\",\"epk\":\"8A870771"
                           "CA779105041966DC462B3B12D7FF87129446F38D1AC39E"
                           "1F408FEB0D\",\"salt\":\"C8EA30CAE1C16CCEEB652D"
                           "AE671A97A3\",\"version\":{\"currentVersion\":"
                           "\"1.0.0\",\"minVersion\":\"1.0.0\"},\"peerAuthId\":\"643"
                           "3376364376365623839346634333933613239396566383"
                           "532623466633335613161306437376334"
                           "3861356233653062323539396162316436396232336136\","
                           "\"peerUserType\":\"0\"}}";

static HWTEST_F(ReceiveDataTest, ReceiveDataTest017_STS_fullprocess_success, TestSize.Level2)
{
    LOG("--------ReceiveDataTest017--------");
    struct hc_call_back callBack = {
        Transmit,
        GetProtocolParams,
        SetSessionKey,
        SetServiceResult,
        ConfirmReceiveRequest
    };
    hc_handle server = get_instance(&g_server_identity, HC_CENTRE, &callBack);
    ASSERT_TRUE(server != nullptr);
    struct operation_parameter params = {g_testServerAuthId, g_testClientAuthId, KEY_LEN};
    int32_t ret = authenticate_peer(server, &params);
    EXPECT_EQ(ret, HC_OK);
    uint8_buff data001 = {
        g_dataStr0171,
        sizeof(g_dataStr0171),
        strlen(reinterpret_cast<char *>(g_dataStr0171))
    };
    ret = receive_data(server, &data001);
    EXPECT_EQ(ret, HC_OK);
    uint8_t dataStr002[] = "{\"authForm\":0,\"message\":32786,\"payload\":"
                           "{\"authReturn\":\"57F9D09AA425FB83AB9BE2AF25FC9E5"
                           "B82F630255AC62872447A9E5802\"}}";
    uint8_buff data002 = {
        dataStr002,
        sizeof(dataStr002),
        strlen(reinterpret_cast<char *>(dataStr002))
    };
    ret = receive_data(server, &data002);
    EXPECT_EQ(ret, HC_OK);
    destroy(&server);
    LOG("--------ReceiveDataTest017--------");
}

static HWTEST_F(ReceiveDataTest, ReceiveDataTest018_STS_auth_ack_error_message, TestSize.Level2)
{
    LOG("--------ReceiveDataTest018--------");
    struct hc_call_back callBack = {
        Transmit,
        GetProtocolParams,
        SetSessionKey,
        SetServiceResult,
        ConfirmReceiveRequest
    };

    hc_handle server = get_instance(&g_server_identity, HC_CENTRE, &callBack);
    ASSERT_TRUE(server != nullptr);
    struct operation_parameter params = {g_testServerAuthId, g_testClientAuthId, KEY_LEN};
    int32_t ret = authenticate_peer(server, &params);
    EXPECT_EQ(ret, HC_OK);
    uint8_t dataStr001[] = "{\"authForm\":0,\"message\":32785,\"payload\":{\"authData\":\"0CE64CAFFA6AD1146EDB618E6F"
                         "1DA15183EFDCAE08F909A6ABA7B9F2676F4E4C2A280A720C3EBB069858DB473191ED51237E201CC"
                         "697D3E10130CE8FB86FD57F66214643874AD17FE91EC3ACBC446CA666CDC5BDFB0EB5BE76DF673C\","
                         "\"challenge\":\"C5914790E4A81F59F286F2F31415A590\",\"epk\":\"8A870771CA779105041966DC4"
                         "62B3B12D7FF87129446F38D1AC39E1F408FEB0D\",\"salt\":\"C8EA30CAE1C16CCEEB652DAE671A97"
                         "A3\",\"version\":{\"currentVersion\":\"1.0.0\",\"minVersion\":\"1.0.0\"},\"peerAuthId\":\"643"
                         "3376364376365623839346634333933613239396566383532623466633335613161306437376334"
                         "3861356233653062323539396162316436396232336136\",\"peerUserType\":\"0\"}}";
    uint8_buff data001 = {
        dataStr001,
        sizeof(dataStr001),
        strlen(reinterpret_cast<char *>(dataStr001))
    };
    ret = receive_data(server, &data001);
    EXPECT_EQ(ret, HC_OK);

    uint8_t dataStr002[] = "{\"authForm\":0,\"message\":32786,\"payload\":{\"errorCode\":17}}";
    uint8_buff data002 = {
        dataStr002,
        sizeof(dataStr002),
        strlen(reinterpret_cast<char *>(dataStr002))
    };
    ret = receive_data(server, &data002);
    EXPECT_EQ(ret, HC_OK);
    destroy(&server);
    LOG("--------ReceiveDataTest018--------");
}

uint8_t g_dataStr0191[] = {"{\"message\":32769,\"payload\":{\"version\":{\"currentVersion\":\"1.0.0\","
                        "\"minVersion\":\"1.0.0\"},"
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

uint8_t g_dataStr0192[] = {"{\"message\":32769,\"payload\":{\"version\":{\"currentVersion\":\"1.0.0\","
                        "\"minVersion\":\"1.0.0\"},\"challenge\":\"76539E5634EDA735A94845C3A4F356D6\","
                        "\"epk\":\"24EBF8D727B19E8A43B20D22F744113C8B49B226D834B2E3C9CB5B0378732D6CF7C658BFB468682A6762"
                        "2D5FE061F4D8102E4D8912377AA785919C529F0C1289F2188E641C6DC626054FC30304DC804FD9F059F5F5D8CEAA29"
                        "A44814F10CC2A770C5BEB0BE86559E4FA85AD6E480DC2A627F5B28626E23B613EAC21101FF1C1DDA76E35A67A5A70B"
                        "C24ECFD0C92F4F69A5B73FD67BE3EFC0904709BEC26490E21A4A04E29211DF393559B4A71F7368B68F529806DB90C5"
                        "8315EDFF0A1738E26E82A54D2030A5B9B270DCF01A2377300135C55B3F6B273CF157246D0DF928D6E3E2886E79ECEB"
                        "F69F98806C37A6128E4E93C9C43DD01B53963458AF60FA1C0E497F5FD4E807DA4F804EE145967D74792AD9B135C2F3"
                        "A25FAA3427B3666C9D30539F008915A53D1FE2E2DDDCFCFD0815976332575F9EDBC9F4946A83116C7A29C38AC1A5FD"
                        "8E5B894DCB4A1A29672D2647D6C734D4EA74E4A077D3403CAD0CA15318D9560FFF163D71B2991D70148F97CD524244"
                        "7DF2B23C856D734CDD39220EC0\"}}"};

uint8_t g_dataStr0193[] = {"{\"message\":32769,\"payload\":{\"version\":{\"currentVersion\":\"1.0.0\","
                        "\"minVersion\":\"1.0.0\"},\"challenge\":\"76539E5634EDA735A94845C3A4F356D6\","
                        "\"salt\":\"025E4B3B2DD3B0E67395C760008A9154\",}}"};

uint8_t g_dataStr0194[] = {"{\"message\":32769,\"payload\":{\"challenge\":\"76539E5634EDA735A94845C3A4F356D6\","
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

uint8_t g_dataStr0195[] = {"{\"message\":32769,\"payload\":{\"challenge\":\"76539E5634EDA735A94845C3A4F356D\","
                        "\"salt\":\"025E4B3B2DD3B0E67395C760008A915\","
                        "\"epk\":\"24EBF8D727B19E8A43B20D22F744113C8B49B226D834B2E3C9CB5B0378732D6CF7C658BFB468682A6762"
                        "2D5FE061F4D8102E4D8912377AA785919C529F0C1289F2188E641C6DC626054FC30304DC804FD9F059F5F5D8CEAA29"
                        "A44814F10CC2A770C5BEB0BE86559E4FA85AD6E480DC2A627F5B28626E23B613EAC21101FF1C1DDA76E35A67A5A70B"
                        "C24ECFD0C92F4F69A5B73FD67BE3EFC0904709BEC26490E21A4A04E29211DF393559B4A71F7368B68F529806DB90C5"
                        "8315EDFF0A1738E26E82A54D2030A5B9B270DCF01A2377300135C55B3F6B273CF157246D0DF928D6E3E2886E79ECEB"
                        "F69F98806C37A6128E4E93C9C43DD01B53963458AF60FA1C0E497F5FD4E807DA4F804EE145967D74792AD9B135C2F3"
                        "A25FAA3427B3666C9D30539F008915A53D1FE2E2DDDCFCFD0815976332575F9EDBC9F4946A83116C7A29C38AC1A5FD"
                        "8E5B894DCB4A1A29672D2647D6C734D4EA74E4A077D3403CAD0CA15318D9560FFF163D71B2991D70148F97CD524244"
                        "7DF2B23C856D734CDD39220EC\"}}"};

static HWTEST_F(ReceiveDataTest, ReceiveDataTest019_pake_client_withoutrandom, TestSize.Level2)
{
    LOG("--------ReceiveDataTest019--------");
    struct hc_call_back callBack = {
        Transmit,
        GetProtocolParams,
        SetSessionKey,
        SetServiceResult,
        ConfirmReceiveRequest
    };
    const struct operation_parameter params = {g_testServerAuthId, g_testClientAuthId, KEY_LEN};
    hc_handle server1 = get_instance(&g_server_identity, HC_CENTRE, &callBack);
    ASSERT_TRUE(server1 != nullptr);
    int32_t ret = start_pake(server1, &params);
    EXPECT_EQ(ret, HC_OK);
    uint8_buff data001 = {
        g_dataStr0191,
        sizeof(g_dataStr0191),
        strlen(reinterpret_cast<char *>(g_dataStr0191))
    };
    ret = receive_data(server1, &data001);
    EXPECT_EQ(ret, HC_OK);
    destroy(&server1);
    hc_handle server2 = get_instance(&g_server_identity, HC_CENTRE, &callBack);
    ASSERT_TRUE(server2 != nullptr);
    ret = start_pake(server2, &params);
    EXPECT_EQ(ret, HC_OK);
    uint8_buff data002 = {
        g_dataStr0192,
        sizeof(g_dataStr0192),
        strlen(reinterpret_cast<char *>(g_dataStr0192))
    };
    ret = receive_data(server2, &data002);
    EXPECT_EQ(ret, HC_OK);
    destroy(&server2);
    hc_handle server3 = get_instance(&g_server_identity, HC_CENTRE, &callBack);
    ASSERT_TRUE(server3 != nullptr);
    ret = start_pake(server3, &params);
    EXPECT_EQ(ret, HC_OK);
    uint8_buff data003 = {
        g_dataStr0193,
        sizeof(g_dataStr0193),
        strlen(reinterpret_cast<char *>(g_dataStr0193))
    };
    ret = receive_data(server3, &data003);
    EXPECT_EQ(ret, HC_OK);
    destroy(&server3);
    LOG("--------ReceiveDataTest019--------");
}

static HWTEST_F(ReceiveDataTest, ReceiveDataTest020_pake_client_withoutrandom2, TestSize.Level2)
{
    LOG("--------ReceiveDataTest020--------");
    struct hc_call_back callBack = {
        Transmit,
        GetProtocolParams,
        SetSessionKey,
        SetServiceResult,
        ConfirmReceiveRequest
    };
    const struct operation_parameter params = {g_testServerAuthId, g_testClientAuthId, KEY_LEN};
    hc_handle server4 = get_instance(&g_server_identity, HC_CENTRE, &callBack);
    ASSERT_TRUE(server4 != nullptr);
    int32_t ret = start_pake(server4, &params);
    EXPECT_EQ(ret, HC_OK);
    uint8_buff data004 = {
        g_dataStr0194,
        sizeof(g_dataStr0194),
        strlen(reinterpret_cast<char *>(g_dataStr0194))
    };
    ret = receive_data(server4, &data004);
    EXPECT_EQ(ret, HC_OK);
    uint8_buff data005 = {
        g_dataStr0195,
        sizeof(g_dataStr0195),
        strlen(reinterpret_cast<char *>(g_dataStr0195))
    };
    ret = receive_data(server4, &data005);
    EXPECT_EQ(ret, HC_OK);
    destroy(&server4);

    LOG("--------ReceiveDataTest020--------");
}
}