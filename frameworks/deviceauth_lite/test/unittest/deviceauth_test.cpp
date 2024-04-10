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
const int KEY_LEN_ERROR = 68;
const int AUTH_ID_LENGTH = 64;
const int ERROR_NUM_LENGTH = -1;
const int ERROR_ZERO_LENGTH = 0;
const int ERROR_LENGTH = 258;

static struct session_identity g_server_identity = {
    153666603,
    {strlen("aaa.bbbb.ccc"), "aaa.bbbb.ccc"},
    {strlen("CarDevice"), "CarDevice"},
    0
};

static struct session_identity g_server_identity001 = {
    153666603,
    {ERROR_LENGTH, "aaa.bbbb.ccc"},
    {strlen("CarDevice"), "CarDevice"},
    0
};

static struct session_identity g_server_identity002 = {
    153666603,
    {strlen("aaa.bbbb.ccc"), "aaa.bbbb.ccc"},
    {ERROR_LENGTH, "CarDevice"},
    0
};

static struct session_identity g_server_identity003 = {
    153666603,
    {ERROR_NUM_LENGTH, "aaa.bbbb.ccc"},
    {ERROR_LENGTH, "CarDevice"},
    0
};

static struct hc_pin g_testPin = {strlen("123456"), "123456"};
static struct hc_pin g_testPin001 = {KEY_LEN_ERROR, "ab"};
static struct hc_pin g_testPin002 = {ERROR_ZERO_LENGTH, "cd"};

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

static struct hc_auth_id g_testClientAuthId001 = {strlen("authClient1"), "authClient1"};
static struct hc_auth_id g_testClientAuthId002 = {strlen("authClient2"), "authClient2"};
static struct hc_auth_id g_testClientAuthId003 = {KEY_LEN_ERROR, ""};

static struct hc_auth_id g_testServerAuthId001 = {0, "authServer1"};
static struct hc_auth_id g_testServerAuthId002 = {-1, "authServer2"};
static struct hc_auth_id g_testServerAuthId003 = {KEY_LEN_ERROR, ""};

struct hc_auth_id *g_authIdClientList[3] = {
    &g_testClientAuthId,
    &g_testClientAuthId001,
    &g_testClientAuthId002
};
struct hc_auth_id **g_authIdList = g_authIdClientList;

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

static void GetProtocolParams001(const struct session_identity *identity, int32_t operationCode,
    struct hc_pin *pin, struct operation_parameter *para)
{
    LOG("--------GetProtocolParams--------");
    LOG("identity session_id[%d] package_name[%s]", identity->session_id, identity->package_name.name);
    LOG("operationCode[%d]", operationCode);
    pin->length = g_testPin.length;
    memcpy_s(pin->pin, pin->length, g_testPin001.pin, pin->length);
    pin->length = KEY_LEN_ERROR;
    para->self_auth_id = g_testServerAuthId;
    para->peer_auth_id = g_testClientAuthId;
    para->key_length = KEY_LEN;
    LOG("--------GetProtocolParams--------");
}

static void GetProtocolParams002(const struct session_identity *identity, int32_t operationCode,
    struct hc_pin *pin, struct operation_parameter *para)
{
    LOG("--------GetProtocolParams--------");
    LOG("identity session_id[%d] package_name[%s]", identity->session_id, identity->package_name.name);
    LOG("operationCode[%d]", operationCode);
    pin->length = g_testPin.length;
    memcpy_s(pin->pin, pin->length, g_testPin002.pin, pin->length);
    para->self_auth_id = g_testServerAuthId003;
    para->peer_auth_id = g_testClientAuthId;
    para->key_length = KEY_LEN_ERROR;
    LOG("--------GetProtocolParams--------");
}

static void GetProtocolParams003(const struct session_identity *identity, int32_t operationCode,
    struct hc_pin *pin, struct operation_parameter *para)
{
    LOG("--------GetProtocolParams--------");
    LOG("identity session_id[%d] package_name[%s]", identity->session_id, identity->package_name.name);
    LOG("operationCode[%d]", operationCode);
    pin->length = g_testPin.length;
    memcpy_s(pin->pin, pin->length, g_testPin.pin, pin->length);
    para->self_auth_id = g_testServerAuthId;
    para->peer_auth_id = g_testClientAuthId003;
    para->key_length = KEY_LEN;
    LOG("--------GetProtocolParams--------");
}

static void GetProtocolParams004(const struct session_identity *identity, int32_t operationCode,
    struct hc_pin *pin, struct operation_parameter *para)
{
    LOG("--------GetProtocolParams--------");
    LOG("identity session_id[%d] package_name[%s]", identity->session_id, identity->package_name.name);
    LOG("operationCode[%d]", operationCode);
    pin->length = g_testPin.length;
    memcpy_s(pin->pin, pin->length, g_testPin.pin, pin->length);
    pin->length = KEY_LEN_ERROR;
    para->self_auth_id = g_testServerAuthId;
    para->peer_auth_id = g_testClientAuthId;
    para->key_length = KEY_LEN_ERROR;
    LOG("--------GetProtocolParams--------");
}

static void GetProtocolParams005(const struct session_identity *identity, int32_t operationCode,
    struct hc_pin *pin, struct operation_parameter *para)
{
    LOG("--------GetProtocolParams--------");
    LOG("identity session_id[%d] package_name[%s]", identity->session_id, identity->package_name.name);
    LOG("operationCode[%d]", operationCode);
    pin->length = g_testPin.length;
    memcpy_s(pin->pin, pin->length, g_testPin.pin, pin->length);
    pin->length = KEY_LEN_ERROR;
    para->self_auth_id = g_testServerAuthId002;
    para->peer_auth_id = g_testClientAuthId;
    para->key_length = KEY_LEN_ERROR;
    LOG("--------GetProtocolParams--------");
}

class GetInstanceTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void GetInstanceTest::SetUpTestCase(void) {}
void GetInstanceTest::TearDownTestCase(void) {}
void GetInstanceTest::SetUp()
{
    InitHcAuthId();
}
void GetInstanceTest::TearDown() {}

static HWTEST_F(GetInstanceTest, GetInstanceTest001, TestSize.Level2)
{
    LOG("--------DeviceAuthTest Test001--------");
    LOG("--------get_instance--------");

    struct hc_call_back callBack = {
        Transmit,
        GetProtocolParams,
        SetSessionKey,
        SetServiceResult,
        ConfirmReceiveRequest
    };

    hc_handle server = get_instance(&g_server_identity, HC_ACCESSORY, &callBack);
    ASSERT_TRUE(server != nullptr);
    struct hichain *hichainTest = reinterpret_cast<struct hichain *>(server);
    EXPECT_EQ(hichainTest->state, 0);
    destroy(&server);
    LOG("--------DeviceAuthTest Test001--------");
}

static HWTEST_F(GetInstanceTest, GetInstanceTest002, TestSize.Level2)
{
    LOG("--------DeviceAuthTest Test002--------");
    LOG("--------get_instance--------");

    struct hc_call_back callBack = {
        Transmit,
        GetProtocolParams,
        SetSessionKey,
        SetServiceResult,
        ConfirmReceiveRequest
    };

    hc_handle server = get_instance(&g_server_identity, HC_CENTRE, &callBack);
    struct hichain *hichainTest = reinterpret_cast<struct hichain *>(server);
    ASSERT_TRUE(server != nullptr);
    EXPECT_EQ(hichainTest->state, 0);
    destroy(&server);
    LOG("--------DeviceAuthTest Test002--------");
}

static HWTEST_F(GetInstanceTest, GetInstanceTest003, TestSize.Level2)
{
    LOG("--------DeviceAuthTest Test003--------");
    LOG("--------get_instance--------");

    struct session_identity serverIdentity = {
        0,
        {18, "testServer"},
        {strlen("testServer"), "testServer"},
        0
    };

    struct hc_call_back callBack = {
        Transmit,
        GetProtocolParams,
        SetSessionKey,
        SetServiceResult,
        ConfirmReceiveRequest
    };
    hc_handle server = get_instance(&serverIdentity, HC_CENTRE, &callBack);
    ASSERT_TRUE(server != nullptr);
    destroy(&server);
    LOG("--------DeviceAuthTest Test003--------");
}

static HWTEST_F(GetInstanceTest, GetInstanceTest004, TestSize.Level2)
{
    LOG("--------DeviceAuthTest Test004--------");
    LOG("--------get_instance--------");

    struct hc_call_back callBack = {
        nullptr,
        GetProtocolParams,
        SetSessionKey,
        SetServiceResult,
        ConfirmReceiveRequest
    };
    hc_handle server = get_instance(&g_server_identity, HC_CENTRE, &callBack);
    ASSERT_TRUE(server == nullptr);
    destroy(&server);
    LOG("--------DeviceAuthTest Test004--------");
}

static HWTEST_F(GetInstanceTest, GetInstanceTest005, TestSize.Level2)
{
    LOG("--------DeviceAuthTest Test005--------");
    LOG("--------get_instance--------");

    struct hc_call_back callBack = {
        Transmit,
        GetProtocolParams,
        SetSessionKey,
        SetServiceResult,
        ConfirmReceiveRequest
    };
    hc_handle server = get_instance(nullptr, HC_CENTRE, &callBack);
    ASSERT_TRUE(server == nullptr);
    destroy(&server);
    LOG("--------DeviceAuthTest Test005--------");
}

static HWTEST_F(GetInstanceTest, GetInstanceTest007, TestSize.Level2)
{
    LOG("--------DeviceAuthTest Test007--------");
    LOG("--------get_instance--------");

    struct hc_call_back callBack = {
        Transmit,
        GetProtocolParams001,
        SetSessionKey,
        SetServiceResult,
        ConfirmReceiveRequest
    };
    hc_handle server = get_instance(&g_server_identity, HC_CENTRE, &callBack);
    ASSERT_TRUE(server != nullptr);
    destroy(&server);
    LOG("--------DeviceAuthTest Test007--------");
}

static HWTEST_F(GetInstanceTest, GetInstanceTest008, TestSize.Level2)
{
    LOG("--------DeviceAuthTest Test008--------");
    LOG("--------get_instance--------");

    struct hc_call_back callBack = {
        Transmit,
        GetProtocolParams002,
        SetSessionKey,
        SetServiceResult,
        ConfirmReceiveRequest
    };
    hc_handle server = get_instance(&g_server_identity, HC_CENTRE, &callBack);
    ASSERT_TRUE(server != nullptr);
    destroy(&server);
    LOG("--------DeviceAuthTest Test008--------");
}

static HWTEST_F(GetInstanceTest, GetInstanceTest009, TestSize.Level2)
{
    LOG("--------DeviceAuthTest Test009--------");
    LOG("--------get_instance--------");

    struct hc_call_back callBack = {
        Transmit,
        GetProtocolParams003,
        SetSessionKey,
        SetServiceResult,
        ConfirmReceiveRequest
    };
    hc_handle server = get_instance(&g_server_identity, HC_CENTRE, &callBack);
    ASSERT_TRUE(server != nullptr);
    destroy(&server);
    LOG("--------DeviceAuthTest Test009--------");
}

static HWTEST_F(GetInstanceTest, GetInstanceTest010, TestSize.Level2)
{
    LOG("--------DeviceAuthTest Test010--------");
    LOG("--------get_instance--------");

    struct hc_call_back callBack = {
        Transmit,
        GetProtocolParams004,
        SetSessionKey,
        SetServiceResult,
        ConfirmReceiveRequest
    };
    hc_handle server = get_instance(&g_server_identity, HC_CENTRE, &callBack);
    ASSERT_TRUE(server != nullptr);
    destroy(&server);
    LOG("--------DeviceAuthTest Test010--------");
}

static HWTEST_F(GetInstanceTest, GetInstanceTest011, TestSize.Level2)
{
    LOG("--------DeviceAuthTest Test011--------");
    LOG("--------get_instance--------");

    struct hc_call_back callBack = {
        Transmit,
        nullptr,
        SetSessionKey,
        SetServiceResult,
        ConfirmReceiveRequest
    };
    hc_handle server = get_instance(&g_server_identity, HC_CENTRE, &callBack);
    ASSERT_TRUE(server == nullptr);
    destroy(&server);
    LOG("--------DeviceAuthTest Test011--------");
}

static HWTEST_F(GetInstanceTest, GetInstanceTest012, TestSize.Level2)
{
    LOG("--------DeviceAuthTest Test012--------");
    LOG("--------get_instance--------");

    struct hc_call_back callBack = {
        Transmit,
        GetProtocolParams,
        nullptr,
        SetServiceResult,
        ConfirmReceiveRequest
    };
    hc_handle server = get_instance(&g_server_identity, HC_CENTRE, &callBack);
    ASSERT_TRUE(server == nullptr);
    destroy(&server);
    LOG("--------DeviceAuthTest Test012--------");
}

static HWTEST_F(GetInstanceTest, GetInstanceTest013, TestSize.Level2)
{
    LOG("--------DeviceAuthTest Test013--------");
    LOG("--------get_instance--------");

    struct hc_call_back callBack = {
        Transmit,
        GetProtocolParams,
        SetSessionKey,
        nullptr,
        ConfirmReceiveRequest
    };
    hc_handle server = get_instance(&g_server_identity, HC_CENTRE, &callBack);
    ASSERT_TRUE(server == nullptr);
    destroy(&server);
    LOG("--------DeviceAuthTest Test013--------");
}

static HWTEST_F(GetInstanceTest, GetInstanceTest014, TestSize.Level2)
{
    LOG("--------DeviceAuthTest Test014--------");
    LOG("--------get_instance--------");

    struct hc_call_back callBack = {
        Transmit,
        GetProtocolParams,
        SetSessionKey,
        SetServiceResult,
        nullptr
    };
    hc_handle server = get_instance(&g_server_identity, HC_CENTRE, &callBack);
    ASSERT_TRUE(server == nullptr);
    destroy(&server);
    LOG("--------DeviceAuthTest Test014--------");
}

static HWTEST_F(GetInstanceTest, GetInstanceTest015, TestSize.Level2)
{
    LOG("--------DeviceAuthTest Test015--------");
    LOG("--------get_instance--------");

    struct hc_call_back callBack = {
        Transmit,
        GetProtocolParams,
        SetSessionKey,
        SetServiceResult,
        ConfirmReceiveRequest
    };
    hc_handle server = get_instance(&g_server_identity001, HC_CENTRE, &callBack);
    ASSERT_TRUE(server == nullptr);
    destroy(&server);
    LOG("--------DeviceAuthTest Test015--------");
}

static HWTEST_F(GetInstanceTest, GetInstanceTest016, TestSize.Level2)
{
    LOG("--------DeviceAuthTest Test016--------");
    LOG("--------get_instance--------");

    struct hc_call_back callBack = {
        Transmit,
        GetProtocolParams,
        SetSessionKey,
        SetServiceResult,
        ConfirmReceiveRequest
    };
    hc_handle server = get_instance(&g_server_identity002, HC_CENTRE, &callBack);
    ASSERT_TRUE(server == nullptr);
    destroy(&server);
    LOG("--------DeviceAuthTest Test016--------");
}

static HWTEST_F(GetInstanceTest, GetInstanceTest017, TestSize.Level2)
{
    LOG("--------DeviceAuthTest Test017--------");
    LOG("--------get_instance--------");

    struct hc_call_back callBack = {
        Transmit,
        GetProtocolParams,
        SetSessionKey,
        SetServiceResult,
        ConfirmReceiveRequest
    };
    hc_handle server = get_instance(&g_server_identity003, HC_CENTRE, &callBack);
    ASSERT_TRUE(server == nullptr);
    destroy(&server);
    LOG("--------DeviceAuthTest Test017--------");
}

/*--------------------------start_pake------------------------*/
class StartPakeTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void StartPakeTest::SetUpTestCase(void) {}
void StartPakeTest::TearDownTestCase(void) {}
void StartPakeTest::SetUp()
{
    InitHcAuthId();
}
void StartPakeTest::TearDown() {}

static HWTEST_F(StartPakeTest, StartPakeTest001, TestSize.Level2)
{
    LOG("--------StartPakeTest StartPakeTest001--------");
    LOG("--------start_pake--------");
    struct hc_call_back callBack = {
        Transmit,
        GetProtocolParams,
        SetSessionKey,
        SetServiceResult,
        ConfirmReceiveRequest
    };
    hc_handle server = get_instance(&g_server_identity, HC_ACCESSORY, &callBack);
    const struct operation_parameter params = {g_testServerAuthId, g_testClientAuthId, KEY_LEN};
    int32_t ret = start_pake(server, &params);
    EXPECT_EQ(ret, HC_OK);
    destroy(&server);
    LOG("--------StartPakeTest StartPakeTest001--------");
}

static HWTEST_F(StartPakeTest, StartPakeTest002, TestSize.Level2)
{
    LOG("--------StartPakeTest StartPakeTest002--------");
    LOG("--------start_pake--------");
    struct hc_call_back callBack = {
        Transmit,
        GetProtocolParams,
        SetSessionKey,
        SetServiceResult,
        ConfirmReceiveRequest
    };
    hc_handle server = get_instance(&g_server_identity, HC_CENTRE, &callBack);
    ASSERT_TRUE(server != nullptr);
    const struct operation_parameter params = {g_testServerAuthId, g_testClientAuthId, KEY_LEN};
    int32_t ret = start_pake(nullptr, &params);
    EXPECT_NE(ret, HC_OK);
    destroy(&server);
    LOG("--------StartPakeTest StartPakeTest002--------");
}

static HWTEST_F(StartPakeTest, StartPakeTest003, TestSize.Level2)
{
    LOG("--------StartPakeTest StartPakeTest003--------");
    LOG("--------start_pake--------");
    struct hc_call_back callBack = {
        Transmit,
        GetProtocolParams,
        SetSessionKey,
        SetServiceResult,
        ConfirmReceiveRequest
    };
    hc_handle server = get_instance(&g_server_identity, HC_CENTRE, &callBack);
    ASSERT_TRUE(server != nullptr);
    int32_t ret = start_pake(server, nullptr);
    EXPECT_NE(ret, HC_OK);
    destroy(&server);
    LOG("--------StartPakeTest StartPakeTest003--------");
}

static HWTEST_F(StartPakeTest, StartPakeTest004, TestSize.Level2)
{
    LOG("--------StartPakeTest StartPakeTest004--------");
    LOG("--------start_pake--------");
    struct hc_call_back callBack = {
        Transmit,
        GetProtocolParams,
        SetSessionKey,
        SetServiceResult,
        ConfirmReceiveRequest
    };
    hc_handle server = get_instance(&g_server_identity, HC_CENTRE, &callBack);
    ASSERT_TRUE(server != nullptr);
    struct pake_client *pakeClient = static_cast<struct pake_client *>(MALLOC(sizeof(struct pake_client)));
    (void)memset_s(pakeClient, sizeof(struct pake_client), 0, sizeof(struct pake_client));

    struct operation_parameter *params =
        static_cast<struct operation_parameter *>(MALLOC(sizeof(struct operation_parameter)));
    (void)memset_s(params, sizeof(struct operation_parameter), 0, sizeof(struct operation_parameter));

    struct hichain *hichainTest = static_cast<struct hichain *>(server);
    hichainTest->pake_client = pakeClient;

    int32_t ret = start_pake(server, params);
    EXPECT_NE(ret, HC_OK);
    destroy(&server);
    FREE(params);
    params = nullptr;
    LOG("--------StartPakeTest StartPakeTest004--------");
}

static HWTEST_F(StartPakeTest, StartPakeTest005, TestSize.Level2)
{
    LOG("--------StartPakeTest StartPakeTest005--------");
    LOG("--------start_pake--------");
    struct hc_call_back callBack = {
        Transmit,
        GetProtocolParams001,
        SetSessionKey,
        SetServiceResult,
        ConfirmReceiveRequest
    };
    hc_handle server = get_instance(&g_server_identity, HC_CENTRE, &callBack);
    ASSERT_TRUE(server != nullptr);
    const struct operation_parameter params = {g_testServerAuthId, g_testClientAuthId, KEY_LEN};
    int32_t ret = start_pake(server, &params);
    EXPECT_NE(ret, HC_OK);
    destroy(&server);
    LOG("--------StartPakeTest StartPakeTest005--------");
}

static HWTEST_F(StartPakeTest, StartPakeTest006, TestSize.Level2)
{
    LOG("--------StartPakeTest StartPakeTest006--------");
    LOG("--------start_pake--------");
    struct hc_call_back callBack = {
        Transmit,
        GetProtocolParams002,
        SetSessionKey,
        SetServiceResult,
        ConfirmReceiveRequest
    };
    hc_handle server = get_instance(&g_server_identity, HC_CENTRE, &callBack);
    ASSERT_TRUE(server != nullptr);
    const struct operation_parameter params = {g_testServerAuthId003, g_testClientAuthId, KEY_LEN};
    int32_t ret = start_pake(server, &params);
    EXPECT_NE(ret, HC_OK);
    destroy(&server);
    LOG("--------StartPakeTest StartPakeTest006--------");
}

static HWTEST_F(StartPakeTest, StartPakeTest007, TestSize.Level2)
{
    LOG("--------StartPakeTest StartPakeTest007--------");
    LOG("--------start_pake--------");
    struct hc_call_back callBack = {
        Transmit,
        GetProtocolParams003,
        SetSessionKey,
        SetServiceResult,
        ConfirmReceiveRequest
    };
    hc_handle server = get_instance(&g_server_identity, HC_CENTRE, &callBack);
    ASSERT_TRUE(server != nullptr);
    const struct operation_parameter params = {g_testServerAuthId003, g_testClientAuthId, KEY_LEN};
    int32_t ret = start_pake(server, &params);
    EXPECT_NE(ret, HC_OK);
    destroy(&server);
    LOG("--------StartPakeTest StartPakeTest007--------");
}

static HWTEST_F(StartPakeTest, StartPakeTest008, TestSize.Level2)
{
    LOG("--------StartPakeTest StartPakeTest008--------");
    LOG("--------start_pake--------");
    struct hc_call_back callBack = {
        Transmit,
        GetProtocolParams004,
        SetSessionKey,
        SetServiceResult,
        ConfirmReceiveRequest
    };
    hc_handle server = get_instance(&g_server_identity, HC_CENTRE, &callBack);
    ASSERT_TRUE(server != nullptr);
    const struct operation_parameter params = {g_testServerAuthId, g_testClientAuthId, KEY_LEN};
    int32_t ret = start_pake(server, &params);
    EXPECT_NE(ret, HC_OK);
    destroy(&server);
    LOG("--------StartPakeTest StartPakeTest008--------");
}

static HWTEST_F(StartPakeTest, StartPakeTest009, TestSize.Level2)
{
    LOG("--------StartPakeTest StartPakeTest009--------");
    LOG("--------build_object--------");
    struct hc_call_back callBack = {
        Transmit,
        GetProtocolParams,
        SetSessionKey,
        SetServiceResult,
        ConfirmReceiveRequest
    };
    hc_handle server = get_instance(&g_server_identity, HC_CENTRE, &callBack);
    ASSERT_TRUE(server != nullptr);
    struct hichain *hichainTest = static_cast<struct hichain *>(server);
    const struct operation_parameter params = {g_testServerAuthId, g_testClientAuthId, KEY_LEN};
    int32_t ret = build_object(hichainTest, PAKE_MODULAR, true, &params);
    EXPECT_EQ(ret, HC_OK);
    destroy(&server);
    LOG("--------StartPakeTest StartPakeTest009--------");
}

static HWTEST_F(StartPakeTest, StartPakeTest010, TestSize.Level2)
{
    LOG("--------StartPakeTest StartPakeTest010--------");
    LOG("--------build_object--------");
    struct hc_call_back callBack = {
        Transmit,
        GetProtocolParams,
        SetSessionKey,
        SetServiceResult,
        ConfirmReceiveRequest
    };
    hc_handle server = get_instance(&g_server_identity, HC_CENTRE, &callBack);
    ASSERT_TRUE(server != nullptr);
    struct hichain *hichainTest = static_cast<struct hichain *>(server);
    const struct operation_parameter *params = nullptr;
    int32_t ret = build_object(hichainTest, SEC_CLONE_MODULAR, false, params);
    EXPECT_NE(ret, HC_OK);
    destroy(&server);
    LOG("--------StartPakeTest StartPakeTest010--------");
}

static HWTEST_F(StartPakeTest, StartPakeTest011, TestSize.Level2)
{
    LOG("--------StartPakeTest StartPakeTest011--------");
    LOG("--------build_object--------");
    struct hc_call_back callBack = {
        Transmit,
        GetProtocolParams,
        SetSessionKey,
        SetServiceResult,
        ConfirmReceiveRequest
    };
    hc_handle server = get_instance(&g_server_identity, HC_CENTRE, &callBack);
    ASSERT_TRUE(server != nullptr);
    struct hichain *hichainTest = static_cast<struct hichain *>(server);
    const struct operation_parameter *params = nullptr;
    int32_t ret = build_object(hichainTest, REMOVE_MODULAR, true, params);
    EXPECT_NE(ret, HC_OK);
    destroy(&server);
    LOG("--------StartPakeTest StartPakeTest011--------");
}

static HWTEST_F(StartPakeTest, StartPakeTest012, TestSize.Level2)
{
    LOG("--------StartPakeTest StartPakeTest012--------");
    LOG("--------build_object--------");
    struct hc_call_back callBack = {
        Transmit,
        GetProtocolParams,
        SetSessionKey,
        SetServiceResult,
        ConfirmReceiveRequest
    };
    hc_handle server = get_instance(&g_server_identity, HC_CENTRE, &callBack);
    ASSERT_TRUE(server != nullptr);
    struct hichain *hichainTest = static_cast<struct hichain *>(server);
    const struct operation_parameter params = {g_testServerAuthId, g_testClientAuthId, KEY_LEN};
    int32_t ret = build_object(hichainTest, STS_MODULAR, true, &params);
    EXPECT_EQ(ret, HC_OK);
    destroy(&server);
    LOG("--------StartPakeTest StartPakeTest012--------");
}

static HWTEST_F(StartPakeTest, StartPakeTest013, TestSize.Level2)
{
    LOG("--------StartPakeTest StartPakeTest013--------");
    LOG("--------build_object--------");
    struct hc_call_back callBack = {
        Transmit,
        GetProtocolParams,
        SetSessionKey,
        SetServiceResult,
        ConfirmReceiveRequest
    };
    hc_handle server = get_instance(&g_server_identity, HC_CENTRE, &callBack);
    ASSERT_TRUE(server != nullptr);
    struct hichain *hichainTest = static_cast<struct hichain *>(server);
    const struct operation_parameter params = {g_testServerAuthId, g_testClientAuthId, KEY_LEN};
    int32_t ret = build_object(hichainTest, STS_MODULAR, true, &params);
    EXPECT_EQ(ret, HC_OK);
    destroy(&server);
    LOG("--------StartPakeTest StartPakeTest013--------");
}

static HWTEST_F(StartPakeTest, StartPakeTest014, TestSize.Level2)
{
    LOG("--------StartPakeTest StartPakeTest014--------");
    LOG("--------build_object--------");
    struct hc_call_back callBack = {
        Transmit,
        GetProtocolParams,
        SetSessionKey,
        SetServiceResult,
        ConfirmReceiveRequest
    };
    hc_handle server = get_instance(&g_server_identity, HC_CENTRE, &callBack);
    ASSERT_TRUE(server != nullptr);
    struct hichain *hichainTest = static_cast<struct hichain *>(server);
    const struct operation_parameter params = {g_testServerAuthId, g_testClientAuthId, KEY_LEN};
    int32_t ret = build_object(hichainTest, INVALID_MODULAR, true, &params);
    EXPECT_EQ(ret, HC_OK);
    destroy(&server);
    LOG("--------StartPakeTest StartPakeTest014--------");
}

static HWTEST_F(StartPakeTest, StartPakeTest015, TestSize.Level2)
{
    LOG("--------StartPakeTest StartPakeTest015--------");
    LOG("--------build_object--------");
    struct hc_call_back callBack = {
        Transmit,
        GetProtocolParams,
        SetSessionKey,
        SetServiceResult,
        ConfirmReceiveRequest
    };
    hc_handle server = get_instance(&g_server_identity, HC_CENTRE, &callBack);
    ASSERT_TRUE(server != nullptr);
    struct hichain *hichainTest = static_cast<struct hichain *>(server);
    const struct operation_parameter params = {g_testServerAuthId, g_testClientAuthId, KEY_LEN};
    int32_t ret = build_object(hichainTest, INVALID_MODULAR, false, &params);
    EXPECT_EQ(ret, HC_OK);
    destroy(&server);
    LOG("--------StartPakeTest StartPakeTest015--------");
}

/*--------------------------authenticate_peer------------------------*/
class AuthenticatePeerTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void AuthenticatePeerTest::SetUpTestCase(void) {}
void AuthenticatePeerTest::TearDownTestCase(void) {}
void AuthenticatePeerTest::SetUp()
{
    InitHcAuthId();
}
void AuthenticatePeerTest::TearDown() {}

static HWTEST_F(AuthenticatePeerTest, AuthenticatePeerTest001, TestSize.Level2)
{
    LOG("--------AuthenticatePeerTest AuthenticatePeerTest001--------");
    LOG("--------authenticate_peer--------");
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
    destroy(&server);
    LOG("--------AuthenticatePeerTest AuthenticatePeerTest001--------");
}

static HWTEST_F(AuthenticatePeerTest, AuthenticatePeerTest002, TestSize.Level2)
{
    LOG("--------AuthenticatePeerTest AuthenticatePeerTest002--------");
    LOG("--------authenticate_peer--------");
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
    int32_t ret = authenticate_peer(nullptr, &params);
    EXPECT_NE(ret, HC_OK);
    destroy(&server);
    LOG("--------AuthenticatePeerTest AuthenticatePeerTest002--------");
}

static HWTEST_F(AuthenticatePeerTest, AuthenticatePeerTest003, TestSize.Level2)
{
    LOG("--------AuthenticatePeerTest AuthenticatePeerTest003--------");
    LOG("--------authenticate_peer--------");
    struct hc_call_back callBack = {
        Transmit,
        GetProtocolParams,
        SetSessionKey,
        SetServiceResult,
        ConfirmReceiveRequest
    };
    hc_handle server = get_instance(&g_server_identity, HC_CENTRE, &callBack);
    ASSERT_TRUE(server != nullptr);
    int32_t ret = authenticate_peer(server, nullptr);
    EXPECT_NE(ret, HC_OK);
    destroy(&server);
    LOG("--------AuthenticatePeerTest AuthenticatePeerTest003--------");
}

static HWTEST_F(AuthenticatePeerTest, AuthenticatePeerTest004, TestSize.Level2)
{
    LOG("--------AuthenticatePeerTest AuthenticatePeerTest004--------");
    LOG("--------authenticate_peer--------");
    struct hc_call_back callBack = {
        Transmit,
        GetProtocolParams,
        SetSessionKey,
        SetServiceResult,
        ConfirmReceiveRequest
    };
    hc_handle server = get_instance(&g_server_identity, HC_CENTRE, &callBack);
    ASSERT_TRUE(server != nullptr);

    struct sts_client *stsClient = static_cast<struct sts_client *>(MALLOC(sizeof(struct sts_client)));
    (void)memset_s(stsClient, sizeof(struct sts_client), 0, sizeof(struct sts_client));

    struct operation_parameter *params =
        static_cast<struct operation_parameter *>(MALLOC(sizeof(struct operation_parameter)));
    (void)memset_s(params, sizeof(struct operation_parameter), 0, sizeof(struct operation_parameter));

    struct hichain *hichainTest = static_cast<struct hichain *>(server);
    hichainTest->sts_client = stsClient;
    int32_t ret = authenticate_peer(server, params);
    EXPECT_NE(ret, HC_OK);
    destroy(&server);
    FREE(params);
    params = nullptr;
    LOG("--------AuthenticatePeerTest AuthenticatePeerTest004--------");
}

static HWTEST_F(AuthenticatePeerTest, AuthenticatePeerTest005, TestSize.Level2)
{
    LOG("--------AuthenticatePeerTest AuthenticatePeerTest005--------");
    LOG("--------authenticate_peer--------");
    struct hc_call_back callBack = {
        Transmit,
        GetProtocolParams001,
        SetSessionKey,
        SetServiceResult,
        ConfirmReceiveRequest
    };
    hc_handle server = get_instance(&g_server_identity, HC_CENTRE, &callBack);
    ASSERT_TRUE(server != nullptr);
    struct hichain *hichainTest = static_cast<struct hichain *>(server);
    ASSERT_TRUE(hichainTest->sts_client == nullptr);

    struct operation_parameter *params =
        static_cast<struct operation_parameter *>(MALLOC(sizeof(struct operation_parameter)));
    (void)memset_s(params, sizeof(struct operation_parameter), 0, sizeof(struct operation_parameter));
    int32_t ret = authenticate_peer(server, params);
    EXPECT_EQ(ret, HC_OK);
    destroy(&server);
    FREE(params);
    params = nullptr;
    LOG("--------AuthenticatePeerTest AuthenticatePeerTest005--------");
}

static HWTEST_F(AuthenticatePeerTest, AuthenticatePeerTest006, TestSize.Level2)
{
    LOG("--------AuthenticatePeerTest AuthenticatePeerTest006--------");
    LOG("--------authenticate_peer--------");
    struct hc_call_back callBack = {
        Transmit,
        GetProtocolParams002,
        SetSessionKey,
        SetServiceResult,
        ConfirmReceiveRequest
    };
    hc_handle server = get_instance(&g_server_identity, HC_CENTRE, &callBack);
    ASSERT_TRUE(server != nullptr);
    struct hichain *hichainTest = static_cast<struct hichain *>(server);
    ASSERT_TRUE(hichainTest->sts_client == nullptr);
    struct operation_parameter params = {g_testServerAuthId003, g_testClientAuthId, KEY_LEN};
    int32_t ret = authenticate_peer(server, &params);
    EXPECT_EQ(ret, HC_OK);
    destroy(&server);
    LOG("--------AuthenticatePeerTest AuthenticatePeerTest006--------");
}

static HWTEST_F(AuthenticatePeerTest, AuthenticatePeerTest007, TestSize.Level2)
{
    LOG("--------AuthenticatePeerTest AuthenticatePeerTest007--------");
    LOG("--------authenticate_peer--------");
    struct hc_call_back callBack = {
        Transmit,
        GetProtocolParams003,
        SetSessionKey,
        SetServiceResult,
        ConfirmReceiveRequest
    };
    hc_handle server = get_instance(&g_server_identity, HC_CENTRE, &callBack);
    ASSERT_TRUE(server != nullptr);
    struct hichain *hichainTest = static_cast<struct hichain *>(server);
    ASSERT_TRUE(hichainTest->sts_client == nullptr);
    struct operation_parameter params = {g_testServerAuthId, g_testClientAuthId003, KEY_LEN};
    int32_t ret = authenticate_peer(server, &params);
    EXPECT_EQ(ret, HC_OK);
    destroy(&server);
    LOG("--------AuthenticatePeerTest AuthenticatePeerTest007--------");
}

static HWTEST_F(AuthenticatePeerTest, AuthenticatePeerTest008, TestSize.Level2)
{
    LOG("--------AuthenticatePeerTest AuthenticatePeerTest008--------");
    LOG("--------authenticate_peer--------");
    struct hc_call_back callBack = {
        Transmit,
        GetProtocolParams004,
        SetSessionKey,
        SetServiceResult,
        ConfirmReceiveRequest
    };
    hc_handle server = get_instance(&g_server_identity, HC_CENTRE, &callBack);
    ASSERT_TRUE(server != nullptr);
    struct hichain *hichainTest = static_cast<struct hichain *>(server);
    ASSERT_TRUE(hichainTest->sts_client == nullptr);
    struct operation_parameter params = {g_testServerAuthId003, g_testClientAuthId003, KEY_LEN};
    int32_t ret = authenticate_peer(server, &params);
    EXPECT_EQ(ret, HC_OK);
    destroy(&server);
    LOG("--------AuthenticatePeerTest AuthenticatePeerTest008--------");
}

/*--------------------------list_trust_peer------------------------*/
class ListTrustPeersTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void ListTrustPeersTest::SetUpTestCase(void) {}
void ListTrustPeersTest::TearDownTestCase(void) {}
void ListTrustPeersTest::SetUp()
{
    InitHcAuthId();
}
void ListTrustPeersTest::TearDown() {}

static HWTEST_F(ListTrustPeersTest, ListTrustPeersTest001, TestSize.Level2)
{
    LOG("--------ListTrustPeersTest ListTrustPeersTest001--------");
    LOG("--------list_trust_peers--------");
    struct hc_call_back callBack = {
        Transmit,
        GetProtocolParams,
        SetSessionKey,
        SetServiceResult,
        ConfirmReceiveRequest
    };
    hc_handle server = get_instance(&g_server_identity, HC_CENTRE, &callBack);
    int ret = list_trust_peers(server, HC_USER_TYPE_ACCESSORY, &g_testClientAuthId, g_authIdList);
    EXPECT_EQ(ret, 0);
    destroy(&server);
    LOG("--------ListTrustPeersTest ListTrustPeersTest001--------");
}

static HWTEST_F(ListTrustPeersTest, ListTrustPeersTest002, TestSize.Level2)
{
    LOG("--------ListTrustPeersTest ListTrustPeersTest002--------");
    LOG("--------list_trust_peers--------");
    int ret = list_trust_peers(nullptr, HC_USER_TYPE_ACCESSORY, &g_testClientAuthId, g_authIdList);
    EXPECT_EQ(ret, 0);
    LOG("--------ListTrustPeersTest ListTrustPeersTest002--------");
}

static HWTEST_F(ListTrustPeersTest, ListTrustPeersTest003, TestSize.Level2)
{
    LOG("--------ListTrustPeersTest ListTrustPeersTest003--------");
    LOG("--------list_trust_peers--------");
    struct hc_call_back callBack = {
        Transmit,
        GetProtocolParams,
        SetSessionKey,
        SetServiceResult,
        ConfirmReceiveRequest
    };
    hc_handle server = get_instance(&g_server_identity, HC_CENTRE, &callBack);
    int ret = list_trust_peers(server, 2, &g_testClientAuthId, g_authIdList);
    EXPECT_EQ(ret, 0);
    destroy(&server);
    LOG("--------ListTrustPeersTest ListTrustPeersTest003--------");
}

static HWTEST_F(ListTrustPeersTest, ListTrustPeersTest004, TestSize.Level2)
{
    LOG("--------ListTrustPeersTest ListTrustPeersTest004--------");
    LOG("--------list_trust_peers--------");
    struct hc_call_back callBack = {
        Transmit,
        GetProtocolParams,
        SetSessionKey,
        SetServiceResult,
        ConfirmReceiveRequest
    };
    hc_handle server = get_instance(&g_server_identity, HC_CENTRE, &callBack);
    int ret = list_trust_peers(server, 0, nullptr, g_authIdList);
    LOG("--------trust peers num is %d--------", ret);
    EXPECT_TRUE(server != nullptr);
    destroy(&server);
    LOG("--------ListTrustPeersTest ListTrustPeersTest004--------");
}

/*--------------------------destroy------------------------*/
class DestroyTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void DestroyTest::SetUpTestCase(void) {}
void DestroyTest::TearDownTestCase(void) {}
void DestroyTest::SetUp()
{
    InitHcAuthId();
}
void DestroyTest::TearDown() {}

static HWTEST_F(DestroyTest, DestroyTest001, TestSize.Level2)
{
    LOG("--------DestroyTest DestroyTest001--------");
    LOG("--------destory--------");
    struct hc_call_back callBack = {
        Transmit,
        GetProtocolParams,
        SetSessionKey,
        SetServiceResult,
        ConfirmReceiveRequest
    };
    hc_handle val = get_instance(&g_server_identity, HC_CENTRE, &callBack);
    destroy(&val);
    EXPECT_TRUE(val == nullptr);
    LOG("--------DestroyTest DestroyTest001--------");
}

static HWTEST_F(DestroyTest, DestroyTest002, TestSize.Level2)
{
    LOG("--------DestroyTest DestroyTest002--------");
    LOG("--------destory--------");
    struct hc_call_back callBack = {
        nullptr,
        GetProtocolParams,
        SetSessionKey,
        SetServiceResult,
        ConfirmReceiveRequest
    };
    hc_handle val = get_instance(&g_server_identity, HC_CENTRE, &callBack);
    ASSERT_TRUE(val == nullptr);
    destroy(&val);
    EXPECT_TRUE(val == nullptr);
    LOG("--------DestroyTest DestroyTest002--------");
}

static HWTEST_F(DestroyTest, DestroyTest003, TestSize.Level2)
{
    LOG("--------DestroyTest DestroyTest003--------");
    LOG("--------destory--------");
    struct hichain *server = static_cast<struct hichain *>(MALLOC(sizeof(struct hichain)));
    (void)memset_s(server, sizeof(struct hichain), 0, sizeof(struct hichain));

    hc_handle serverTest = static_cast<hc_handle>(server);
    destroy(&serverTest);
    EXPECT_TRUE(serverTest == nullptr);
    LOG("--------DestroyTest DestroyTest003--------");
}

static HWTEST_F(DestroyTest, DestroyTest004, TestSize.Level2)
{
    LOG("--------DestroyTest DestroyTest004--------");
    LOG("--------destory--------");
    struct hichain *server = static_cast<struct hichain *>(MALLOC(sizeof(struct hichain)));
    (void)memset_s(server, sizeof(struct hichain), 0, sizeof(struct hichain));

    struct pake_server *pakeServer = static_cast<struct pake_server *>(MALLOC(sizeof(struct pake_server)));
    (void)memset_s(pakeServer, sizeof(struct pake_server), 0, sizeof(struct pake_server));

    server->pake_server = pakeServer;
    hc_handle serverTest = static_cast<hc_handle>(server);
    destroy(&serverTest);
    EXPECT_TRUE(serverTest == nullptr);
    LOG("--------DestroyTest DestroyTest004--------");
}

static HWTEST_F(DestroyTest, DestroyTest005, TestSize.Level2)
{
    LOG("--------DestroyTest DestroyTest005--------");
    LOG("--------destory--------");
    struct hichain *server = static_cast<struct hichain *>(MALLOC(sizeof(struct hichain)));
    (void)memset_s(server, sizeof(struct hichain), 0, sizeof(struct hichain));

    struct sts_server *stsServer = static_cast<struct sts_server *>(MALLOC(sizeof(struct sts_server)));
    (void)memset_s(stsServer, sizeof(struct sts_server), 0, sizeof(struct sts_server));

    server->sts_server = stsServer;
    hc_handle serverTest = static_cast<hc_handle>(server);
    destroy(&serverTest);
    EXPECT_TRUE(serverTest == nullptr);
    LOG("--------DestroyTest DestroyTest005--------");
}

static HWTEST_F(DestroyTest, DestroyTest006, TestSize.Level2)
{
    LOG("--------DestroyTest DestroyTest006--------");
    LOG("--------destory--------");
    struct hichain *server = static_cast<struct hichain *>(MALLOC(sizeof(struct hichain)));
    (void)memset_s(server, sizeof(struct hichain), 0, sizeof(struct hichain));

    struct sts_client *stsClient = static_cast<struct sts_client *>(MALLOC(sizeof(struct sts_client)));
    (void)memset_s(stsClient, sizeof(struct sts_client), 0, sizeof(struct sts_client));

    server->sts_client = stsClient;
    hc_handle serverTest = static_cast<hc_handle>(server);
    destroy(&serverTest);
    EXPECT_TRUE(serverTest == nullptr);
    LOG("--------DestroyTest DestroyTest006--------");
}

static HWTEST_F(DestroyTest, DestroyTest007, TestSize.Level2)
{
    LOG("--------DestroyTest DestroyTest007--------");
    LOG("--------destory--------");
    struct hichain *server = static_cast<struct hichain *>(MALLOC(sizeof(struct hichain)));
    (void)memset_s(server, sizeof(struct hichain), 0, sizeof(struct hichain));

    struct auth_info_cache *authInfo = static_cast<struct auth_info_cache *>(MALLOC(sizeof(struct auth_info_cache)));
    (void)memset_s(authInfo, sizeof(struct auth_info_cache), 0, sizeof(struct auth_info_cache));

    server->auth_info = authInfo;
    hc_handle serverTest = static_cast<hc_handle>(server);
    destroy(&serverTest);
    EXPECT_TRUE(serverTest == nullptr);
    LOG("--------DestroyTest DestroyTest007--------");
}

static HWTEST_F(DestroyTest, DestroyTest008, TestSize.Level2)
{
    LOG("--------DestroyTest DestroyTest008--------");
    LOG("--------destory--------");
    struct hichain *server = static_cast<struct hichain *>(MALLOC(sizeof(struct hichain)));
    (void)memset_s(server, sizeof(struct hichain), 0, sizeof(struct hichain));

    struct sec_clone_server *secCloneServer =
        static_cast<struct sec_clone_server *>(MALLOC(sizeof(struct sec_clone_server)));
    (void)memset_s(secCloneServer, sizeof(struct sec_clone_server), 0, sizeof(struct sec_clone_server));

    server->sec_clone_server = secCloneServer;
    hc_handle serverTest = static_cast<hc_handle>(server);
    destroy(&serverTest);
    EXPECT_TRUE(serverTest == nullptr);
    LOG("--------DestroyTest DestroyTest008--------");
}

/*--------------------------delete_local_auth_info------------------------*/
class DeleteLocalAuthInfoTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void DeleteLocalAuthInfoTest::SetUpTestCase(void) {}
void DeleteLocalAuthInfoTest::TearDownTestCase(void) {}
void DeleteLocalAuthInfoTest::SetUp()
{
    InitHcAuthId();
}
void DeleteLocalAuthInfoTest::TearDown() {}

static HWTEST_F(DeleteLocalAuthInfoTest, DeleteLocalAuthInfoTest001, TestSize.Level2)
{
    LOG("--------DeleteLocalAuthInfoTest DeleteLocalAuthInfoTest001--------");
    LOG("--------DeleteLocalAuthInfo--------");
    struct hc_call_back callBack = {
        Transmit,
        GetProtocolParams,
        SetSessionKey,
        SetServiceResult,
        ConfirmReceiveRequest
    };
    hc_handle server = get_instance(&g_server_identity, HC_CENTRE, &callBack);
    ASSERT_TRUE(server != nullptr);

    struct hc_user_info car_user_info = {
        g_testServerAuthId,
        1
    };
    int32_t trustedPeersNum = delete_local_auth_info(server, &car_user_info);
    EXPECT_EQ(trustedPeersNum, 0);

    destroy(&server);
    LOG("--------DeleteLocalAuthInfoTest DeleteLocalAuthInfoTest001--------");
}

static HWTEST_F(DeleteLocalAuthInfoTest, DeleteLocalAuthInfoTest002, TestSize.Level2)
{
    LOG("--------DeleteLocalAuthInfoTest DeleteLocalAuthInfoTest002--------");
    LOG("--------DeleteLocalAuthInfo--------");
    struct hc_call_back callBack = {
        Transmit,
        GetProtocolParams,
        SetSessionKey,
        SetServiceResult,
        ConfirmReceiveRequest
    };
    hc_handle server = get_instance(&g_server_identity, HC_CENTRE, &callBack);
    ASSERT_TRUE(server != nullptr);

    int32_t trustedPeersNum = delete_local_auth_info(server, nullptr);
    EXPECT_NE(trustedPeersNum, 0);

    destroy(&server);
    LOG("--------DeleteLocalAuthInfoTest DeleteLocalAuthInfoTest002--------");
}

static HWTEST_F(DeleteLocalAuthInfoTest, DeleteLocalAuthInfoTest003, TestSize.Level2)
{
    LOG("--------DeleteLocalAuthInfoTest DeleteLocalAuthInfoTest003--------");
    LOG("--------DeleteLocalAuthInfo--------");
    struct hc_call_back callBack = {
        Transmit,
        GetProtocolParams,
        SetSessionKey,
        SetServiceResult,
        ConfirmReceiveRequest
    };

    struct hc_user_info userInfo = {
        g_testServerAuthId,
        HC_USER_TYPE_ACCESSORY
    };

    hc_handle server = get_instance(&g_server_identity, HC_CENTRE, &callBack);
    ASSERT_TRUE(server != nullptr);
    struct hichain *hichainTest = static_cast<struct hichain *>(server);
    hichainTest->identity.service_type.length = 0;
    ASSERT_EQ(hichainTest->identity.service_type.length, 0);
    int32_t trustedPeersNum = delete_local_auth_info(server, &userInfo);
    EXPECT_NE(trustedPeersNum, 0);
    destroy(&server);
    LOG("--------DeleteLocalAuthInfoTest DeleteLocalAuthInfoTest003--------");
}

static HWTEST_F(DeleteLocalAuthInfoTest, DeleteLocalAuthInfoTest004, TestSize.Level2)
{
    LOG("--------DeleteLocalAuthInfoTest DeleteLocalAuthInfoTest004--------");
    LOG("--------DeleteLocalAuthInfo--------");
    struct hc_call_back callBack = {
        Transmit,
        GetProtocolParams005,
        SetSessionKey,
        SetServiceResult,
        ConfirmReceiveRequest
    };

    struct hc_user_info userInfo = {
        g_testServerAuthId,
        1
    };

    hc_handle server = get_instance(&g_server_identity, HC_CENTRE, &callBack);
    ASSERT_TRUE(server != nullptr);
    int32_t trustedPeersNum = delete_local_auth_info(server, &userInfo);
    EXPECT_EQ(trustedPeersNum, 0);
    destroy(&server);
    LOG("--------DeleteLocalAuthInfoTest DeleteLocalAuthInfoTest004--------");
}

/*--------------------------IsTrustPeerTest------------------------*/

static struct hc_user_info carUserInfo = {
    g_testServerAuthId,
    HC_USER_TYPE_ACCESSORY
};

class IsTrustPeerTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void IsTrustPeerTest::SetUpTestCase(void) {}
void IsTrustPeerTest::TearDownTestCase(void) {}
void IsTrustPeerTest::SetUp()
{
    InitHcAuthId();
}

void IsTrustPeerTest::TearDown() {}

static HWTEST_F(IsTrustPeerTest, IsTrustPeerTest002, TestSize.Level2)
{
    LOG("--------IsTrustPeerTest Test002--------");
    LOG("--------is_trust_peer--------");
    struct hc_call_back callBack = {
        Transmit,
        GetProtocolParams,
        SetSessionKey,
        SetServiceResult,
        ConfirmReceiveRequest
    };

    hc_handle server = get_instance(&g_server_identity, HC_CENTRE, &callBack);
    ASSERT_TRUE(server != nullptr);
    int32_t ret = is_trust_peer(server, nullptr);
    EXPECT_EQ(ret, HC_NOT_TRUST_PEER);
    destroy(&server);
    LOG("--------IsTrustPeerTest Test002--------");
}

static HWTEST_F(IsTrustPeerTest, IsTrustPeerTest003, TestSize.Level2)
{
    LOG("--------IsTrustPeerTest Test003--------");
    LOG("--------is_trust_peer--------");
    struct hc_call_back callBack = {
        nullptr,
        GetProtocolParams,
        SetSessionKey,
        SetServiceResult,
        ConfirmReceiveRequest
    };

    hc_handle server = get_instance(&g_server_identity, HC_CENTRE, &callBack);
    ASSERT_TRUE(server == nullptr);
    int32_t ret = is_trust_peer(server, &carUserInfo);
    EXPECT_EQ(ret, HC_NOT_TRUST_PEER);
    destroy(&server);
    LOG("--------IsTrustPeerTest Test003--------");
}

static HWTEST_F(IsTrustPeerTest, IsTrustPeerTest004, TestSize.Level2)
{
    LOG("--------IsTrustPeerTest Test004--------");
    LOG("--------is_trust_peer--------");
    struct hc_call_back callBack = {
        Transmit,
        GetProtocolParams,
        SetSessionKey,
        SetServiceResult,
        ConfirmReceiveRequest
    };

    struct hc_user_info userInfo = {
        g_testServerAuthId003,
        HC_USER_TYPE_ACCESSORY
    };

    hc_handle server = get_instance(&g_server_identity, HC_CENTRE, &callBack);
    ASSERT_TRUE(server != nullptr);
    int32_t ret = is_trust_peer(server, &userInfo);
    EXPECT_EQ(ret, HC_NOT_TRUST_PEER);
    destroy(&server);
    LOG("--------IsTrustPeerTest Test004--------");
}

static HWTEST_F(IsTrustPeerTest, IsTrustPeerTest005, TestSize.Level2)
{
    LOG("--------IsTrustPeerTest Test005--------");
    LOG("--------is_trust_peer--------");
    struct hc_call_back callBack = {
        Transmit,
        GetProtocolParams,
        SetSessionKey,
        SetServiceResult,
        ConfirmReceiveRequest
    };

    struct hc_user_info userInfo = {
        g_testServerAuthId,
        2
    };

    hc_handle server = get_instance(&g_server_identity, HC_CENTRE, &callBack);
    ASSERT_TRUE(server != nullptr);
    int32_t ret = is_trust_peer(server, &userInfo);
    EXPECT_EQ(ret, HC_NOT_TRUST_PEER);
    destroy(&server);
    LOG("--------IsTrustPeerTest Test005--------");
}

static HWTEST_F(IsTrustPeerTest, IsTrustPeerTest006, TestSize.Level2)
{
    LOG("--------IsTrustPeerTest Test006--------");
    LOG("--------is_trust_peer--------");
    struct hc_call_back callBack = {
        Transmit,
        GetProtocolParams,
        SetSessionKey,
        SetServiceResult,
        ConfirmReceiveRequest
    };

    struct hc_user_info userInfo = {
        g_testServerAuthId,
        HC_USER_TYPE_ACCESSORY
    };

    hc_handle server = get_instance(&g_server_identity, HC_CENTRE, &callBack);
    ASSERT_TRUE(server != nullptr);
    struct hichain *hichainTest = static_cast<struct hichain *>(server);
    (void)memset_s(&(hichainTest->identity), sizeof(hichainTest->identity), 0, sizeof(hichainTest->identity));
    ASSERT_EQ(hichainTest->identity.package_name.length, 0);
    int32_t ret = is_trust_peer(server, &userInfo);
    EXPECT_EQ(ret, HC_GEN_SERVICE_ID_FAILED);
    destroy(&server);
    LOG("--------IsTrustPeerTest Test006--------");
}

static HWTEST_F(IsTrustPeerTest, IsTrustPeerTest007, TestSize.Level2)
{
    LOG("--------IsTrustPeerTest Test007--------");
    LOG("--------is_trust_peer--------");
    struct hc_call_back callBack = {
        Transmit,
        GetProtocolParams,
        SetSessionKey,
        SetServiceResult,
        ConfirmReceiveRequest
    };

    struct hc_user_info userInfo = {
        g_testServerAuthId,
        HC_USER_TYPE_ACCESSORY
    };

    hc_handle server = get_instance(&g_server_identity, HC_CENTRE, &callBack);
    ASSERT_TRUE(server != nullptr);
    struct hichain *hichainTest = static_cast<struct hichain *>(server);
    hichainTest->identity.service_type.length = 0;
    ASSERT_EQ(hichainTest->identity.service_type.length, 0);
    int32_t ret = is_trust_peer(server, &userInfo);
    EXPECT_EQ(ret, HC_GEN_SERVICE_ID_FAILED);
    destroy(&server);
    LOG("--------IsTrustPeerTest Test007--------");
}

static HWTEST_F(IsTrustPeerTest, IsTrustPeerTest008, TestSize.Level2)
{
    LOG("--------IsTrustPeerTest Test008--------");
    LOG("--------is_trust_peer--------");
    struct hc_call_back callBack = {
        Transmit,
        GetProtocolParams,
        SetSessionKey,
        SetServiceResult,
        ConfirmReceiveRequest
    };

    struct hc_user_info userInfo = {
        g_testServerAuthId,
        HC_USER_TYPE_ACCESSORY
    };

    hc_handle server = get_instance(&g_server_identity, HC_CENTRE, &callBack);
    ASSERT_TRUE(server != nullptr);
    struct hichain *hichainTest = static_cast<struct hichain *>(server);
    (void)memset_s(hichainTest->identity.package_name.name, sizeof(hichainTest->identity.package_name.name),
        0, sizeof(hichainTest->identity.package_name.name));
    (void)memset_s(hichainTest->identity.service_type.type, sizeof(hichainTest->identity.service_type.type),
        0, sizeof(hichainTest->identity.service_type.type));
    int32_t ret = is_trust_peer(server, &userInfo);
    EXPECT_EQ(ret, HC_NOT_TRUST_PEER);
    destroy(&server);
    LOG("--------IsTrustPeerTest Test008--------");
}

static HWTEST_F(IsTrustPeerTest, IsTrustPeerTest009, TestSize.Level2)
{
    LOG("--------IsTrustPeerTest Test009--------");
    LOG("--------is_trust_peer--------");
    struct hc_call_back callBack = {
        Transmit,
        GetProtocolParams,
        SetSessionKey,
        SetServiceResult,
        ConfirmReceiveRequest
    };

    struct hc_user_info userInfo = {
        g_testServerAuthId001,
        HC_USER_TYPE_ACCESSORY
    };

    hc_handle server = get_instance(&g_server_identity, HC_CENTRE, &callBack);
    ASSERT_TRUE(server != nullptr);
    int32_t ret = is_trust_peer(server, &userInfo);
    EXPECT_EQ(ret, HC_NOT_TRUST_PEER);
    destroy(&server);
    LOG("--------IsTrustPeerTest Test009--------");
}

static HWTEST_F(IsTrustPeerTest, IsTrustPeerTest010, TestSize.Level2)
{
    LOG("--------IsTrustPeerTest Test010--------");
    LOG("--------is_trust_peer--------");
    struct hc_call_back callBack = {
        Transmit,
        GetProtocolParams,
        SetSessionKey,
        SetServiceResult,
        ConfirmReceiveRequest
    };

    struct hc_user_info userInfo = {
        g_testServerAuthId002,
        HC_USER_TYPE_ACCESSORY
    };

    hc_handle server = get_instance(&g_server_identity, HC_CENTRE, &callBack);
    ASSERT_TRUE(server != nullptr);
    struct hichain *hichainTest = static_cast<struct hichain *>(server);
    (void)memset_s(hichainTest->identity.package_name.name, sizeof(hichainTest->identity.package_name.name),
        0, sizeof(hichainTest->identity.package_name.name));
    (void)memset_s(hichainTest->identity.service_type.type, sizeof(hichainTest->identity.service_type.type),
        0, sizeof(hichainTest->identity.service_type.type));
    int32_t ret = is_trust_peer(server, &userInfo);
    EXPECT_EQ(ret, HC_NOT_TRUST_PEER);
    destroy(&server);
    LOG("--------IsTrustPeerTest Test010--------");
}

/*--------------------------registe_log------------------------*/

class RegisteLogTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void RegisteLogTest::SetUpTestCase(void) {}
void RegisteLogTest::TearDownTestCase(void) {}
void RegisteLogTest::SetUp()
{
    InitHcAuthId();
}

void RegisteLogTest::TearDown() {}

const int32_t MAX_LOG_BUFF_LENGTH = 1024;

void TestLogd(const char *tag, const char *funcName, const char *format, ...)
{
    va_list ap;
    char logBuff[MAX_LOG_BUFF_LENGTH];
    va_start(ap, format);
    if (vsnprintf_s(logBuff, MAX_LOG_BUFF_LENGTH, MAX_LOG_BUFF_LENGTH - 1, format, ap) == -1) {
        va_end(ap);
        return;
    }
}

static HWTEST_F(RegisteLogTest, RegisteLogTest001, TestSize.Level2)
{
    struct log_func_group logFunc = {
        TestLogd,
        TestLogd,
        TestLogd,
        TestLogd
    };
    registe_log(&logFunc);
}

static HWTEST_F(RegisteLogTest, RegisteLogTest002, TestSize.Level2)
{
    struct log_func_group logFunc = {
        nullptr,
        TestLogd,
        TestLogd,
        TestLogd
    };
    registe_log(&logFunc);
}

static HWTEST_F(RegisteLogTest, RegisteLogTest003, TestSize.Level2)
{
    struct log_func_group logFunc = {
        TestLogd,
        nullptr,
        TestLogd,
        TestLogd
    };
    registe_log(&logFunc);
}

static HWTEST_F(RegisteLogTest, RegisteLogTest004, TestSize.Level2)
{
    struct log_func_group logFunc = {
        TestLogd,
        TestLogd,
        nullptr,
        TestLogd
    };
    registe_log(&logFunc);
}

static HWTEST_F(RegisteLogTest, RegisteLogTest005, TestSize.Level2)
{
    struct log_func_group logFunc = {
        TestLogd,
        TestLogd,
        TestLogd,
        nullptr
    };
    registe_log(&logFunc);
}

/*--------------------------get_json_test------------------------*/

static cJSON *root = nullptr;
static cJSON *payload = nullptr;
static cJSON *root_array = nullptr;

class JsonUtilTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void JsonUtilTest::SetUpTestCase(void) {}
void JsonUtilTest::TearDownTestCase(void) {}
void JsonUtilTest::SetUp()
{
    root = cJSON_CreateObject();
    cJSON_AddNumberToObject(root, "message", 1);
    cJSON_AddStringToObject(root, "test", "C5914790E4");
    cJSON_AddTrueToObject(root, "bool");

    payload = cJSON_CreateObject();
    cJSON_AddStringToObject(payload, "challenge", "E01AE0AA018ECDA852ACA4CCA45FCC56");
    cJSON_AddStringToObject(payload, "kcfData", "4A4EB6622524CBBF7DC96412A82BF4CB6022F50226A201DB3B3C55B4F0707345");
    cJSON_AddItemToObject(root, "payload", payload);

    root_array = cJSON_CreateArray();
    cJSON_AddItemToArray(root_array, cJSON_CreateNumber(11)); /* 11 : any int for test */
    cJSON_AddItemToArray(root_array, cJSON_CreateString("banana"));
    cJSON_AddItemToArray(root_array, cJSON_CreateTrue());
}

void JsonUtilTest::TearDown() {}


static HWTEST_F(JsonUtilTest, get_json_int_test001, TestSize.Level2)
{
    json_pobject obj = reinterpret_cast<void *>(root);
    char *temp = nullptr;
    int32_t ret = get_json_int(obj, temp);
    EXPECT_NE(ret, -1);
}

static HWTEST_F(JsonUtilTest, get_json_int_test002, TestSize.Level2)
{
    json_pobject obj = nullptr;
    char *temp = nullptr;
    int32_t ret = get_json_int(obj, temp);
    EXPECT_EQ(ret, -1);
}

static HWTEST_F(JsonUtilTest, get_json_int_test003, TestSize.Level2)
{
    json_pobject obj = reinterpret_cast<void *>(root);
    std::string field = "mesage";
    int32_t ret = get_json_int(obj, field.c_str());
    EXPECT_EQ(ret, -1);
    field = "message";
    ret = get_json_int(obj, field.c_str());
    EXPECT_EQ(ret, 1);
}


static HWTEST_F(JsonUtilTest, get_json_bool_test001, TestSize.Level2)
{
    json_pobject obj = reinterpret_cast<void *>(root);
    char *temp = nullptr;
    int32_t ret = get_json_bool(obj, temp);
    EXPECT_NE(ret, -1);
}

static HWTEST_F(JsonUtilTest, get_json_bool_test002, TestSize.Level2)
{
    json_pobject obj = nullptr;
    char *temp = nullptr;
    int32_t ret = get_json_bool(obj, temp);
    EXPECT_EQ(ret, -1);
}

static HWTEST_F(JsonUtilTest, get_json_bool_test003, TestSize.Level2)
{
    json_pobject obj = reinterpret_cast<void *>(root);
    std::string field = "booll";
    int32_t ret = get_json_bool(obj, field.c_str());
    EXPECT_EQ(ret, -1);
    field = "bool";
    ret = get_json_bool(obj, field.c_str());
    EXPECT_EQ(ret, 1);
}


static HWTEST_F(JsonUtilTest, get_array_size_test001, TestSize.Level2)
{
    json_pobject obj = reinterpret_cast<void *>(root);
    int32_t ret = get_array_size(obj);
    EXPECT_EQ(ret, -1);
}

static HWTEST_F(JsonUtilTest, get_array_size_test002, TestSize.Level2)
{
    json_pobject obj = reinterpret_cast<void *>(root_array);
    int32_t ret = get_array_size(obj);
    EXPECT_NE(ret, -1);
}


static HWTEST_F(JsonUtilTest, get_array_idx_test001, TestSize.Level2)
{
    json_pobject obj = reinterpret_cast<void *>(root);
    obj = get_array_idx(obj, 1);
    EXPECT_EQ(obj, nullptr);
}

static HWTEST_F(JsonUtilTest, get_array_idx_test002, TestSize.Level2)
{
    json_pobject obj = reinterpret_cast<void *>(root_array);
    obj = get_array_idx(obj, 1);
    EXPECT_NE(obj, nullptr);
}


static HWTEST_F(JsonUtilTest, add_bool_to_object_test001, TestSize.Level2)
{
    json_pobject obj = reinterpret_cast<void *>(root);
    std::string field = "test_bool_false";
    json_pobject pobject = add_bool_to_object(obj, field.c_str(), 0);
    EXPECT_TRUE(pobject != nullptr);
    field = "test_bool_true";
    pobject = add_bool_to_object(obj, field.c_str(), 1);
    EXPECT_TRUE(pobject != nullptr);
    int32_t ret = get_json_bool(obj, field.c_str());
    EXPECT_EQ(ret, 1);
}


static HWTEST_F(JsonUtilTest, string_convert_test001, TestSize.Level2)
{
    json_pobject obj = reinterpret_cast<void *>(root);
    char *temp = nullptr;
    uint8_t *str = nullptr;
    uint32_t *length = nullptr;
    uint32_t maxLen = 10;
    int32_t ret = string_convert(obj, temp, str, length, maxLen);
    EXPECT_EQ(ret, HC_INPUT_ERROR);
}

static HWTEST_F(JsonUtilTest, string_convert_test002, TestSize.Level2)
{
    json_pobject obj = reinterpret_cast<void *>(root);
    std::string temp = "test";
    uint8_t *str = nullptr;
    uint32_t *length = nullptr;
    uint32_t maxLen = 9;
    int32_t ret = string_convert(obj, temp.c_str(), str, length, maxLen);
    EXPECT_EQ(ret, HC_INPUT_ERROR);
}

static HWTEST_F(JsonUtilTest, string_convert_test003, TestSize.Level2)
{
    json_pobject obj = reinterpret_cast<void *>(root);
    std::string temp = "test";
    uint8_t *str = nullptr;
    uint32_t *length = nullptr;
    uint32_t maxLen = 11;
    int32_t ret = string_convert(obj, temp.c_str(), str, length, maxLen);
    EXPECT_EQ(ret, HC_MEMCPY_ERROR);
}
}
