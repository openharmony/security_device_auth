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
#include "deviceauth_test.h"
#include <cstdint>
#include <cstdlib>
#include "gtest/gtest.h"
#include "gmock/gmock.h"
#include "securec.h"
#include "hichain.h"
#include "distribution.h"
#include "huks_adapter.h"
#include "log.h"

extern "C" {
    #include "auth_info.h"
    #include "build_object.h"
    #include "commonutil.h"
    #include "jsonutil.h"
    #include "cJSON.h"
}
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

enum HksErrorCode{
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
    struct pake_client *pake_client = (struct pake_client *)MALLOC(sizeof(struct pake_client));
    (void)memset_s(pake_client, sizeof(struct pake_client), 0, sizeof(struct pake_client));

    struct operation_parameter *params = (struct operation_parameter *)MALLOC(sizeof(struct operation_parameter));
    (void)memset_s(pake_client, sizeof(struct operation_parameter), 0, sizeof(struct operation_parameter));

    struct hichain *hichainTest = static_cast<struct hichain *>(server);
    hichainTest->pake_client = pake_client;

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

    struct sts_client *sts_client = (struct sts_client *)MALLOC(sizeof(struct sts_client));
    (void)memset_s(sts_client, sizeof(struct sts_client), 0, sizeof(struct sts_client));

    struct operation_parameter *params = (struct operation_parameter *)MALLOC(sizeof(struct operation_parameter));
    (void)memset_s(params, sizeof(struct operation_parameter), 0, sizeof(struct operation_parameter));

    struct hichain *hichainTest = static_cast<struct hichain *>(server);
    hichainTest->sts_client = sts_client;
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

    struct operation_parameter *params = (struct operation_parameter *)MALLOC(sizeof(struct operation_parameter));
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
    EXPECT_NE(ret, 0);
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
    struct hichain *server = (struct hichain *)MALLOC(sizeof(struct hichain));
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
    struct hichain *server = (struct hichain *)MALLOC(sizeof(struct hichain));
    (void)memset_s(server, sizeof(struct hichain), 0, sizeof(struct hichain));

    struct pake_server *pake_server = (struct pake_server *)MALLOC(sizeof(struct pake_server));
    (void)memset_s(pake_server, sizeof(struct pake_server), 0, sizeof(struct pake_server));

    server->pake_server = pake_server;
    hc_handle serverTest = static_cast<hc_handle>(server);
    destroy(&serverTest);
    EXPECT_TRUE(serverTest == nullptr);
    LOG("--------DestroyTest DestroyTest004--------");
}

static HWTEST_F(DestroyTest, DestroyTest005, TestSize.Level2)
{
    LOG("--------DestroyTest DestroyTest005--------");
    LOG("--------destory--------");
    struct hichain *server = (struct hichain *)MALLOC(sizeof(struct hichain));
    (void)memset_s(server, sizeof(struct hichain), 0, sizeof(struct hichain));

    struct sts_server *sts_server = (struct sts_server *)MALLOC(sizeof(struct sts_server));
    (void)memset_s(sts_server, sizeof(struct sts_server), 0, sizeof(struct sts_server));

    server->sts_server = sts_server;
    hc_handle serverTest = static_cast<hc_handle>(server);
    destroy(&serverTest);
    EXPECT_TRUE(serverTest == nullptr);
    LOG("--------DestroyTest DestroyTest005--------");
}

static HWTEST_F(DestroyTest, DestroyTest006, TestSize.Level2)
{
    LOG("--------DestroyTest DestroyTest006--------");
    LOG("--------destory--------");
    struct hichain *server = (struct hichain *)MALLOC(sizeof(struct hichain));
    (void)memset_s(server, sizeof(struct hichain), 0, sizeof(struct hichain));

    struct sts_client *sts_client = (struct sts_client *)MALLOC(sizeof(struct sts_client));
    (void)memset_s(sts_client, sizeof(struct sts_client), 0, sizeof(struct sts_client));

    server->sts_client = sts_client;
    hc_handle serverTest = static_cast<hc_handle>(server);
    destroy(&serverTest);
    EXPECT_TRUE(serverTest == nullptr);
    LOG("--------DestroyTest DestroyTest006--------");
}

static HWTEST_F(DestroyTest, DestroyTest007, TestSize.Level2)
{
    LOG("--------DestroyTest DestroyTest007--------");
    LOG("--------destory--------");
    struct hichain *server = (struct hichain *)MALLOC(sizeof(struct hichain));
    (void)memset_s(server, sizeof(struct hichain), 0, sizeof(struct hichain));

    struct auth_info_cache *auth_info = (struct auth_info_cache *)MALLOC(sizeof(struct auth_info_cache));
    (void)memset_s(auth_info, sizeof(struct auth_info_cache), 0, sizeof(struct auth_info_cache));

    server->auth_info = auth_info;
    hc_handle serverTest = static_cast<hc_handle>(server);
    destroy(&serverTest);
    EXPECT_TRUE(serverTest == nullptr);
    LOG("--------DestroyTest DestroyTest007--------");
}

static HWTEST_F(DestroyTest, DestroyTest008, TestSize.Level2)
{
    LOG("--------DestroyTest DestroyTest008--------");
    LOG("--------destory--------");
    struct hichain *server = (struct hichain *)MALLOC(sizeof(struct hichain));
    (void)memset_s(server, sizeof(struct hichain), 0, sizeof(struct hichain));

    struct sec_clone_server *sec_clone_server = (struct sec_clone_server *)MALLOC(sizeof(struct sec_clone_server));
    (void)memset_s(sec_clone_server, sizeof(struct sec_clone_server), 0, sizeof(struct sec_clone_server));

    server->sec_clone_server = sec_clone_server;
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
    EXPECT_EQ(g_result, KEY_AGREEMENT_END);

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
    uint8_t dataStr001[] = {"{\"message\":32769,\"payload\":{\"version\":{\"currentVersion\":\"1.0.0\","
                        "\"minVersion\":\"1.0.0\"},\"challenge\":\"76539E5634EDA735A94845C3A4F356D6\","
                        "\"salt\":\"025E4B3B2DD3B0E67395C760008A9154\","
                        "\"epk\":""}}"};
    uint8_buff data001 = {
        dataStr001,
        sizeof(dataStr001),
        strlen(reinterpret_cast<char *>(dataStr001))
    };
    ret = receive_data(server, &data001);
    EXPECT_EQ(ret, HC_OK);

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

    uint8_t dataStr002[] = {"{\"message\":0,\"payload\":{\"kcfData\":\"463853720FFFC312084B9FF288E17"
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
    LOG("--------ReceiveDataTest008--------");
}

// static HWTEST_F(ReceiveDataTest, ReceiveDataTest009_pake_client2, TestSize.Level2)
// {
//     LOG("--------ReceiveDataTest009--------");
//     struct hc_call_back callBack = {
//         Transmit,
//         GetProtocolParams,
//         SetSessionKey,
//         SetServiceResult,
//         ConfirmReceiveRequest
//     };
//     hc_handle server = get_instance(&g_server_identity, HC_CENTRE, &callBack);
//     ASSERT_TRUE(server != nullptr);

//     uint8_t dataStr[] = "{\"message\":32770,\"payload\":{\""\
//         "kcfData\":\"4A4EB6622524CBBF7DC96412A82BF4CB6022F50226A201DB3B3C55B4F0707345\"}}";
//     uint8_buff data = {
//         dataStr,
//         sizeof(dataStr),
//         strlen(reinterpret_cast<char *>(dataStr))
//     };
//     receive_data(server, &data);
//     EXPECT_EQ(g_result, END_FAILED);

//     destroy(&server);
//     LOG("--------ReceiveDataTest009--------");
// }

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
    struct hichain *hc_server = static_cast<struct hichain *>(server);
    hc_server->operation_code = BIND;
    hc_server->last_state = KEY_AGREEMENT_STATE;
    hc_server->state = OPERATION_STATE;
    struct operation_parameter params = {g_testServerAuthId, g_testClientAuthId, KEY_LEN};
    build_object(hc_server, PAKE_MODULAR, true, &params);
    hc_server->pake_client->client_info.protocol_base_info.state = START_REQUEST;
    hc_server->pake_client->client_info.protocol_base_info.last_state = PROTOCOL_INIT;
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

// static HWTEST_F(ReceiveDataTest, ReceiveDataTest011_pake_server3, TestSize.Level2)
// {
//     LOG("--------ReceiveDataTest011--------");
//     struct hc_call_back callBack = {
//         Transmit,
//         GetProtocolParams,
//         SetSessionKey,
//         SetServiceResult,
//         ConfirmReceiveRequest
//     };
//     hc_handle server = get_instance(&g_server_identity, HC_CENTRE, &callBack);
//     ASSERT_TRUE(server != nullptr);

//     uint8_t dataStr[] = "{\"message\":3,\"payload\":{"\
//         "\"exAuthInfo\":\"QWERTYUIOPASDFGHJKLZXCVBNM1234567890QWERTYUIOPASDFGHJKLZXCVBNM1234567890\"}}";
//     uint8_buff data = {
//         dataStr,
//         sizeof(dataStr),
//         strlen(reinterpret_cast<char *>(dataStr))
//     };
//     receive_data(server, &data);
//     EXPECT_EQ(g_result, END_FAILED);

//     destroy(&server);
//     LOG("--------ReceiveDataTest011--------");
// }

// static HWTEST_F(ReceiveDataTest, ReceiveDataTest012_pake_server3error, TestSize.Level2)
// {
//     LOG("--------ReceiveDataTest012--------");
//     struct hc_call_back callBack = {
//         Transmit,
//         GetProtocolParams,
//         SetSessionKey,
//         SetServiceResult,
//         ConfirmReceiveRequest
//     };

//     hc_handle server = get_instance(&g_server_identity, HC_CENTRE, &callBack);
//     ASSERT_TRUE(server != nullptr);

//     uint8_t dataStr[] = "{\"message\":3,\"payload\":{}}";
//     uint8_buff data = {
//         dataStr,
//         sizeof(dataStr),
//         strlen(reinterpret_cast<char *>(dataStr))
//     };
//     receive_data(server, &data);
//     EXPECT_EQ(g_result, END_FAILED);

//     destroy(&server);
//     LOG("--------ReceiveDataTest012--------");
// }

// static HWTEST_F(ReceiveDataTest, ReceiveDataTest013_pake_client3, TestSize.Level2)
// {
//     LOG("--------ReceiveDataTest013--------");
//     struct hc_call_back callBack = {
//         Transmit,
//         GetProtocolParams,
//         SetSessionKey,
//         SetServiceResult,
//         ConfirmReceiveRequest
//     };

//     hc_handle server = get_instance(&g_server_identity, HC_CENTRE, &callBack);
//     ASSERT_TRUE(server != nullptr);

//     uint8_t dataStr[] = "{\"message\":32771,\"payload\":{"\
//         "\"exAuthInfo\":\"QWERTYUIOPASDFGHJKLZXCVBNM1234567890QWERTYUIOPASDFGHJKLZXCVBNM1234567890\"}}";
//     uint8_buff data = {
//         dataStr,
//         sizeof(dataStr),
//         strlen(reinterpret_cast<char *>(dataStr))
//     };
//     receive_data(server, &data);
//     EXPECT_EQ(g_result, END_FAILED);

//     destroy(&server);
//     LOG("--------ReceiveDataTest013--------");
// }

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
    struct hichain *hc_server = static_cast<struct hichain *>(server);
    hc_server->operation_code = BIND;
    hc_server->last_state = OPERATION_STATE;
    hc_server->state = OVER_STATE;
    struct operation_parameter params = {g_testServerAuthId, g_testClientAuthId, KEY_LEN};
    build_object(hc_server, PAKE_MODULAR, true, &params);
    hc_server->pake_client->client_info.protocol_base_info.state = END_REQUEST;
    hc_server->pake_client->client_info.protocol_base_info.last_state = START_REQUEST;
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
    uint8_t dataStr001[] = "{\"message\":32769,\"payload\":{\"version\":{\"currentVersion\":\"1.0.0\",\"minVersion\":\"1.0.0\"},"
                           "\"challenge\":\"EF6768B27F8BB03128195903788D415A\",\"salt\":\"41F4D7096B21DA799A722DA00EB8B030\",\"epk\":\"5F990513D00D2"
                           "206A5AA4AAF7659A066236DDCD3CB806EE6373B8FA2F15AA72274A20709B350D8CD17358FD123E7393FE12B5CE4D0CAE62854DBC33425"
                           "F7B49E727F029C5AA724962E221E6095C8ACC6C8AABA5F4A9DCCB8AF1BD6CEA09B6AEBD2058C1BD1572005FE5096F1D840F7C78E83D89"
                           "A803C6FF49BF98C03FCEA32247816DF3EB39A52BCCB215747E91B9831BDB5E3349C7AA8FCCF121B1CFD2E5CC1861CD85D47AC698E9933"
                           "30110889C2221D45ECA9515956FEA641B64C5EC81F449DF74D863539AF4923E13220A513E473352CC532F4710DFB199A5C520D19D14C7"
                           "4EA425721E8EDAFD655E024C99DA1C130EAFB4B420A0B0A85FEB9030546B8B3FC9F307F50ABEDC249AB69BA3442D8A567D2D2F2A001AF"
                           "A21D6A9F6FD0D4AB2153EB737094692318FC0C4FCD8026D73585FFD2D411CD7703FF9B7B981C42FF4C969E75D846CDFAC54E122A1B073"
                           "CAD7123E8B06C7B51FFC832942001FA33E3E85BB3DE306BB2AE2BEC7D1ABBD3D466FFD87FCA3CE65254E4D5A97AD29DFAB4F0\"}}";
    uint8_buff data001 = {
        dataStr001,
        sizeof(dataStr001),
        strlen(reinterpret_cast<char *>(dataStr001))
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
    struct hichain *hc_server = static_cast<struct hichain *>(server);
    hc_server->operation_code = AUTHENTICATE;
    struct operation_parameter params = {g_testServerAuthId, g_testClientAuthId, KEY_LEN};
    build_object(hc_server, STS_MODULAR, true, &params);
    hc_server->sts_client->client_info.protocol_base_info.state = END_REQUEST;
    hc_server->sts_client->client_info.protocol_base_info.last_state = PROTOCOL_INIT;
    uint8_t dataStr[] = "{\"authForm\":0,\"message\":32785,\"payload\":{\"authData\":\"4A4EB6622524CBBF7DC96412A82BF4CB6022F50226A201DB3B3C55"\
                        ",\"challenge\":\"A1714848785F27C22B31\","\
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

    uint8_t dataStr002[] = "{\"authForm\":0,\"message\":32786,\"payload\":{\"authReturn\":\"57F9D09AA425FB83AB9BE2AF25FC9E5"
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
    uint8_t dataStr001[] = {"{\"message\":32769,\"payload\":{\"version\":{\"currentVersion\":\"1.0.0\","
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
    uint8_buff data001 = {
        dataStr001,
        sizeof(dataStr001),
        strlen(reinterpret_cast<char *>(dataStr001))
    };
    ret = receive_data(server1, &data001);
    EXPECT_EQ(ret, HC_OK);
    destroy(&server1);

    hc_handle server2 = get_instance(&g_server_identity, HC_CENTRE, &callBack);
    ASSERT_TRUE(server2 != nullptr);
    ret = start_pake(server2, &params);
    uint8_t dataStr002[] = {"{\"message\":32769,\"payload\":{\"version\":{\"currentVersion\":\"1.0.0\","
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
    uint8_buff data002 = {
        dataStr002,
        sizeof(dataStr002),
        strlen(reinterpret_cast<char *>(dataStr002))
    };
    ret = receive_data(server2, &data002);
    EXPECT_EQ(ret, HC_OK);
    destroy(&server2);

    hc_handle server3 = get_instance(&g_server_identity, HC_CENTRE, &callBack);
    ASSERT_TRUE(server3 != nullptr);
    ret = start_pake(server3, &params);
    uint8_t dataStr003[] = {"{\"message\":32769,\"payload\":{\"version\":{\"currentVersion\":\"1.0.0\","
                        "\"minVersion\":\"1.0.0\"},\"challenge\":\"76539E5634EDA735A94845C3A4F356D6\","
                        "\"salt\":\"025E4B3B2DD3B0E67395C760008A9154\",}}"};
    uint8_buff data003 = {
        dataStr003,
        sizeof(dataStr003),
        strlen(reinterpret_cast<char *>(dataStr003))
    };
    ret = receive_data(server3, &data003);
    EXPECT_EQ(ret, HC_OK);
    destroy(&server3);

    hc_handle server4 = get_instance(&g_server_identity, HC_CENTRE, &callBack);
    ASSERT_TRUE(server4 != nullptr);
    ret = start_pake(server4, &params);
    uint8_t dataStr004[] = {"{\"message\":32769,\"payload\":{\"challenge\":\"76539E5634EDA735A94845C3A4F356D6\","
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
    uint8_buff data004 = {
        dataStr004,
        sizeof(dataStr004),
        strlen(reinterpret_cast<char *>(dataStr004))
    };
    ret = receive_data(server4, &data004);
    EXPECT_EQ(ret, HC_OK);

    uint8_t dataStr005[] = {"{\"message\":32769,\"payload\":{\"challenge\":\"76539E5634EDA735A94845C3A4F356D\","
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
    uint8_buff data005 = {
        dataStr005,
        sizeof(dataStr005),
        strlen(reinterpret_cast<char *>(dataStr005))
    };
    ret = receive_data(server4, &data005);
    EXPECT_EQ(ret, HC_OK);
    destroy(&server4);

    LOG("--------ReceiveDataTest019--------");
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

static HWTEST_F(IsTrustPeerTest, IsTrustPeerTest001, TestSize.Level2)
{
    LOG("--------IsTrustPeerTest Test001--------");
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
    struct operation_parameter params = {g_testServerAuthId, g_testClientAuthId, KEY_LEN};
    int32_t ret = start_pake(server, &params);
    ret = authenticate_peer(server, &params);
    ret = is_trust_peer(server, &carUserInfo);
    EXPECT_EQ(ret, HC_NOT_TRUST_PEER);
    destroy(&server);
    LOG("--------IsTrustPeerTest Test001--------");
}

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
    struct hichain *hichainTest = (struct hichain *)server;
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
    struct hichain *hichainTest = (struct hichain *)server;
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
    struct hichain *hichainTest = (struct hichain *)server;
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
    struct hichain *hichainTest = (struct hichain *)server;
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

class registeLogTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void registeLogTest::SetUpTestCase(void) {}
void registeLogTest::TearDownTestCase(void) {}
void registeLogTest::SetUp()
{
    InitHcAuthId();
}

void registeLogTest::TearDown() {}

const int32_t MAX_LOG_BUFF_LENGTH = 1024;

void testLogd(const char *tag, const char *func_name, const char *format, ...)
{
    va_list ap;
    char logBuff[MAX_LOG_BUFF_LENGTH];
    va_start(ap, format);
    if(vsnprintf_s(logBuff, MAX_LOG_BUFF_LENGTH, MAX_LOG_BUFF_LENGTH - 1, format, ap) == -1)
    {
        va_end(ap);
        return;
    }
}

static HWTEST_F(registeLogTest, registeLogTest001, TestSize.Level2)
{
    struct log_func_group logFunc = {
        testLogd,
        testLogd,
        testLogd,
        testLogd
    };
    registe_log(&logFunc);
}

static HWTEST_F(registeLogTest, registeLogTest002, TestSize.Level2)
{
    struct log_func_group logFunc = {
        nullptr,
        testLogd,
        testLogd,
        testLogd
    };
    registe_log(&logFunc);
}

static HWTEST_F(registeLogTest, registeLogTest003, TestSize.Level2)
{
    struct log_func_group logFunc = {
        testLogd,
        nullptr,
        testLogd,
        testLogd
    };
    registe_log(&logFunc);
}

static HWTEST_F(registeLogTest, registeLogTest004, TestSize.Level2)
{
    struct log_func_group logFunc = {
        testLogd,
        testLogd,
        nullptr,
        testLogd
    };
    registe_log(&logFunc);
}

static HWTEST_F(registeLogTest, registeLogTest005, TestSize.Level2)
{
    struct log_func_group logFunc = {
        testLogd,
        testLogd,
        testLogd,
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
    cJSON_AddItemToArray(root_array, cJSON_CreateNumber(11));
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
    field = "test_bool_true";
    pobject = add_bool_to_object(obj, field.c_str(), 1);
    int32_t ret = get_json_bool(obj, field.c_str());
    EXPECT_EQ(ret, 1);    
}


static HWTEST_F(JsonUtilTest, string_convert_test001, TestSize.Level2)
{
    json_pobject obj = reinterpret_cast<void *>(root);
    char *temp = nullptr;
    uint8_t *str = nullptr;
    uint32_t *length = nullptr;
    uint32_t max_len = 10;
    int32_t ret = string_convert(obj, temp, str, length, max_len);
    EXPECT_EQ(ret, HC_INPUT_ERROR);    
}

static HWTEST_F(JsonUtilTest, string_convert_test002, TestSize.Level2)
{
    json_pobject obj = reinterpret_cast<void *>(root);
    std::string temp = "test";
    uint8_t *str = nullptr;
    uint32_t *length = nullptr;
    uint32_t max_len = 9;
    int32_t ret = string_convert(obj, temp.c_str(), str, length, max_len);
    EXPECT_EQ(ret, HC_INPUT_ERROR);    
}

static HWTEST_F(JsonUtilTest, string_convert_test003, TestSize.Level2)
{
    json_pobject obj = reinterpret_cast<void *>(root);
    std::string temp = "test";
    uint8_t *str = nullptr;
    uint32_t *length = nullptr;
    uint32_t max_len = 11;
    int32_t ret = string_convert(obj, temp.c_str(), str, length, max_len);
    EXPECT_EQ(ret, HC_MEMCPY_ERROR);    
}

}
