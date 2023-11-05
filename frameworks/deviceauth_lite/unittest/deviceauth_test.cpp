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
#include "build_object.h"

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

enum hc_user_type {
    HC_USER_TYPE_ACCESSORY = 0,
    HC_USER_TYPE_CONTROLLER = 1
};

static struct hc_pin g_test_pin = {strlen("123456"), "123456"};

static struct hc_auth_id g_test_client_auth_id;
static struct hc_auth_id g_test_server_auth_Id;

static int32_t g_result;

uint8_t g_test_phone_id[65] = {"14bb6543b893a3250f5793fbbbd48be56641505dc6514be1bb37b032903ebc67"};
uint8_t g_test_car_id[65] = {"14bb6543b893a3250f5793fbbbd48be56641505dc6514be1bb37b032903abcde"};

void init_hc_auth_id()
{
    memcpy_s(g_test_client_auth_id.auth_id, AUTH_ID_LENGTH, g_test_phone_id, AUTH_ID_LENGTH);
    g_test_client_auth_id.length = AUTH_ID_LENGTH;

    memcpy_s(g_test_server_auth_Id.auth_id, AUTH_ID_LENGTH, g_test_car_id, AUTH_ID_LENGTH);
    g_test_server_auth_Id.length = AUTH_ID_LENGTH;

    return;
}

static struct hc_auth_id g_test_client_auth_id_001 = {strlen("authClient1"), "authClient1"};
static struct hc_auth_id g_test_client_auth_id_002 = {strlen("authClient2"), "authClient2"};

struct hc_auth_id *auth_id_client_list[3] = {
    &g_test_client_auth_id,
    &g_test_client_auth_id_001,
    &g_test_client_auth_id_002
};
struct hc_auth_id **auth_id_list = auth_id_client_list;

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
    para->self_auth_id = g_test_client_auth_id_001;
    para->peer_auth_id = g_test_client_auth_id_002;
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
    init_hc_auth_id();
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
    ASSERT_TRUE(server != NULL);
    struct hichain *hichain_test = (struct hichain *)server;
    EXPECT_EQ(hichain_test->state, 0);
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
    struct hichain *hichain_test = (struct hichain *)server;
    ASSERT_TRUE(server != NULL);
    EXPECT_EQ(hichain_test->state, 0);
    destroy(&server);
    LOG("--------DeviceAuthTest Test002--------");
}

static HWTEST_F(GetInstanceTest, GetInstanceTest003, TestSize.Level2)
{
    LOG("--------DeviceAuthTest Test003--------");
    LOG("--------get_instance--------");

    struct session_identity h_serverIdentity = {
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
    hc_handle server = get_instance(&h_serverIdentity, HC_CENTRE, &callBack);
    ASSERT_TRUE(server != NULL);
    destroy(&server);
    LOG("--------DeviceAuthTest Test003--------");
}

static HWTEST_F(GetInstanceTest, GetInstanceTest004, TestSize.Level2)
{
    LOG("--------DeviceAuthTest Test004--------");
    LOG("--------get_instance--------");

    struct hc_call_back callBack = {
        NULL,
        GetProtocolParams,
        SetSessionKey,
        SetServiceResult,
        ConfirmReceiveRequest
    };
    hc_handle server = get_instance(&g_server_identity, HC_CENTRE, &callBack);
    ASSERT_TRUE(server == NULL);
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
    hc_handle server = get_instance(NULL, HC_CENTRE, &callBack);
    ASSERT_TRUE(server == NULL);
    destroy(&server);
    LOG("--------DeviceAuthTest Test005--------");
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
    init_hc_auth_id();
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
    const struct operation_parameter params = {g_test_server_auth_Id, g_test_client_auth_id, KEY_LEN};
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
    ASSERT_TRUE(server != NULL);
    const struct operation_parameter params = {g_test_server_auth_Id, g_test_client_auth_id, KEY_LEN};
    int32_t ret = start_pake(NULL, &params);
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
    ASSERT_TRUE(server != NULL);
    int32_t ret = start_pake(server, NULL);
    EXPECT_NE(ret, HC_OK);
    destroy(&server);    
    LOG("--------StartPakeTest StartPakeTest003--------");
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
    init_hc_auth_id();
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
    ASSERT_TRUE(server != NULL);
    struct operation_parameter params = {g_test_server_auth_Id, g_test_client_auth_id, KEY_LEN};
    int32_t ret = authenticate_peer(server, &params);
    EXPECT_EQ(ret, HC_BUILD_OBJECT_FAILED);
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
    ASSERT_TRUE(server != NULL);
    struct operation_parameter params = {g_test_server_auth_Id, g_test_client_auth_id, KEY_LEN};
    int32_t ret = authenticate_peer(NULL, &params);
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
    ASSERT_TRUE(server != NULL);
    int32_t ret = authenticate_peer(server, NULL);
    EXPECT_NE(ret, HC_OK);
    destroy(&server);    
    LOG("--------AuthenticatePeerTest AuthenticatePeerTest003--------");
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
    init_hc_auth_id();
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
    int ret = list_trust_peers(server, HC_USER_TYPE_ACCESSORY, &g_test_client_auth_id, auth_id_list);
    EXPECT_EQ(ret, 0);
    destroy(&server);    
    LOG("--------ListTrustPeersTest ListTrustPeersTest001--------");
}

static HWTEST_F(ListTrustPeersTest, ListTrustPeersTest002, TestSize.Level2)
{
    LOG("--------ListTrustPeersTest ListTrustPeersTest002--------");
    LOG("--------list_trust_peers--------");
    int ret = list_trust_peers(NULL, HC_USER_TYPE_ACCESSORY, &g_test_client_auth_id, auth_id_list);
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
    int ret = list_trust_peers(server, 2, &g_test_client_auth_id, auth_id_list);
    EXPECT_EQ(ret, 0);
    destroy(&server);    
    LOG("--------ListTrustPeersTest ListTrustPeersTest003--------");
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
    init_hc_auth_id();
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
    EXPECT_TRUE(val == NULL);
    LOG("--------DestroyTest DestroyTest001--------");
}

static HWTEST_F(DestroyTest, DestroyTest002, TestSize.Level2)
{
    LOG("--------DestroyTest DestroyTest002--------");
    LOG("--------destory--------");
    struct hc_call_back callBack = {
        Transmit,
        GetProtocolParams,
        SetSessionKey,
        SetServiceResult,
        ConfirmReceiveRequest
    };
    hc_handle val = get_instance(&g_server_identity, HC_CENTRE, &callBack);
    val = NULL;
    destroy(&val);
    EXPECT_TRUE(val == NULL);
    LOG("--------DestroyTest DestroyTest002--------");
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
    init_hc_auth_id();
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
    ASSERT_TRUE(server != NULL);

    struct hc_user_info car_user_info = {
        g_test_server_auth_Id,
        1
    };
    int32_t trusted_peers_num = delete_local_auth_info(server, &car_user_info);
    EXPECT_EQ(trusted_peers_num, 0);

    destroy(&server);
    LOG("--------DeleteLocalAuthInfoTest DeleteLocalAuthInfoTest001--------");
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
    init_hc_auth_id();
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

    hc_handle server = get_instance(&g_server_identity, HC_CENTRE, &callBack);
    ASSERT_TRUE(server != NULL);

    uint8_t data_str[] = "";
    uint8_buff data = {
        data_str,
        sizeof(data_str),
        strlen((char *) data_str)
    };
    receive_data(server, &data);
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
    ASSERT_TRUE(server != NULL);

    uint8_t data_str[] = "{\"message\":0}";
    uint8_buff data = {
        data_str,
        sizeof(data_str),
        strlen((char *) data_str)
    };
    receive_data(server, &data);
    EXPECT_EQ(g_result, END_FAILED);

    destroy(&server);
    LOG("--------ReceiveDataTest002--------");
}

static HWTEST_F(ReceiveDataTest, ReceiveDataTest003_pake_server1, TestSize.Level2)
{
    LOG("--------ReceiveDataTest003--------");

    struct hc_call_back callBack = {
        Transmit,
        GetProtocolParams,
        SetSessionKey,
        SetServiceResult,
        ConfirmReceiveRequest
    };

    hc_handle server = get_instance(&g_server_identity, HC_CENTRE, &callBack);
    ASSERT_TRUE(server != NULL);

    uint8_t data_str[] = "{\"message\":1,\"payload\":{\"version\":{\"currentVersion\":\"1.0.0\","\
        "\"minVersion\":\"1.0.0\"},\"support256mod\":true,\"operationCode\":1}}";
    uint8_buff data = {
        data_str,
        sizeof(data_str),
        strlen((char *) data_str)
    };
    receive_data(server, &data);
    EXPECT_EQ(g_result, KEY_AGREEMENT_PROCESSING);

    destroy(&server);
    LOG("--------ReceiveDataTest003--------");
}

static HWTEST_F(ReceiveDataTest, ReceiveDataTest004_pake_server1error, TestSize.Level2)
{
    LOG("--------ReceiveDataTest004--------");
    struct hc_call_back callBack = {
        Transmit,
        GetProtocolParams,
        SetSessionKey,
        SetServiceResult,
        ConfirmReceiveRequest
    };
    hc_handle server = get_instance(&g_server_identity, HC_CENTRE, &callBack);
    ASSERT_TRUE(server != NULL);

    uint8_t data_str[] = "{\"message\":1,\"payload\":{"\
        "\"support256mod\":true,\"operationCode\":1}}";
    uint8_buff data = {
        data_str,
        sizeof(data_str),
        strlen((char *) data_str)
    };
    receive_data(server, &data);
    EXPECT_EQ(g_result, END_FAILED);

    destroy(&server);
    LOG("--------ReceiveDataTest004--------");
}

static HWTEST_F(ReceiveDataTest, ReceiveDataTest005_pake_client1, TestSize.Level2)
{
    LOG("--------ReceiveDataTest005--------");
    struct hc_call_back callBack = {
        Transmit,
        GetProtocolParams,
        SetSessionKey,
        SetServiceResult,
        ConfirmReceiveRequest
    };
    hc_handle server = get_instance(&g_server_identity, HC_CENTRE, &callBack);
    ASSERT_TRUE(server != NULL);

    uint8_t data_str[] = "{\"message\":32769,\"payload\":{\"version\":{"\
        "\"currentVersion\":\"1.0.0\",\"minVersion\":\"1.0.0\"},\"challenge\":\"E01AE0AA018ECDA852ACA4CCA45FCC56\","\
        "\"salt\":\"6DDD4B7A0FDD999E9355A10D68F79EA9\",\"epk\":\"QWERTYUIOPASDFGHJKLZXCVBNM1234567890\"}}";
    uint8_buff data = {
        data_str,
        sizeof(data_str),
        strlen((char *) data_str)
    };
    receive_data(server, &data);
    EXPECT_EQ(g_result, END_FAILED);
    destroy(&server);
    LOG("--------ReceiveDataTest005--------");
}

static HWTEST_F(ReceiveDataTest, ReceiveDataTest006_pake_client1error, TestSize.Level2)
{
    LOG("--------ReceiveDataTest006--------");
    struct hc_call_back callBack = {
        Transmit,
        GetProtocolParams,
        SetSessionKey,
        SetServiceResult,
        ConfirmReceiveRequest
    };

    hc_handle server = get_instance(&g_server_identity, HC_CENTRE, &callBack);
    ASSERT_TRUE(server != NULL);

    uint8_t data_str[] = "{\"message\":32769,\"payload\":{\"version\":{"\
        "\"currentVersion\":\"1.0.0\",\"minVersion\":\"1.0.0\"},\"challenge\":\"E01AE0AA018ECDA852ACA4CCA45FCC56\","\
        "\"salt\":\"6DDD4B7A0FDD999E9355A10D68F79EA9\"}}";
    uint8_buff data = {
        data_str,
        sizeof(data_str),
        strlen((char *) data_str)
    };
    receive_data(server, &data);
    EXPECT_EQ(g_result, END_FAILED);

    destroy(&server);
    LOG("--------ReceiveDataTest006--------");
}

static HWTEST_F(ReceiveDataTest, ReceiveDataTest007_pake_server2, TestSize.Level2)
{
    LOG("--------ReceiveDataTest007--------");
    struct hc_call_back callBack = {
        Transmit,
        GetProtocolParams,
        SetSessionKey,
        SetServiceResult,
        ConfirmReceiveRequest
    };

    hc_handle server = get_instance(&g_server_identity, HC_CENTRE, &callBack);
    ASSERT_TRUE(server != NULL);

    uint8_t data_str[] = "{\"message\":2,\"payload\":{"\
        "\"kcfData\":\"4A4EB6622524CBBF7DC96412A82BF4CB6022F50226A201DB3B3C55B4F0707345\","\
        "\"challenge\":\"E01AE0AA018ECDA852ACA4CCA45FCC56\", \"epk\":\"QWERTYUIOPASDFGHJKLZXCVBNM1234567890\"}}";
    uint8_buff data = {
        data_str,
        sizeof(data_str),
        strlen((char *) data_str)
    };
    receive_data(server, &data);
    EXPECT_EQ(g_result, END_FAILED);

    destroy(&server);
    LOG("--------ReceiveDataTest007--------");
}

static HWTEST_F(ReceiveDataTest, ReceiveDataTest008_pake_server2error, TestSize.Level2)
{
    LOG("--------ReceiveDataTest008--------");
    struct hc_call_back callBack = {
        Transmit,
        GetProtocolParams,
        SetSessionKey,
        SetServiceResult,
        ConfirmReceiveRequest
    };

    hc_handle server = get_instance(&g_server_identity, HC_CENTRE, &callBack);
    ASSERT_TRUE(server != NULL);

    uint8_t data_str[] = "{\"message\":2,\"payload\":{"\
        "\"kcfData\":\"4A4EB6622524CBBF7DC96412A82BF4CB6022F50226A201DB3B3C55B4F0707345\","\
        "\"challenge\":\"E01AE0AA018ECDA852ACA4CCA45FCC56\"}}"; 
    uint8_buff data = {
        data_str,
        sizeof(data_str),
        strlen((char *) data_str)
    };
    receive_data(server, &data);
    EXPECT_EQ(g_result, END_FAILED);

    destroy(&server);
    LOG("--------ReceiveDataTest008--------");
}

static HWTEST_F(ReceiveDataTest, ReceiveDataTest009_pake_client2, TestSize.Level2)
{
    LOG("--------ReceiveDataTest009--------");
    struct hc_call_back callBack = {
        Transmit,
        GetProtocolParams,
        SetSessionKey,
        SetServiceResult,
        ConfirmReceiveRequest
    };
    hc_handle server = get_instance(&g_server_identity, HC_CENTRE, &callBack);
    ASSERT_TRUE(server != NULL);

    uint8_t data_str[] = "{\"message\":32770,\"payload\":{\""\
        "kcfData\":\"4A4EB6622524CBBF7DC96412A82BF4CB6022F50226A201DB3B3C55B4F0707345\"}}";   
    uint8_buff data = {
        data_str,
        sizeof(data_str),
        strlen((char *) data_str)
    };
    receive_data(server, &data);
    EXPECT_EQ(g_result, END_FAILED);

    destroy(&server);
    LOG("--------ReceiveDataTest009--------");
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
    ASSERT_TRUE(server != NULL);

    uint8_t data_str[] = "{\"message\":32770,\"payload\":{}}";
    uint8_buff data = {
        data_str,
        sizeof(data_str),
        strlen((char *) data_str)
    };
    receive_data(server, &data);
    EXPECT_EQ(g_result, END_FAILED);

    destroy(&server);
    LOG("--------ReceiveDataTest010--------");
}

static HWTEST_F(ReceiveDataTest, ReceiveDataTest011_pake_server3, TestSize.Level2)
{
    LOG("--------ReceiveDataTest011--------");
    struct hc_call_back callBack = {
        Transmit,
        GetProtocolParams,
        SetSessionKey,
        SetServiceResult,
        ConfirmReceiveRequest
    };
    hc_handle server = get_instance(&g_server_identity, HC_CENTRE, &callBack);
    ASSERT_TRUE(server != NULL);

    uint8_t data_str[] = "{\"message\":3,\"payload\":{"\
        "\"exAuthInfo\":\"QWERTYUIOPASDFGHJKLZXCVBNM1234567890QWERTYUIOPASDFGHJKLZXCVBNM1234567890\"}}";
    uint8_buff data = {
        data_str,
        sizeof(data_str),
        strlen((char *) data_str)
    };
    receive_data(server, &data);
    EXPECT_EQ(g_result, END_FAILED);

    destroy(&server);
    LOG("--------ReceiveDataTest011--------");
}

static HWTEST_F(ReceiveDataTest, ReceiveDataTest012_pake_server3error, TestSize.Level2)
{
    LOG("--------ReceiveDataTest012--------");
    struct hc_call_back callBack = {
        Transmit,
        GetProtocolParams,
        SetSessionKey,
        SetServiceResult,
        ConfirmReceiveRequest
    };

    hc_handle server = get_instance(&g_server_identity, HC_CENTRE, &callBack);
    ASSERT_TRUE(server != NULL);

    uint8_t data_str[] = "{\"message\":3,\"payload\":{}}";
    uint8_buff data = {
        data_str,
        sizeof(data_str),
        strlen((char *) data_str)
    };
    receive_data(server, &data);
    EXPECT_EQ(g_result, END_FAILED);

    destroy(&server);
    LOG("--------ReceiveDataTest012--------");
}

static HWTEST_F(ReceiveDataTest, ReceiveDataTest013_pake_client3, TestSize.Level2)
{
    LOG("--------ReceiveDataTest013--------");
    struct hc_call_back callBack = {
        Transmit,
        GetProtocolParams,
        SetSessionKey,
        SetServiceResult,
        ConfirmReceiveRequest
    };

    hc_handle server = get_instance(&g_server_identity, HC_CENTRE, &callBack);
    ASSERT_TRUE(server != NULL);

    uint8_t data_str[] = "{\"message\":32771,\"payload\":{"\
        "\"exAuthInfo\":\"QWERTYUIOPASDFGHJKLZXCVBNM1234567890QWERTYUIOPASDFGHJKLZXCVBNM1234567890\"}}";
    uint8_buff data = {
        data_str,
        sizeof(data_str),
        strlen((char *) data_str)
    };
    receive_data(server, &data);
    EXPECT_EQ(g_result, END_FAILED);

    destroy(&server);
    LOG("--------ReceiveDataTest013--------");
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
    ASSERT_TRUE(server != NULL);

    uint8_t data_str[] = "{\"message\":32771,\"payload\":{}}";
    uint8_buff data = {
        data_str,
        sizeof(data_str),
        strlen((char *) data_str)
    };
    receive_data(server, &data);
    EXPECT_EQ(g_result, END_FAILED);

    destroy(&server);
    LOG("--------ReceiveDataTest014--------");
}

}
