/*
 * Copyright (c) 2020-2022 Huawei Device Co., Ltd.
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
#include "cJSON.h"
#include "huks_adapter_test.h"
#include "auth_info_test.h"

#define LOG(format, ...) (printf(format"\n", ##__VA_ARGS__))

using namespace std;
using namespace testing::ext;


namespace {
const int KEY_LEN = 16;
const int AUTH_ID_LENGTH = 64;
const int ERROR_ZERO_LENGTH = 0;
const int ERROR_LENGTH = 258;

int32_t GenerateSignMessage(hc_handle handle, struct uint8_buff *message);

static struct session_identity g_server_identity = {
    153666603,
    {strlen("aaa.bbbb.ccc"), "aaa.bbbb.ccc"},
    {strlen("CarDevice"), "CarDevice"},
    0
};

static struct session_identity g_server_identity_001 = {
    153666603,
    {ERROR_LENGTH, "aaa.bbbb.ccc"},
    {strlen("CarDevice"), "CarDevice"},
    0
};

static struct session_identity g_server_identity_002 = {
    153666603,
    {strlen("aaa.bbbb.ccc"), "aaa.bbbb.ccc"},
    {ERROR_LENGTH, "CarDevice"},
    0
};

static struct session_identity g_server_identity_003 = {
    153666603,
    {ERROR_ZERO_LENGTH, "aaa.bbbb.ccc"},
    {ERROR_LENGTH, "CarDevice"},
    0
};

static struct session_identity g_server_identity_004 = {
    153666603,
    {HC_PACKAGE_NAME_BUFF_LEN, ""},
    {HC_SERVICE_TYPE_BUFF_LEN, "CarDevice"},
    0
};

static struct session_identity g_server_identity_005 = {
    153666603,
    {strlen("aaa.bbbb.ccc"), "aaa.bbbb.ccc"},
    {HC_SERVICE_TYPE_BUFF_LEN, ""},
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

static struct hc_auth_id g_test_client_auth_id_001 = {strlen("authClient1"), "authClient1"};
static struct hc_auth_id g_test_client_auth_id_002 = {strlen("authClient2"), "authClient2"};

struct hc_auth_id *g_authIdClientList[3] = {
    &g_test_client_auth_id,
    &g_test_client_auth_id_001,
    &g_test_client_auth_id_002
};

struct hc_auth_id **g_authIdList = g_authIdClientList;

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

class HuksAdapterTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void HuksAdapterTest::SetUpTestCase(void) {}
void HuksAdapterTest::TearDownTestCase(void) {}
void HuksAdapterTest::SetUp()
{
    InitHcAuthId();
}
void HuksAdapterTest::TearDown() {}

static HWTEST_F(HuksAdapterTest, GenerateServiceIdTest001, TestSize.Level2)
{
    LOG("--------HuksAdapterTest Test001--------");
    LOG("--------generate_service_id--------");
    struct service_id service_id = generate_service_id(&g_server_identity);
    EXPECT_GT(service_id.length, 0);
    LOG("--------HuksAdapterTest Test001--------");
}

static HWTEST_F(HuksAdapterTest, GenerateServiceIdTest002, TestSize.Level2)
{
    LOG("--------HuksAdapterTest Test002--------");
    LOG("--------generate_service_id--------");
    struct service_id service_id = generate_service_id(&g_server_identity_001);
    EXPECT_EQ(service_id.length, 0);
    LOG("--------HuksAdapterTest Test002--------");
}

static HWTEST_F(HuksAdapterTest, GenerateServiceIdTest003, TestSize.Level2)
{
    LOG("--------HuksAdapterTest Test003--------");
    LOG("--------generate_service_id--------");
    struct service_id service_id = generate_service_id(&g_server_identity_002);
    EXPECT_EQ(service_id.length, 0);
    LOG("--------HuksAdapterTest Test003--------");
}

static HWTEST_F(HuksAdapterTest, GenerateServiceIdTest004, TestSize.Level2)
{
    LOG("--------HuksAdapterTest Test004--------");
    LOG("--------generate_service_id--------");
    struct service_id service_id = generate_service_id(&g_server_identity_003);
    EXPECT_EQ(service_id.length, 0);
    LOG("--------HuksAdapterTest Test004--------");
}

static HWTEST_F(HuksAdapterTest, GenerateServiceIdTest005, TestSize.Level2)
{
    LOG("--------HuksAdapterTest Test005--------");
    LOG("--------generate_service_id--------");
    struct session_identity *identity = nullptr;
    struct service_id service_id = generate_service_id(identity);
    EXPECT_EQ(service_id.length, 0);
    LOG("--------HuksAdapterTest Test005--------");
}

static HWTEST_F(HuksAdapterTest, GenerateServiceIdTest006, TestSize.Level2)
{
    LOG("--------HuksAdapterTest Test006--------");
    LOG("--------generate_service_id--------");
    struct service_id service_id = generate_service_id(&g_server_identity_004);
    EXPECT_GT(service_id.length, 0);
    LOG("--------HuksAdapterTest Test006--------");
}

static HWTEST_F(HuksAdapterTest, GenerateServiceIdTest007, TestSize.Level2)
{
    LOG("--------HuksAdapterTest Test007--------");
    LOG("--------generate_service_id--------");
    struct service_id service_id = generate_service_id(&g_server_identity_005);
    EXPECT_GT(service_id.length, 0);
    LOG("--------HuksAdapterTest Test007--------");
}

static HWTEST_F(HuksAdapterTest, GenerateKeyAliasTest001, TestSize.Level2)
{
    LOG("--------HuksAdapterTest Test008--------");
    LOG("--------generate_key_alias--------");
    enum huks_key_alias_type alias_type = KEY_ALIAS_ACCESSOR_PK;
    struct service_id service_id = generate_service_id(&g_server_identity);
    EXPECT_GT(service_id.length, 0);
    struct hc_key_alias hc_key_alias = generate_key_alias(&service_id, &g_test_client_auth_id, alias_type);
    EXPECT_GT(hc_key_alias.length, 0);
    LOG("--------HuksAdapterTest Test008--------");
}

static HWTEST_F(HuksAdapterTest, GenerateKeyAliasTest002, TestSize.Level2)
{
    LOG("--------HuksAdapterTest Test009--------");
    LOG("--------generate_key_alias--------");
    enum huks_key_alias_type alias_type = KEY_ALIAS_ACCESSOR_PK;
    struct hc_key_alias hc_key_alias = generate_key_alias(nullptr, &g_test_client_auth_id, alias_type);
    EXPECT_EQ(hc_key_alias.length, 0);
    LOG("--------HuksAdapterTest Test009--------");
}

static HWTEST_F(HuksAdapterTest, GenerateKeyAliasTest003, TestSize.Level2)
{
    LOG("--------HuksAdapterTest Test010--------");
    LOG("--------generate_key_alias--------");
    enum huks_key_alias_type alias_type = KEY_ALIAS_CONTROLLER_PK;
    struct service_id service_id = {65, "as"};
    struct hc_key_alias hc_key_alias = generate_key_alias(&service_id, &g_test_client_auth_id, alias_type);
    EXPECT_EQ(hc_key_alias.length, 0);
    LOG("--------HuksAdapterTest Test010--------");
}

static HWTEST_F(HuksAdapterTest, GenerateKeyAliasTest004, TestSize.Level2)
{
    LOG("--------HuksAdapterTest Test011--------");
    LOG("--------generate_key_alias--------");
    enum huks_key_alias_type alias_type = KEY_ALIAS_CONTROLLER_PK;
    struct service_id service_id = generate_service_id(&g_server_identity);
    EXPECT_GT(service_id.length, 0);
    struct hc_auth_id test_client_auth_id = {65, "as"};
    struct hc_key_alias hc_key_alias = generate_key_alias(&service_id, &test_client_auth_id, alias_type);
    EXPECT_EQ(hc_key_alias.length, 0);
    LOG("--------HuksAdapterTest Test011--------");
}

static HWTEST_F(HuksAdapterTest, GenerateStKeyPairTest001, TestSize.Level2)
{
    LOG("--------HuksAdapterTest Test012--------");
    LOG("--------generate_st_key_pair--------");
    struct st_key_pair *st_key_pair = static_cast<struct st_key_pair *>(MALLOC(sizeof(struct st_key_pair)));
    (void)memset_s(st_key_pair, sizeof(*st_key_pair), 0, sizeof(*st_key_pair));
    int32_t status = generate_st_key_pair(st_key_pair);
    EXPECT_EQ(status, ERROR_CODE_SUCCESS);
    FREE(st_key_pair);
    LOG("--------HuksAdapterTest Test012--------");
}

static HWTEST_F(HuksAdapterTest, GenerateLtKeyPairTest001, TestSize.Level2)
{
    LOG("--------HuksAdapterTest Test013--------");
    LOG("--------generate_lt_key_pair--------");
    struct service_id service_id = generate_service_id(&g_server_identity);
    EXPECT_GT(service_id.length, 0);
    struct hc_key_alias alias = generate_key_alias(&service_id, &g_test_client_auth_id, KEY_ALIAS_ACCESSOR_PK);
    int32_t ret = generate_lt_key_pair(&alias, &g_test_client_auth_id);
    EXPECT_EQ(ret, HC_OK);
    LOG("--------HuksAdapterTest Test013--------");
}

static struct ltpk lt_public_key = { 0, {0} };

static HWTEST_F(HuksAdapterTest, ExportLtPublicKeyTest001, TestSize.Level2)
{
    LOG("--------HuksAdapterTest Test014--------");
    LOG("--------export_lt_public_key--------");
    struct service_id service_id = generate_service_id(&g_server_identity);
    EXPECT_GT(service_id.length, 0);
    struct hc_key_alias alias = generate_key_alias(&service_id, &g_test_client_auth_id, KEY_ALIAS_ACCESSOR_PK);
    int32_t ret = export_lt_public_key(&alias, &lt_public_key);
    EXPECT_EQ(ret, HC_OK);
    LOG("--------HuksAdapterTest Test014--------");
}

static HWTEST_F(HuksAdapterTest, DeleteLtPublicKeyTest001, TestSize.Level2)
{
    LOG("--------HuksAdapterTest Test015--------");
    LOG("--------delete_lt_public_key--------");
    struct service_id service_id = generate_service_id(&g_server_identity);
    EXPECT_GT(service_id.length, 0);
    struct hc_key_alias alias = generate_key_alias(&service_id, &g_test_client_auth_id, KEY_ALIAS_ACCESSOR_PK);
    int32_t ret = delete_lt_public_key(&alias);
    EXPECT_EQ(ret, ERROR_CODE_SUCCESS);
    LOG("--------HuksAdapterTest Test015--------");
}

static HWTEST_F(HuksAdapterTest, DeleteLtPublicKeyTest002, TestSize.Level2)
{
    LOG("--------HuksAdapterTest Test016--------");
    LOG("--------delete_lt_public_key--------");
    int32_t ret = delete_lt_public_key(nullptr);
    EXPECT_NE(ret, ERROR_CODE_SUCCESS);
    LOG("--------HuksAdapterTest Test016--------");
}

static HWTEST_F(HuksAdapterTest, ImportLtPublicKeyTest001, TestSize.Level2)
{
    LOG("--------HuksAdapterTest Test017--------");
    LOG("--------import_lt_public_key--------");
    struct service_id service_id = generate_service_id(&g_server_identity);
    EXPECT_GT(service_id.length, 0);
    struct hc_key_alias alias = generate_key_alias(&service_id, &g_test_client_auth_id, KEY_ALIAS_ACCESSOR_PK);
    int32_t userType = 1;
    int32_t pairType = -1;
    int32_t ret = import_lt_public_key(&alias, &lt_public_key, userType, pairType, &g_test_client_auth_id);
    EXPECT_NE(ret, ERROR_CODE_SUCCESS);
    LOG("--------HuksAdapterTest Test017--------");
}

static HWTEST_F(HuksAdapterTest, ImportLtPublicKeyTest002, TestSize.Level2)
{
    LOG("--------HuksAdapterTest Test018--------");
    LOG("--------import_lt_public_key--------");
    struct service_id service_id = generate_service_id(&g_server_identity);
    EXPECT_GT(service_id.length, 0);
    struct hc_key_alias alias = generate_key_alias(&service_id, &g_test_client_auth_id, KEY_ALIAS_ACCESSOR_PK);
    int32_t userType = -1;
    int32_t pairType = 2;
    int32_t ret = import_lt_public_key(&alias, &lt_public_key, userType, pairType, &g_test_client_auth_id);
    EXPECT_NE(ret, ERROR_CODE_SUCCESS);
    LOG("--------HuksAdapterTest Test018--------");
}

static HWTEST_F(HuksAdapterTest, ImportLtPublicKeyTest003, TestSize.Level2)
{
    LOG("--------HuksAdapterTest Test019--------");
    LOG("--------import_lt_public_key--------");
    struct service_id service_id = generate_service_id(&g_server_identity);
    EXPECT_GT(service_id.length, 0);
    struct hc_key_alias alias = generate_key_alias(&service_id, &g_test_client_auth_id, KEY_ALIAS_ACCESSOR_PK);
    int32_t userType = 7;
    int32_t pairType = 0;
    int32_t ret = import_lt_public_key(&alias, &lt_public_key, userType, pairType, &g_test_client_auth_id);
    EXPECT_NE(ret, ERROR_CODE_SUCCESS);
    LOG("--------HuksAdapterTest Test019--------");
}

static HWTEST_F(HuksAdapterTest, ImportLtPublicKeyTest004, TestSize.Level2)
{
    LOG("--------HuksAdapterTest Test020--------");
    LOG("--------import_lt_public_key--------");
    int32_t userType = 4;
    int32_t pairType = 0;
    int32_t ret = import_lt_public_key(nullptr, &lt_public_key, userType, pairType, &g_test_client_auth_id);
    EXPECT_NE(ret, ERROR_CODE_SUCCESS);
    LOG("--------HuksAdapterTest Test020--------");
}

static HWTEST_F(HuksAdapterTest, ImportLtPublicKeyTest005, TestSize.Level2)
{
    LOG("--------HuksAdapterTest Test021--------");
    LOG("--------import_lt_public_key--------");
    int32_t userType = 4;
    int32_t pairType = 1;
    struct service_id service_id = generate_service_id(&g_server_identity);
    EXPECT_GT(service_id.length, 0);
    struct hc_key_alias alias = generate_key_alias(&service_id, &g_test_client_auth_id, KEY_ALIAS_ACCESSOR_PK);
    int32_t ret = import_lt_public_key(&alias, nullptr, userType, pairType, &g_test_client_auth_id);
    EXPECT_NE(ret, ERROR_CODE_SUCCESS);
    LOG("--------HuksAdapterTest Test021--------");
}

static HWTEST_F(HuksAdapterTest, ImportLtPublicKeyTest006, TestSize.Level2)
{
    LOG("--------HuksAdapterTest Test022--------");
    LOG("--------import_lt_public_key--------");
    int32_t userType = 1;
    int32_t pairType = 1;
    struct service_id service_id = generate_service_id(&g_server_identity);
    EXPECT_GT(service_id.length, 0);
    struct hc_key_alias alias = generate_key_alias(&service_id, &g_test_client_auth_id, KEY_ALIAS_ACCESSOR_PK);
    int32_t ret = import_lt_public_key(&alias, &lt_public_key, userType, pairType, nullptr);
    EXPECT_NE(ret, ERROR_CODE_SUCCESS);
    LOG("--------HuksAdapterTest Test022--------");
}

static HWTEST_F(HuksAdapterTest, CheckLtPublicKeyExistTest001, TestSize.Level2)
{
    LOG("--------HuksAdapterTest Test023--------");
    LOG("--------check_lt_public_key_exist--------");
    struct service_id service_id = generate_service_id(&g_server_identity);
    EXPECT_GT(service_id.length, 0);
    struct hc_key_alias alias = generate_key_alias(&service_id, &g_test_client_auth_id, KEY_ALIAS_ACCESSOR_PK);
    int32_t ret = check_lt_public_key_exist(&alias);
    EXPECT_NE(ret, ERROR_CODE_SUCCESS);
    LOG("--------HuksAdapterTest Test023--------");
}

static HWTEST_F(HuksAdapterTest, CheckLtPublicKeyExistTest002, TestSize.Level2)
{
    LOG("--------HuksAdapterTest Test024--------");
    LOG("--------check_lt_public_key_exist--------");
    struct service_id service_id = generate_service_id(nullptr);
    EXPECT_EQ(service_id.length, 0);
    struct hc_key_alias alias = generate_key_alias(&service_id, &g_test_client_auth_id, KEY_ALIAS_ACCESSOR_PK);
    int32_t ret = check_lt_public_key_exist(&alias);
    EXPECT_NE(ret, ERROR_CODE_SUCCESS);
    LOG("--------HuksAdapterTest Test024--------");
}

static HWTEST_F(HuksAdapterTest, CheckLtPublicKeyExistTest003, TestSize.Level2)
{
    LOG("--------HuksAdapterTest Test025--------");
    LOG("--------check_lt_public_key_exist--------");
    int32_t ret = check_lt_public_key_exist(nullptr);
    EXPECT_EQ(ret, HC_INPUT_ERROR);
    struct hc_key_alias alias;
    (void)memset_s(&alias, sizeof(alias), 0, sizeof(alias));
    alias.length = 1;
    ret = check_lt_public_key_exist(&alias);
    EXPECT_NE(ret, ERROR_CODE_SUCCESS);
    LOG("--------HuksAdapterTest Test025--------");
}

static HWTEST_F(HuksAdapterTest, CheckKeyAliasIsOwnerTest001, TestSize.Level2)
{
    LOG("--------HuksAdapterTest Test026--------");
    LOG("--------check_key_alias_is_owner--------");
    struct service_id service_id = generate_service_id(&g_server_identity);
    EXPECT_GT(service_id.length, 0);
    struct hc_key_alias alias = generate_key_alias(&service_id, &g_test_client_auth_id, KEY_ALIAS_ACCESSOR_PK);
    int32_t ret = check_key_alias_is_owner(&alias);
    EXPECT_NE(ret, ERROR_CODE_SUCCESS);
    LOG("--------HuksAdapterTest Test026--------");
}

static HWTEST_F(HuksAdapterTest, CheckKeyAliasIsOwnerTest002, TestSize.Level2)
{
    LOG("--------HuksAdapterTest Test027--------");
    LOG("--------check_key_alias_is_owner--------");
    struct service_id service_id = generate_service_id(nullptr);
    EXPECT_EQ(service_id.length, 0);
    struct hc_key_alias alias = generate_key_alias(&service_id, &g_test_client_auth_id, KEY_ALIAS_ACCESSOR_PK);
    int32_t ret = check_key_alias_is_owner(&alias);
    EXPECT_NE(ret, ERROR_CODE_SUCCESS);
    LOG("--------HuksAdapterTest Test027--------");
}

static HWTEST_F(HuksAdapterTest, GetLtKeyInfoTest001, TestSize.Level2)
{
    LOG("--------HuksAdapterTest Test028--------");
    LOG("--------get_lt_key_info--------");
    struct huks_key_type key_type;
    struct hc_auth_id auth_id;
    struct service_id service_id = generate_service_id(&g_server_identity);
    EXPECT_GT(service_id.length, 0);
    struct hc_key_alias alias = generate_key_alias(&service_id, &g_test_client_auth_id, KEY_ALIAS_ACCESSOR_PK);
    int32_t ret = get_lt_key_info(&alias, &key_type, &auth_id);
    EXPECT_NE(ret, ERROR_CODE_SUCCESS);
    LOG("--------HuksAdapterTest Test028--------");
}

static HWTEST_F(HuksAdapterTest, GetLtPublicKeyListTest001, TestSize.Level2)
{
    LOG("--------HuksAdapterTest Test029--------");
    LOG("--------get_lt_public_key_list--------");
    uint32_t count = 0;
    enum huks_key_alias_type alias_type = KEY_ALIAS_CONTROLLER_PK;
    int32_t ret = get_lt_public_key_list(&g_test_client_auth_id, alias_type, *g_authIdList, &count);
    EXPECT_EQ(ret, ERROR_CODE_SUCCESS);
    LOG("--------HuksAdapterTest Test029--------");
}

static HWTEST_F(HuksAdapterTest, ComputeStsSharedSecretTest001, TestSize.Level2)
{
    LOG("--------HuksAdapterTest Test030--------");
    LOG("--------compute_sts_shared_secret--------");
    struct st_key_pair st_key_pair;
    int32_t ret = generate_st_key_pair(&st_key_pair);
    EXPECT_EQ(ret, ERROR_CODE_SUCCESS);
    struct sts_shared_secret shared_secret;
    ret = compute_sts_shared_secret(&(st_key_pair.st_private_key), &(st_key_pair.st_public_key), &shared_secret);
    EXPECT_EQ(ret, ERROR_CODE_SUCCESS);
    LOG("--------HuksAdapterTest Test030--------");
}

static HWTEST_F(HuksAdapterTest, ComputeStsSharedSecretTest002, TestSize.Level2)
{
    LOG("--------HuksAdapterTest Test031--------");
    LOG("--------compute_sts_shared_secret--------");
    struct stpk peer_public_key = {4, {"9A87"}};
    struct st_key_pair key_pair;
    int32_t ret = generate_st_key_pair(&key_pair);
    EXPECT_EQ(ret, ERROR_CODE_SUCCESS);
    struct sts_shared_secret shared_secret;
    ret = compute_sts_shared_secret(&(key_pair.st_private_key), &peer_public_key, &shared_secret);
    EXPECT_NE(ret, ERROR_CODE_SUCCESS);
    LOG("--------HuksAdapterTest Test031--------");
}

static HWTEST_F(HuksAdapterTest, ComputeStsSharedSecretTest003, TestSize.Level2)
{
    LOG("--------HuksAdapterTest Test032--------");
    LOG("--------compute_sts_shared_secret--------");
    uint8_t temp[] = {"9A8781AE9ACFDBFD577DF72949A4731F"};
    struct stpk stpk_test;
    stpk_test.length = 32;
    memcpy_s(stpk_test.stpk, sizeof(stpk_test.stpk), temp, stpk_test.length);
    stpk_test.length = 0;
    struct st_key_pair key_pair;
    int32_t ret = generate_st_key_pair(&key_pair);
    EXPECT_EQ(ret, ERROR_CODE_SUCCESS);
    struct sts_shared_secret shared_secret;
    ret = compute_sts_shared_secret(&(key_pair.st_private_key), &stpk_test, &shared_secret);
    EXPECT_NE(ret, ERROR_CODE_FAILED);
    LOG("--------HuksAdapterTest Test032--------");
}

static struct signature signature = {0, {0}};
static HWTEST_F(HuksAdapterTest, SignTest001, TestSize.Level2)
{
    LOG("--------HuksAdapterTest Test033--------");
    LOG("--------sign--------");
    struct hc_call_back callBack = {
        Transmit,
        GetProtocolParams,
        SetSessionKey,
        SetServiceResult,
        ConfirmReceiveRequest
    };

    struct operation_parameter params = {g_test_server_auth_id, g_test_client_auth_id, KEY_LEN};
    hc_handle server = get_instance(&g_server_identity, HC_CENTRE, &callBack);
    int32_t ret = authenticate_peer(server, &params);
    EXPECT_EQ(ret, HC_OK);
    struct hichain *hichainTest = reinterpret_cast<struct hichain *>(server);
    struct uint8_buff message;
    (void)memset_s(&message, sizeof(message), 0, sizeof(message));
    ret = GenerateSignMessage(reinterpret_cast<void *>(hichainTest->sts_client), &message);
    EXPECT_EQ(ret, HC_OK);
    struct service_id service_id = generate_service_id(&g_server_identity);
    EXPECT_GT(service_id.length, 0);
    struct hc_key_alias alias = generate_key_alias(&service_id, &g_test_client_auth_id, KEY_ALIAS_ACCESSOR_PK);
    ret = sign(&alias, &message, &signature);
    EXPECT_NE(ret, ERROR_CODE_SUCCESS);
    FREE(message.val);
    LOG("--------HuksAdapterTest Test033--------");
}

static HWTEST_F(HuksAdapterTest, SignTest002, TestSize.Level2)
{
    LOG("--------HuksAdapterTest Test034--------");
    LOG("--------sign--------");
    uint8_t dataMsg[] = {"9A8781AE9ACFDBFD577DF72949A4731F"};

    struct uint8_buff message = {
        dataMsg,
        sizeof(dataMsg),
        strlen(reinterpret_cast<char *>(dataMsg))
    };

    uint8_t dataStr[] = {"9A8781AE9ACFDBFD577DF72949A4731FE73208026B2BBD7822CFE170F01C5C09"};
    struct signature sign_result;
    (void)memset_s(&sign_result, sizeof(struct signature), 0, sizeof(struct signature));
    sign_result.length = HC_SIGNATURE_LEN;
    memcpy_s(sign_result.signature, sizeof(sign_result.signature), dataStr, HC_SIGNATURE_LEN);

    struct service_id service_id = generate_service_id(&g_server_identity);
    EXPECT_GT(service_id.length, 0);
    struct hc_key_alias alias = generate_key_alias(&service_id, &g_test_client_auth_id, KEY_ALIAS_ACCESSOR_PK);
    int32_t ret = sign(&alias, &message, &sign_result);
    EXPECT_NE(ret, ERROR_CODE_SUCCESS);
    LOG("--------HuksAdapterTest Test034--------");
}

static HWTEST_F(HuksAdapterTest, SignTest003, TestSize.Level2)
{
    LOG("--------HuksAdapterTest Test035--------");
    LOG("--------sign--------");
    uint8_t dataMsg[] = "{\"message\":32770,\"payload\":{"
        "\"kcfData\":\"4A4EB6622524CBBF7DC96412A82BF4CB6022F50226A201DB3B3C55B4F0707345\","
        "\"challenge\":\"E01AE0AA018ECDA852ACA4CCA45FCC56\"}}";

    struct uint8_buff message = {
        dataMsg,
        sizeof(dataMsg),
        strlen(reinterpret_cast<char *>(dataMsg))
    };

    uint8_t dataStr[] = {"9A8781AE9ACFDBFD577DF72949A4731FE73208026B2BBD7822CFE170F01C5C09"};
    struct signature sign_result;
    (void)memset_s(&sign_result, sizeof(struct signature), 0, sizeof(struct signature));
    sign_result.length = HC_SIGNATURE_LEN;
    memcpy_s(sign_result.signature, sizeof(sign_result.signature), dataStr, HC_SIGNATURE_LEN);
    struct service_id service_id = generate_service_id(&g_server_identity);
    EXPECT_GT(service_id.length, 0);
    struct hc_key_alias alias = generate_key_alias(&service_id, &g_test_client_auth_id, KEY_ALIAS_ACCESSOR_PK);
    int32_t ret = sign(&alias, &message, &sign_result);
    EXPECT_NE(ret, ERROR_CODE_SUCCESS);
    LOG("--------HuksAdapterTest Test035--------");
}

static HWTEST_F(HuksAdapterTest, VerifyTest001, TestSize.Level2)
{
    LOG("--------HuksAdapterTest Test036--------");
    LOG("--------verify--------");
    struct hc_call_back callBack = {
        Transmit,
        GetProtocolParams,
        SetSessionKey,
        SetServiceResult,
        ConfirmReceiveRequest
    };

    struct operation_parameter params = {g_test_server_auth_id, g_test_client_auth_id, KEY_LEN};
    hc_handle server = get_instance(&g_server_identity, HC_CENTRE, &callBack);
    int32_t ret = authenticate_peer(server, &params);
    EXPECT_EQ(ret, HC_OK);
    struct hichain *hichainTest = reinterpret_cast<struct hichain *>(server);
    struct uint8_buff message;
    (void)memset_s(&message, sizeof(message), 0, sizeof(message));
    ret = GenerateSignMessage(reinterpret_cast<void *>(hichainTest->sts_client), &message);
    EXPECT_EQ(ret, HC_OK);
    struct service_id service_id = generate_service_id(&g_server_identity);
    EXPECT_GT(service_id.length, 0);
    struct hc_key_alias alias = generate_key_alias(&service_id, &g_test_client_auth_id, KEY_ALIAS_ACCESSOR_PK);
    ret = verify(&alias, HC_USER_TYPE_CONTROLLER, &message, &signature);
    EXPECT_NE(ret, ERROR_CODE_SUCCESS);
    FREE(message.val);
    LOG("--------HuksAdapterTest Test036--------");
}

static HWTEST_F(HuksAdapterTest, VerifyWithPublicKeyTest001, TestSize.Level2)
{
    LOG("--------HuksAdapterTest Test037--------");
    LOG("--------verify_with_public_key--------");
    struct hc_call_back callBack = {
        Transmit,
        GetProtocolParams,
        SetSessionKey,
        SetServiceResult,
        ConfirmReceiveRequest
    };
    int32_t userType = 1;
    struct var_buffer public_key;
    public_key.length = 128;
    uint8_t dataMsg[] = {"BB4DA8D3B2E76EAF968C67DAFCC6ECD20A72668EA43220C2835AEDD6D84E2A314203E4"
                         "1D9F5E3D0C297CA1C0C61969ECC04658044FEF87FE141B0E374CAD5357"};
    memcpy_s(public_key.data, sizeof(public_key.data), dataMsg, sizeof(public_key.data));
    struct operation_parameter params = {g_test_server_auth_id, g_test_client_auth_id, KEY_LEN};

    hc_handle server = get_instance(&g_server_identity, HC_CENTRE, &callBack);
    int32_t ret = authenticate_peer(server, &params);
    EXPECT_EQ(ret, HC_OK);
    struct signature sign_result = {0, {0}};
    uint8_t dataStr[] = {"9A8781AE9ACFDBFD577DF72949A4731FE73208026B2BBD7822CFE170F01C5C09"};
    (void)memset_s(&sign_result, sizeof(struct signature), 0, sizeof(struct signature));
    sign_result.length = HC_SIGNATURE_LEN;
    memcpy_s(sign_result.signature, sizeof(sign_result.signature), dataStr, HC_SIGNATURE_LEN);

    struct hichain *hichainTest = reinterpret_cast<struct hichain *>(server);
    struct uint8_buff message;
    (void)memset_s(&message, sizeof(message), 0, sizeof(message));
    ret = GenerateSignMessage(reinterpret_cast<void *>(hichainTest->sts_client), &message);
    EXPECT_EQ(ret, HC_OK);

    ret = verify_with_public_key(userType, &message, &public_key, &sign_result);
    EXPECT_NE(ret, ERROR_CODE_SUCCESS);
    FREE(message.val);
    LOG("--------HuksAdapterTest Test037--------");
}

static HWTEST_F(HuksAdapterTest, VerifyWithPublicKeyTest002, TestSize.Level2)
{
    LOG("--------HuksAdapterTest Test038--------");
    LOG("--------verify_with_public_key--------");
    int32_t userType = 1;
    struct var_buffer public_key;
    (void)memset_s(&public_key, sizeof(public_key), 0, sizeof(public_key));
    public_key.length = 128;

    struct signature sign_result;
    (void)memset_s(&sign_result, sizeof(sign_result), 0, sizeof(sign_result));
    sign_result.length = HC_SIGNATURE_LEN;

    struct uint8_buff message;
    (void)memset_s(&message, sizeof(message), 0, sizeof(message));

    int32_t ret = verify_with_public_key(userType, nullptr, &public_key, &sign_result);
    EXPECT_EQ(ret, HC_INPUT_ERROR);
    ret = verify_with_public_key(userType, &message, nullptr, &sign_result);
    EXPECT_EQ(ret, HC_INPUT_ERROR);
    ret = verify_with_public_key(userType, &message, &public_key, nullptr);
    EXPECT_EQ(ret, HC_INPUT_ERROR);
    LOG("--------HuksAdapterTest Test038--------");
}

static HWTEST_F(HuksAdapterTest, CheckDlSpekePublicKeyTest001, TestSize.Level2)
{
    LOG("--------HuksAdapterTest Test039--------");
    LOG("--------CheckDlSpekePublicKey--------");

    int32_t result = CheckDlSpekePublicKey(nullptr, HC_BIG_PRIME_MAX_LEN_384);
    EXPECT_EQ(result, HC_INPUT_PTR_NULL);
    struct var_buffer key;
    key.length = 500;
    uint8_t data[] = {"123456789"};
    memcpy_s(key.data, sizeof(data), data, sizeof(data));
    result = CheckDlSpekePublicKey(&key, HC_BIG_PRIME_MAX_LEN_384);
    EXPECT_EQ(result, HC_INPUT_ERROR);

    key.length = 1;
    key.data[0] = 0;
    result = CheckDlSpekePublicKey(&key, HC_BIG_PRIME_MAX_LEN_384);
    EXPECT_EQ(result, HC_MEMCPY_ERROR);

    key.data[0] = 1;
    result = CheckDlSpekePublicKey(&key, HC_BIG_PRIME_MAX_LEN_384);
    EXPECT_EQ(result, HC_MEMCPY_ERROR);

    key.data[0] = 0xFF;
    result = CheckDlSpekePublicKey(&key, HC_BIG_PRIME_MAX_LEN_384);
    EXPECT_EQ(result, HC_OK);
    LOG("--------HuksAdapterTest Test039--------");
}

static HWTEST_F(HuksAdapterTest, CheckDlSpekePublicKeyTest002, TestSize.Level2)
{
    LOG("--------HuksAdapterTest Test040--------");
    LOG("--------CheckDlSpekePublicKey--------");

    int32_t result = CheckDlSpekePublicKey(nullptr, HC_BIG_PRIME_MAX_LEN_384);
    ASSERT_EQ(result, HC_INPUT_PTR_NULL);
    struct var_buffer key;
    key.length = 11;
    uint8_t data[] = "123456789";
    memcpy_s(key.data, sizeof(data), data, sizeof(data));
    result = CheckDlSpekePublicKey(&key, HC_BIG_PRIME_MAX_LEN_256);
    ASSERT_EQ(result, HC_OK);
    LOG("--------HuksAdapterTest Test040--------");
}

static HWTEST_F(HuksAdapterTest, CalBignumExpTest001, TestSize.Level2)
{
    LOG("--------HuksAdapterTest Test041--------");
    LOG("--------cal_bignum_exp--------");
    struct var_buffer base;
    base.length = 11;
    uint8_t data[] = "123456789";
    memcpy_s(base.data, sizeof(data), data, sizeof(data));

    struct var_buffer exp;
    exp.length = 1;
    exp.data[0] = 0;

    struct big_num out_result = {1, {0}};

    int32_t result = cal_bignum_exp(nullptr, &exp, HC_BIG_PRIME_MAX_LEN_384, &out_result);
    EXPECT_EQ(result, HC_INPUT_ERROR);
    result = cal_bignum_exp(&base, nullptr, HC_BIG_PRIME_MAX_LEN_384, &out_result);
    EXPECT_EQ(result, HC_INPUT_ERROR);
    result = cal_bignum_exp(&base, &exp, HC_BIG_PRIME_MAX_LEN_256, nullptr);
    EXPECT_EQ(result, HC_INPUT_ERROR);
    LOG("--------HuksAdapterTest Test041--------");
}

static HWTEST_F(HuksAdapterTest, CalBignumExpTest002, TestSize.Level2)
{
    LOG("--------HuksAdapterTest Test042--------");
    LOG("--------cal_bignum_exp--------");
    struct var_buffer base;
    base.length = 11;
    uint8_t data[] = "123456789";
    memcpy_s(base.data, sizeof(data), data, sizeof(data));

    struct var_buffer exp;
    exp.length = 11;
    exp.data[0] = 0;

    struct big_num out_result = {1, {0}};

    int32_t result = cal_bignum_exp(&base, &exp, 0, &out_result);
    EXPECT_EQ(result, HC_LARGE_PRIME_NUMBER_LEN_UNSUPPORT);
    result = cal_bignum_exp(&base, &exp, 1000, &out_result);
    EXPECT_EQ(result, HC_LARGE_PRIME_NUMBER_LEN_UNSUPPORT);
    LOG("--------HuksAdapterTest Test042--------");
}

static HWTEST_F(HuksAdapterTest, CalBignumExpTest003, TestSize.Level2)
{
    LOG("--------HuksAdapterTest Test043--------");
    LOG("--------cal_bignum_exp--------");
    struct var_buffer base;
    base.length = 11;
    uint8_t data[] = "123456789";
    memcpy_s(base.data, sizeof(data), data, sizeof(data));

    struct var_buffer exp;
    exp.length = 1;
    exp.data[0] = 0;

    struct big_num out_result = {0, {0}};

    int32_t result = cal_bignum_exp(&base, &exp, HC_BIG_PRIME_MAX_LEN_256, &out_result);
    EXPECT_NE(result, HC_INPUT_ERROR);
    result = cal_bignum_exp(&base, &exp, HC_BIG_PRIME_MAX_LEN_384, &out_result);
    EXPECT_NE(result, HC_INPUT_ERROR);
    LOG("--------HuksAdapterTest Test043--------");
}

static HWTEST_F(HuksAdapterTest, ComputeHmacTest001, TestSize.Level2)
{
    LOG("--------HuksAdapterTest Test044--------");
    LOG("--------compute_hmac--------");
    struct var_buffer key;
    key.length = 11;
    uint8_t data[] = "123456789";
    memcpy_s(key.data, sizeof(data), data, sizeof(data));

    uint8_t dataMsg[] = "{\"message\":32770,\"payload\":{"
        "\"kcfData\":\"4A4EB6622524CBBF7DC96412A82BF4CB6022F50226A201DB3B3C55B4F0707345\","
        "\"challenge\":\"E01AE0AA018ECDA852ACA4CCA45FCC56\"}}";

    struct uint8_buff message = {
        dataMsg,
        sizeof(dataMsg),
        strlen(reinterpret_cast<char *>(dataMsg))
    };

    struct hmac out_hamc = {0, {0}};

    int32_t result = compute_hmac(&key, &message, &out_hamc);
    EXPECT_NE(result, ERROR_CODE_SUCCESS);
    LOG("--------HuksAdapterTest Test044--------");
}

static HWTEST_F(HuksAdapterTest, ComputeHmacTest002, TestSize.Level2)
{
    LOG("--------HuksAdapterTest Test045--------");
    LOG("--------compute_hmac--------");
    struct var_buffer key;
    (void)memset_s(&key, sizeof(key), 0, sizeof(key));
    key.length = 16;

    struct uint8_buff message;
    (void)memset_s(&message, sizeof(message), 0, sizeof(message));

    struct hmac out_hamc;
    (void)memset_s(&out_hamc, sizeof(out_hamc), 0, sizeof(out_hamc));

    int32_t result = compute_hmac(nullptr, &message, &out_hamc);
    EXPECT_EQ(result, HC_INPUT_ERROR);
    result = compute_hmac(&key, nullptr, &out_hamc);
    EXPECT_EQ(result, HC_INPUT_ERROR);
    result = compute_hmac(&key, &message, nullptr);
    EXPECT_EQ(result, HC_INPUT_ERROR);
    LOG("--------HuksAdapterTest Test045--------");
}

static HWTEST_F(HuksAdapterTest, ComputeHkdfTest001, TestSize.Level2)
{
    LOG("--------HuksAdapterTest Test046--------");
    LOG("--------compute_hkdf--------");
    struct var_buffer shared_secret;
    shared_secret.length = 11;
    uint8_t data[] = "123456789";
    memcpy_s(shared_secret.data, sizeof(data), data, sizeof(data));

    struct hc_salt salt = {1, {0}};
    char keyInfo;
    uint32_t hkdfLen = 1;

    struct var_buffer out_hkdf;
    out_hkdf.data[0] = 0;
    out_hkdf.length = 64;

    int32_t result = compute_hkdf(&shared_secret, &salt, &keyInfo, hkdfLen, &out_hkdf);
    EXPECT_NE(result, ERROR_CODE_SUCCESS);
    LOG("--------HuksAdapterTest Test046--------");
}

static HWTEST_F(HuksAdapterTest, AesGcmEncryptTest001, TestSize.Level2)
{
    LOG("--------HuksAdapterTest Test047--------");
    LOG("--------aes_gcm_encrypt--------");
    struct var_buffer key;
    key.length = 16;
    uint8_t data[] = "123456789";
    memcpy_s(key.data, sizeof(data), data, sizeof(data));

    uint8_t dataMsg[] = "{\"message\":32770,\"payload\":{"
        "\"kcfData\":\"4A4EB6622524CBBF7DC96412A82BF4CB6022F50226A201DB3B3C55B4F0707345\","
        "\"challenge\":\"E01AE0AA018ECDA852ACA4CCA45FCC56\"}}";

    struct uint8_buff message = {
        dataMsg,
        sizeof(dataMsg),
        strlen(reinterpret_cast<char *>(dataMsg))
    };

    struct aes_aad aad= {64, {0}};

    struct uint8_buff out_plain;
    out_plain.length = 1;
    out_plain.size = 64;

    int32_t result = aes_gcm_encrypt(&key, &message, &aad, &out_plain);
    EXPECT_NE(result, ERROR_CODE_SUCCESS);
    out_plain.length = 64;
    result = aes_gcm_encrypt(&key, &message, &aad, &out_plain);
    EXPECT_NE(result, ERROR_CODE_SUCCESS);
    LOG("--------HuksAdapterTest Test047--------");
}

static HWTEST_F(HuksAdapterTest, AesGcmEncryptTest002, TestSize.Level2)
{
    LOG("--------HuksAdapterTest Test048--------");
    LOG("--------aes_gcm_encrypt--------");
    struct var_buffer key;
    (void)memset_s(&key, sizeof(key), 0, sizeof(key));
    key.length = 16;

    struct uint8_buff message;
    (void)memset_s(&message, sizeof(message), 0, sizeof(message));

    struct aes_aad aad;
    (void)memset_s(&aad, sizeof(aad), 0, sizeof(aad));

    struct uint8_buff out_plain;
    (void)memset_s(&out_plain, sizeof(out_plain), 0, sizeof(out_plain));

    int32_t result = aes_gcm_encrypt(nullptr, &message, &aad, &out_plain);
    EXPECT_EQ(result, HC_INPUT_ERROR);
    result = aes_gcm_encrypt(&key, nullptr, &aad, &out_plain);
    EXPECT_EQ(result, HC_INPUT_ERROR);
    result = aes_gcm_encrypt(&key, &message, nullptr, &out_plain);
    EXPECT_EQ(result, HC_INPUT_ERROR);
    result = aes_gcm_encrypt(&key, &message, &aad, nullptr);
    EXPECT_EQ(result, HC_INPUT_ERROR);
    LOG("--------HuksAdapterTest Test048--------");
}

static HWTEST_F(HuksAdapterTest, AesGcmDecryptTest001, TestSize.Level2)
{
    LOG("--------HuksAdapterTest Test049--------");
    LOG("--------aes_gcm_decrypt--------");
    struct var_buffer key;
    key.length = 11;
    uint8_t data[] = "123456789";
    memcpy_s(key.data, sizeof(data), data, sizeof(data));

    uint8_t dataMsg[] = "{\"message\":32770,\"payload\":{"
        "\"kcfData\":\"4A4EB6622524CBBF7DC96412A82BF4CB6022F50226A201DB3B3C55B4F0707345\","
        "\"challenge\":\"E01AE0AA018ECDA852ACA4CCA45FCC56\"}}";

    struct uint8_buff message = {
        dataMsg,
        sizeof(dataMsg),
        strlen(reinterpret_cast<char *>(dataMsg))
    };

    struct aes_aad aad = {1, {1}};

    struct uint8_buff out_plain;
    (void)memset_s(&out_plain, sizeof(out_plain), 0, sizeof(out_plain));
    out_plain.size = 0;
    out_plain.length = 0;

    int32_t result = aes_gcm_decrypt(&key, &message, &aad, &out_plain);
    EXPECT_NE(result, ERROR_CODE_SUCCESS);
    LOG("--------HuksAdapterTest Test049--------");
}

static HWTEST_F(HuksAdapterTest, AesGcmDecryptTest002, TestSize.Level2)
{
    LOG("--------HuksAdapterTest Test050--------");
    LOG("--------aes_gcm_decrypt--------");
    struct var_buffer key;
    (void)memset_s(&key, sizeof(key), 0, sizeof(key));
    key.length = 16;

    struct uint8_buff cipher;
    cipher.size = 64;
    cipher.length = 64;

    struct aes_aad aad;
    (void)memset_s(&aad, sizeof(aad), 0, sizeof(aad));
    aad.length = 64;

    struct uint8_buff out_plain;
    (void)memset_s(&out_plain, sizeof(out_plain), 0, sizeof(out_plain));
    out_plain.size = 64;
    out_plain.length = 64;

    int32_t result = aes_gcm_decrypt(&key, &cipher, &aad, &out_plain);
    EXPECT_NE(result, ERROR_CODE_SUCCESS);
    LOG("--------HuksAdapterTest Test050--------");
}

static HWTEST_F(HuksAdapterTest, AesGcmDecryptTest003, TestSize.Level2)
{
    LOG("--------HuksAdapterTest Test051--------");
    LOG("--------aes_gcm_decrypt--------");
    struct var_buffer key;
    (void)memset_s(&key, sizeof(key), 0, sizeof(key));
    key.length = 1;

    struct uint8_buff cipher;
    cipher.size = 1;
    cipher.length = 30;

    struct aes_aad aad;
    (void)memset_s(&aad, sizeof(aad), 0, sizeof(aad));
    aad.length = 1;

    struct uint8_buff out_plain;
    (void)memset_s(&out_plain, sizeof(out_plain), 0, sizeof(out_plain));
    out_plain.size = 0;
    out_plain.length = 1;

    int32_t result = aes_gcm_decrypt(&key, &cipher, &aad, &out_plain);
    EXPECT_NE(result, ERROR_CODE_SUCCESS);
    LOG("--------HuksAdapterTest Test051--------");
}

static HWTEST_F(HuksAdapterTest, AesGcmDecryptTest004, TestSize.Level2)
{
    LOG("--------HuksAdapterTest Test052--------");
    LOG("--------aes_gcm_decrypt--------");
    struct var_buffer key;
    (void)memset_s(&key, sizeof(key), 0, sizeof(key));
    key.length = 16;

    struct uint8_buff cipher;
    cipher.size = 64;
    cipher.length = 64;

    struct aes_aad aad;
    (void)memset_s(&aad, sizeof(aad), 0, sizeof(aad));
    aad.length = 64;

    struct uint8_buff out_plain;
    (void)memset_s(&out_plain, sizeof(out_plain), 0, sizeof(out_plain));
    out_plain.size = 64;
    out_plain.length = 64;

    int32_t result = aes_gcm_decrypt(nullptr, &cipher, &aad, &out_plain);
    EXPECT_EQ(result, HC_INPUT_ERROR);
    result = aes_gcm_decrypt(&key, nullptr, &aad, &out_plain);
    EXPECT_EQ(result, HC_INPUT_ERROR);
    result = aes_gcm_decrypt(&key, &cipher, nullptr, &out_plain);
    EXPECT_EQ(result, HC_INPUT_ERROR);
    result = aes_gcm_decrypt(&key, &cipher, &aad, nullptr);
    EXPECT_EQ(result, HC_INPUT_ERROR);
    LOG("--------HuksAdapterTest Test052--------");
}

static HWTEST_F(HuksAdapterTest, ReceiveDataTest001, TestSize.Level2)
{
    LOG("--------HuksAdapterTest Test053--------");
    LOG("--------receive_data--------");
    struct hc_call_back callBack = {
        Transmit,
        GetProtocolParams,
        SetSessionKey,
        SetServiceResult,
        ConfirmReceiveRequest
    };

    hc_handle server = get_instance(&g_server_identity, HC_CENTRE, &callBack);
    struct operation_parameter params = {g_test_server_auth_id, g_test_client_auth_id, KEY_LEN};
    int32_t ret = authenticate_peer(server, &params);
    EXPECT_EQ(ret, HC_OK);
    uint8_t dataStr001[] = "{\"authForm\":0,\"message\":32785,\"payload\":{"
	"\"authData\":\"0CE64CAFFA6AD1146EDB618E6F1DA15183EFDCAE08F909A6ABA7B9F2676F4E"
    "4C2A280A720C3EBB069858DB473191ED51237E201CC697D3E10130CE8FB86FD57F66214643874"
    "AD17FE91EC3ACBC446CA666CDC5BDFB0EB5BE76DF673C\","
	"\"challenge\":\"C5914790E4A81F59F286F2F31415A590\","
	"\"epk\":\"8A870771CA779105041966DC462B3B12D7FF87129446F38D1AC39E1F408FEB0D\","
	"\"salt\":\"C8EA30CAE1C16CCEEB652DAE671A97A3\","
	"\"version\":{\"currentVersion\":\"1.0.0\",\"minVersion\":\"1.0.0\"},"
	"\"peerAuthId\":\"6433376364376365623839346634333933613239396566383532623466633"
    "3356131613064373763343861356233653062323539396162316436396232336136\","
	"\"peerUserType\":\"0\"}}";

    struct uint8_buff data001 = {
        dataStr001,
        sizeof(dataStr001),
        strlen(reinterpret_cast<char *>(dataStr001))
    };

    ret = receive_data(server, &data001);
    EXPECT_EQ(ret, HC_OK);

    uint8_t dataStr002[] = "{\"authForm\":0,\"message\":32786,\"payload\":{"
    "\"authReturn\":\"57F9D09AA425FB83AB9BE2AF25FC9E5B82F630255AC62872447A9E5802\"}}";

    struct uint8_buff data002 = {
        dataStr002,
        sizeof(dataStr002),
        strlen(reinterpret_cast<char *>(dataStr002))
    };

    ret = receive_data(server, &data002);
    EXPECT_EQ(ret, HC_OK);
    destroy(&server);
    LOG("--------HuksAdapterTest Test053--------");
}

static HWTEST_F(HuksAdapterTest, GenerateRandomTest001, TestSize.Level2)
{
    LOG("--------HuksAdapterTest Test054--------");
    LOG("--------generate_random--------");
    uint32_t length = 0;
    struct random_value value = generate_random(length);
    EXPECT_EQ(value.length, 0);
    LOG("--------HuksAdapterTest Test054--------");
}

static HWTEST_F(HuksAdapterTest, GenerateRandomTest002, TestSize.Level2)
{
    LOG("--------HuksAdapterTest Test055--------");
    LOG("--------generate_random--------");
    uint32_t length = 33;
    struct random_value value = generate_random(length);
    EXPECT_EQ(value.length, 0);
    LOG("--------HuksAdapterTest Test055--------");
}

static HWTEST_F(HuksAdapterTest, GenerateRandomTest003, TestSize.Level2)
{
    LOG("--------HuksAdapterTest Test056--------");
    LOG("--------generate_random--------");
    uint32_t length = 32;
    struct random_value value = generate_random(length);
    EXPECT_GT(value.length, 0);
    LOG("--------HuksAdapterTest Test056--------");
}

int32_t GenerateSignMessage(hc_handle handle, struct uint8_buff *message)
{
    LOG("Called generate sign message");
    check_ptr_return_val(handle, HC_INPUT_ERROR);
    check_ptr_return_val(message, HC_INPUT_ERROR);
    struct sts_client *stsClient = static_cast<struct sts_client *>(handle);

    int len = stsClient->peer_public_key.length + stsClient->peer_id.length +
              stsClient->self_public_key.length + stsClient->self_id.length;
    uint8_t *info = static_cast<uint8_t *>(MALLOC(len));
    if (info == nullptr) {
        LOG("Malloc info failed");
        return HC_MALLOC_FAILED;
    }

    int32_t pos = 0;
    (void)memcpy_s(info + pos, len - pos, stsClient->peer_public_key.stpk, stsClient->peer_public_key.length);
    pos += stsClient->peer_public_key.length;
    (void)memcpy_s(info + pos, len - pos, stsClient->peer_id.auth_id, stsClient->peer_id.length);
    pos += stsClient->peer_id.length;
    (void)memcpy_s(info + pos, len - pos, stsClient->self_public_key.stpk, stsClient->self_public_key.length);
    pos += stsClient->self_public_key.length;
    (void)memcpy_s(info + pos, len - pos, stsClient->self_id.auth_id, stsClient->self_id.length);

    message->val = info;
    message->length = len;
    message->size = len;
    return HC_OK;
}

/*------------------------auth_info------------------------*/

class AuthInfoTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void AuthInfoTest::SetUpTestCase(void) {}
void AuthInfoTest::TearDownTestCase(void) {}
void AuthInfoTest::SetUp()
{
    InitHcAuthId();
}
void AuthInfoTest::TearDown() {}


static HWTEST_F(AuthInfoTest, get_pake_session_key_test001, TestSize.Level2)
{
    struct hc_call_back callBack = {
        Transmit,
        GetProtocolParams,
        SetSessionKey,
        SetServiceResult,
        ConfirmReceiveRequest
    };

    hc_handle server = get_instance(&g_server_identity, HC_CENTRE, &callBack);
    struct hichain *hichainTest = reinterpret_cast<struct hichain *>(server);
    struct pake_server pake_server;
    (void)memset_s(&pake_server, sizeof(pake_server), 0, sizeof(pake_server));
    hichainTest->pake_server = &pake_server;
    const struct pake_session_key *key = get_pake_session_key(hichainTest);
    EXPECT_NE(key, nullptr);
}

static HWTEST_F(AuthInfoTest, get_pake_session_key_test002, TestSize.Level2)
{
    struct hc_call_back callBack = {
        Transmit,
        GetProtocolParams,
        SetSessionKey,
        SetServiceResult,
        ConfirmReceiveRequest
    };

    hc_handle server = get_instance(&g_server_identity, HC_CENTRE, &callBack);
    struct hichain *hichainTest = reinterpret_cast<struct hichain *>(server);
    const struct pake_session_key *key = get_pake_session_key(hichainTest);
    EXPECT_EQ(key, nullptr);
}


static HWTEST_F(AuthInfoTest, get_pake_self_challenge_test001, TestSize.Level2)
{
    struct hc_call_back callBack = {
        Transmit,
        GetProtocolParams,
        SetSessionKey,
        SetServiceResult,
        ConfirmReceiveRequest
    };

    hc_handle server = get_instance(&g_server_identity, HC_CENTRE, &callBack);
    struct hichain *hichainTest = reinterpret_cast<struct hichain *>(server);
    struct pake_server pake_server;
    (void)memset_s(&pake_server, sizeof(pake_server), 0, sizeof(pake_server));
    hichainTest->pake_server = &pake_server;
    const struct challenge *challenge = get_pake_self_challenge(hichainTest);
    EXPECT_NE(challenge, nullptr);
}

static HWTEST_F(AuthInfoTest, get_pake_self_challenge_test002, TestSize.Level2)
{
    struct hc_call_back callBack = {
        Transmit,
        GetProtocolParams,
        SetSessionKey,
        SetServiceResult,
        ConfirmReceiveRequest
    };

    hc_handle server = get_instance(&g_server_identity, HC_CENTRE, &callBack);
    struct hichain *hichainTest = reinterpret_cast<struct hichain *>(server);
    const struct challenge *challenge = get_pake_self_challenge(hichainTest);
    EXPECT_EQ(challenge, nullptr);
}


static HWTEST_F(AuthInfoTest, get_pake_peer_challenge_test001, TestSize.Level2)
{
    struct hc_call_back callBack = {
        Transmit,
        GetProtocolParams,
        SetSessionKey,
        SetServiceResult,
        ConfirmReceiveRequest
    };

    hc_handle server = get_instance(&g_server_identity, HC_CENTRE, &callBack);
    struct hichain *hichainTest = reinterpret_cast<struct hichain *>(server);
    struct pake_server pake_server;
    (void)memset_s(&pake_server, sizeof(pake_server), 0, sizeof(pake_server));
    hichainTest->pake_server = &pake_server;
    const struct challenge *challenge = get_pake_peer_challenge(hichainTest);
    EXPECT_NE(challenge, nullptr);
}

static HWTEST_F(AuthInfoTest, get_pake_peer_challenge_test002, TestSize.Level2)
{
    struct hc_call_back callBack = {
        Transmit,
        GetProtocolParams,
        SetSessionKey,
        SetServiceResult,
        ConfirmReceiveRequest
    };

    hc_handle server = get_instance(&g_server_identity, HC_CENTRE, &callBack);
    struct hichain *hichainTest = reinterpret_cast<struct hichain *>(server);
    const struct challenge *challenge = get_pake_peer_challenge(hichainTest);
    EXPECT_EQ(challenge, nullptr);
}


static HWTEST_F(AuthInfoTest, get_pake_self_auth_id_test001, TestSize.Level2)
{
    struct hc_call_back callBack = {
        Transmit,
        GetProtocolParams,
        SetSessionKey,
        SetServiceResult,
        ConfirmReceiveRequest
    };

    hc_handle server = get_instance(&g_server_identity, HC_CENTRE, &callBack);
    struct hichain *hichainTest = reinterpret_cast<struct hichain *>(server);
    struct pake_server pake_server;
    (void)memset_s(&pake_server, sizeof(pake_server), 0, sizeof(pake_server));
    hichainTest->pake_server = &pake_server;
    const struct hc_auth_id *hcAuthId = get_pake_self_auth_id(hichainTest);
    EXPECT_NE(hcAuthId, nullptr);
}

static HWTEST_F(AuthInfoTest, get_pake_self_auth_id_test002, TestSize.Level2)
{
    struct hc_call_back callBack = {
        Transmit,
        GetProtocolParams,
        SetSessionKey,
        SetServiceResult,
        ConfirmReceiveRequest
    };

    hc_handle server = get_instance(&g_server_identity, HC_CENTRE, &callBack);
    struct hichain *hichainTest = reinterpret_cast<struct hichain *>(server);
    const struct hc_auth_id *hcAuthId = get_pake_self_auth_id(hichainTest);
    EXPECT_EQ(hcAuthId, nullptr);
}


static HWTEST_F(AuthInfoTest, get_sts_session_key_test001, TestSize.Level2)
{
    struct hc_call_back callBack = {
        Transmit,
        GetProtocolParams,
        SetSessionKey,
        SetServiceResult,
        ConfirmReceiveRequest
    };

    hc_handle server = get_instance(&g_server_identity, HC_CENTRE, &callBack);
    struct hichain *hichainTest = reinterpret_cast<struct hichain *>(server);
    struct sts_server sts_server;
    (void)memset_s(&sts_server, sizeof(sts_server), 0, sizeof(sts_server));
    hichainTest->sts_server = &sts_server;
    const struct sts_session_key *key = get_sts_session_key(hichainTest);
    EXPECT_NE(key, nullptr);
}

static HWTEST_F(AuthInfoTest, get_sts_session_key_test002, TestSize.Level2)
{
    struct hc_call_back callBack = {
        Transmit,
        GetProtocolParams,
        SetSessionKey,
        SetServiceResult,
        ConfirmReceiveRequest
    };

    hc_handle server = get_instance(&g_server_identity, HC_CENTRE, &callBack);
    struct hichain *hichainTest = reinterpret_cast<struct hichain *>(server);
    const struct sts_session_key *key = get_sts_session_key(hichainTest);
    EXPECT_EQ(key, nullptr);
}

static HWTEST_F(AuthInfoTest, save_auth_info_test001, TestSize.Level2)
{
    struct hc_call_back callBack = {
        Transmit,
        GetProtocolParams,
        SetSessionKey,
        SetServiceResult,
        ConfirmReceiveRequest
    };

    int32_t pairType = 1;
    struct auth_info_cache cache;
    struct ltpk ltpk;
    (void)memset_s(&ltpk, sizeof(ltpk), 0, sizeof(ltpk));
    cache.user_type = HC_USER_TYPE_ACCESSORY;
    cache.auth_id = g_test_server_auth_id;
    cache.ltpk = ltpk;
    hc_handle server = get_instance(&g_server_identity, HC_CENTRE, &callBack);
    struct hichain *hichainTest = reinterpret_cast<struct hichain *>(server);
    int32_t ret = save_auth_info(hichainTest, pairType, &cache);
    EXPECT_EQ(ret, HC_SAVE_LTPK_FAILED);
}

static HWTEST_F(AuthInfoTest, save_auth_info_test002, TestSize.Level2)
{
    int32_t pairType = 1;
    struct auth_info_cache cache;
    struct ltpk ltpk;
    (void)memset_s(&ltpk, sizeof(ltpk), 0, sizeof(ltpk));
    cache.user_type = HC_USER_TYPE_CONTROLLER;
    struct hc_auth_id auth_id;
    (void)memset_s(&auth_id, sizeof(auth_id), 0, sizeof(auth_id));
    cache.auth_id = auth_id;
    cache.ltpk = ltpk;
    int32_t ret = save_auth_info(nullptr, pairType, &cache);
    EXPECT_EQ(ret, HC_GEN_SERVICE_ID_FAILED);
}

static HWTEST_F(AuthInfoTest, destroy_auth_client_test001, TestSize.Level2)
{
    destroy_auth_client(nullptr);
}
}