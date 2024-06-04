/*
 * Copyright (C) 2023 Huawei Device Co., Ltd.
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

#include <gtest/gtest.h>
#include <gmock/gmock.h>
#include "auth_code_import.h"
#include "device_auth_defines.h"
#include "exception_controller.h"
#include "expand_sub_session.h"
#include "hc_types.h"
#include "hks_api.h"
#include "hks_param.h"
#include "hks_type.h"
#include "json_utils.h"
#include "memory_mock.h"
#include "memory_monitor.h"
#include "pub_key_exchange.h"
#include "uint8buff_utils.h"

using namespace std;
using namespace testing::ext;

namespace {
#define NONCE_LEN 12
#define ENCRYPTION_KEY_LEN 32
#define INVALID_CMD_TYPE 100

static const char *AUTH_ID_C_VAL = "5420459D93FE773F9945FD64277FBA2CAB8FB996DDC1D0B97676FBB1242B3930";
static const char *AUTH_ID_S_VAL = "52E2706717D5C39D736E134CC1E3BE1BAA2AA52DB7C76A37C749558BD2E6492C";
static const char *GROUP_ID = "E2EE6F830B176B2C96A9F99BFAE2A61F5D1490B9F4A090E9D8C2874C230C7C21";
static const char *GROUP_OWNER = "testApp";

static Uint8Buff g_authIdC = { (uint8_t *)AUTH_ID_C_VAL, 64 };
static Uint8Buff g_authIdS = { (uint8_t *)AUTH_ID_S_VAL, 64 };

static AuthCodeImportParams g_paramsC = { 0, GROUP_OWNER, GROUP_ID, g_authIdC,  };
static AuthCodeImportParams g_paramsS = { 0, GROUP_OWNER, GROUP_ID, g_authIdS };
static PubKeyExchangeParams g_25519ParamsC = { 0, GROUP_OWNER, GROUP_ID, g_authIdC };
static PubKeyExchangeParams g_25519ParamsS = { 0, GROUP_OWNER, GROUP_ID, g_authIdS };

static uint8_t g_nonceVal[NONCE_LEN] = { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12 };
static Uint8Buff g_nonce = { g_nonceVal, NONCE_LEN };

static uint8_t g_encryptionKeyVal[ENCRYPTION_KEY_LEN] = { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16,
    17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32 };
static Uint8Buff g_encryptionKey = { g_encryptionKeyVal, ENCRYPTION_KEY_LEN };

class ExpandSubSessionTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void ExpandSubSessionTest::SetUpTestCase()
{
    HksInitialize();
}

void ExpandSubSessionTest::TearDownTestCase() {}

void ExpandSubSessionTest::SetUp()
{
    InitExceptionController();
    HcInitMallocMonitor();
    cJSON_Hooks hooks = {
        .malloc_fn = MockMallocForJson,
        .free_fn = MockFree
    };
    cJSON_InitHooks(&hooks);
}

void ExpandSubSessionTest::TearDown()
{
    bool isMemoryLeak = IsMemoryLeak();
    EXPECT_FALSE(isMemoryLeak);
    if (isMemoryLeak) {
        ReportMonitor();
    }
    cJSON_Hooks hooks = {
        .malloc_fn = malloc,
        .free_fn = free
    };
    cJSON_InitHooks(&hooks);
    HcDestroyMallocMonitor();
    DestroyExceptionController();
}

HWTEST_F(ExpandSubSessionTest, ExpandSubSessionTest001, TestSize.Level0)
{
    ExpandSubSession *self = NULL;
    int32_t res = CreateExpandSubSession(&g_nonce, &g_encryptionKey, &self);
    ASSERT_EQ(res, HC_SUCCESS);
    ASSERT_NE(self, nullptr);
    self->destroy(self);
}

HWTEST_F(ExpandSubSessionTest, ExpandSubSessionTest002, TestSize.Level0)
{
    ExpandSubSession *client;
    int32_t res = CreateExpandSubSession(&g_nonce, &g_encryptionKey, &client);
    ASSERT_EQ(res, HC_SUCCESS);
    ASSERT_NE(client, nullptr);

    ExpandSubSession *server;
    res = CreateExpandSubSession(&g_nonce, &g_encryptionKey, &server);
    ASSERT_EQ(res, HC_SUCCESS);
    ASSERT_NE(server, nullptr);

    res = client->addCmd(client, AUTH_CODE_IMPORT_CMD_TYPE, (void *)&g_paramsC, true, ABORT_IF_ERROR);
    ASSERT_EQ(res, HC_SUCCESS);
    res = server->addCmd(server, AUTH_CODE_IMPORT_CMD_TYPE, (void *)&g_paramsS, false, ABORT_IF_ERROR);
    ASSERT_EQ(res, HC_SUCCESS);
    res = client->addCmd(client, PUB_KEY_EXCHANGE_CMD_TYPE, (void *)&g_25519ParamsC, true, ABORT_IF_ERROR);
    ASSERT_EQ(res, HC_SUCCESS);
    res = server->addCmd(server, PUB_KEY_EXCHANGE_CMD_TYPE, (void *)&g_25519ParamsS, false, ABORT_IF_ERROR);
    ASSERT_EQ(res, HC_SUCCESS);

    CJson *clientOut = nullptr;
    CJson *serverOut = nullptr;

    res = client->start(client, &clientOut);
    ASSERT_EQ(res, HC_SUCCESS);
    ASSERT_NE(clientOut, nullptr);

    res = server->process(server, clientOut, &serverOut);
    FreeJson(clientOut);
    clientOut = nullptr;
    ASSERT_EQ(res, HC_SUCCESS);
    ASSERT_NE(serverOut, nullptr);
    ASSERT_EQ(server->state, EXPAND_STATE_FINISH);

    res = client->process(client, serverOut, &clientOut);
    FreeJson(serverOut);
    serverOut = nullptr;
    ASSERT_EQ(res, HC_SUCCESS);
    ASSERT_EQ(clientOut, nullptr);
    ASSERT_EQ(client->state, EXPAND_STATE_FINISH);

    client->destroy(client);
    server->destroy(server);
}

HWTEST_F(ExpandSubSessionTest, ExpandSubSessionTest101, TestSize.Level0)
{
    ExpandSubSession *self;
    int32_t res = CreateExpandSubSession(nullptr, &g_encryptionKey, &self);
    ASSERT_NE(res, HC_SUCCESS);
}

HWTEST_F(ExpandSubSessionTest, ExpandSubSessionTest102, TestSize.Level0)
{
    Uint8Buff invalidNonce = { nullptr, 0 };
    ExpandSubSession *self;
    int32_t res = CreateExpandSubSession(&invalidNonce, &g_encryptionKey, &self);
    ASSERT_NE(res, HC_SUCCESS);
}

HWTEST_F(ExpandSubSessionTest, ExpandSubSessionTest103, TestSize.Level0)
{
    ExpandSubSession *self;
    int32_t res = CreateExpandSubSession(&g_nonce, nullptr, &self);
    ASSERT_NE(res, HC_SUCCESS);
}

HWTEST_F(ExpandSubSessionTest, ExpandSubSessionTest104, TestSize.Level0)
{
    Uint8Buff invalidEncKey = { nullptr, 0 };
    ExpandSubSession *self;
    int32_t res = CreateExpandSubSession(&invalidEncKey, &invalidEncKey, &self);
    ASSERT_NE(res, HC_SUCCESS);
}

HWTEST_F(ExpandSubSessionTest, ExpandSubSessionTest105, TestSize.Level0)
{
    int32_t res = CreateExpandSubSession(&g_nonce, &g_encryptionKey, nullptr);
    ASSERT_NE(res, HC_SUCCESS);
}

HWTEST_F(ExpandSubSessionTest, ExpandSubSessionTest106, TestSize.Level0)
{
    ExpandSubSession *self = nullptr;
    int32_t res = CreateExpandSubSession(&g_nonce, &g_encryptionKey, &self);
    ASSERT_EQ(res, HC_SUCCESS);
    ASSERT_NE(self, nullptr);

    self->destroy(nullptr);
    self->destroy(self);
}

HWTEST_F(ExpandSubSessionTest, ExpandSubSessionTest107, TestSize.Level0)
{
    ExpandSubSession *self;
    int32_t res = CreateExpandSubSession(&g_nonce, &g_encryptionKey, &self);
    ASSERT_EQ(res, HC_SUCCESS);
    ASSERT_NE(self, nullptr);

    res = self->addCmd(nullptr, AUTH_CODE_IMPORT_CMD_TYPE, (void *)&g_paramsC, true, ABORT_IF_ERROR);
    ASSERT_NE(res, HC_SUCCESS);

    self->destroy(self);
}

HWTEST_F(ExpandSubSessionTest, ExpandSubSessionTest108, TestSize.Level0)
{
    ExpandSubSession *self;
    int32_t res = CreateExpandSubSession(&g_nonce, &g_encryptionKey, &self);
    ASSERT_EQ(res, HC_SUCCESS);
    ASSERT_NE(self, nullptr);

    res = self->addCmd(self, AUTH_CODE_IMPORT_CMD_TYPE, nullptr, true, ABORT_IF_ERROR);
    ASSERT_NE(res, HC_SUCCESS);

    self->destroy(self);
}

HWTEST_F(ExpandSubSessionTest, ExpandSubSessionTest109, TestSize.Level0)
{
    ExpandSubSession *self;
    int32_t res = CreateExpandSubSession(&g_nonce, &g_encryptionKey, &self);
    ASSERT_EQ(res, HC_SUCCESS);
    ASSERT_NE(self, nullptr);

    self->state = EXPAND_STATE_RUNNING;

    res = self->addCmd(self, AUTH_CODE_IMPORT_CMD_TYPE, (void *)&g_paramsC, true, ABORT_IF_ERROR);
    ASSERT_NE(res, HC_SUCCESS);

    self->destroy(self);
}

HWTEST_F(ExpandSubSessionTest, ExpandSubSessionTest110, TestSize.Level0)
{
    ExpandSubSession *self;
    int32_t res = CreateExpandSubSession(&g_nonce, &g_encryptionKey, &self);
    ASSERT_EQ(res, HC_SUCCESS);
    ASSERT_NE(self, nullptr);

    res = self->addCmd(self, INVALID_CMD_TYPE, (void *)&g_paramsC, true, ABORT_IF_ERROR);
    ASSERT_NE(res, HC_SUCCESS);

    self->destroy(self);
}

HWTEST_F(ExpandSubSessionTest, ExpandSubSessionTest111, TestSize.Level0)
{
    ExpandSubSession *self;
    int32_t res = CreateExpandSubSession(&g_nonce, &g_encryptionKey, &self);
    ASSERT_EQ(res, HC_SUCCESS);
    ASSERT_NE(self, nullptr);

    CJson *out = nullptr;
    res = self->start(nullptr, &out);
    ASSERT_NE(res, HC_SUCCESS);

    self->destroy(self);
}

HWTEST_F(ExpandSubSessionTest, ExpandSubSessionTest112, TestSize.Level0)
{
    ExpandSubSession *self;
    int32_t res = CreateExpandSubSession(&g_nonce, &g_encryptionKey, &self);
    ASSERT_EQ(res, HC_SUCCESS);
    ASSERT_NE(self, nullptr);

    res = self->start(self, nullptr);
    ASSERT_NE(res, HC_SUCCESS);

    self->destroy(self);
}

HWTEST_F(ExpandSubSessionTest, ExpandSubSessionTest113, TestSize.Level0)
{
    ExpandSubSession *self;
    int32_t res = CreateExpandSubSession(&g_nonce, &g_encryptionKey, &self);
    ASSERT_EQ(res, HC_SUCCESS);
    ASSERT_NE(self, nullptr);

    self->state = EXPAND_STATE_RUNNING;

    CJson *out = nullptr;
    res = self->start(self, &out);
    ASSERT_NE(res, HC_SUCCESS);

    self->destroy(self);
}

HWTEST_F(ExpandSubSessionTest, ExpandSubSessionTest114, TestSize.Level0)
{
    ExpandSubSession *self;
    int32_t res = CreateExpandSubSession(&g_nonce, &g_encryptionKey, &self);
    ASSERT_EQ(res, HC_SUCCESS);
    ASSERT_NE(self, nullptr);

    CJson *out = nullptr;
    res = self->start(self, &out);
    ASSERT_NE(res, HC_SUCCESS);

    self->destroy(self);
}

HWTEST_F(ExpandSubSessionTest, ExpandSubSessionTest115, TestSize.Level0)
{
    ExpandSubSession *self;
    int32_t res = CreateExpandSubSession(&g_nonce, &g_encryptionKey, &self);
    ASSERT_EQ(res, HC_SUCCESS);
    ASSERT_NE(self, nullptr);

    CJson in;
    CJson *out = nullptr;
    res = self->process(nullptr, &in, &out);
    ASSERT_NE(res, HC_SUCCESS);

    self->destroy(self);
}

HWTEST_F(ExpandSubSessionTest, ExpandSubSessionTest116, TestSize.Level0)
{
    ExpandSubSession *self;
    int32_t res = CreateExpandSubSession(&g_nonce, &g_encryptionKey, &self);
    ASSERT_EQ(res, HC_SUCCESS);
    ASSERT_NE(self, nullptr);

    CJson *out = nullptr;
    res = self->process(self, nullptr, &out);
    ASSERT_NE(res, HC_SUCCESS);

    self->destroy(self);
}

HWTEST_F(ExpandSubSessionTest, ExpandSubSessionTest117, TestSize.Level0)
{
    ExpandSubSession *self;
    int32_t res = CreateExpandSubSession(&g_nonce, &g_encryptionKey, &self);
    ASSERT_EQ(res, HC_SUCCESS);
    ASSERT_NE(self, nullptr);

    CJson in;
    res = self->process(self, &in, nullptr);
    ASSERT_NE(res, HC_SUCCESS);

    self->destroy(self);
}

HWTEST_F(ExpandSubSessionTest, ExpandSubSessionTest118, TestSize.Level0)
{
    ExpandSubSession *self;
    int32_t res = CreateExpandSubSession(&g_nonce, &g_encryptionKey, &self);
    ASSERT_EQ(res, HC_SUCCESS);
    ASSERT_NE(self, nullptr);

    self->state = EXPAND_STATE_FINISH;

    CJson in;
    CJson *out = nullptr;
    res = self->process(self, &in, &out);
    ASSERT_NE(res, HC_SUCCESS);

    self->destroy(self);
}

HWTEST_F(ExpandSubSessionTest, ExpandSubSessionTest119, TestSize.Level0)
{
    bool isSupport = IsCmdSupport(AUTH_CODE_IMPORT_CMD_TYPE);
    ASSERT_EQ(isSupport, true);
    isSupport = IsCmdSupport(INVALID_CMD_TYPE);
    ASSERT_EQ(isSupport, false);
}

static int32_t LoopProcess(ExpandSubSession *client, ExpandSubSession *server)
{
    CJson *clientOut = nullptr;
    CJson *serverOut = nullptr;
    int32_t res = client->start(client, &clientOut);
    if (res != HC_SUCCESS) {
        FreeJson(clientOut);
        clientOut = nullptr;
        return res;
    }
    res = server->process(server, clientOut, &serverOut);
    FreeJson(clientOut);
    clientOut = nullptr;
    if (res != HC_SUCCESS) {
        FreeJson(serverOut);
        serverOut = nullptr;
        return res;
    }
    res = client->process(client, serverOut, &clientOut);
    FreeJson(serverOut);
    serverOut = nullptr;
    if (clientOut != nullptr) {
        FreeJson(clientOut);
        clientOut = nullptr;
    }
    return res;
}

static int32_t TestMemoryInner(ExpandSubSession **clientPtr, ExpandSubSession **serverPtr)
{
    int32_t res = CreateExpandSubSession(&g_nonce, &g_encryptionKey, clientPtr);
    if (res != HC_SUCCESS) {
        return res;
    }
    ExpandSubSession *client = *clientPtr;
    res = CreateExpandSubSession(&g_nonce, &g_encryptionKey, serverPtr);
    if (res != HC_SUCCESS) {
        return res;
    }
    ExpandSubSession *server = *serverPtr;
    res = client->addCmd(client, AUTH_CODE_IMPORT_CMD_TYPE, (void *)&g_paramsC, true, ABORT_IF_ERROR);
    if (res != HC_SUCCESS) {
        return res;
    }
    res = server->addCmd(server, AUTH_CODE_IMPORT_CMD_TYPE, (void *)&g_paramsS, false, ABORT_IF_ERROR);
    if (res != HC_SUCCESS) {
        return res;
    }
    res = client->addCmd(client, PUB_KEY_EXCHANGE_CMD_TYPE, (void *)&g_25519ParamsC, true, ABORT_IF_ERROR);
    if (res != HC_SUCCESS) {
        return res;
    }
    res = server->addCmd(server, PUB_KEY_EXCHANGE_CMD_TYPE, (void *)&g_25519ParamsS, false, ABORT_IF_ERROR);
    if (res != HC_SUCCESS) {
        return res;
    }
    return LoopProcess(client, server);
}

static int32_t TestMemoryException(void)
{
    ExpandSubSession *client = nullptr;
    ExpandSubSession *server = nullptr;
    int32_t res = TestMemoryInner(&client, &server);
    if (client != nullptr) {
        client->destroy(client);
    }
    if (server != nullptr) {
        server->destroy(server);
    }
    return res;
}

HWTEST_F(ExpandSubSessionTest, ExpandSubSessionTest126, TestSize.Level0)
{
    SetControllerMode(true);
    int32_t res = TestMemoryException();
    ASSERT_EQ(res, HC_SUCCESS);

    uint32_t callNum = GetCallNum();
    for (uint32_t i = 0; i < callNum; i++) {
        SetThrowExceptionIndex(i);
        (void)TestMemoryException();
        bool isMemoryLeak = IsMemoryLeak();
        EXPECT_FALSE(isMemoryLeak);
        if (isMemoryLeak) {
            ReportMonitor();
            break;
        }
    }
}
}
