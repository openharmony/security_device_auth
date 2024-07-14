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

#include "expandsubsession_fuzzer.h"

#include "expand_sub_session.h"
#include "device_auth_defines.h"
#include "auth_code_import.h"
#include "hc_types.h"
#include "hks_api.h"
#include "hks_param.h"
#include "hks_type.h"
#include "json_utils.h"
#include "pub_key_exchange.h"
#include "uint8buff_utils.h"

namespace OHOS {
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
static PubKeyExchangeParams g_25519ParamsC = { 0, GROUP_OWNER, GROUP_ID, g_authIdC, false };
static PubKeyExchangeParams g_25519ParamsS = { 0, GROUP_OWNER, GROUP_ID, g_authIdS, false };

static uint8_t g_nonceVal[NONCE_LEN] = { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12 };
static Uint8Buff g_nonce = { g_nonceVal, NONCE_LEN };

static uint8_t g_encryptionKeyVal[ENCRYPTION_KEY_LEN] = { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16,
    17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32 };
static Uint8Buff g_encryptionKey = { g_encryptionKeyVal, ENCRYPTION_KEY_LEN };

static void ExpandSubSessionTest01(void)
{
    HksInitialize();
    ExpandSubSession *self = NULL;
    (void)CreateExpandSubSession(&g_nonce, &g_encryptionKey, &self);
    self->destroy(self);
}

static void ExpandSubSessionTest02(void)
{
    HksInitialize();
    ExpandSubSession *client;
    int32_t res = CreateExpandSubSession(&g_nonce, &g_encryptionKey, &client);

    ExpandSubSession *server;
    res = CreateExpandSubSession(&g_nonce, &g_encryptionKey, &server);

    res = client->addCmd(client, AUTH_CODE_IMPORT_CMD_TYPE, (void *)&g_paramsC, true, ABORT_IF_ERROR);
    res = server->addCmd(server, AUTH_CODE_IMPORT_CMD_TYPE, (void *)&g_paramsS, false, ABORT_IF_ERROR);
    res = client->addCmd(client, PUB_KEY_EXCHANGE_CMD_TYPE, (void *)&g_25519ParamsC, true, ABORT_IF_ERROR);
    res = server->addCmd(server, PUB_KEY_EXCHANGE_CMD_TYPE, (void *)&g_25519ParamsS, false, ABORT_IF_ERROR);

    CJson *clientOut = nullptr;
    CJson *serverOut = nullptr;

    res = client->start(client, &clientOut);

    res = server->process(server, clientOut, &serverOut);
    FreeJson(clientOut);
    clientOut = nullptr;

    res = client->process(client, serverOut, &clientOut);
    FreeJson(serverOut);
    serverOut = nullptr;

    client->destroy(client);
    server->destroy(server);
}

static void ExpandSubSessionTest03(void)
{
    HksInitialize();
    ExpandSubSession *self;
    (void)CreateExpandSubSession(nullptr, &g_encryptionKey, &self);
}

static void ExpandSubSessionTest04(void)
{
    HksInitialize();
    Uint8Buff invalidNonce = { nullptr, 0 };
    ExpandSubSession *self;
    (void)CreateExpandSubSession(&invalidNonce, &g_encryptionKey, &self);
}

static void ExpandSubSessionTest05(void)
{
    HksInitialize();
    ExpandSubSession *self;
    (void)CreateExpandSubSession(&g_nonce, nullptr, &self);
}

static void ExpandSubSessionTest06(void)
{
    HksInitialize();
    Uint8Buff invalidEncKey = { nullptr, 0 };
    ExpandSubSession *self;
    (void)CreateExpandSubSession(&invalidEncKey, &invalidEncKey, &self);
}

static void ExpandSubSessionTest07(void)
{
    HksInitialize();
    (void)CreateExpandSubSession(&g_nonce, &g_encryptionKey, nullptr);
}

static void ExpandSubSessionTest08(void)
{
    HksInitialize();
    ExpandSubSession *self = nullptr;
    (void)CreateExpandSubSession(&g_nonce, &g_encryptionKey, &self);

    self->destroy(nullptr);
    self->destroy(self);
}

static void ExpandSubSessionTest09(void)
{
    HksInitialize();
    ExpandSubSession *self;
    int32_t res = CreateExpandSubSession(&g_nonce, &g_encryptionKey, &self);

    res = self->addCmd(nullptr, AUTH_CODE_IMPORT_CMD_TYPE, (void *)&g_paramsC, true, ABORT_IF_ERROR);
    self->destroy(self);
}

static void ExpandSubSessionTest10(void)
{
    HksInitialize();
    ExpandSubSession *self;
    int32_t res = CreateExpandSubSession(&g_nonce, &g_encryptionKey, &self);

    res = self->addCmd(self, AUTH_CODE_IMPORT_CMD_TYPE, nullptr, true, ABORT_IF_ERROR);
    self->destroy(self);
}

static void ExpandSubSessionTest11(void)
{
    HksInitialize();
    ExpandSubSession *self;
    int32_t res = CreateExpandSubSession(&g_nonce, &g_encryptionKey, &self);

    self->state = EXPAND_STATE_RUNNING;
    res = self->addCmd(self, AUTH_CODE_IMPORT_CMD_TYPE, (void *)&g_paramsC, true, ABORT_IF_ERROR);
    self->destroy(self);
}

static void ExpandSubSessionTest12(void)
{
    HksInitialize();
    ExpandSubSession *self;
    int32_t res = CreateExpandSubSession(&g_nonce, &g_encryptionKey, &self);

    res = self->addCmd(self, INVALID_CMD_TYPE, (void *)&g_paramsC, true, ABORT_IF_ERROR);
    self->destroy(self);
}

static void ExpandSubSessionTest13(void)
{
    HksInitialize();
    ExpandSubSession *self;
    int32_t res = CreateExpandSubSession(&g_nonce, &g_encryptionKey, &self);

    CJson *out = nullptr;
    res = self->start(nullptr, &out);
    self->destroy(self);
}

static void ExpandSubSessionTest14(void)
{
    HksInitialize();
    ExpandSubSession *self;
    int32_t res = CreateExpandSubSession(&g_nonce, &g_encryptionKey, &self);

    res = self->start(self, nullptr);
    self->destroy(self);
}

static void ExpandSubSessionTest15(void)
{
    HksInitialize();
    ExpandSubSession *self;
    int32_t res = CreateExpandSubSession(&g_nonce, &g_encryptionKey, &self);

    self->state = EXPAND_STATE_RUNNING;
    CJson *out = nullptr;
    res = self->start(self, &out);
    self->destroy(self);
}

static void ExpandSubSessionTest16(void)
{
    HksInitialize();
    ExpandSubSession *self;
    int32_t res = CreateExpandSubSession(&g_nonce, &g_encryptionKey, &self);

    CJson *out = nullptr;
    res = self->start(self, &out);
    self->destroy(self);
}

static void ExpandSubSessionTest17(void)
{
    HksInitialize();
    ExpandSubSession *self;
    int32_t res = CreateExpandSubSession(&g_nonce, &g_encryptionKey, &self);

    CJson in;
    CJson *out = nullptr;
    res = self->process(nullptr, &in, &out);
    self->destroy(self);
}

static void ExpandSubSessionTest18(void)
{
    HksInitialize();
    ExpandSubSession *self;
    int32_t res = CreateExpandSubSession(&g_nonce, &g_encryptionKey, &self);

    CJson *out = nullptr;
    res = self->process(self, nullptr, &out);
    self->destroy(self);
}

static void ExpandSubSessionTest19(void)
{
    HksInitialize();
    ExpandSubSession *self;
    int32_t res = CreateExpandSubSession(&g_nonce, &g_encryptionKey, &self);
    CJson in;
    res = self->process(self, &in, nullptr);
    self->destroy(self);
}

static void ExpandSubSessionTest20(void)
{
    HksInitialize();
    ExpandSubSession *self;
    int32_t res = CreateExpandSubSession(&g_nonce, &g_encryptionKey, &self);
    self->state = EXPAND_STATE_FINISH;

    CJson in;
    CJson *out = nullptr;
    res = self->process(self, &in, &out);
    self->destroy(self);
}

static void ExpandSubSessionTest21(void)
{
    HksInitialize();
    bool isSupport = IsCmdSupport(AUTH_CODE_IMPORT_CMD_TYPE);
    isSupport = IsCmdSupport(INVALID_CMD_TYPE);
}

bool FuzzDoCallback(const uint8_t* data, size_t size)
{
    (void)data;
    (void)size;
    (void)ExpandSubSessionTest01();
    (void)ExpandSubSessionTest02();
    (void)ExpandSubSessionTest03();
    (void)ExpandSubSessionTest04();
    (void)ExpandSubSessionTest05();
    (void)ExpandSubSessionTest06();
    (void)ExpandSubSessionTest07();
    (void)ExpandSubSessionTest08();
    (void)ExpandSubSessionTest09();
    (void)ExpandSubSessionTest10();
    (void)ExpandSubSessionTest11();
    (void)ExpandSubSessionTest12();
    (void)ExpandSubSessionTest13();
    (void)ExpandSubSessionTest14();
    (void)ExpandSubSessionTest15();
    (void)ExpandSubSessionTest16();
    (void)ExpandSubSessionTest17();
    (void)ExpandSubSessionTest18();
    (void)ExpandSubSessionTest19();
    (void)ExpandSubSessionTest20();
    (void)ExpandSubSessionTest21();
    return true;
}
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    OHOS::FuzzDoCallback(data, size);
    return 0;
}

