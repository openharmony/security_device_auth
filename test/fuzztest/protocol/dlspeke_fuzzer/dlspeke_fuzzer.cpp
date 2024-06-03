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

#include "dlspeke_fuzzer.h"

#include <cstddef>
#include <cstdint>

#include "device_auth_defines.h"
#include "hc_types.h"
#include "hks_api.h"
#include "hks_param.h"
#include "hks_type.h"
#include "dl_speke_protocol.h"
#include "json_utils.h"
#include "uint8buff_utils.h"

namespace OHOS {
#define PSK_SIZE 32
#define INVALID_CURVE_TYPE 0
static const uint8_t g_pskVal[PSK_SIZE] = { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19,
    20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32 };
static const char *g_authIdCVal = "5420459D93FE773F9945FD64277FBA2CAB8FB996DDC1D0B97676FBB1242B3930";
static const char *g_authIdSVal = "52E2706717D5C39D736E134CC1E3BE1BAA2AA52DB7C76A37C749558BD2E6492C";
static const char *g_msgCVal = "client send msg";
static const char *g_msgSVal = "server send msg";

static Uint8Buff g_psk = { (uint8_t *)g_pskVal, PSK_SIZE };
static Uint8Buff g_authIdC = { (uint8_t *)g_authIdCVal, 64 };
static Uint8Buff g_authIdS = { (uint8_t *)g_authIdSVal, 64 };
static Uint8Buff g_msgC = { (uint8_t *)g_msgCVal, 16 };
static Uint8Buff g_msgS = { (uint8_t *)g_msgSVal, 16 };
static DlSpekeInitParams g_prime384ParamsC = { DL_SPEKE_PRIME_MOD_384, g_authIdC };
static DlSpekeInitParams g_prime384ParamsS = { DL_SPEKE_PRIME_MOD_384, g_authIdS };
static DlSpekeInitParams g_prime256ParamsC = { DL_SPEKE_PRIME_MOD_256, g_authIdC };
static DlSpekeInitParams g_prime256ParamsS = { DL_SPEKE_PRIME_MOD_256, g_authIdS };

static void dlSpekeTest01(void)
{
    BaseProtocol *self;
    CreateDlSpekeProtocol(&g_prime384ParamsC, true, &self);
    self->destroy(self);
}

static void dlSpekeTest02(void)
{
    BaseProtocol *client;
    int32_t res = CreateDlSpekeProtocol(&g_prime384ParamsC, true, &client);

    BaseProtocol *server;
    res = CreateDlSpekeProtocol(&g_prime384ParamsS, false, &server);

    res = client->setPsk(client, &g_psk);
    res = server->setPsk(server, &g_psk);

    CJson *clientOut = nullptr;
    CJson *serverOut = nullptr;

    res = client->setSelfProtectedMsg(client, &g_msgC);
    res = client->setPeerProtectedMsg(client, &g_msgS);
    res = server->setSelfProtectedMsg(server, &g_msgS);
    res = server->setPeerProtectedMsg(server, &g_msgC);

    res = client->start(client, &clientOut);

    while (clientOut != nullptr || serverOut != nullptr) {
        if (clientOut != nullptr) {
            res = server->process(server, clientOut, &serverOut);
            FreeJson(clientOut);
            clientOut = nullptr;
        } else {
            res = client->process(client, serverOut, &clientOut);
            FreeJson(serverOut);
            serverOut = nullptr;
        }
    }
    Uint8Buff clientKey = { nullptr, 0 };
    res = client->getSessionKey(client, &clientKey);
    FreeUint8Buff(&clientKey);
    Uint8Buff serverKey = { nullptr, 0 };
    res = server->getSessionKey(server, &serverKey);
    FreeUint8Buff(&serverKey);

    client->destroy(client);
    server->destroy(server);
}

static void dlSpekeTest03(void)
{
    BaseProtocol *client;
    int32_t res = CreateDlSpekeProtocol(&g_prime256ParamsC, true, &client);

    BaseProtocol *server;
    res = CreateDlSpekeProtocol(&g_prime256ParamsS, false, &server);

    res = client->setPsk(client, &g_psk);
    res = server->setPsk(server, &g_psk);

    CJson *clientOut = nullptr;
    CJson *serverOut = nullptr;

    res = client->setSelfProtectedMsg(client, &g_msgC);
    res = client->setPeerProtectedMsg(client, &g_msgS);
    res = server->setSelfProtectedMsg(server, &g_msgS);
    res = server->setPeerProtectedMsg(server, &g_msgC);

    res = client->start(client, &clientOut);

    while (clientOut != nullptr || serverOut != nullptr) {
        if (clientOut != nullptr) {
            res = server->process(server, clientOut, &serverOut);
            FreeJson(clientOut);
            clientOut = nullptr;
        } else {
            res = client->process(client, serverOut, &clientOut);
            FreeJson(serverOut);
            serverOut = nullptr;
        }
    }
    Uint8Buff clientKey = { nullptr, 0 };
    res = client->getSessionKey(client, &clientKey);
    FreeUint8Buff(&clientKey);
    Uint8Buff serverKey = { nullptr, 0 };
    res = server->getSessionKey(server, &serverKey);
    FreeUint8Buff(&serverKey);

    client->destroy(client);
    server->destroy(server);
}

static void dlSpekeTest04(void)
{
    BaseProtocol *client;
    int32_t res = CreateDlSpekeProtocol(&g_prime384ParamsC, true, &client);

    BaseProtocol *server;
    res = CreateDlSpekeProtocol(&g_prime384ParamsS, false, &server);

    res = client->setPsk(client, &g_psk);
    res = server->setPsk(server, &g_psk);

    CJson *clientOut = nullptr;
    CJson *serverOut = nullptr;

    res = client->start(client, &clientOut);

    while (clientOut != nullptr || serverOut != nullptr) {
        if (clientOut != nullptr) {
            res = server->process(server, clientOut, &serverOut);
            FreeJson(clientOut);
            clientOut = nullptr;
        } else {
            res = client->process(client, serverOut, &clientOut);
            FreeJson(serverOut);
            serverOut = nullptr;
        }
    }
    Uint8Buff clientKey;
    res = client->getSessionKey(client, &clientKey);
    FreeUint8Buff(&clientKey);
    Uint8Buff serverKey;
    res = server->getSessionKey(server, &serverKey);
    FreeUint8Buff(&serverKey);

    client->destroy(client);
    server->destroy(server);
}

static void dlSpekeTest05(void)
{
    BaseProtocol *self;
    CreateDlSpekeProtocol(nullptr, true, &self);
}

static void dlSpekeTest06(void)
{
    CreateDlSpekeProtocol(&g_prime384ParamsC, true, nullptr);
}

static void dlSpekeTest07(void)
{
    DlSpekeInitParams errParams = { DL_SPEKE_PRIME_MOD_384, { nullptr, 0 } };
    BaseProtocol *self;
    CreateDlSpekeProtocol(&errParams, true, &self);
}

static void dlSpekeTest08(void)
{
    BaseProtocol *self;
    int32_t res = CreateDlSpekeProtocol(&g_prime384ParamsC, true, &self);

    res = self->setPsk(nullptr, &g_psk);

    self->destroy(self);
}

static void dlSpekeTest09(void)
{
    BaseProtocol *self;
    int32_t res = CreateDlSpekeProtocol(&g_prime384ParamsC, true, &self);

    res = self->setPsk(self, nullptr);

    self->destroy(self);
}

static void dlSpekeTest10(void)
{
    BaseProtocol *self;
    int32_t res = CreateDlSpekeProtocol(&g_prime384ParamsC, true, &self);

    Uint8Buff errParams = { nullptr, PSK_SIZE };
    res = self->setPsk(self, &errParams);

    self->destroy(self);
}

static void dlSpekeTest11(void)
{
    BaseProtocol *self;
    int32_t res = CreateDlSpekeProtocol(&g_prime384ParamsC, true, &self);

    Uint8Buff errParams = { (uint8_t *)g_pskVal, 0 };
    res = self->setPsk(self, &errParams);

    self->destroy(self);
}

static void dlSpekeTest12(void)
{
    BaseProtocol *self;
    int32_t res = CreateDlSpekeProtocol(&g_prime384ParamsC, true, &self);

    CJson *out = nullptr;
    res = self->start(nullptr, &out);

    self->destroy(self);
}

static void dlSpekeTest13(void)
{
    BaseProtocol *self;
    int32_t res = CreateDlSpekeProtocol(&g_prime384ParamsC, true, &self);

    res = self->start(self, nullptr);

    self->destroy(self);
}

static void dlSpekeTest14(void)
{
    BaseProtocol *self;
    int32_t res = CreateDlSpekeProtocol(&g_prime384ParamsC, true, &self);

    self->curState = self->finishState;

    CJson *out = nullptr;
    res = self->start(self, &out);

    self->destroy(self);
}

static void dlSpekeTest15(void)
{
    BaseProtocol *self;
    int32_t res = CreateDlSpekeProtocol(&g_prime384ParamsC, true, &self);

    self->curState = self->failState;

    CJson *out = nullptr;
    res = self->start(self, &out);

    self->destroy(self);
}

static void dlSpekeTest16(void)
{
    BaseProtocol *self;
    int32_t res = CreateDlSpekeProtocol(&g_prime384ParamsC, true, &self);

    CJson recvMsg;
    CJson *sendMsg = nullptr;
    res = self->process(nullptr, &recvMsg, &sendMsg);

    self->destroy(self);
}

static void dlSpekeTest17(void)
{
    BaseProtocol *self;
    int32_t res = CreateDlSpekeProtocol(&g_prime384ParamsC, true, &self);

    CJson *sendMsg = nullptr;
    res = self->process(self, nullptr, &sendMsg);

    self->destroy(self);
}

static void dlSpekeTest18(void)
{
    BaseProtocol *self;
    int32_t res = CreateDlSpekeProtocol(&g_prime384ParamsC, true, &self);

    CJson recvMsg;
    res = self->process(self, &recvMsg, nullptr);

    self->destroy(self);
}

static void dlSpekeTest19(void)
{
    BaseProtocol *self;
    int32_t res = CreateDlSpekeProtocol(&g_prime384ParamsC, true, &self);

    self->curState = self->finishState;

    CJson recvMsg;
    CJson *sendMsg = nullptr;
    res = self->process(self, &recvMsg, &sendMsg);

    self->destroy(self);
}

static void dlSpekeTest20(void)
{
    BaseProtocol *self;
    int32_t res = CreateDlSpekeProtocol(&g_prime384ParamsC, true, &self);

    self->curState = self->failState;

    CJson recvMsg;
    CJson *sendMsg = nullptr;
    res = self->process(self, &recvMsg, &sendMsg);

    self->destroy(self);
}

static void dlSpekeTest21(void)
{
    BaseProtocol *self;
    int32_t res = CreateDlSpekeProtocol(&g_prime384ParamsC, true, &self);

    res = self->setSelfProtectedMsg(nullptr, &g_msgC);

    self->destroy(self);
}

static void dlSpekeTest22(void)
{
    BaseProtocol *self;
    int32_t res = CreateDlSpekeProtocol(&g_prime384ParamsC, true, &self);

    res = self->setSelfProtectedMsg(self, nullptr);

    self->destroy(self);
}

static void dlSpekeTest23(void)
{
    BaseProtocol *self;
    int32_t res = CreateDlSpekeProtocol(&g_prime384ParamsC, true, &self);

    res = self->setPeerProtectedMsg(nullptr, &g_msgS);

    self->destroy(self);
}

static void dlSpekeTest24(void)
{
    BaseProtocol *self;
    int32_t res = CreateDlSpekeProtocol(&g_prime384ParamsC, true, &self);

    res = self->setPeerProtectedMsg(self, nullptr);

    self->destroy(self);
}

static void dlSpekeTest25(void)
{
    BaseProtocol *self;
    int32_t res = CreateDlSpekeProtocol(&g_prime384ParamsC, true, &self);

    Uint8Buff key = { nullptr, 0 };
    res = self->getSessionKey(nullptr, &key);

    self->destroy(self);
}

static void dlSpekeTest26(void)
{
    BaseProtocol *self;
    int32_t res = CreateDlSpekeProtocol(&g_prime384ParamsC, true, &self);

    res = self->getSessionKey(self, nullptr);

    self->destroy(self);
}

static void dlSpekeTest27(void)
{
    BaseProtocol *self;
    int32_t res = CreateDlSpekeProtocol(&g_prime384ParamsC, true, &self);

    Uint8Buff key = { nullptr, 0 };
    res = self->getSessionKey(self, &key);

    self->destroy(self);
}

static void dlSpekeTest28(void)
{
    BaseProtocol *self;
    CreateDlSpekeProtocol(&g_prime384ParamsC, true, &self);

    self->destroy(nullptr);
    self->destroy(self);
}

bool FuzzDoCallback(const uint8_t* data, size_t size)
{
    (void)data;
    (void)size;
    (void)dlSpekeTest01();
    (void)dlSpekeTest02();
    (void)dlSpekeTest03();
    (void)dlSpekeTest04();
    (void)dlSpekeTest05();
    (void)dlSpekeTest06();
    (void)dlSpekeTest07();
    (void)dlSpekeTest08();
    (void)dlSpekeTest09();
    (void)dlSpekeTest10();
    (void)dlSpekeTest11();
    (void)dlSpekeTest12();
    (void)dlSpekeTest13();
    (void)dlSpekeTest14();
    (void)dlSpekeTest15();
    (void)dlSpekeTest16();
    (void)dlSpekeTest17();
    (void)dlSpekeTest18();
    (void)dlSpekeTest19();
    (void)dlSpekeTest20();
    (void)dlSpekeTest21();
    (void)dlSpekeTest22();
    (void)dlSpekeTest23();
    (void)dlSpekeTest24();
    (void)dlSpekeTest25();
    (void)dlSpekeTest26();
    (void)dlSpekeTest27();
    (void)dlSpekeTest28();
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

