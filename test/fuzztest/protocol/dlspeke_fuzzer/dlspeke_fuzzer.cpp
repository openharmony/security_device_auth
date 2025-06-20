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
#include "device_auth.h"
#include "base/security/device_auth/services/session_manager/src/session/v2/auth_sub_session/protocol_lib/dl_speke_protocol.c"


namespace OHOS {
#define PSK_SIZE 32
#define INVALID_CURVE_TYPE 0
static const uint8_t PSK_VAL[PSK_SIZE] = { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19,
    20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32 };
static const char *AUTH_ID_C_VAL = "5420459D93FE773F9945FD64277FBA2CAB8FB996DDC1D0B97676FBB1242B3930";
static const char *AUTH_ID_S_VAL = "52E2706717D5C39D736E134CC1E3BE1BAA2AA52DB7C76A37C749558BD2E6492C";
static const char *MSG_C_VAL = "client send msg";
static const char *MSG_S_VAL = "server send msg";
static const int32_t ERROR_CODE = 0;

static Uint8Buff g_psk = { (uint8_t *)PSK_VAL, PSK_SIZE };
static Uint8Buff g_authIdC = { (uint8_t *)AUTH_ID_C_VAL, 64 };
static Uint8Buff g_authIdS = { (uint8_t *)AUTH_ID_S_VAL, 64 };
static Uint8Buff g_msgC = { (uint8_t *)MSG_C_VAL, 16 };
static Uint8Buff g_msgS = { (uint8_t *)MSG_S_VAL, 16 };
static DlSpekeInitParams g_prime384ParamsC = { DL_SPEKE_PRIME_MOD_384, g_authIdC, DEFAULT_OS_ACCOUNT };
static DlSpekeInitParams g_prime384ParamsS = { DL_SPEKE_PRIME_MOD_384, g_authIdS, DEFAULT_OS_ACCOUNT };
static DlSpekeInitParams g_prime256ParamsC = { DL_SPEKE_PRIME_MOD_256, g_authIdC, DEFAULT_OS_ACCOUNT };
static DlSpekeInitParams g_prime256ParamsS = { DL_SPEKE_PRIME_MOD_256, g_authIdS, DEFAULT_OS_ACCOUNT };

static void DlSpekeTest01(void)
{
    HksInitialize();
    BaseProtocol *self;
    CreateDlSpekeProtocol(&g_prime384ParamsC, true, &self);
    self->destroy(self);
}

static void DlSpekeTest02(void)
{
    HksInitialize();
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

static void DlSpekeTest03(void)
{
    HksInitialize();
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

static void DlSpekeTest04(void)
{
    HksInitialize();
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

static void DlSpekeTest05(void)
{
    HksInitialize();
    BaseProtocol *self;
    CreateDlSpekeProtocol(nullptr, true, &self);
}

static void DlSpekeTest06(void)
{
    HksInitialize();
    CreateDlSpekeProtocol(&g_prime384ParamsC, true, nullptr);
}

static void DlSpekeTest07(void)
{
    HksInitialize();
    DlSpekeInitParams errParams = { DL_SPEKE_PRIME_MOD_384, { nullptr, 0 }, DEFAULT_OS_ACCOUNT };
    BaseProtocol *self;
    CreateDlSpekeProtocol(&errParams, true, &self);
}

static void DlSpekeTest08(void)
{
    HksInitialize();
    BaseProtocol *self;
    int32_t res = CreateDlSpekeProtocol(&g_prime384ParamsC, true, &self);

    res = self->setPsk(nullptr, &g_psk);

    self->destroy(self);
}

static void DlSpekeTest09(void)
{
    HksInitialize();
    BaseProtocol *self;
    int32_t res = CreateDlSpekeProtocol(&g_prime384ParamsC, true, &self);

    res = self->setPsk(self, nullptr);

    self->destroy(self);
}

static void DlSpekeTest10(void)
{
    HksInitialize();
    BaseProtocol *self;
    int32_t res = CreateDlSpekeProtocol(&g_prime384ParamsC, true, &self);

    Uint8Buff errParams = { nullptr, PSK_SIZE };
    res = self->setPsk(self, &errParams);

    self->destroy(self);
}

static void DlSpekeTest11(void)
{
    HksInitialize();
    BaseProtocol *self;
    int32_t res = CreateDlSpekeProtocol(&g_prime384ParamsC, true, &self);

    Uint8Buff errParams = { (uint8_t *)PSK_VAL, 0 };
    res = self->setPsk(self, &errParams);

    self->destroy(self);
}

static void DlSpekeTest12(void)
{
    HksInitialize();
    BaseProtocol *self;
    int32_t res = CreateDlSpekeProtocol(&g_prime384ParamsC, true, &self);

    CJson *out = nullptr;
    res = self->start(nullptr, &out);

    self->destroy(self);
}

static void DlSpekeTest13(void)
{
    HksInitialize();
    BaseProtocol *self;
    int32_t res = CreateDlSpekeProtocol(&g_prime384ParamsC, true, &self);

    res = self->start(self, nullptr);

    self->destroy(self);
}

static void DlSpekeTest14(void)
{
    HksInitialize();
    BaseProtocol *self;
    int32_t res = CreateDlSpekeProtocol(&g_prime384ParamsC, true, &self);

    self->curState = self->finishState;

    CJson *out = nullptr;
    res = self->start(self, &out);

    self->destroy(self);
}

static void DlSpekeTest15(void)
{
    HksInitialize();
    BaseProtocol *self;
    int32_t res = CreateDlSpekeProtocol(&g_prime384ParamsC, true, &self);

    self->curState = self->failState;

    CJson *out = nullptr;
    res = self->start(self, &out);

    self->destroy(self);
}

static void DlSpekeTest16(void)
{
    HksInitialize();
    BaseProtocol *self;
    int32_t res = CreateDlSpekeProtocol(&g_prime384ParamsC, true, &self);

    CJson recvMsg;
    CJson *sendMsg = nullptr;
    res = self->process(nullptr, &recvMsg, &sendMsg);

    self->destroy(self);
}

static void DlSpekeTest17(void)
{
    HksInitialize();
    BaseProtocol *self;
    int32_t res = CreateDlSpekeProtocol(&g_prime384ParamsC, true, &self);

    CJson *sendMsg = nullptr;
    res = self->process(self, nullptr, &sendMsg);

    self->destroy(self);
}

static void DlSpekeTest18(void)
{
    HksInitialize();
    BaseProtocol *self;
    int32_t res = CreateDlSpekeProtocol(&g_prime384ParamsC, true, &self);

    CJson recvMsg;
    res = self->process(self, &recvMsg, nullptr);

    self->destroy(self);
}

static void DlSpekeTest19(void)
{
    HksInitialize();
    BaseProtocol *self;
    int32_t res = CreateDlSpekeProtocol(&g_prime384ParamsC, true, &self);

    self->curState = self->finishState;

    CJson recvMsg;
    CJson *sendMsg = nullptr;
    res = self->process(self, &recvMsg, &sendMsg);

    self->destroy(self);
}

static void DlSpekeTest20(void)
{
    HksInitialize();
    BaseProtocol *self;
    int32_t res = CreateDlSpekeProtocol(&g_prime384ParamsC, true, &self);

    self->curState = self->failState;

    CJson recvMsg;
    CJson *sendMsg = nullptr;
    res = self->process(self, &recvMsg, &sendMsg);

    self->destroy(self);
}

static void DlSpekeTest21(void)
{
    HksInitialize();
    BaseProtocol *self;
    int32_t res = CreateDlSpekeProtocol(&g_prime384ParamsC, true, &self);

    res = self->setSelfProtectedMsg(nullptr, &g_msgC);

    self->destroy(self);
}

static void DlSpekeTest22(void)
{
    HksInitialize();
    BaseProtocol *self;
    int32_t res = CreateDlSpekeProtocol(&g_prime384ParamsC, true, &self);

    res = self->setSelfProtectedMsg(self, nullptr);

    self->destroy(self);
}

static void DlSpekeTest23(void)
{
    HksInitialize();
    BaseProtocol *self;
    int32_t res = CreateDlSpekeProtocol(&g_prime384ParamsC, true, &self);

    res = self->setPeerProtectedMsg(nullptr, &g_msgS);

    self->destroy(self);
}

static void DlSpekeTest24(void)
{
    HksInitialize();
    BaseProtocol *self;
    int32_t res = CreateDlSpekeProtocol(&g_prime384ParamsC, true, &self);

    res = self->setPeerProtectedMsg(self, nullptr);

    self->destroy(self);
}

static void DlSpekeTest25(void)
{
    HksInitialize();
    BaseProtocol *self;
    int32_t res = CreateDlSpekeProtocol(&g_prime384ParamsC, true, &self);

    Uint8Buff key = { nullptr, 0 };
    res = self->getSessionKey(nullptr, &key);

    self->destroy(self);
}

static void DlSpekeTest26(void)
{
    HksInitialize();
    BaseProtocol *self;
    int32_t res = CreateDlSpekeProtocol(&g_prime384ParamsC, true, &self);

    res = self->getSessionKey(self, nullptr);

    self->destroy(self);
}

static void DlSpekeTest27(void)
{
    HksInitialize();
    BaseProtocol *self;
    int32_t res = CreateDlSpekeProtocol(&g_prime384ParamsC, true, &self);

    Uint8Buff key = { nullptr, 0 };
    res = self->getSessionKey(self, &key);

    self->destroy(self);
}

static void DlSpekeTest28(void)
{
    HksInitialize();
    BaseProtocol *self;
    CreateDlSpekeProtocol(&g_prime384ParamsC, true, &self);

    self->destroy(nullptr);
    self->destroy(self);
}

static void DlSpekeTest29(void)
{
    CJson *json = CreateJson();
    ReturnError(ERROR_CODE, nullptr);
    NotifyPeerError(ERROR_CODE, &json);
    ThrowException(nullptr, nullptr, nullptr);
    FreeJson(json);
}

bool FuzzDoCallback(const uint8_t* data, size_t size)
{
    (void)data;
    (void)size;
    (void)DlSpekeTest01();
    (void)DlSpekeTest02();
    (void)DlSpekeTest03();
    (void)DlSpekeTest04();
    (void)DlSpekeTest05();
    (void)DlSpekeTest06();
    (void)DlSpekeTest07();
    (void)DlSpekeTest08();
    (void)DlSpekeTest09();
    (void)DlSpekeTest10();
    (void)DlSpekeTest11();
    (void)DlSpekeTest12();
    (void)DlSpekeTest13();
    (void)DlSpekeTest14();
    (void)DlSpekeTest15();
    (void)DlSpekeTest16();
    (void)DlSpekeTest17();
    (void)DlSpekeTest18();
    (void)DlSpekeTest19();
    (void)DlSpekeTest20();
    (void)DlSpekeTest21();
    (void)DlSpekeTest22();
    (void)DlSpekeTest23();
    (void)DlSpekeTest24();
    (void)DlSpekeTest25();
    (void)DlSpekeTest26();
    (void)DlSpekeTest27();
    (void)DlSpekeTest28();
    (void)DlSpekeTest29();
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

