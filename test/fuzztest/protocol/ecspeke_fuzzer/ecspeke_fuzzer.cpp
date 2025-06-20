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

#include "ecspeke_fuzzer.h"

#include <cstddef>
#include <cstdint>

#include "device_auth_defines.h"
#include "hc_types.h"
#include "hks_api.h"
#include "hks_param.h"
#include "hks_type.h"
#include "ec_speke_protocol.h"
#include "json_utils.h"
#include "uint8buff_utils.h"
#include "device_auth.h"
#include "base/security/device_auth/services/session_manager/src/session/v2/auth_sub_session/protocol_lib/ec_speke_protocol.c"

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
static EcSpekeInitParams g_P256ParamsC = { CURVE_TYPE_256, g_authIdC, DEFAULT_OS_ACCOUNT };
static EcSpekeInitParams g_P256ParamsS = { CURVE_TYPE_256, g_authIdS, DEFAULT_OS_ACCOUNT };
static EcSpekeInitParams g_X25519ParamsC = { CURVE_TYPE_25519, g_authIdC, DEFAULT_OS_ACCOUNT };
static EcSpekeInitParams g_X25519ParamsS = { CURVE_TYPE_25519, g_authIdS, DEFAULT_OS_ACCOUNT };

static void ECSpekeTest01(void)
{
    HksInitialize();
    BaseProtocol *self;
    CreateEcSpekeProtocol(&g_X25519ParamsC, true, &self);
    self->destroy(self);
}

static void ECSpekeTest02(void)
{
    HksInitialize();
    BaseProtocol *client;
    int32_t res = CreateEcSpekeProtocol(&g_X25519ParamsC, true, &client);

    BaseProtocol *server;
    res = CreateEcSpekeProtocol(&g_X25519ParamsS, false, &server);

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

static void ECSpekeTest03(void)
{
    HksInitialize();
    BaseProtocol *client;
    int32_t res = CreateEcSpekeProtocol(&g_P256ParamsC, true, &client);

    BaseProtocol *server;
    res = CreateEcSpekeProtocol(&g_P256ParamsS, false, &server);

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

static void ECSpekeTest04(void)
{
    HksInitialize();
    BaseProtocol *client;
    int32_t res = CreateEcSpekeProtocol(&g_X25519ParamsC, true, &client);

    BaseProtocol *server;
    res = CreateEcSpekeProtocol(&g_X25519ParamsS, false, &server);

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

static void ECSpekeTest05(void)
{
    HksInitialize();
    BaseProtocol *self;
    CreateEcSpekeProtocol(nullptr, true, &self);
}

static void ECSpekeTest06(void)
{
    HksInitialize();
    CreateEcSpekeProtocol(&g_X25519ParamsC, true, nullptr);
}

static void ECSpekeTest07(void)
{
    HksInitialize();
    EcSpekeInitParams errParams = { INVALID_CURVE_TYPE, g_authIdC, DEFAULT_OS_ACCOUNT };
    BaseProtocol *self;
    CreateEcSpekeProtocol(&errParams, true, &self);
}

static void ECSpekeTest08(void)
{
    HksInitialize();
    EcSpekeInitParams errParams = { CURVE_TYPE_25519, { nullptr, 0 }, DEFAULT_OS_ACCOUNT };
    BaseProtocol *self;
    CreateEcSpekeProtocol(&errParams, true, &self);
}

static void ECSpekeTest09(void)
{
    HksInitialize();
    BaseProtocol *self;
    int32_t res = CreateEcSpekeProtocol(&g_X25519ParamsC, true, &self);

    res = self->setPsk(nullptr, &g_psk);

    self->destroy(self);
}

static void ECSpekeTest10(void)
{
    HksInitialize();
    BaseProtocol *self;
    int32_t res = CreateEcSpekeProtocol(&g_X25519ParamsC, true, &self);
    res = self->setPsk(self, nullptr);
    self->destroy(self);
}

static void ECSpekeTest11(void)
{
    HksInitialize();
    BaseProtocol *self;
    int32_t res = CreateEcSpekeProtocol(&g_X25519ParamsC, true, &self);

    Uint8Buff errParams = { nullptr, PSK_SIZE };
    res = self->setPsk(self, &errParams);

    self->destroy(self);
}

static void ECSpekeTest12(void)
{
    HksInitialize();
    BaseProtocol *self;
    int32_t res = CreateEcSpekeProtocol(&g_X25519ParamsC, true, &self);

    Uint8Buff errParams = { (uint8_t *)PSK_VAL, 0 };
    res = self->setPsk(self, &errParams);

    self->destroy(self);
}

static void ECSpekeTest13(void)
{
    HksInitialize();
    BaseProtocol *self;
    int32_t res = CreateEcSpekeProtocol(&g_X25519ParamsC, true, &self);

    CJson *out = nullptr;
    res = self->start(nullptr, &out);

    self->destroy(self);
}

static void ECSpekeTest14(void)
{
    HksInitialize();
    BaseProtocol *self;
    int32_t res = CreateEcSpekeProtocol(&g_X25519ParamsC, true, &self);

    res = self->start(self, nullptr);

    self->destroy(self);
}

static void ECSpekeTest15(void)
{
    HksInitialize();
    BaseProtocol *self;
    int32_t res = CreateEcSpekeProtocol(&g_X25519ParamsC, true, &self);

    self->curState = self->finishState;

    CJson *out = nullptr;
    res = self->start(self, &out);

    self->destroy(self);
}

static void ECSpekeTest16(void)
{
    HksInitialize();
    BaseProtocol *self;
    int32_t res = CreateEcSpekeProtocol(&g_X25519ParamsC, true, &self);

    self->curState = self->failState;

    CJson *out = nullptr;
    res = self->start(self, &out);

    self->destroy(self);
}

static void ECSpekeTest17(void)
{
    HksInitialize();
    BaseProtocol *self;
    int32_t res = CreateEcSpekeProtocol(&g_X25519ParamsC, true, &self);

    CJson recvMsg;
    CJson *sendMsg = nullptr;
    res = self->process(nullptr, &recvMsg, &sendMsg);

    self->destroy(self);
}

static void ECSpekeTest18(void)
{
    HksInitialize();
    BaseProtocol *self;
    int32_t res = CreateEcSpekeProtocol(&g_X25519ParamsC, true, &self);

    CJson *sendMsg = nullptr;
    res = self->process(self, nullptr, &sendMsg);

    self->destroy(self);
}

static void ECSpekeTest19(void)
{
    HksInitialize();
    BaseProtocol *self;
    int32_t res = CreateEcSpekeProtocol(&g_X25519ParamsC, true, &self);

    CJson recvMsg;
    res = self->process(self, &recvMsg, nullptr);

    self->destroy(self);
}

static void ECSpekeTest20(void)
{
    HksInitialize();
    BaseProtocol *self;
    int32_t res = CreateEcSpekeProtocol(&g_X25519ParamsC, true, &self);

    self->curState = self->finishState;

    CJson recvMsg;
    CJson *sendMsg = nullptr;
    res = self->process(self, &recvMsg, &sendMsg);

    self->destroy(self);
}

static void ECSpekeTest21(void)
{
    HksInitialize();
    BaseProtocol *self;
    int32_t res = CreateEcSpekeProtocol(&g_X25519ParamsC, true, &self);

    self->curState = self->failState;

    CJson recvMsg;
    CJson *sendMsg = nullptr;
    res = self->process(self, &recvMsg, &sendMsg);

    self->destroy(self);
}

static void ECSpekeTest22(void)
{
    HksInitialize();
    BaseProtocol *self;
    int32_t res = CreateEcSpekeProtocol(&g_X25519ParamsC, true, &self);

    res = self->setSelfProtectedMsg(nullptr, &g_msgC);

    self->destroy(self);
}

static void ECSpekeTest23(void)
{
    HksInitialize();
    BaseProtocol *self;
    int32_t res = CreateEcSpekeProtocol(&g_X25519ParamsC, true, &self);

    res = self->setSelfProtectedMsg(self, nullptr);

    self->destroy(self);
}

static void ECSpekeTest24(void)
{
    HksInitialize();
    BaseProtocol *self;
    int32_t res = CreateEcSpekeProtocol(&g_X25519ParamsC, true, &self);

    res = self->setPeerProtectedMsg(nullptr, &g_msgS);

    self->destroy(self);
}

static void ECSpekeTest25(void)
{
    HksInitialize();
    BaseProtocol *self;
    int32_t res = CreateEcSpekeProtocol(&g_X25519ParamsC, true, &self);

    res = self->setPeerProtectedMsg(self, nullptr);

    self->destroy(self);
}

static void ECSpekeTest26(void)
{
    HksInitialize();
    BaseProtocol *self;
    int32_t res = CreateEcSpekeProtocol(&g_X25519ParamsC, true, &self);

    Uint8Buff key = { nullptr, 0 };
    res = self->getSessionKey(nullptr, &key);

    self->destroy(self);
}

static void ECSpekeTest27(void)
{
    HksInitialize();
    BaseProtocol *self;
    int32_t res = CreateEcSpekeProtocol(&g_X25519ParamsC, true, &self);

    res = self->getSessionKey(self, nullptr);

    self->destroy(self);
}

static void ECSpekeTest28(void)
{
    HksInitialize();
    BaseProtocol *self;
    int32_t res = CreateEcSpekeProtocol(&g_X25519ParamsC, true, &self);

    Uint8Buff key = { nullptr, 0 };
    res = self->getSessionKey(self, &key);

    self->destroy(self);
}

static void ECSpekeTest29(void)
{
    HksInitialize();
    BaseProtocol *self;
    CreateEcSpekeProtocol(&g_X25519ParamsC, true, &self);

    self->destroy(nullptr);
    self->destroy(self);
}

static void ECSpekeTest30(void)
{
    CJson *json = CreateJson();
    NotifyPeerError(ERROR_CODE, &json);
    ReturnError(ERROR_CODE, nullptr);
    ThrowException(nullptr, nullptr, nullptr);
    FreeJson(json);
}

bool FuzzDoCallback(const uint8_t* data, size_t size)
{
    (void)data;
    (void)size;
    (void)ECSpekeTest01();
    (void)ECSpekeTest02();
    (void)ECSpekeTest03();
    (void)ECSpekeTest04();
    (void)ECSpekeTest05();
    (void)ECSpekeTest06();
    (void)ECSpekeTest07();
    (void)ECSpekeTest08();
    (void)ECSpekeTest09();
    (void)ECSpekeTest10();
    (void)ECSpekeTest11();
    (void)ECSpekeTest12();
    (void)ECSpekeTest13();
    (void)ECSpekeTest14();
    (void)ECSpekeTest15();
    (void)ECSpekeTest16();
    (void)ECSpekeTest17();
    (void)ECSpekeTest18();
    (void)ECSpekeTest19();
    (void)ECSpekeTest20();
    (void)ECSpekeTest21();
    (void)ECSpekeTest22();
    (void)ECSpekeTest23();
    (void)ECSpekeTest24();
    (void)ECSpekeTest25();
    (void)ECSpekeTest26();
    (void)ECSpekeTest27();
    (void)ECSpekeTest28();
    (void)ECSpekeTest29();
    (void)ECSpekeTest30();
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

