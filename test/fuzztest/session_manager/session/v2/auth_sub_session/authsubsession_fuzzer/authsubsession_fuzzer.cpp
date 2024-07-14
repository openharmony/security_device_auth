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

#include "authsubsession_fuzzer.h"

#include "auth_sub_session.h"
#include "device_auth_defines.h"
#include "ec_speke_protocol.h"
#include "hc_types.h"
#include "hks_api.h"
#include "hks_param.h"
#include "hks_type.h"
#include "iso_protocol.h"
#include "json_utils.h"
#include "uint8buff_utils.h"

namespace OHOS {
#define PSK_SIZE 32
#define PROTOCOL_TYPE_INVALID (-1)
static const uint8_t PSK_VAL[PSK_SIZE] = { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19,
    20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32 };
static const char *AUTH_ID_C_VAL = "5420459D93FE773F9945FD64277FBA2CAB8FB996DDC1D0B97676FBB1242B3930";
static const char *AUTH_ID_S_VAL = "52E2706717D5C39D736E134CC1E3BE1BAA2AA52DB7C76A37C749558BD2E6492C";
static const char *MSG_C_VAL = "client send msg";
static const char *MSG_S_VAL = "server send msg";

static Uint8Buff g_psk = { (uint8_t *)PSK_VAL, PSK_SIZE };
static Uint8Buff g_authIdC = { (uint8_t *)AUTH_ID_C_VAL, 64 };
static Uint8Buff g_authIdS = { (uint8_t *)AUTH_ID_S_VAL, 64 };
static Uint8Buff g_msgC = { (uint8_t *)MSG_C_VAL, 16 };
static Uint8Buff g_msgS = { (uint8_t *)MSG_S_VAL, 16 };
static IsoInitParams g_paramsC = { g_authIdC };
static IsoInitParams g_paramsS = { g_authIdS };
static EcSpekeInitParams g_P256ParamsC = { CURVE_TYPE_256, g_authIdC };
static EcSpekeInitParams g_P256ParamsS = { CURVE_TYPE_256, g_authIdS };
static EcSpekeInitParams g_X25519ParamsC = { CURVE_TYPE_25519, g_authIdC };
static EcSpekeInitParams g_X25519ParamsS = { CURVE_TYPE_25519, g_authIdS };

static void AuthSubSessionTest01(void)
{
    HksInitialize();
    AuthSubSession *self;
    (void)CreateAuthSubSession(PROTOCOL_TYPE_ISO, (void *)&g_paramsC, true, &self);
    self->destroy(self);
}

static void AuthSubSessionTest02(void)
{
    HksInitialize();
    AuthSubSession *client;
    int32_t res = CreateAuthSubSession(PROTOCOL_TYPE_ISO, (void *)&g_paramsC, true, &client);

    AuthSubSession *server;
    res = CreateAuthSubSession(PROTOCOL_TYPE_ISO, (void *)&g_paramsS, false, &server);

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

static void AuthSubSessionTest03(void)
{
    HksInitialize();
    AuthSubSession *client;
    int32_t res = CreateAuthSubSession(PROTOCOL_TYPE_ISO, (void *)&g_paramsC, true, &client);

    AuthSubSession *server;
    res = CreateAuthSubSession(PROTOCOL_TYPE_ISO, (void *)&g_paramsS, false, &server);

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

static void AuthSubSessionTest04(void)
{
    HksInitialize();
    AuthSubSession *self;
    (void)CreateAuthSubSession(PROTOCOL_TYPE_EC_SPEKE, (void *)&g_P256ParamsC, true, &self);
    self->destroy(self);
}

static void AuthSubSessionTest05(void)
{
    HksInitialize();
    AuthSubSession *client;
    int32_t res = CreateAuthSubSession(PROTOCOL_TYPE_EC_SPEKE, (void *)&g_P256ParamsC, true, &client);

    AuthSubSession *server;
    res = CreateAuthSubSession(PROTOCOL_TYPE_EC_SPEKE, (void *)&g_P256ParamsS, false, &server);

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

static void AuthSubSessionTest06(void)
{
    HksInitialize();
    AuthSubSession *client;
    int32_t res = CreateAuthSubSession(PROTOCOL_TYPE_EC_SPEKE, (void *)&g_P256ParamsC, true, &client);

    AuthSubSession *server;
    res = CreateAuthSubSession(PROTOCOL_TYPE_EC_SPEKE, (void *)&g_P256ParamsS, false, &server);

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

static void AuthSubSessionTest07(void)
{
    HksInitialize();
    AuthSubSession *self;
    (void)CreateAuthSubSession(PROTOCOL_TYPE_EC_SPEKE, (void *)&g_X25519ParamsC, true, &self);
    self->destroy(self);
}

static void AuthSubSessionTest08(void)
{
    HksInitialize();
    AuthSubSession *client;
    int32_t res = CreateAuthSubSession(PROTOCOL_TYPE_EC_SPEKE, (void *)&g_X25519ParamsC, true, &client);

    AuthSubSession *server;
    res = CreateAuthSubSession(PROTOCOL_TYPE_EC_SPEKE, (void *)&g_X25519ParamsS, false, &server);

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

static void AuthSubSessionTest09(void)
{
    HksInitialize();
    AuthSubSession *client;
    int32_t res = CreateAuthSubSession(PROTOCOL_TYPE_EC_SPEKE, (void *)&g_X25519ParamsC, true, &client);

    AuthSubSession *server;
    res = CreateAuthSubSession(PROTOCOL_TYPE_EC_SPEKE, (void *)&g_X25519ParamsS, false, &server);

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

static void AuthSubSessionTest10(void)
{
    HksInitialize();
    AuthSubSession *self;
    (void)CreateAuthSubSession(PROTOCOL_TYPE_ISO, nullptr, true, &self);
}

static void AuthSubSessionTest11(void)
{
    HksInitialize();
    (void)CreateAuthSubSession(PROTOCOL_TYPE_ISO, &g_paramsC, true, nullptr);
}

static void AuthSubSessionTest12(void)
{
    HksInitialize();
    IsoInitParams errParams = { nullptr, 32 };
    AuthSubSession *self;
    (void)CreateAuthSubSession(PROTOCOL_TYPE_ISO, &errParams, true, &self);
}

static void AuthSubSessionTest13(void)
{
    HksInitialize();
    IsoInitParams errParams = { (uint8_t *)AUTH_ID_C_VAL, 0 };
    AuthSubSession *self;
    (void)CreateAuthSubSession(PROTOCOL_TYPE_ISO, &errParams, true, &self);
}

static void AuthSubSessionTest14(void)
{
    HksInitialize();
    AuthSubSession *self;
    int32_t res = CreateAuthSubSession(PROTOCOL_TYPE_ISO, &g_paramsC, true, &self);

    res = self->setPsk(nullptr, &g_psk);
    self->destroy(self);
}

static void AuthSubSessionTest15(void)
{
    HksInitialize();
    AuthSubSession *self;
    int32_t res = CreateAuthSubSession(PROTOCOL_TYPE_ISO, &g_paramsC, true, &self);

    res = self->setPsk(self, nullptr);
    self->destroy(self);
}

static void AuthSubSessionTest16(void)
{
    HksInitialize();
    AuthSubSession *self;
    int32_t res = CreateAuthSubSession(PROTOCOL_TYPE_ISO, &g_paramsC, true, &self);

    Uint8Buff errParams = { nullptr, PSK_SIZE };
    res = self->setPsk(self, &errParams);
    self->destroy(self);
}

static void AuthSubSessionTest17(void)
{
    HksInitialize();
    AuthSubSession *self;
    int32_t res = CreateAuthSubSession(PROTOCOL_TYPE_ISO, &g_paramsC, true, &self);

    Uint8Buff errParams = { (uint8_t *)PSK_VAL, 0 };
    res = self->setPsk(self, &errParams);
    self->destroy(self);
}

static void AuthSubSessionTest18(void)
{
    HksInitialize();
    AuthSubSession *self;
    int32_t res = CreateAuthSubSession(PROTOCOL_TYPE_ISO, &g_paramsC, true, &self);
    CJson *out = nullptr;
    res = self->start(nullptr, &out);
    self->destroy(self);
}

static void AuthSubSessionTest19(void)
{
    HksInitialize();
    AuthSubSession *self;
    int32_t res = CreateAuthSubSession(PROTOCOL_TYPE_ISO, &g_paramsC, true, &self);
    res = self->start(self, nullptr);
    self->destroy(self);
}

static void AuthSubSessionTest20(void)
{
    HksInitialize();
    AuthSubSession *self;
    int32_t res = CreateAuthSubSession(PROTOCOL_TYPE_ISO, &g_paramsC, true, &self);
    CJson *out = nullptr;
    res = self->start(self, &out);
    FreeJson(out);
    out = nullptr;

    res = self->start(self, &out);
    self->destroy(self);
}

static void AuthSubSessionTest21(void)
{
    HksInitialize();
    bool isSupport = IsProtocolSupport(PROTOCOL_TYPE_ISO);
    isSupport = IsProtocolSupport(PROTOCOL_TYPE_INVALID);
}

static void AuthSubSessionTest22(void)
{
    HksInitialize();
    AuthSubSession *self;
    (void)CreateAuthSubSession(PROTOCOL_TYPE_INVALID, &g_paramsC, true, &self);
}

static void AuthSubSessionTest23(void)
{
    HksInitialize();
    AuthSubSession *self;
    int32_t res = CreateAuthSubSession(PROTOCOL_TYPE_ISO, &g_paramsC, true, &self);

    CJson recvMsg;
    CJson *sendMsg = nullptr;
    res = self->process(nullptr, &recvMsg, &sendMsg);
    self->destroy(self);
}

static void AuthSubSessionTest24(void)
{
    HksInitialize();
    AuthSubSession *self;
    int32_t res = CreateAuthSubSession(PROTOCOL_TYPE_ISO, &g_paramsC, true, &self);

    CJson *sendMsg = nullptr;
    res = self->process(self, nullptr, &sendMsg);
    self->destroy(self);
}

static void AuthSubSessionTest25(void)
{
    HksInitialize();
    AuthSubSession *self;
    int32_t res = CreateAuthSubSession(PROTOCOL_TYPE_ISO, &g_paramsC, true, &self);
    CJson recvMsg;
    res = self->process(self, &recvMsg, nullptr);
    self->destroy(self);
}

static void AuthSubSessionTest26(void)
{
    HksInitialize();
    AuthSubSession *self;
    int32_t res = CreateAuthSubSession(PROTOCOL_TYPE_ISO, &g_paramsC, true, &self);
    res = self->setSelfProtectedMsg(nullptr, &g_msgC);

    self->destroy(self);
}

static void AuthSubSessionTest27(void)
{
    HksInitialize();
    AuthSubSession *self;
    int32_t res = CreateAuthSubSession(PROTOCOL_TYPE_ISO, &g_paramsC, true, &self);
    res = self->setSelfProtectedMsg(self, nullptr);
    self->destroy(self);
}

static void AuthSubSessionTest28(void)
{
    HksInitialize();
    AuthSubSession *self;
    int32_t res = CreateAuthSubSession(PROTOCOL_TYPE_ISO, &g_paramsC, true, &self);
    res = self->setPeerProtectedMsg(nullptr, &g_msgS);
    self->destroy(self);
}

static void AuthSubSessionTest29(void)
{
    HksInitialize();
    AuthSubSession *self;
    int32_t res = CreateAuthSubSession(PROTOCOL_TYPE_ISO, &g_paramsC, true, &self);
    res = self->setPeerProtectedMsg(self, nullptr);
    self->destroy(self);
}

static void AuthSubSessionTest30(void)
{
    HksInitialize();
    AuthSubSession *self;
    int32_t res = CreateAuthSubSession(PROTOCOL_TYPE_ISO, &g_paramsC, true, &self);

    Uint8Buff key = { nullptr, 0 };
    res = self->getSessionKey(nullptr, &key);
    self->destroy(self);
}

static void AuthSubSessionTest31(void)
{
    HksInitialize();
    AuthSubSession *self;
    int32_t res = CreateAuthSubSession(PROTOCOL_TYPE_ISO, &g_paramsC, true, &self);
    res = self->getSessionKey(self, nullptr);
    self->destroy(self);
}

static void AuthSubSessionTest32(void)
{
    HksInitialize();
    AuthSubSession *self;
    int32_t res = CreateAuthSubSession(PROTOCOL_TYPE_ISO, &g_paramsC, true, &self);
    Uint8Buff key = { nullptr, 0 };
    res = self->getSessionKey(self, &key);
    self->destroy(self);
}

static void AuthSubSessionTest33(void)
{
    HksInitialize();
    AuthSubSession *self;
    (void)CreateAuthSubSession(PROTOCOL_TYPE_ISO, &g_paramsC, true, &self);
    self->destroy(nullptr);
    self->destroy(self);
}

bool FuzzDoCallback(const uint8_t* data, size_t size)
{
    (void)data;
    (void)size;
    (void)AuthSubSessionTest01();
    (void)AuthSubSessionTest02();
    (void)AuthSubSessionTest03();
    (void)AuthSubSessionTest04();
    (void)AuthSubSessionTest05();
    (void)AuthSubSessionTest06();
    (void)AuthSubSessionTest07();
    (void)AuthSubSessionTest08();
    (void)AuthSubSessionTest09();
    (void)AuthSubSessionTest10();
    (void)AuthSubSessionTest11();
    (void)AuthSubSessionTest12();
    (void)AuthSubSessionTest13();
    (void)AuthSubSessionTest14();
    (void)AuthSubSessionTest15();
    (void)AuthSubSessionTest16();
    (void)AuthSubSessionTest17();
    (void)AuthSubSessionTest18();
    (void)AuthSubSessionTest19();
    (void)AuthSubSessionTest20();
    (void)AuthSubSessionTest21();
    (void)AuthSubSessionTest22();
    (void)AuthSubSessionTest23();
    (void)AuthSubSessionTest24();
    (void)AuthSubSessionTest25();
    (void)AuthSubSessionTest26();
    (void)AuthSubSessionTest27();
    (void)AuthSubSessionTest28();
    (void)AuthSubSessionTest29();
    (void)AuthSubSessionTest30();
    (void)AuthSubSessionTest31();
    (void)AuthSubSessionTest32();
    (void)AuthSubSessionTest33();
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

