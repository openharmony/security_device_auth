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

#include "iso_fuzzer.h"

#include <cstddef>
#include <cstdint>

#include "device_auth_defines.h"
#include "hc_types.h"
#include "hks_api.h"
#include "hks_param.h"
#include "hks_type.h"
#include "iso_protocol.h"
#include "json_utils.h"
#include "uint8buff_utils.h"

namespace OHOS {
#define PSK_SIZE 32
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

static void IsoTest01(void)
{
    HksInitialize();
    BaseProtocol *self;
    (void)CreateIsoProtocol(&g_paramsC, true, &self);
    self->destroy(self);
}

static void IsoTest02(void)
{
    HksInitialize();
    BaseProtocol *client;
    int32_t res = CreateIsoProtocol(&g_paramsC, true, &client);

    BaseProtocol *server;
    res = CreateIsoProtocol(&g_paramsS, false, &server);

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

static void IsoTest03(void)
{
    HksInitialize();
    BaseProtocol *client;
    int32_t res = CreateIsoProtocol(&g_paramsC, true, &client);

    BaseProtocol *server;
    res = CreateIsoProtocol(&g_paramsS, false, &server);

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

static void IsoTest04(void)
{
    HksInitialize();
    BaseProtocol *self;
    (void)CreateIsoProtocol(nullptr, true, &self);
}

static void IsoTest05(void)
{
    HksInitialize();
    (void)CreateIsoProtocol(&g_paramsC, true, nullptr);
}

static void IsoTest06(void)
{
    HksInitialize();
    IsoInitParams errParams = { nullptr, 32 };
    BaseProtocol *self;
    (void)CreateIsoProtocol(&errParams, true, &self);
}

static void IsoTest07(void)
{
    HksInitialize();
    IsoInitParams errParams = { (uint8_t *)AUTH_ID_C_VAL, 0 };
    BaseProtocol *self;
    (void)CreateIsoProtocol(&errParams, true, &self);
}

static void IsoTest08(void)
{
    HksInitialize();
    BaseProtocol *self;
    (void)CreateIsoProtocol(&g_paramsC, true, &self);
    (void)self->setPsk(nullptr, &g_psk);
    self->destroy(self);
}

static void IsoTest09(void)
{
    HksInitialize();
    BaseProtocol *self;
    int32_t res = CreateIsoProtocol(&g_paramsC, true, &self);
    res = self->setPsk(self, nullptr);
    self->destroy(self);
}

static void IsoTest10(void)
{
    HksInitialize();
    BaseProtocol *self;
    int32_t res = CreateIsoProtocol(&g_paramsC, true, &self);
    Uint8Buff errParams = { nullptr, PSK_SIZE };
    res = self->setPsk(self, &errParams);
    self->destroy(self);
}

static void IsoTest11(void)
{
    HksInitialize();
    BaseProtocol *self;
    int32_t res = CreateIsoProtocol(&g_paramsC, true, &self);
    Uint8Buff errParams = { (uint8_t *)PSK_VAL, 0 };
    res = self->setPsk(self, &errParams);
    self->destroy(self);
}

static void IsoTest12(void)
{
    HksInitialize();
    BaseProtocol *self;
    int32_t res = CreateIsoProtocol(&g_paramsC, true, &self);
    CJson *out = nullptr;
    res = self->start(nullptr, &out);
    self->destroy(self);
}

static void IsoTest13(void)
{
    HksInitialize();
    BaseProtocol *self;
    int32_t res = CreateIsoProtocol(&g_paramsC, true, &self);
    res = self->start(self, nullptr);
    self->destroy(self);
}

static void IsoTest14(void)
{
    HksInitialize();
    BaseProtocol *self;
    int32_t res = CreateIsoProtocol(&g_paramsC, true, &self);
    self->curState = self->finishState;
    CJson *out = nullptr;
    res = self->start(self, &out);
    self->destroy(self);
}

static void IsoTest15(void)
{
    HksInitialize();
    BaseProtocol *self;
    int32_t res = CreateIsoProtocol(&g_paramsC, true, &self);
    self->curState = self->failState;
    CJson *out = nullptr;
    res = self->start(self, &out);
    self->destroy(self);
}

static void IsoTest16(void)
{
    HksInitialize();
    BaseProtocol *self;
    int32_t res = CreateIsoProtocol(&g_paramsC, true, &self);
    CJson recvMsg;
    CJson *sendMsg = nullptr;
    res = self->process(nullptr, &recvMsg, &sendMsg);
    self->destroy(self);
}

static void IsoTest17(void)
{
    HksInitialize();
    BaseProtocol *self;
    int32_t res = CreateIsoProtocol(&g_paramsC, true, &self);
    CJson *sendMsg = nullptr;
    res = self->process(self, nullptr, &sendMsg);
    self->destroy(self);
}

static void IsoTest18(void)
{
    HksInitialize();
    BaseProtocol *self;
    int32_t res = CreateIsoProtocol(&g_paramsC, true, &self);
    CJson recvMsg;
    res = self->process(self, &recvMsg, nullptr);
    self->destroy(self);
}

static void IsoTest19(void)
{
    HksInitialize();
    BaseProtocol *self;
    int32_t res = CreateIsoProtocol(&g_paramsC, true, &self);
    self->curState = self->finishState;
    CJson recvMsg;
    CJson *sendMsg = nullptr;
    res = self->process(self, &recvMsg, &sendMsg);
    self->destroy(self);
}

static void IsoTest20(void)
{
    HksInitialize();
    BaseProtocol *self;
    int32_t res = CreateIsoProtocol(&g_paramsC, true, &self);
    self->curState = self->failState;
    CJson recvMsg;
    CJson *sendMsg = nullptr;
    res = self->process(self, &recvMsg, &sendMsg);
    self->destroy(self);
}

static void IsoTest21(void)
{
    HksInitialize();
    BaseProtocol *self;
    int32_t res = CreateIsoProtocol(&g_paramsC, true, &self);
    res = self->setSelfProtectedMsg(nullptr, &g_msgC);
    self->destroy(self);
}

static void IsoTest22(void)
{
    HksInitialize();
    BaseProtocol *self;
    int32_t res = CreateIsoProtocol(&g_paramsC, true, &self);
    res = self->setSelfProtectedMsg(self, nullptr);
    self->destroy(self);
}

static void IsoTest23(void)
{
    HksInitialize();
    BaseProtocol *self;
    int32_t res = CreateIsoProtocol(&g_paramsC, true, &self);
    res = self->setPeerProtectedMsg(nullptr, &g_msgS);
    self->destroy(self);
}

static void IsoTest24(void)
{
    HksInitialize();
    BaseProtocol *self;
    int32_t res = CreateIsoProtocol(&g_paramsC, true, &self);
    res = self->setPeerProtectedMsg(self, nullptr);
    self->destroy(self);
}

static void IsoTest25(void)
{
    HksInitialize();
    BaseProtocol *self;
    int32_t res = CreateIsoProtocol(&g_paramsC, true, &self);
    Uint8Buff key = { nullptr, 0 };
    res = self->getSessionKey(nullptr, &key);
    self->destroy(self);
}

static void IsoTest26(void)
{
    HksInitialize();
    BaseProtocol *self;
    int32_t res = CreateIsoProtocol(&g_paramsC, true, &self);
    res = self->getSessionKey(self, nullptr);
    self->destroy(self);
}

static void IsoTest27(void)
{
    HksInitialize();
    BaseProtocol *self;
    int32_t res = CreateIsoProtocol(&g_paramsC, true, &self);
    Uint8Buff key = { nullptr, 0 };
    res = self->getSessionKey(self, &key);
    self->destroy(self);
}

static void IsoTest28(void)
{
    HksInitialize();
    BaseProtocol *self;
    (void)CreateIsoProtocol(&g_paramsC, true, &self);
    self->destroy(nullptr);
    self->destroy(self);
}

bool FuzzDoCallback(const uint8_t* data, size_t size)
{
    (void)data;
    (void)size;
    (void)IsoTest01();
    (void)IsoTest02();
    (void)IsoTest03();
    (void)IsoTest04();
    (void)IsoTest05();
    (void)IsoTest06();
    (void)IsoTest07();
    (void)IsoTest08();
    (void)IsoTest09();
    (void)IsoTest10();
    (void)IsoTest11();
    (void)IsoTest12();
    (void)IsoTest13();
    (void)IsoTest14();
    (void)IsoTest15();
    (void)IsoTest16();
    (void)IsoTest17();
    (void)IsoTest18();
    (void)IsoTest19();
    (void)IsoTest20();
    (void)IsoTest21();
    (void)IsoTest22();
    (void)IsoTest23();
    (void)IsoTest24();
    (void)IsoTest25();
    (void)IsoTest26();
    (void)IsoTest27();
    (void)IsoTest28();
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

