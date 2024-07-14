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

#include "pubkeyexchange_fuzzer.h"

#include "auth_code_import.h"
#include "device_auth_defines.h"
#include "pub_key_exchange.h"
#include "hc_types.h"
#include "hks_api.h"
#include "hks_param.h"
#include "hks_type.h"
#include "json_utils.h"
#include "uint8buff_utils.h"

namespace OHOS {
static const char *AUTH_ID_C_VAL = "5420459D93FE773F9945FD64277FBA2CAB8FB996DDC1D0B97676FBB1242B3930";
static const char *AUTH_ID_S_VAL = "52E2706717D5C39D736E134CC1E3BE1BAA2AA52DB7C76A37C749558BD2E6492C";
static const char *GROUP_ID = "E2EE6F830B176B2C96A9F99BFAE2A61F5D1490B9F4A090E9D8C2874C230C7C21";
static const char *GROUP_OWNER = "testApp";

static Uint8Buff g_authIdC = { (uint8_t *)AUTH_ID_C_VAL, 64 };
static Uint8Buff g_authIdS = { (uint8_t *)AUTH_ID_S_VAL, 64 };
static PubKeyExchangeParams g_paramsC = { 0, GROUP_OWNER, GROUP_ID, g_authIdC, false };
static PubKeyExchangeParams g_paramsS = { 0, GROUP_OWNER, GROUP_ID, g_authIdS, false };

static const char *INVALID_MSG1 = "{\"errCode\": 1}";
static const char *INVALID_MSG2 = "{\"event\": -1, \"errCode\": 1}";
static const char *INVALID_MSG3 = "{\"event\": 10, \"errCode\": 1}";
static const char *ERROR_MSG1 = "{\"event\": 3, \"errCode\": 1}";
static const char *ERROR_MSG2 = "{\"event\": 3}";

static void PubkeyExchangeTest01(void)
{
    HksInitialize();
    BaseCmd *self = CreatePubKeyExchangeCmd((void *)&g_paramsC, true, ABORT_IF_ERROR);
    self->destroy(self);
}

static void PubkeyExchangeTest02(void)
{
    HksInitialize();
    BaseCmd *client = CreatePubKeyExchangeCmd((void *)&g_paramsC, true, ABORT_IF_ERROR);

    BaseCmd *server = CreatePubKeyExchangeCmd((void *)&g_paramsS, false, ABORT_IF_ERROR);

    CJson *clientOut = nullptr;
    CJson *serverOut = nullptr;

    int32_t res = client->start(client, &clientOut);

    CmdState clientState;
    CmdState serverState;
    res = server->process(server, clientOut, &serverOut, &serverState);
    FreeJson(clientOut);
    clientOut = nullptr;

    res = client->process(client, serverOut, &clientOut, &clientState);
    FreeJson(serverOut);
    serverOut = nullptr;

    client->destroy(client);
    server->destroy(server);
}

static void PubkeyExchangeTest03(void)
{
    HksInitialize();
    (void)CreatePubKeyExchangeCmd(nullptr, true, ABORT_IF_ERROR);
}

static void PubkeyExchangeTest04(void)
{
    HksInitialize();
    PubKeyExchangeParams errorParams = { 0, nullptr, GROUP_ID, g_authIdC, false };
    (void)CreatePubKeyExchangeCmd((void *)(&errorParams), true, ABORT_IF_ERROR);
}

static void PubkeyExchangeTest05(void)
{
    HksInitialize();
    PubKeyExchangeParams errorParams = { 0, GROUP_OWNER, nullptr, g_authIdC, false };
    (void)CreatePubKeyExchangeCmd((void *)(&errorParams), true, ABORT_IF_ERROR);
}

static void PubkeyExchangeTest06(void)
{
    HksInitialize();
    PubKeyExchangeParams errorParams = { 0, GROUP_OWNER, GROUP_ID, { nullptr, 0 }, false };
    (void)CreatePubKeyExchangeCmd((void *)(&errorParams), true, ABORT_IF_ERROR);
}

static void PubkeyExchangeTest07(void)
{
    HksInitialize();
    PubKeyExchangeParams errorParams = { 0, GROUP_OWNER, GROUP_ID, { (uint8_t *)AUTH_ID_C_VAL, 0 }, false };
    (void)CreatePubKeyExchangeCmd((void *)(&errorParams), true, ABORT_IF_ERROR);
}

static void PubkeyExchangeTest08(void)
{
    HksInitialize();
    BaseCmd *self = CreatePubKeyExchangeCmd((void *)&g_paramsC, true, ABORT_IF_ERROR);
    self->destroy(nullptr);
    self->destroy(self);
}

static void PubkeyExchangeTest09(void)
{
    HksInitialize();
    BaseCmd *self = CreatePubKeyExchangeCmd((void *)&g_paramsC, true, ABORT_IF_ERROR);

    CJson *out = nullptr;
    (void)self->start(nullptr, &out);
    self->destroy(self);
}

static void PubkeyExchangeTest10(void)
{
    HksInitialize();
    BaseCmd *self = CreatePubKeyExchangeCmd((void *)&g_paramsC, true, ABORT_IF_ERROR);
    (void)self->start(self, nullptr);
    self->destroy(self);
}

static void PubkeyExchangeTest11(void)
{
    HksInitialize();
    BaseCmd *self = CreatePubKeyExchangeCmd((void *)&g_paramsC, true, ABORT_IF_ERROR);

    CJson *out = nullptr;
    (void)self->start(self, &out);
    FreeJson(out);
    out = nullptr;

    (void)self->start(self, &out);
    self->destroy(self);
}

static void PubkeyExchangeTest12(void)
{
    HksInitialize();
    BaseCmd *self = CreatePubKeyExchangeCmd((void *)&g_paramsC, true, ABORT_IF_ERROR);

    CJson in;
    CJson *out = nullptr;
    CmdState state;
    (void)self->process(nullptr, &in, &out, &state);
    self->destroy(self);
}

static void PubkeyExchangeTest13(void)
{
    HksInitialize();
    BaseCmd *self = CreatePubKeyExchangeCmd((void *)&g_paramsC, true, ABORT_IF_ERROR);

    CJson *out = nullptr;
    CmdState state;
    (void)self->process(self, nullptr, &out, &state);
    self->destroy(self);
}

static void PubkeyExchangeTest14(void)
{
    HksInitialize();
    BaseCmd *self = CreatePubKeyExchangeCmd((void *)&g_paramsC, true, ABORT_IF_ERROR);
    CJson in;
    CmdState state;
    (void)self->process(self, &in, nullptr, &state);
    self->destroy(self);
}

static void PubkeyExchangeTest15(void)
{
    HksInitialize();
    BaseCmd *self = CreatePubKeyExchangeCmd((void *)&g_paramsC, true, ABORT_IF_ERROR);

    CJson in;
    CJson *out = nullptr;
    (void)self->process(self, &in, &out, nullptr);
    self->destroy(self);
}

static void PubkeyExchangeTest16(void)
{
    HksInitialize();
    BaseCmd *self = CreatePubKeyExchangeCmd((void *)&g_paramsC, true, ABORT_IF_ERROR);
    self->curState = self->finishState;

    CJson in;
    CJson *out = nullptr;
    CmdState state;
    (void)self->process(self, &in, &out, &state);
    self->destroy(self);
}

static void PubkeyExchangeTest17(void)
{
    HksInitialize();
    BaseCmd *self = CreatePubKeyExchangeCmd((void *)&g_paramsC, true, ABORT_IF_ERROR);

    self->curState = self->failState;

    CJson in;
    CJson *out = nullptr;
    CmdState state;
    (void)self->process(self, &in, &out, &state);
    self->destroy(self);
}

static void PubkeyExchangeTest18(void)
{
    HksInitialize();
    BaseCmd *self = CreatePubKeyExchangeCmd((void *)&g_paramsS, false, ABORT_IF_ERROR);

    CJson *failEvent = CreateJsonFromString(ERROR_MSG1);
    CJson *out = nullptr;
    CmdState state;
    (void)self->process(self, failEvent, &out, &state);
    FreeJson(failEvent);

    self->destroy(self);
}

static void PubkeyExchangeTest19(void)
{
    HksInitialize();
    BaseCmd *self = CreatePubKeyExchangeCmd((void *)&g_paramsS, false, ABORT_IF_ERROR);

    CJson *failEvent = CreateJsonFromString(ERROR_MSG2);
    CJson *out = nullptr;
    CmdState state;
    (void)self->process(self, failEvent, &out, &state);
    FreeJson(failEvent);

    self->destroy(self);
}

static void PubkeyExchangeTest20(void)
{
    HksInitialize();
    BaseCmd *self = CreatePubKeyExchangeCmd((void *)&g_paramsS, false, ABORT_IF_ERROR);

    CJson *invalidMsg = CreateJsonFromString(INVALID_MSG1);
    CJson *out = nullptr;
    CmdState state;
    (void)self->process(self, invalidMsg, &out, &state);
    FreeJson(invalidMsg);

    self->destroy(self);
}

static void PubkeyExchangeTest21(void)
{
    HksInitialize();
    BaseCmd *self = CreatePubKeyExchangeCmd((void *)&g_paramsS, false, ABORT_IF_ERROR);

    CJson *invalidMsg = CreateJsonFromString(INVALID_MSG2);
    CJson *out = nullptr;
    CmdState state;
    (void)self->process(self, invalidMsg, &out, &state);
    FreeJson(invalidMsg);

    self->destroy(self);
}

static void PubkeyExchangeTest22(void)
{
    HksInitialize();
    BaseCmd *self = CreatePubKeyExchangeCmd((void *)&g_paramsS, false, ABORT_IF_ERROR);

    CJson *invalidMsg = CreateJsonFromString(INVALID_MSG3);
    CJson *out = nullptr;
    CmdState state;
    (void)self->process(self, invalidMsg, &out, &state);
    FreeJson(invalidMsg);

    self->destroy(self);
}

bool FuzzDoCallback(const uint8_t* data, size_t size)
{
    (void)data;
    (void)size;
    (void)PubkeyExchangeTest01();
    (void)PubkeyExchangeTest02();
    (void)PubkeyExchangeTest03();
    (void)PubkeyExchangeTest04();
    (void)PubkeyExchangeTest05();
    (void)PubkeyExchangeTest06();
    (void)PubkeyExchangeTest07();
    (void)PubkeyExchangeTest08();
    (void)PubkeyExchangeTest09();
    (void)PubkeyExchangeTest10();
    (void)PubkeyExchangeTest11();
    (void)PubkeyExchangeTest12();
    (void)PubkeyExchangeTest13();
    (void)PubkeyExchangeTest14();
    (void)PubkeyExchangeTest15();
    (void)PubkeyExchangeTest16();
    (void)PubkeyExchangeTest17();
    (void)PubkeyExchangeTest18();
    (void)PubkeyExchangeTest19();
    (void)PubkeyExchangeTest20();
    (void)PubkeyExchangeTest21();
    (void)PubkeyExchangeTest22();
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

