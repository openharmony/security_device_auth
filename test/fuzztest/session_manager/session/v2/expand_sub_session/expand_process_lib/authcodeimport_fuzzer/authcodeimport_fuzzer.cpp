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

#include "authcodeimport_fuzzer.h"

#include "auth_code_import.h"
#include "device_auth_defines.h"
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
static AuthCodeImportParams g_paramsC = { 0, GROUP_OWNER, GROUP_ID, g_authIdC };
static AuthCodeImportParams g_paramsS = { 0, GROUP_OWNER, GROUP_ID, g_authIdS };

static const char *INVALID_MSG1 = "{\"errCode\": 1}";
static const char *INVALID_MSG2 = "{\"event\": -1, \"errCode\": 1}";
static const char *INVALID_MSG3 = "{\"event\": 10, \"errCode\": 1}";
static const char *ERROR_MSG1 = "{\"event\": 3, \"errCode\": 1}";
static const char *ERROR_MSG2 = "{\"event\": 3}";

void SetUpTestCase()
{
    HksInitialize();
}

void AuthCodeImportTest001()
{
    BaseCmd *self = CreateAuthCodeImportCmd((void *)&g_paramsC, true, ABORT_IF_ERROR);
    if (self != nullptr) {
        self->destroy(self);
    }
}

void AuthCodeImportTest002()
{
    BaseCmd *client = CreateAuthCodeImportCmd((void *)&g_paramsC, true, ABORT_IF_ERROR);
    if (client == nullptr) {
        return;
    }

    BaseCmd *server = CreateAuthCodeImportCmd((void *)&g_paramsS, false, ABORT_IF_ERROR);
    if (server == nullptr) {
        return;
    }
    CJson *clientOut = nullptr;
    CJson *serverOut = nullptr;

    int32_t res = client->start(client, &clientOut);
    if (res != HC_SUCCESS) {
        return;
    }
    if (clientOut == nullptr) {
        return;
    }
    CmdState clientState;
    CmdState serverState;
    res = server->process(server, clientOut, &serverOut, &serverState);
    FreeJson(clientOut);
    clientOut = nullptr;
    if (res != HC_SUCCESS) {
        return;
    }
    if (serverOut == nullptr) {
        return;
    }
    if (serverState != CMD_STATE_FINISH) {
        return;
    }
    res = client->process(client, serverOut, &clientOut, &clientState);
    FreeJson(serverOut);
    serverOut = nullptr;
    if (res != HC_SUCCESS) {
        return;
    }
    if (clientOut != nullptr) {
        return;
    }
    if (clientState != CMD_STATE_FINISH) {
        return;
    }
    client->destroy(client);
    server->destroy(server);
}

void AuthCodeImportTest101()
{
    BaseCmd *self = CreateAuthCodeImportCmd(nullptr, true, ABORT_IF_ERROR);
    if (self != nullptr) {
        self->destroy(self);
    }
}

void AuthCodeImportTest102()
{
    AuthCodeImportParams errorParams = { 0, nullptr, GROUP_ID, g_authIdC };
    BaseCmd *self = CreateAuthCodeImportCmd((void *)(&errorParams), true, ABORT_IF_ERROR);
    if (self != nullptr) {
        self->destroy(self);
    }
}

void AuthCodeImportTest103()
{
    AuthCodeImportParams errorParams = { 0, GROUP_OWNER, nullptr, g_authIdC };
    BaseCmd *self = CreateAuthCodeImportCmd((void *)(&errorParams), true, ABORT_IF_ERROR);
    if (self != nullptr) {
        self->destroy(self);
    }
}

void AuthCodeImportTest104()
{
    AuthCodeImportParams errorParams = { 0, GROUP_OWNER, GROUP_ID, { nullptr, 0 } };
    BaseCmd *self = CreateAuthCodeImportCmd((void *)(&errorParams), true, ABORT_IF_ERROR);
    if (self != nullptr) {
        self->destroy(self);
    }
}

void AuthCodeImportTest105()
{
    AuthCodeImportParams errorParams = { 0, GROUP_OWNER, GROUP_ID, { (uint8_t *)AUTH_ID_C_VAL, 0 } };
    BaseCmd *self = CreateAuthCodeImportCmd((void *)(&errorParams), true, ABORT_IF_ERROR);
    if (self != nullptr) {
        self->destroy(self);
    }
}

void AuthCodeImportTest106()
{
    BaseCmd *self = CreateAuthCodeImportCmd((void *)&g_paramsC, true, ABORT_IF_ERROR);
    if (self == nullptr) {
        return;
    }
    self->destroy(nullptr);
    self->destroy(self);
}

void AuthCodeImportTest107()
{
    BaseCmd *self = CreateAuthCodeImportCmd((void *)&g_paramsC, true, ABORT_IF_ERROR);
    if (self == nullptr) {
        return;
    }
    CJson *out = nullptr;
    int32_t res = self->start(nullptr, &out);
    if (res == HC_SUCCESS) {
        return;
    }
    self->destroy(self);
}

void AuthCodeImportTest108()
{
    BaseCmd *self = CreateAuthCodeImportCmd((void *)&g_paramsC, true, ABORT_IF_ERROR);
    if (self == nullptr) {
        return;
    }
    int32_t res = self->start(self, nullptr);
    if (res == HC_SUCCESS) {
        return;
    }
    self->destroy(self);
}

void AuthCodeImportTest109()
{
    BaseCmd *self = CreateAuthCodeImportCmd((void *)&g_paramsC, true, ABORT_IF_ERROR);
    if (self == nullptr) {
        return;
    }
    CJson *out = nullptr;
    int32_t res = self->start(self, &out);
    FreeJson(out);
    out = nullptr;

    res = self->start(self, &out);
    if (res == HC_SUCCESS) {
        return;
    }
    self->destroy(self);
}

void AuthCodeImportTest110()
{
    BaseCmd *self = CreateAuthCodeImportCmd((void *)&g_paramsC, true, ABORT_IF_ERROR);
    if (self == nullptr) {
        return;
    }
    CJson in;
    CJson *out = nullptr;
    CmdState state;
    int32_t res = self->process(nullptr, &in, &out, &state);
    if (res == HC_SUCCESS) {
        return;
    }
    self->destroy(self);
}

void AuthCodeImportTest111()
{
    BaseCmd *self = CreateAuthCodeImportCmd((void *)&g_paramsC, true, ABORT_IF_ERROR);
    if (self == nullptr) {
        return;
    }
    CJson *out = nullptr;
    CmdState state;
    int32_t res = self->process(self, nullptr, &out, &state);
    if (res == HC_SUCCESS) {
        return;
    }
    self->destroy(self);
}

void AuthCodeImportTest112()
{
    BaseCmd *self = CreateAuthCodeImportCmd((void *)&g_paramsC, true, ABORT_IF_ERROR);
    if (self == nullptr) {
        return;
    }
    CJson in;
    CmdState state;
    int32_t res = self->process(self, &in, nullptr, &state);
    if (res == HC_SUCCESS) {
        return;
    }
    self->destroy(self);
}

void AuthCodeImportTest113()
{
    BaseCmd *self = CreateAuthCodeImportCmd((void *)&g_paramsC, true, ABORT_IF_ERROR);
    if (self == nullptr) {
        return;
    }
    CJson in;
    CJson *out = nullptr;
    int32_t res = self->process(self, &in, &out, nullptr);
    if (res == HC_SUCCESS) {
        return;
    }
    self->destroy(self);
}

void AuthCodeImportTest114()
{
    BaseCmd *self = CreateAuthCodeImportCmd((void *)&g_paramsC, true, ABORT_IF_ERROR);
    if (self == nullptr) {
        return;
    }
    self->curState = self->finishState;

    CJson in;
    CJson *out = nullptr;
    CmdState state;
    int32_t res = self->process(self, &in, &out, &state);
    if (res == HC_SUCCESS) {
        return;
    }
    self->destroy(self);
}

void AuthCodeImportTest115()
{
    BaseCmd *self = CreateAuthCodeImportCmd((void *)&g_paramsC, true, ABORT_IF_ERROR);
    if (self == nullptr) {
        return;
    }
    self->curState = self->failState;

    CJson in;
    CJson *out = nullptr;
    CmdState state;
    int32_t res = self->process(self, &in, &out, &state);
    if (res == HC_SUCCESS) {
        return;
    }
    self->destroy(self);
}

void AuthCodeImportTest116()
{
    BaseCmd *self = CreateAuthCodeImportCmd((void *)&g_paramsS, false, ABORT_IF_ERROR);
    if (self == nullptr) {
        return;
    }
    CJson *failEvent = CreateJsonFromString(ERROR_MSG1);
    if (failEvent == nullptr) {
        return;
    }
    CJson *out = nullptr;
    CmdState state;
    int32_t res = self->process(self, failEvent, &out, &state);
    FreeJson(failEvent);
    if (res != HC_ERR_PEER_ERROR) {
        return;
    }
    if (out != nullptr) {
        return;
    }
    self->destroy(self);
}

void AuthCodeImportTest117()
{
    BaseCmd *self = CreateAuthCodeImportCmd((void *)&g_paramsS, false, ABORT_IF_ERROR);
    if (self == nullptr) {
        return;
    }
    CJson *failEvent = CreateJsonFromString(ERROR_MSG2);
    if (failEvent == nullptr) {
        return;
    }
    CJson *out = nullptr;
    CmdState state;
    int32_t res = self->process(self, failEvent, &out, &state);
    FreeJson(failEvent);
    if (res != HC_ERR_PEER_ERROR) {
        return;
    }
    if (out != nullptr) {
        return;
    }
    self->destroy(self);
}

void AuthCodeImportTest118()
{
    BaseCmd *self = CreateAuthCodeImportCmd((void *)&g_paramsS, false, ABORT_IF_ERROR);
    if (self == nullptr) {
        return;
    }
    CJson *invalidMsg = CreateJsonFromString(INVALID_MSG1);
    if (invalidMsg == nullptr) {
        return;
    }
    CJson *out = nullptr;
    CmdState state;
    int32_t res = self->process(self, invalidMsg, &out, &state);
    FreeJson(invalidMsg);
    if (res != HC_SUCCESS) {
        return;
    }
    if (out != nullptr) {
        return;
    }
    self->destroy(self);
}

void AuthCodeImportTest119()
{
    BaseCmd *self = CreateAuthCodeImportCmd((void *)&g_paramsS, false, ABORT_IF_ERROR);
    if (self == nullptr) {
        return;
    }
    CJson *invalidMsg = CreateJsonFromString(INVALID_MSG2);
    if (invalidMsg == nullptr) {
        return;
    }
    CJson *out = nullptr;
    CmdState state;
    int32_t res = self->process(self, invalidMsg, &out, &state);
    FreeJson(invalidMsg);
    if (res != HC_SUCCESS) {
        return;
    }
    if (out != nullptr) {
        return;
    }
    self->destroy(self);
}

void AuthCodeImportTest120()
{
    BaseCmd *self = CreateAuthCodeImportCmd((void *)&g_paramsS, false, ABORT_IF_ERROR);
    if (self == nullptr) {
        return;
    }
    CJson *invalidMsg = CreateJsonFromString(INVALID_MSG3);
    if (invalidMsg == nullptr) {
        return;
    }
    CJson *out = nullptr;
    CmdState state;
    int32_t res = self->process(self, invalidMsg, &out, &state);
    FreeJson(invalidMsg);
    if (res != HC_SUCCESS) {
        return;
    }
    if (out != nullptr) {
        return;
    }
    self->destroy(self);
}

bool FuzzDoCallback(const uint8_t* data, size_t size)
{
    (void)data;
    (void)size;
    SetUpTestCase();
    (void)AuthCodeImportTest001();
    (void)AuthCodeImportTest002();
    (void)AuthCodeImportTest101();
    (void)AuthCodeImportTest102();
    (void)AuthCodeImportTest103();
    (void)AuthCodeImportTest104();
    (void)AuthCodeImportTest105();
    (void)AuthCodeImportTest106();
    (void)AuthCodeImportTest107();
    (void)AuthCodeImportTest108();
    (void)AuthCodeImportTest109();
    (void)AuthCodeImportTest110();
    (void)AuthCodeImportTest111();
    (void)AuthCodeImportTest112();
    (void)AuthCodeImportTest113();
    (void)AuthCodeImportTest114();
    (void)AuthCodeImportTest115();
    (void)AuthCodeImportTest116();
    (void)AuthCodeImportTest117();
    (void)AuthCodeImportTest118();
    (void)AuthCodeImportTest119();
    (void)AuthCodeImportTest120();
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

