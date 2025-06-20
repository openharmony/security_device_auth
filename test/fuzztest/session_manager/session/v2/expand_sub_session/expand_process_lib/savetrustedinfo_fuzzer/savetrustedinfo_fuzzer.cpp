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

#include "savetrustedinfo_fuzzer.h"

#include "device_auth_defines.h"
#include "common_defs.h"
#include "group_data_manager.h"
#include "device_auth.h"
#include "hc_types.h"
#include "hc_dev_info.h"
#include "hks_api.h"
#include "hks_param.h"
#include "hks_type.h"
#include "json_utils.h"
#include "save_trusted_info.h"
#include "uint8buff_utils.h"
#include "base/security/device_auth/services/session_manager/src/session/v2/expand_sub_session/expand_process_lib/save_trusted_info.c"

namespace OHOS {
static const char *AUTH_ID_C = "5420459D93FE773F9945FD64277FBA2CAB8FB996DDC1D0B97676FBB1242B3930";
static const char *AUTH_ID_S = "52E2706717D5C39D736E134CC1E3BE1BAA2AA52DB7C76A37C749558BD2E6492C";
static const char *GROUP_ID = "E2EE6F830B176B2C96A9F99BFAE2A61F5D1490B9F4A090E9D8C2874C230C7C21";
static const char *USER_ID_C = "9F207900038F91FEF95DD042FE2874E44269DC28B639681698809A67EDAD08E3";
static const char *USER_ID_S = "9F207900038F91FEF95DD042FE2874E44269DC28B639681698809A67EDAD08E3";
static const char *UDID = "9F207900038F91FEF95DD042FE2874E44269DC28B639681698809A67EDAD08E3";
static const char *GROUP_NAME = "testGroup";
static const char *GROUP_OWNER = "testApp";

#define TEST_OS_ACCOUNT_ID1 0
#define TEST_OS_ACCOUNT_ID2 100
#define TEST_USER_TYPE 0

static SaveTrustedInfoParams g_paramsC = { TEST_OS_ACCOUNT_ID1, ASYMMETRIC_CRED, DEVICE_TYPE_ACCESSORY,
    GROUP_VISIBILITY_PUBLIC, GROUP_OWNER, GROUP_ID, AUTH_ID_C, false };
static SaveTrustedInfoParams g_paramsS = { TEST_OS_ACCOUNT_ID2, ASYMMETRIC_CRED, DEVICE_TYPE_ACCESSORY,
    GROUP_VISIBILITY_PUBLIC, GROUP_OWNER, GROUP_ID, AUTH_ID_S, false };

static const char *INVALID_MSG1 = "{\"errCode\": 1}";
static const char *INVALID_MSG2 = "{\"event\": -1, \"errCode\": 1}";
static const char *INVALID_MSG3 = "{\"event\": 10, \"errCode\": 1}";
static const char *ERROR_MSG1 = "{\"event\": 3, \"errCode\": 1}";
static const char *ERROR_MSG2 = "{\"event\": 3}";

static const int TEST_DEV_AUTH_BUFFER_SIZE = 128;

typedef struct {
    int32_t osAccountId;
    int32_t credType;
    int32_t userTypeSelf;
    int32_t visibility;
    const char *groupId;
    const char *groupName;
    const char *appId;
    const char *authIdSelf;
    const char *udidSelf;
    const char *userIdSelf;
} CreateParams;

static void RemoveDir(const char *path)
{
    char strBuf[TEST_DEV_AUTH_BUFFER_SIZE] = {0};
    if (path == nullptr) {
        return;
    }
    if (sprintf_s(strBuf, sizeof(strBuf) - 1, "rm -rf %s", path) < 0) {
        return;
    }
    system(strBuf);
    return;
}

static void DeleteDatabase()
{
    const char *groupPath = GetStorageDirPath();
    RemoveDir(groupPath);
    return;
}

static int32_t GenerateGroupParams(const CreateParams *params, TrustedGroupEntry *groupParams)
{
    if (!StringSetPointer(&groupParams->name, params->groupName)) {
        return HC_ERR_MEMORY_COPY;
    }
    if (!StringSetPointer(&groupParams->id, params->groupId)) {
        return HC_ERR_MEMORY_COPY;
    }
    HcString ownerName = CreateString();
    if (!StringSetPointer(&ownerName, params->appId)) {
        DeleteString(&ownerName);
        return HC_ERR_MEMORY_COPY;
    }
    if (groupParams->managers.pushBackT(&groupParams->managers, ownerName) == NULL) {
        DeleteString(&ownerName);
        return HC_ERR_MEMORY_COPY;
    }
    groupParams->visibility = params->visibility;
    groupParams->type = PEER_TO_PEER_GROUP;
    groupParams->expireTime = DEFAULT_EXPIRE_TIME;
    return HC_SUCCESS;
}

static int32_t GenerateSelfDevParams(const CreateParams *params, TrustedDeviceEntry *devParams)
{
    if (!StringSetPointer(&devParams->udid, params->udidSelf)) {
        return HC_ERR_MEMORY_COPY;
    }
    if (!StringSetPointer(&devParams->authId, params->authIdSelf)) {
        return HC_ERR_MEMORY_COPY;
    }
    if (!StringSetPointer(&devParams->groupId, params->groupId)) {
        return HC_ERR_MEMORY_COPY;
    }
    if (!StringSetPointer(&devParams->serviceType, params->groupId)) {
        return HC_ERR_MEMORY_COPY;
    }
    devParams->devType = params->userTypeSelf;
    devParams->source = SELF_CREATED;
    devParams->credential = params->credType;
    return HC_SUCCESS;
}

static int32_t AddTrustedGroup(const CreateParams *params)
{
    TrustedGroupEntry *groupParams = CreateGroupEntry();
    if (groupParams == NULL) {
        return HC_ERR_ALLOC_MEMORY;
    }
    int32_t res = GenerateGroupParams(params, groupParams);
    if (res != HC_SUCCESS) {
        DestroyGroupEntry(groupParams);
        return res;
    }
    res = AddGroup(params->osAccountId, groupParams);
    DestroyGroupEntry(groupParams);
    return res;
}

static int32_t AddSelfTrustedDevice(const CreateParams *params)
{
    TrustedDeviceEntry *devParams = CreateDeviceEntry();
    if (devParams == NULL) {
        return HC_ERR_ALLOC_MEMORY;
    }
    int32_t res = GenerateSelfDevParams(params, devParams);
    if (res != HC_SUCCESS) {
        DestroyDeviceEntry(devParams);
        return res;
    }
    res = AddTrustedDevice(params->osAccountId, devParams);
    DestroyDeviceEntry(devParams);
    return res;
}

static int32_t CreatePeerToPeerGroup(const CreateParams *params)
{
    int32_t res = AddTrustedGroup(params);
    if (res != HC_SUCCESS) {
        return res;
    }
    return AddSelfTrustedDevice(params);
}

static void SaveTrustedInfoTest00(void)
{
    BaseCmd *self = CreateSaveTrustedInfoCmd((void *)&g_paramsC, true, ABORT_IF_ERROR);
    self->destroy(self);
}

static void SaveTrustedInfoTest03(void)
{
    (void)CreateSaveTrustedInfoCmd(nullptr, true, ABORT_IF_ERROR);
}

static void SaveTrustedInfoTest04(void)
{
    SaveTrustedInfoParams errorParams = { 0, ASYMMETRIC_CRED, DEVICE_TYPE_ACCESSORY, GROUP_VISIBILITY_PUBLIC,
        nullptr, GROUP_ID, AUTH_ID_C, false };
    (void)CreateSaveTrustedInfoCmd((void *)(&errorParams), true, ABORT_IF_ERROR);
}

static void SaveTrustedInfoTest05(void)
{
    SaveTrustedInfoParams errorParams = { 0, ASYMMETRIC_CRED, DEVICE_TYPE_ACCESSORY, GROUP_VISIBILITY_PUBLIC,
        GROUP_OWNER, nullptr, AUTH_ID_C, false };
    (void)CreateSaveTrustedInfoCmd((void *)(&errorParams), true, ABORT_IF_ERROR);
}

static void SaveTrustedInfoTest06(void)
{
    SaveTrustedInfoParams errorParams = { 0, ASYMMETRIC_CRED, DEVICE_TYPE_ACCESSORY, GROUP_VISIBILITY_PUBLIC,
        GROUP_OWNER, GROUP_ID, nullptr, false };
    (void)CreateSaveTrustedInfoCmd((void *)(&errorParams), true, ABORT_IF_ERROR);
}

static void SaveTrustedInfoTest07(void)
{
    BaseCmd *self = CreateSaveTrustedInfoCmd((void *)&g_paramsC, true, ABORT_IF_ERROR);
    self->destroy(nullptr);
    self->destroy(self);
}

static void SaveTrustedInfoTest08(void)
{
    BaseCmd *self = CreateSaveTrustedInfoCmd((void *)&g_paramsC, true, ABORT_IF_ERROR);

    CJson *out = nullptr;
    (void)self->start(nullptr, &out);
    self->destroy(self);
}

static void SaveTrustedInfoTest09(void)
{
    BaseCmd *self = CreateSaveTrustedInfoCmd((void *)&g_paramsC, true, ABORT_IF_ERROR);
    (void)self->start(self, nullptr);
    self->destroy(self);
}

static void SaveTrustedInfoTest10(void)
{
    DeleteDatabase();
    int32_t res = InitDatabase();
    CreateParams params = { TEST_OS_ACCOUNT_ID2, SYMMETRIC_CRED, DEVICE_TYPE_ACCESSORY, GROUP_VISIBILITY_PUBLIC,
        GROUP_ID, GROUP_NAME, GROUP_OWNER, AUTH_ID_S, AUTH_ID_S, USER_ID_S };
    res = CreatePeerToPeerGroup(&params);

    BaseCmd *self = CreateSaveTrustedInfoCmd((void *)&g_paramsC, true, ABORT_IF_ERROR);

    CJson *out = nullptr;
    res = self->start(self, &out);
    FreeJson(out);
    out = nullptr;
    res = self->start(self, &out);
    self->destroy(self);
    DestroyDatabase();
}

static void SaveTrustedInfoTest11(void)
{
    BaseCmd *self = CreateSaveTrustedInfoCmd((void *)&g_paramsC, true, ABORT_IF_ERROR);

    CJson in;
    CJson *out = nullptr;
    CmdState state;
    (void)self->process(nullptr, &in, &out, &state);
    self->destroy(self);
}

static void SaveTrustedInfoTest12(void)
{
    BaseCmd *self = CreateSaveTrustedInfoCmd((void *)&g_paramsC, true, ABORT_IF_ERROR);
    CJson *out = nullptr;
    CmdState state;
    (void)self->process(self, nullptr, &out, &state);
    self->destroy(self);
}

static void SaveTrustedInfoTest13(void)
{
    BaseCmd *self = CreateSaveTrustedInfoCmd((void *)&g_paramsC, true, ABORT_IF_ERROR);

    CJson in;
    CmdState state;
    (void)self->process(self, &in, nullptr, &state);
    self->destroy(self);
}

static void SaveTrustedInfoTest14(void)
{
    BaseCmd *self = CreateSaveTrustedInfoCmd((void *)&g_paramsC, true, ABORT_IF_ERROR);
    CJson in;
    CJson *out = nullptr;
    (void)self->process(self, &in, &out, nullptr);
    self->destroy(self);
}

static void SaveTrustedInfoTest15(void)
{
    BaseCmd *self = CreateSaveTrustedInfoCmd((void *)&g_paramsC, true, ABORT_IF_ERROR);

    self->curState = self->finishState;
    CJson in;
    CJson *out = nullptr;
    CmdState state;
    (void)self->process(self, &in, &out, &state);
    self->destroy(self);
}

static void SaveTrustedInfoTest16(void)
{
    BaseCmd *self = CreateSaveTrustedInfoCmd((void *)&g_paramsC, true, ABORT_IF_ERROR);

    self->curState = self->failState;
    CJson in;
    CJson *out = nullptr;
    CmdState state;
    (void)self->process(self, &in, &out, &state);
    self->destroy(self);
}

static void SaveTrustedInfoTest17(void)
{
    BaseCmd *self = CreateSaveTrustedInfoCmd((void *)&g_paramsS, false, ABORT_IF_ERROR);

    CJson *failEvent = CreateJsonFromString(ERROR_MSG1);
    CJson *out = nullptr;
    CmdState state;
    (void)self->process(self, failEvent, &out, &state);
    FreeJson(failEvent);
    self->destroy(self);
}

static void SaveTrustedInfoTest18(void)
{
    BaseCmd *self = CreateSaveTrustedInfoCmd((void *)&g_paramsS, false, ABORT_IF_ERROR);

    CJson *failEvent = CreateJsonFromString(ERROR_MSG2);
    CJson *out = nullptr;
    CmdState state;
    (void)self->process(self, failEvent, &out, &state);
    FreeJson(failEvent);
    self->destroy(self);
}

static void SaveTrustedInfoTest19(void)
{
    BaseCmd *self = CreateSaveTrustedInfoCmd((void *)&g_paramsS, false, ABORT_IF_ERROR);
    CJson *invalidMsg = CreateJsonFromString(INVALID_MSG1);
    CJson *out = nullptr;
    CmdState state;
    (void)self->process(self, invalidMsg, &out, &state);
    FreeJson(invalidMsg);
    self->destroy(self);
}

static void SaveTrustedInfoTest20(void)
{
    BaseCmd *self = CreateSaveTrustedInfoCmd((void *)&g_paramsS, false, ABORT_IF_ERROR);
    CJson *invalidMsg = CreateJsonFromString(INVALID_MSG2);
    CJson *out = nullptr;
    CmdState state;
    (void)self->process(self, invalidMsg, &out, &state);
    FreeJson(invalidMsg);

    self->destroy(self);
}

static void SaveTrustedInfoTest21(void)
{
    BaseCmd *self = CreateSaveTrustedInfoCmd((void *)&g_paramsS, false, ABORT_IF_ERROR);
    CJson *invalidMsg = CreateJsonFromString(INVALID_MSG3);
    CJson *out = nullptr;
    CmdState state;
    (void)self->process(self, invalidMsg, &out, &state);
    FreeJson(invalidMsg);
    self->destroy(self);
}

static void SaveTrustedInfoTest22(void)
{
    CmdParams params = {
        .osAccountId = TEST_OS_ACCOUNT_ID1,
        .groupId = nullptr
    };
    (void)ServerSendTrustedInfoParseEvent(nullptr, &params);

    CJson *json = CreateJson();
    (void)AddStringToJson(json, FIELD_AUTH_ID_CLIENT, AUTH_ID_C);
    (void)ServerSendTrustedInfoParseEvent(json, &params);

    (void)AddStringToJson(json, FIELD_UDID_CLIENT, UDID);
    (void)ServerSendTrustedInfoParseEvent(json, &params);

    (void)AddIntToJson(json, FIELD_USER_TYPE_CLIENT, TEST_USER_TYPE);
    (void)ServerSendTrustedInfoParseEvent(json, &params);

    (void)AddStringToJson(json, FIELD_GROUP_NAME, GROUP_NAME);
    (void)ServerSendTrustedInfoParseEvent(json, &params);

    (void)AddStringToJson(json, FIELD_USER_ID_CLIENT, USER_ID_C);
    (void)ServerSendTrustedInfoParseEvent(json, &params);
    FreeJson(json);
}

bool FuzzDoCallback(const uint8_t* data, size_t size)
{
    (void)data;
    (void)size;
    (void)SaveTrustedInfoTest00();
    (void)SaveTrustedInfoTest03();
    (void)SaveTrustedInfoTest04();
    (void)SaveTrustedInfoTest05();
    (void)SaveTrustedInfoTest06();
    (void)SaveTrustedInfoTest07();
    (void)SaveTrustedInfoTest08();
    (void)SaveTrustedInfoTest09();
    (void)SaveTrustedInfoTest10();
    (void)SaveTrustedInfoTest11();
    (void)SaveTrustedInfoTest12();
    (void)SaveTrustedInfoTest13();
    (void)SaveTrustedInfoTest14();
    (void)SaveTrustedInfoTest15();
    (void)SaveTrustedInfoTest16();
    (void)SaveTrustedInfoTest17();
    (void)SaveTrustedInfoTest18();
    (void)SaveTrustedInfoTest19();
    (void)SaveTrustedInfoTest20();
    (void)SaveTrustedInfoTest21();
    (void)SaveTrustedInfoTest22();
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

