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

#include "account_module_defines.h"
#include "alg_loader.h"
#include "common_defs.h"
#include "device_auth.h"
#include "device_auth_defines.h"
#include "json_utils.h"
#include "securec.h"
#include "base_group_auth.h"
#include "json_utils.h"
#include "hc_string.h"
#include "group_auth_data_operation.h"
#include "account_related_group_auth.h"
#include "data_manager.h"

namespace OHOS {
#define NUM_TWO 2

void SetUp()
{
    (void)InitDeviceAuthService();
}

void TearDown()
{
    DestroyDeviceAuthService();
}

void AccountRelatedGroupAuthTest001()
{
    AccountRelatedGroupAuth *groupAuth = (AccountRelatedGroupAuth *)GetAccountRelatedGroupAuth();
    CJson *param = CreateJson();
    if (param == nullptr) {
        return;
    }
    QueryGroupParams queryParams;
    GroupEntryVec vec = CreateGroupEntryVec();
    (void)groupAuth->getAccountCandidateGroup(0, param, &queryParams, &vec); // For unit test.

    AddStringToJson(param, FIELD_USER_ID, "unit_test"); // For unit test.
    (void)groupAuth->getAccountCandidateGroup(0, param, &queryParams, &vec); // For unit test.
    FreeJson(param);

    ClearGroupEntryVec(&vec);
    // Identical group branch can not be dealed.
}

static bool OnTransmitTrue(int64_t requestId, const uint8_t *data, uint32_t dataLen)
{
    (void)requestId;
    (void)data;
    (void)dataLen;
    return true;
}

static bool OnTransmitFalse(int64_t requestId, const uint8_t *data, uint32_t dataLen)
{
    (void)requestId;
    (void)data;
    (void)dataLen;
    return false;
}

static void OnSessionKeyReturned(int64_t requestId, const uint8_t *sessionKey, uint32_t sessionKeyLen)
{
    (void)requestId;
    (void)sessionKey;
    (void)sessionKeyLen;
}

static void OnFinish(int64_t requestId, int operationCode, const char *returnData)
{
    (void)requestId;
    (void)operationCode;
    (void)returnData;
}

static void OnError(int64_t requestId, int operationCode, int errorCode, const char *errorReturn)
{
    (void)requestId;
    (void)operationCode;
    (void)errorCode;
    (void)errorReturn;
}

static char *OnRequest(int64_t requestId, int operationCode, const char *reqParams)
{
    (void)requestId;
    (void)operationCode;
    (void)reqParams;
    return nullptr;
}

static DeviceAuthCallback g_deviceAuthCallBack = {
    .onTransmit = OnTransmitTrue,
    .onSessionKeyReturned = OnSessionKeyReturned,
    .onFinish = OnFinish,
    .onError = OnError,
    .onRequest = OnRequest
};

void AccountRelatedGroupAuthTest002()
{
    CJson *authParam = CreateJson();
    if (authParam == nullptr) {
        return;
    }
    CJson *out = CreateJson();
    if (out == nullptr) {
        FreeJson(authParam);
        return;
    }
    (void)GetAccountRelatedGroupAuth()->onFinish(0, authParam, out, nullptr); // For unit test.

    CJson *sendToPeer = CreateJson();
    if (out == nullptr) {
        FreeJson(authParam);
        FreeJson(out);
        return;
    }
    (void)AddObjToJson(out, FIELD_SEND_TO_PEER, sendToPeer);
    (void)GetAccountRelatedGroupAuth()->onFinish(0, authParam, out, nullptr); // For unit test.

    (void)AddStringToJson(sendToPeer, "test_key", "test_value"); // For unit test.
    (void)AddObjToJson(out, FIELD_SEND_TO_PEER, sendToPeer);
    (void)GetAccountRelatedGroupAuth()->onFinish(0, authParam, out, nullptr); // For unit test.

    (void)GetAccountRelatedGroupAuth()->onFinish(0, authParam, out, &g_deviceAuthCallBack); // For unit test.
    FreeJson(sendToPeer);
    FreeJson(out);
    FreeJson(authParam);
}

void AccountRelatedGroupAuthTest0021()
{
    CJson *authParam = CreateJson();
    if (authParam == nullptr) {
        return;
    }
    CJson *out = CreateJson();
    if (out == nullptr) {
        FreeJson(authParam);
        return;
    }
    CJson *sendToPeer = CreateJson();
    if (sendToPeer == nullptr) {
        FreeJson(authParam);
        FreeJson(out);
        return;
    }
    (void)GetAccountRelatedGroupAuth()->onFinish(0, authParam, out, nullptr); // For unit test.

    (void)AddObjToJson(out, FIELD_SEND_TO_PEER, sendToPeer);
    (void)GetAccountRelatedGroupAuth()->onFinish(0, authParam, out, nullptr); // For unit test.

    (void)AddStringToJson(sendToPeer, "test_key", "test_value"); // For unit test.
    (void)AddObjToJson(out, FIELD_SEND_TO_PEER, sendToPeer);
    (void)GetAccountRelatedGroupAuth()->onFinish(0, authParam, out, nullptr); // For unit test.

    (void)GetAccountRelatedGroupAuth()->onFinish(0, authParam, out, &g_deviceAuthCallBack); // For unit test.

    g_deviceAuthCallBack.onTransmit = OnTransmitFalse;
    (void)GetAccountRelatedGroupAuth()->onFinish(0, authParam, out, &g_deviceAuthCallBack); // For unit test.
    FreeJson(sendToPeer);
    FreeJson(out);
    FreeJson(authParam);
}

// OnAccountFinish -> ReturnSessionKey success branch.
void AccountRelatedGroupAuthTest0022()
{
    CJson *authParam = CreateJson();
    if (authParam == nullptr) {
        return;
    }
    CJson *out = CreateJson();
    if (out == nullptr) {
        FreeJson(authParam);
        return;
    }
    CJson *sendToPeer = CreateJson();
    if (sendToPeer == nullptr) {
        FreeJson(authParam);
        FreeJson(out);
        return;
    }

    (void)AddObjToJson(out, FIELD_SEND_TO_PEER, sendToPeer);
    (void)AddStringToJson(sendToPeer, "test_key", "test_value"); // For unit test.
    (void)AddObjToJson(out, FIELD_SEND_TO_PEER, sendToPeer);

    (void)AddIntToJson(authParam, FIELD_KEY_LENGTH, NUM_TWO); // For unit test.
    uint8_t sessionKeyTest[2] = { 0x31, 0x32 }; // For unit test.
    (void)AddByteToJson(out, FIELD_SESSION_KEY, sessionKeyTest, sizeof(sessionKeyTest));
    (void)GetAccountRelatedGroupAuth()->onFinish(0, authParam, out, &g_deviceAuthCallBack); // For unit test.
    FreeJson(sendToPeer);
    FreeJson(out);
    FreeJson(authParam);
}

// OnAccountFinish -> AddTrustedDeviceForAccount success failed.
void AccountRelatedGroupAuthTest0023()
{
    CJson *authParam = CreateJson();
    CJson *out = CreateJson();
    CJson *sendToPeer = CreateJson();

    (void)AddObjToJson(out, FIELD_SEND_TO_PEER, sendToPeer);
    (void)AddStringToJson(sendToPeer, "test_key", "test_value"); // For unit test.
    (void)AddObjToJson(out, FIELD_SEND_TO_PEER, sendToPeer);

    (void)AddIntToJson(authParam, FIELD_KEY_LENGTH, NUM_TWO); // For unit test.
    uint8_t sessionKeyTest[2] = { 0x31, 0x32 }; // For unit test.
    (void)AddByteToJson(out, FIELD_SESSION_KEY, sessionKeyTest, sizeof(sessionKeyTest));

    (void)AddIntToJson(authParam, FIELD_OS_ACCOUNT_ID, 0);
    (void)GetAccountRelatedGroupAuth()->onFinish(0, authParam, out, &g_deviceAuthCallBack); // For unit test.

    (void)AddStringToJson(authParam, FIELD_PEER_CONN_DEVICE_ID, "CONN_DEVICE_ID"); // For unit test.
    (void)GetAccountRelatedGroupAuth()->onFinish(0, authParam, out, &g_deviceAuthCallBack); // For unit test.

    (void)AddStringToJson(authParam, FIELD_GROUP_ID, "GROUP_ID"); // For unit test.
    (void)GetAccountRelatedGroupAuth()->onFinish(0, authParam, out, &g_deviceAuthCallBack); // For unit test.

    CJson *sendToSelf = CreateJson();

    (void)AddObjToJson(out, FIELD_SEND_TO_SELF, sendToSelf);
    (void)GetAccountRelatedGroupAuth()->onFinish(0, authParam, out, &g_deviceAuthCallBack); // For unit test.

    (void)AddIntToJson(sendToSelf, FIELD_CREDENTIAL_TYPE, NUM_TWO);
    (void)AddObjToJson(out, FIELD_SEND_TO_SELF, sendToSelf);
    (void)GetAccountRelatedGroupAuth()->onFinish(0, authParam, out, &g_deviceAuthCallBack); // For unit test.
    
    (void)AddStringToJson(sendToSelf, FIELD_DEV_ID, "DEV_ID"); // For unit test.
    (void)AddObjToJson(out, FIELD_SEND_TO_SELF, sendToSelf);
    (void)GetAccountRelatedGroupAuth()->onFinish(0, authParam, out, &g_deviceAuthCallBack); // For unit test.

    (void)AddStringToJson(sendToSelf, FIELD_USER_ID, "USER_ID"); // For unit test.
    (void)AddObjToJson(out, FIELD_SEND_TO_SELF, sendToSelf);
    (void)GetAccountRelatedGroupAuth()->onFinish(0, authParam, out, &g_deviceAuthCallBack); // For unit test.

    FreeJson(sendToSelf);
    FreeJson(out);
    FreeJson(sendToPeer);
    FreeJson(authParam);
}

void AccountRelatedGroupAuthTest004()
{
    TrustedGroupEntry *entry = CreateGroupEntry();
    if (entry == nullptr) {
        return;
    }
    TrustedDeviceEntry *localAuthInfo = CreateDeviceEntry();
    if (localAuthInfo == nullptr) {
        DestroyGroupEntry(entry);
        return;
    }
    CJson *paramsData = CreateJson();
    if (paramsData == nullptr) {
        DestroyGroupEntry(entry);
        DestroyDeviceEntry(localAuthInfo);
        return;
    }

    (void)GetAccountRelatedGroupAuth()->fillDeviceAuthInfo(0, entry, localAuthInfo, paramsData); // For unit test.

    FreeJson(paramsData);
    DestroyGroupEntry(entry);
    DestroyDeviceEntry(localAuthInfo);
}

void AccountRelatedGroupAuthTest0041()
{
    TrustedGroupEntry *entry = CreateGroupEntry();
    if (entry == nullptr) {
        return;
    }
    TrustedDeviceEntry *localAuthInfo = CreateDeviceEntry();
    if (localAuthInfo == nullptr) {
        DestroyGroupEntry(entry);
        return;
    }
    CJson *paramsData = CreateJson();
    if (paramsData == nullptr) {
        DestroyGroupEntry(entry);
        DestroyDeviceEntry(localAuthInfo);
        return;
    }

    (void)AddStringToJson(paramsData, FIELD_PEER_CONN_DEVICE_ID, "CONN_DEVICE_ID"); // For unit test.
    (void)GetAccountRelatedGroupAuth()->fillDeviceAuthInfo(0, entry,
        localAuthInfo, paramsData); // For unit test.

    FreeJson(paramsData);
    DestroyGroupEntry(entry);
    DestroyDeviceEntry(localAuthInfo);
}

void AccountRelatedGroupAuthTest0042()
{
    TrustedGroupEntry *entry = CreateGroupEntry();
    if (entry == nullptr) {
        return;
    }
    TrustedDeviceEntry *localAuthInfo = CreateDeviceEntry();
    if (localAuthInfo == nullptr) {
        DestroyGroupEntry(entry);
        return;
    }
    CJson *paramsData = CreateJson();
    if (paramsData == nullptr) {
        DestroyGroupEntry(entry);
        DestroyDeviceEntry(localAuthInfo);
        return;
    }
    (void)AddStringToJson(paramsData, FIELD_PEER_CONN_DEVICE_ID, "CONN_DEVICE_ID"); // For unit test.

    entry->userId = CreateString();
    (void)StringSetPointer(&entry->userId, "selfUserId"); // For unit test.
    (void)GetAccountRelatedGroupAuth()->fillDeviceAuthInfo(0, entry,
        localAuthInfo, paramsData); // For unit test.

    FreeJson(paramsData);
    DestroyGroupEntry(entry);
    DestroyDeviceEntry(localAuthInfo);
}

void AccountRelatedGroupAuthTest0043()
{
    TrustedGroupEntry *entry = CreateGroupEntry();
    if (entry == nullptr) {
        return;
    }
    TrustedDeviceEntry *localAuthInfo = CreateDeviceEntry();
    if (localAuthInfo == nullptr) {
        DestroyGroupEntry(entry);
        return;
    }
    CJson *paramsData = CreateJson();
    if (paramsData == nullptr) {
        DestroyGroupEntry(entry);
        DestroyDeviceEntry(localAuthInfo);
        return;
    }
    (void)AddStringToJson(paramsData, FIELD_PEER_CONN_DEVICE_ID, "CONN_DEVICE_ID"); // For unit test.
    entry->userId = CreateString();
    (void)StringSetPointer(&entry->userId, "selfUserId"); // For unit test.

    entry->id = CreateString();
    (void)StringSetPointer(&entry->id, "groupId"); // For unit test.
    (void)GetAccountRelatedGroupAuth()->fillDeviceAuthInfo(0, entry,
        localAuthInfo, paramsData); // For unit test.

    FreeJson(paramsData);
    DestroyGroupEntry(entry);
    DestroyDeviceEntry(localAuthInfo);
}

void AccountRelatedGroupAuthTest00431()
{
    TrustedGroupEntry *entry = CreateGroupEntry();
    if (entry == nullptr) {
        return;
    }
    TrustedDeviceEntry *localAuthInfo = CreateDeviceEntry();
    if (localAuthInfo == nullptr) {
        DestroyGroupEntry(entry);
        return;
    }
    CJson *paramsData = CreateJson();
    if (paramsData == nullptr) {
        DestroyGroupEntry(entry);
        DestroyDeviceEntry(localAuthInfo);
        return;
    }
    (void)AddStringToJson(paramsData, FIELD_PEER_CONN_DEVICE_ID, "CONN_DEVICE_ID"); // For unit test.
    entry->userId = CreateString();
    (void)StringSetPointer(&entry->userId, "selfUserId"); // For unit test.

    entry->id = CreateString();
    (void)StringSetPointer(&entry->id, "groupId"); // For unit test.

    localAuthInfo->udid = CreateString();
    (void)StringSetPointer(&localAuthInfo->udid, "selfDeviceId"); // For unit test.
    (void)GetAccountRelatedGroupAuth()->fillDeviceAuthInfo(0, entry,
        localAuthInfo, paramsData); // For unit test.

    FreeJson(paramsData);
    DestroyGroupEntry(entry);
    DestroyDeviceEntry(localAuthInfo);
}

void AccountRelatedGroupAuthTest0044()
{
    TrustedGroupEntry *entry = CreateGroupEntry();
    if (entry == nullptr) {
        return;
    }
    TrustedDeviceEntry *localAuthInfo = CreateDeviceEntry();
    if (localAuthInfo == nullptr) {
        DestroyGroupEntry(entry);
        return;
    }
    CJson *paramsData = CreateJson();
    if (paramsData == nullptr) {
        DestroyGroupEntry(entry);
        DestroyDeviceEntry(localAuthInfo);
        return;
    }
    entry->userId = CreateString();
    (void)StringSetPointer(&entry->userId, "selfUserId");
    entry->id = CreateString();
    (void)StringSetPointer(&entry->id, "groupId");

    localAuthInfo->udid = CreateString();
    (void)StringSetPointer(&localAuthInfo->udid, "selfDeviceId");
    localAuthInfo->udid = CreateString();
    (void)StringSetPointer(&localAuthInfo->udid, "selfDevId");

    (void)AddStringToJson(paramsData, FIELD_PEER_CONN_DEVICE_ID, "CONN_DEVICE_ID");
    (void)GetAccountRelatedGroupAuth()->fillDeviceAuthInfo(0, entry,
        localAuthInfo, paramsData); // For unit test.

    FreeJson(paramsData);
    DestroyGroupEntry(entry);
    DestroyDeviceEntry(localAuthInfo);
}

void AccountRelatedGroupAuthTest007()
{
    CJson *confirmationJson = CreateJson();
    if (confirmationJson == nullptr) {
        return;
    }
    CJson *dataFromClient = CreateJson();
    if (dataFromClient == nullptr) {
        FreeJson(confirmationJson);
        return;
    }
    (void)GetAccountRelatedGroupAuth()->combineServerConfirmParams(confirmationJson, dataFromClient);
    FreeJson(confirmationJson);
    FreeJson(dataFromClient);
}

void AccountRelatedGroupAuthTest0071()
{
    CJson *confirmationJson = CreateJson();
    if (confirmationJson == nullptr) {
        return;
    }
    CJson *dataFromClient = CreateJson();
    if (dataFromClient == nullptr) {
        FreeJson(confirmationJson);
        return;
    }

    (void)AddStringToJson(confirmationJson, FIELD_PEER_CONN_DEVICE_ID, "CONN_DEVICE_ID"); // For unit test.
    (void)GetAccountRelatedGroupAuth()->combineServerConfirmParams(confirmationJson, dataFromClient);
    FreeJson(confirmationJson);
    FreeJson(dataFromClient);
}
// Ending for account_related_group_auth.c test.

bool FuzzDoRegCallback(const uint8_t* data, size_t size)
{
    (void)data;
    (void)size;
    SetUp();
    AccountRelatedGroupAuthTest001();
    AccountRelatedGroupAuthTest002();
    AccountRelatedGroupAuthTest0021();
    AccountRelatedGroupAuthTest0022();
    AccountRelatedGroupAuthTest0023();
    AccountRelatedGroupAuthTest004();
    AccountRelatedGroupAuthTest0041();
    AccountRelatedGroupAuthTest0042();
    AccountRelatedGroupAuthTest0043();
    AccountRelatedGroupAuthTest00431();
    AccountRelatedGroupAuthTest0044();
    AccountRelatedGroupAuthTest007();
    AccountRelatedGroupAuthTest0071();

    TearDown();
    return true;
}

}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    OHOS::FuzzDoRegCallback(data, size);
    return 0;
}

