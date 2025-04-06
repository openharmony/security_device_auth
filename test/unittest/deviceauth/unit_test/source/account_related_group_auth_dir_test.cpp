/*
 * Copyright (C) 2023 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "account_related_group_auth_dir_test.h"
#include <cinttypes>
#include <unistd.h>
#include <gtest/gtest.h>
#include "../../../../../services/legacy/group_auth/src/group_auth_manager/account_related_group_auth/account_related_group_auth.c"
using namespace std;
using namespace testing::ext;

namespace {
// Beginning for account_related_group_auth.c test.
#define TEST_OS_ACCOUNT_ID 0
#define TEST_USER_ID "UserId"
#define TEST_AUTH_FORM (-1)
#define TEST_EXT_DATA "testExtData"
#define TEST_DEVICE_ID "testDeviceId"
#define TEST_GROUP_ID "testGroupId"
#define TEST_REQUEST_ID 123

class AccountRelatedGroupAuthTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void AccountRelatedGroupAuthTest::SetUpTestCase() {}

void AccountRelatedGroupAuthTest::TearDownTestCase() {}

void AccountRelatedGroupAuthTest::SetUp()
{
    int ret = InitDeviceAuthService();
    EXPECT_EQ(ret, HC_SUCCESS);
}

void AccountRelatedGroupAuthTest::TearDown()
{
    DestroyDeviceAuthService();
}

HWTEST_F(AccountRelatedGroupAuthTest, AccountRelatedGroupAuthTest001, TestSize.Level0)
{
    AccountRelatedGroupAuth *groupAuth = (AccountRelatedGroupAuth *)GetAccountRelatedGroupAuth();
    ASSERT_NE(groupAuth, nullptr);
    CJson *param = CreateJson();
    ASSERT_NE(param, nullptr);
    QueryGroupParams queryParams;
    GroupEntryVec vec = CreateGroupEntryVec();
    (void)groupAuth->getAccountCandidateGroup(0, param, &queryParams, &vec); // For unit test.

    int32_t ret = AddStringToJson(param, FIELD_USER_ID, "unit_test"); // For unit test.
    EXPECT_EQ(ret, HC_SUCCESS);
    (void)groupAuth->getAccountCandidateGroup(0, param, &queryParams, &vec); // For unit test.
    EXPECT_EQ(ret, HC_SUCCESS);
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

HWTEST_F(AccountRelatedGroupAuthTest, AccountRelatedGroupAuthTest002, TestSize.Level0)
{
    CJson *authParam = CreateJson();
    ASSERT_NE(authParam, nullptr);
    CJson *out = CreateJson();
    if (out == nullptr) {
        FreeJson(authParam);
        return;
    }
    int32_t ret = HC_ERROR;
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
    ret = AddObjToJson(out, FIELD_SEND_TO_PEER, sendToPeer);
    FreeJson(sendToPeer);
    FreeJson(out);
    FreeJson(authParam);
    EXPECT_EQ(ret, HC_SUCCESS);
}

HWTEST_F(AccountRelatedGroupAuthTest, AccountRelatedGroupAuthTest0021, TestSize.Level0)
{
    int32_t ret = HC_ERROR;
    CJson *authParam = CreateJson();
    ASSERT_NE(authParam, nullptr);
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
    ret = AddObjToJson(out, FIELD_SEND_TO_PEER, sendToPeer);
    EXPECT_EQ(ret, HC_SUCCESS);
    FreeJson(sendToPeer);
    FreeJson(out);
    FreeJson(authParam);
}

// OnAccountFinish -> ReturnSessionKey success branch.
HWTEST_F(AccountRelatedGroupAuthTest, AccountRelatedGroupAuthTest0022, TestSize.Level0)
{
    int32_t ret = HC_ERROR;
    CJson *authParam = CreateJson();
    ASSERT_NE(authParam, nullptr);
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

    (void)AddIntToJson(authParam, FIELD_KEY_LENGTH, 2); // For unit test.
    uint8_t sessionKeyTest[2] = { 0x31, 0x32 }; // For unit test.
    (void)AddByteToJson(out, FIELD_SESSION_KEY, sessionKeyTest, sizeof(sessionKeyTest));
    (void)GetAccountRelatedGroupAuth()->onFinish(0, authParam, out, &g_deviceAuthCallBack); // For unit test.
    ret = AddObjToJson(out, FIELD_SEND_TO_PEER, sendToPeer);
    EXPECT_EQ(ret, HC_SUCCESS);
    FreeJson(sendToPeer);
    FreeJson(out);
    FreeJson(authParam);
}

// OnAccountFinish -> AddTrustedDeviceForAccount success failed.
HWTEST_F(AccountRelatedGroupAuthTest, AccountRelatedGroupAuthTest0023, TestSize.Level0)
{
    int32_t ret = HC_ERROR;
    CJson *authParam = CreateJson();
    CJson *out = CreateJson();
    CJson *sendToPeer = CreateJson();

    (void)AddObjToJson(out, FIELD_SEND_TO_PEER, sendToPeer);
    (void)AddStringToJson(sendToPeer, "test_key", "test_value"); // For unit test.
    (void)AddObjToJson(out, FIELD_SEND_TO_PEER, sendToPeer);

    (void)AddIntToJson(authParam, FIELD_KEY_LENGTH, 2); // For unit test.
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

    (void)AddIntToJson(sendToSelf, FIELD_CREDENTIAL_TYPE, 2);
    (void)AddObjToJson(out, FIELD_SEND_TO_SELF, sendToSelf);
    (void)GetAccountRelatedGroupAuth()->onFinish(0, authParam, out, &g_deviceAuthCallBack); // For unit test.
    
    (void)AddStringToJson(sendToSelf, FIELD_DEV_ID, "DEV_ID"); // For unit test.
    (void)AddObjToJson(out, FIELD_SEND_TO_SELF, sendToSelf);
    (void)GetAccountRelatedGroupAuth()->onFinish(0, authParam, out, &g_deviceAuthCallBack); // For unit test.

    (void)AddStringToJson(sendToSelf, FIELD_USER_ID, "USER_ID"); // For unit test.
    (void)AddObjToJson(out, FIELD_SEND_TO_SELF, sendToSelf);
    (void)GetAccountRelatedGroupAuth()->onFinish(0, authParam, out, &g_deviceAuthCallBack); // For unit test.
    ret = AddObjToJson(out, FIELD_SEND_TO_SELF, sendToSelf);
    EXPECT_EQ(ret, HC_SUCCESS);
    FreeJson(sendToSelf);
    FreeJson(out);
    FreeJson(sendToPeer);
    FreeJson(authParam);
}

HWTEST_F(AccountRelatedGroupAuthTest, AccountRelatedGroupAuthTest004, TestSize.Level0)
{
    TrustedGroupEntry *entry = CreateGroupEntry();
    ASSERT_NE(entry, nullptr);
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

    int32_t res = GetAccountRelatedGroupAuth()->fillDeviceAuthInfo(0, entry,
        localAuthInfo, paramsData); // For unit test.

    FreeJson(paramsData);
    EXPECT_NE(res, HC_SUCCESS);
    DestroyGroupEntry(entry);
    DestroyDeviceEntry(localAuthInfo);
}

HWTEST_F(AccountRelatedGroupAuthTest, AccountRelatedGroupAuthTest0041, TestSize.Level0)
{
    TrustedGroupEntry *entry = CreateGroupEntry();
    ASSERT_NE(entry, nullptr);
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

    int32_t res = AddStringToJson(paramsData, FIELD_PEER_CONN_DEVICE_ID, "CONN_DEVICE_ID"); // For unit test.
    EXPECT_EQ(res, HC_SUCCESS);

    (void)GetAccountRelatedGroupAuth()->fillDeviceAuthInfo(0, entry,
        localAuthInfo, paramsData); // For unit test.

    FreeJson(paramsData);
    DestroyGroupEntry(entry);
    DestroyDeviceEntry(localAuthInfo);
}

HWTEST_F(AccountRelatedGroupAuthTest, AccountRelatedGroupAuthTest0042, TestSize.Level0)
{
    TrustedGroupEntry *entry = CreateGroupEntry();
    ASSERT_NE(entry, nullptr);
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
    int32_t ret = GetAccountRelatedGroupAuth()->fillDeviceAuthInfo(0, entry,
        localAuthInfo, paramsData); // For unit test.
    EXPECT_EQ(ret, HC_SUCCESS);

    FreeJson(paramsData);
    DestroyGroupEntry(entry);
    DestroyDeviceEntry(localAuthInfo);
}

HWTEST_F(AccountRelatedGroupAuthTest, AccountRelatedGroupAuthTest0043, TestSize.Level0)
{
    TrustedGroupEntry *entry = CreateGroupEntry();
    ASSERT_NE(entry, nullptr);
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
    int32_t ret = GetAccountRelatedGroupAuth()->fillDeviceAuthInfo(0, entry,
        localAuthInfo, paramsData); // For unit test.
    EXPECT_EQ(ret, HC_SUCCESS);

    FreeJson(paramsData);
    DestroyGroupEntry(entry);
    DestroyDeviceEntry(localAuthInfo);
}

HWTEST_F(AccountRelatedGroupAuthTest, AccountRelatedGroupAuthTest00431, TestSize.Level0)
{
    TrustedGroupEntry *entry = CreateGroupEntry();
    ASSERT_NE(entry, nullptr);
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
    int32_t ret = GetAccountRelatedGroupAuth()->fillDeviceAuthInfo(0, entry,
        localAuthInfo, paramsData); // For unit test.
    EXPECT_EQ(ret, HC_SUCCESS);

    FreeJson(paramsData);
    DestroyGroupEntry(entry);
    DestroyDeviceEntry(localAuthInfo);
}

HWTEST_F(AccountRelatedGroupAuthTest, AccountRelatedGroupAuthTest0044, TestSize.Level0)
{
    TrustedGroupEntry *entry = CreateGroupEntry();
    ASSERT_NE(entry, nullptr);
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
    int32_t ret = GetAccountRelatedGroupAuth()->fillDeviceAuthInfo(0, entry,
        localAuthInfo, paramsData); // For unit test.
    EXPECT_EQ(ret, HC_SUCCESS);

    FreeJson(paramsData);
    DestroyGroupEntry(entry);
    DestroyDeviceEntry(localAuthInfo);
}

HWTEST_F(AccountRelatedGroupAuthTest, AccountRelatedGroupAuthTest007, TestSize.Level0)
{
    CJson *confirmationJson = CreateJson();
    ASSERT_NE(confirmationJson, nullptr);
    CJson *dataFromClient = CreateJson();
    if (dataFromClient == nullptr) {
        FreeJson(confirmationJson);
        return;
    }
    int32_t ret = GetAccountRelatedGroupAuth()->combineServerConfirmParams(confirmationJson, dataFromClient);
    EXPECT_NE(ret, HC_SUCCESS);
    FreeJson(confirmationJson);
    FreeJson(dataFromClient);
}

HWTEST_F(AccountRelatedGroupAuthTest, AccountRelatedGroupAuthTest0071, TestSize.Level0)
{
    CJson *confirmationJson = CreateJson();
    ASSERT_NE(confirmationJson, nullptr);
    CJson *dataFromClient = CreateJson();
    if (dataFromClient == nullptr) {
        FreeJson(confirmationJson);
        return;
    }

    (void)AddStringToJson(confirmationJson, FIELD_PEER_CONN_DEVICE_ID, "CONN_DEVICE_ID"); // For unit test.
    int32_t ret = GetAccountRelatedGroupAuth()->combineServerConfirmParams(confirmationJson, dataFromClient);
    EXPECT_EQ(ret, HC_SUCCESS);
    FreeJson(confirmationJson);
    FreeJson(dataFromClient);
}

HWTEST_F(AccountRelatedGroupAuthTest, AccountRelatedGroupAuthTest008, TestSize.Level0)
{
    CJson *in = CreateJson();
    int32_t ret = GetUserIdForAccount(in, in);
    EXPECT_NE(ret, HC_SUCCESS);
    FreeJson(in);
}

HWTEST_F(AccountRelatedGroupAuthTest, AccountRelatedGroupAuthTest009, TestSize.Level0)
{
    char *userIdDb = nullptr;
    char *peerUserIdInDb = nullptr;
    bool ret = IsUserIdEqual(userIdDb, peerUserIdInDb);
    EXPECT_NE(ret, true);
}

HWTEST_F(AccountRelatedGroupAuthTest, AccountRelatedGroupAuthTest010, TestSize.Level0)
{
    TrustedGroupEntry *entry = CreateGroupEntry();
    bool ret = IsPeerInAccountRelatedGroup(entry, nullptr, ALL_GROUP);
    EXPECT_NE(ret, true);

    QueryGroupParams params = {
        .groupId = nullptr,
        .groupName = nullptr,
        .ownerName = nullptr,
        .userId = nullptr,
        .groupType = ALL_GROUP,
        .groupVisibility = ALL_GROUP_VISIBILITY
    };
    GaGetAccountGroup(TEST_OS_ACCOUNT_ID, IDENTICAL_ACCOUNT_GROUP, nullptr, &params, nullptr);
    DestroyGroupEntry(entry);
}

HWTEST_F(AccountRelatedGroupAuthTest, AccountRelatedGroupAuthTest011, TestSize.Level0)
{
    int32_t ret = QueryAuthGroupForServer(TEST_OS_ACCOUNT_ID, nullptr, nullptr);
    EXPECT_NE(ret, HC_SUCCESS);
    CJson *in = CreateJson();
    (void)AddStringToJson(in, FIELD_USER_ID, TEST_USER_ID);
    ret = QueryAuthGroupForServer(TEST_OS_ACCOUNT_ID, nullptr, in);
    EXPECT_NE(ret, HC_SUCCESS);
    (void)AddIntToJson(in, FIELD_AUTH_FORM, TEST_AUTH_FORM);
    ret = QueryAuthGroupForServer(TEST_OS_ACCOUNT_ID, nullptr, in);
    EXPECT_NE(ret, HC_SUCCESS);
    FreeJson(in);
}

HWTEST_F(AccountRelatedGroupAuthTest, AccountRelatedGroupAuthTest012, TestSize.Level0)
{
    CJson *in = CreateJson();
    char *peerUserId = nullptr;
    int32_t ret = GetPeerUserIdFromReceivedData(in, &peerUserId);
    EXPECT_NE(ret, HC_SUCCESS);
    (void)AddStringToJson(in, FIELD_PLUGIN_EXT_DATA, TEST_EXT_DATA);
    ret = GetPeerUserIdFromReceivedData(in, &peerUserId);
    EXPECT_NE(ret, HC_SUCCESS);
    (void)AddStringToJson(in, FIELD_USER_ID, TEST_USER_ID);
    ret = GetPeerUserIdFromReceivedData(in, &peerUserId);
    EXPECT_NE(ret, HC_SUCCESS);
    FreeJson(in);
}

HWTEST_F(AccountRelatedGroupAuthTest, AccountRelatedGroupAuthTest013, TestSize.Level0)
{
    CJson *in = CreateJson();
    int32_t ret = QueryGroupForAccountPlugin(TEST_OS_ACCOUNT_ID, nullptr, in);
    EXPECT_NE(ret, HC_SUCCESS);
    (void)AddIntToJson(in, FIELD_AUTH_FORM, TEST_AUTH_FORM);
    ret = QueryGroupForAccountPlugin(TEST_OS_ACCOUNT_ID, nullptr, in);
    EXPECT_NE(ret, HC_SUCCESS);
    FreeJson(in);
}

HWTEST_F(AccountRelatedGroupAuthTest, AccountRelatedGroupAuthTest014, TestSize.Level0)
{
    CJson *in = CreateJson();
    TrustedGroupEntry *entry = CreateGroupEntry();
    int32_t ret = AddSelfDevInfoForServer(TEST_OS_ACCOUNT_ID, entry, in);
    EXPECT_NE(ret, HC_SUCCESS);
    DestroyGroupEntry(entry);
    AddServerParamsForAccountPlugin(in);
    (void)AddIntToJson(in, FIELD_OS_ACCOUNT_ID, TEST_OS_ACCOUNT_ID);
    AddServerParamsForAccountPlugin(in);
    FreeJson(in);
}

HWTEST_F(AccountRelatedGroupAuthTest, AccountRelatedGroupAuthTest015, TestSize.Level0)
{
    CJson *in = CreateJson();
    int32_t ret = AddSelfAccountInfoForServer(in);
    EXPECT_NE(ret, HC_SUCCESS);
    (void)AddIntToJson(in, FIELD_OS_ACCOUNT_ID, TEST_OS_ACCOUNT_ID);
    ret = AddSelfAccountInfoForServer(in);
    EXPECT_NE(ret, HC_SUCCESS);
    FreeJson(in);
}

HWTEST_F(AccountRelatedGroupAuthTest, AccountRelatedGroupAuthTest016, TestSize.Level0)
{
    CJson *in = CreateJson();
    int32_t ret = AddTrustedDeviceForAccount(in, in);
    EXPECT_NE(ret, HC_SUCCESS);
    (void)AddIntToJson(in, FIELD_OS_ACCOUNT_ID, TEST_OS_ACCOUNT_ID);
    ret = AddTrustedDeviceForAccount(in, in);
    EXPECT_NE(ret, HC_SUCCESS);
    (void)AddStringToJson(in, FIELD_PEER_CONN_DEVICE_ID, TEST_DEVICE_ID);
    ret = AddTrustedDeviceForAccount(in, in);
    EXPECT_NE(ret, HC_SUCCESS);
    (void)AddStringToJson(in, FIELD_GROUP_ID, TEST_GROUP_ID);
    ret = AddTrustedDeviceForAccount(in, in);
    EXPECT_NE(ret, HC_SUCCESS);
    FreeJson(in);
}

HWTEST_F(AccountRelatedGroupAuthTest, AccountRelatedGroupAuthTest017, TestSize.Level0)
{
    CJson *in = CreateJson();
    int32_t ret = AccountOnFinishToSelf(TEST_REQUEST_ID, in, in, nullptr);
    EXPECT_NE(ret, HC_SUCCESS);
    FreeJson(in);
}

// Ending for account_related_group_auth.c test.
}