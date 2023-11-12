/*
 * Copyright (C) 2022 Huawei Device Co., Ltd.
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

#include <cinttypes>
#include <unistd.h>
#include <gtest/gtest.h>
#include "alg_defs.h"
#include "common_defs.h"
#include "device_auth.h"
#include "group_operation_common.h"
#include "hc_dev_info.h"
#include "json_utils.h"
#include "securec.h"

using namespace std;
using namespace testing::ext;

namespace {

static const char *g_normalStr = "abc";
static const Uint8Buff g_normalBuff = { 0, 0 };

static int32_t GenerateGroupParams(const CJson *jsonParams, const char *groupId, TrustedGroupEntry *groupParams)
{
    (void)jsonParams;
    (void)groupId;
    (void)groupParams;
    return HC_SUCCESS;
}

static int32_t GenerateDevParams(const CJson *jsonParams, const char *groupId, TrustedDeviceEntry *devParams)
{
    (void)jsonParams;
    (void)groupId;
    (void)devParams;
    return HC_SUCCESS;
}

class GroupOperationTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void GroupOperationTest::SetUpTestCase()
{
    int32_t ret = InitDeviceAuthService();
    ASSERT_EQ(ret, HC_SUCCESS);
}

void GroupOperationTest::TearDownTestCase()
{
    DestroyDeviceAuthService();
}

void GroupOperationTest::SetUp() {}
void GroupOperationTest::TearDown() {}

HWTEST_F(GroupOperationTest, GroupOperationTest001, TestSize.Level0)
{
    TrustedGroupEntry *entry = GetGroupEntryById(DEFAULT_OS_ACCOUNT, nullptr);
    ASSERT_EQ(entry, nullptr);
}

HWTEST_F(GroupOperationTest, GroupOperationTest002, TestSize.Level0)
{
    bool ret = IsTrustedDeviceInGroup(DEFAULT_OS_ACCOUNT, nullptr, g_normalStr, true);
    ASSERT_EQ(ret, false);
}

HWTEST_F(GroupOperationTest, GroupOperationTest003, TestSize.Level0)
{
    bool ret = IsTrustedDeviceInGroup(DEFAULT_OS_ACCOUNT, g_normalStr, nullptr, true);
    ASSERT_EQ(ret, false);
}

HWTEST_F(GroupOperationTest, GroupOperationTest004, TestSize.Level0)
{
    bool ret = IsTrustedDeviceInGroup(DEFAULT_OS_ACCOUNT, g_normalStr, g_normalStr, true);
    ASSERT_EQ(ret, false);
}

HWTEST_F(GroupOperationTest, GroupOperationTest005, TestSize.Level0)
{
    bool ret = IsGroupOwner(DEFAULT_OS_ACCOUNT, nullptr, g_normalStr);
    ASSERT_EQ(ret, false);
}

HWTEST_F(GroupOperationTest, GroupOperationTest006, TestSize.Level0)
{
    bool ret = IsGroupOwner(DEFAULT_OS_ACCOUNT, g_normalStr, nullptr);
    ASSERT_EQ(ret, false);
}

HWTEST_F(GroupOperationTest, GroupOperationTest007, TestSize.Level0)
{
    bool ret = IsGroupOwner(DEFAULT_OS_ACCOUNT, g_normalStr, g_normalStr);
    ASSERT_EQ(ret, false);
}

HWTEST_F(GroupOperationTest, GroupOperationTest008, TestSize.Level0)
{
    bool ret = IsGroupExistByGroupId(DEFAULT_OS_ACCOUNT, nullptr);
    ASSERT_EQ(ret, false);
}

HWTEST_F(GroupOperationTest, GroupOperationTest009, TestSize.Level0)
{
    int32_t ret = CheckGroupAccessible(DEFAULT_OS_ACCOUNT, nullptr, g_normalStr);
    ASSERT_NE(ret, HC_SUCCESS);
}

HWTEST_F(GroupOperationTest, GroupOperationTest010, TestSize.Level0)
{
    int32_t ret = CheckGroupAccessible(DEFAULT_OS_ACCOUNT, g_normalStr, nullptr);
    ASSERT_NE(ret, HC_SUCCESS);
}

HWTEST_F(GroupOperationTest, GroupOperationTest011, TestSize.Level0)
{
    int32_t ret = CheckGroupAccessible(DEFAULT_OS_ACCOUNT, g_normalStr, g_normalStr);
    ASSERT_NE(ret, HC_SUCCESS);
}

HWTEST_F(GroupOperationTest, GroupOperationTest012, TestSize.Level0)
{
    int32_t ret = CheckGroupEditAllowed(DEFAULT_OS_ACCOUNT, nullptr, g_normalStr);
    ASSERT_NE(ret, HC_SUCCESS);
}

HWTEST_F(GroupOperationTest, GroupOperationTest013, TestSize.Level0)
{
    int32_t ret = CheckGroupEditAllowed(DEFAULT_OS_ACCOUNT, g_normalStr, nullptr);
    ASSERT_NE(ret, HC_SUCCESS);
}

HWTEST_F(GroupOperationTest, GroupOperationTest014, TestSize.Level0)
{
    int32_t ret = CheckGroupEditAllowed(DEFAULT_OS_ACCOUNT, g_normalStr, g_normalStr);
    ASSERT_NE(ret, HC_SUCCESS);
}

HWTEST_F(GroupOperationTest, GroupOperationTest015, TestSize.Level0)
{
    int32_t ret = GetGroupInfo(DEFAULT_OS_ACCOUNT, PEER_TO_PEER_GROUP, g_normalStr, g_normalStr, g_normalStr, nullptr);
    ASSERT_NE(ret, HC_SUCCESS);
}

HWTEST_F(GroupOperationTest, GroupOperationTest016, TestSize.Level0)
{
    int32_t ret = GetTrustedDevInfoById(DEFAULT_OS_ACCOUNT, nullptr, true, g_normalStr, nullptr);
    ASSERT_NE(ret, HC_SUCCESS);
}

HWTEST_F(GroupOperationTest, GroupOperationTest017, TestSize.Level0)
{
    int32_t ret = GetTrustedDevInfoById(DEFAULT_OS_ACCOUNT, g_normalStr, true, nullptr, nullptr);
    ASSERT_NE(ret, HC_SUCCESS);
}

HWTEST_F(GroupOperationTest, GroupOperationTest018, TestSize.Level0)
{
    int32_t ret = GetTrustedDevInfoById(DEFAULT_OS_ACCOUNT, g_normalStr, true, g_normalStr, nullptr);
    ASSERT_NE(ret, HC_SUCCESS);
}

HWTEST_F(GroupOperationTest, GroupOperationTest019, TestSize.Level0)
{
    uint8_t *hashMessage = NULL;
    uint32_t messageSize = 0;
    int32_t ret = GetHashMessage(nullptr, &g_normalBuff, &hashMessage, &messageSize);
    ASSERT_NE(ret, HC_SUCCESS);
}

HWTEST_F(GroupOperationTest, GroupOperationTest020, TestSize.Level0)
{
    uint8_t *hashMessage = NULL;
    uint32_t messageSize = 0;
    int32_t ret = GetHashMessage(&g_normalBuff, nullptr, &hashMessage, &messageSize);
    ASSERT_NE(ret, HC_SUCCESS);
}

HWTEST_F(GroupOperationTest, GroupOperationTest021, TestSize.Level0)
{
    uint32_t messageSize = 0;
    int32_t ret = GetHashMessage(&g_normalBuff, &g_normalBuff, nullptr, &messageSize);
    ASSERT_NE(ret, HC_SUCCESS);
}

HWTEST_F(GroupOperationTest, GroupOperationTest022, TestSize.Level0)
{
    uint8_t *hashMessage = NULL;
    int32_t ret = GetHashMessage(&g_normalBuff, &g_normalBuff, &hashMessage, nullptr);
    ASSERT_NE(ret, HC_SUCCESS);
}

HWTEST_F(GroupOperationTest, GroupOperationTest023, TestSize.Level0)
{
    int32_t num = GetCurDeviceNumByGroupId(DEFAULT_OS_ACCOUNT, nullptr);
    ASSERT_EQ(num, 0);
}

HWTEST_F(GroupOperationTest, GroupOperationTest024, TestSize.Level0)
{
    int32_t ret = AssertPeerDeviceNotSelf(nullptr);
    ASSERT_NE(ret, HC_SUCCESS);
}

HWTEST_F(GroupOperationTest, GroupOperationTest025, TestSize.Level0)
{
    char localUdid[INPUT_UDID_LEN] = { 0 };
    (void)HcGetUdid((uint8_t *)localUdid, INPUT_UDID_LEN);
    int32_t ret = AssertPeerDeviceNotSelf(localUdid);
    ASSERT_NE(ret, HC_SUCCESS);
}

HWTEST_F(GroupOperationTest, GroupOperationTest026, TestSize.Level0)
{
    int32_t ret = CheckGroupExist(DEFAULT_OS_ACCOUNT, nullptr);
    ASSERT_NE(ret, HC_SUCCESS);
}

HWTEST_F(GroupOperationTest, GroupOperationTest027, TestSize.Level0)
{
    CJson *jsonParams = CreateJson();
    int32_t ret = AddGroupToDatabaseByJson(DEFAULT_OS_ACCOUNT, nullptr, jsonParams, g_normalStr);
    FreeJson(jsonParams);
    ASSERT_NE(ret, HC_SUCCESS);
}

HWTEST_F(GroupOperationTest, GroupOperationTest028, TestSize.Level0)
{
    int32_t ret = AddGroupToDatabaseByJson(DEFAULT_OS_ACCOUNT, GenerateGroupParams, nullptr, g_normalStr);
    ASSERT_NE(ret, HC_SUCCESS);
}

HWTEST_F(GroupOperationTest, GroupOperationTest029, TestSize.Level0)
{
    CJson *jsonParams = CreateJson();
    int32_t ret = AddGroupToDatabaseByJson(DEFAULT_OS_ACCOUNT, GenerateGroupParams, jsonParams, nullptr);
    FreeJson(jsonParams);
    ASSERT_NE(ret, HC_SUCCESS);
}

HWTEST_F(GroupOperationTest, GroupOperationTest030, TestSize.Level0)
{
    CJson *jsonParams = CreateJson();
    int32_t ret = AddDeviceToDatabaseByJson(DEFAULT_OS_ACCOUNT, nullptr, jsonParams, g_normalStr);
    FreeJson(jsonParams);
    ASSERT_NE(ret, HC_SUCCESS);
}

HWTEST_F(GroupOperationTest, GroupOperationTest031, TestSize.Level0)
{
    int32_t ret = AddDeviceToDatabaseByJson(DEFAULT_OS_ACCOUNT, GenerateDevParams, nullptr, g_normalStr);
    ASSERT_NE(ret, HC_SUCCESS);
}

HWTEST_F(GroupOperationTest, GroupOperationTest032, TestSize.Level0)
{
    CJson *jsonParams = CreateJson();
    int32_t ret = AddDeviceToDatabaseByJson(DEFAULT_OS_ACCOUNT, GenerateDevParams, jsonParams, nullptr);
    FreeJson(jsonParams);
    ASSERT_NE(ret, HC_SUCCESS);
}

HWTEST_F(GroupOperationTest, GroupOperationTest033, TestSize.Level0)
{
    int32_t ret = DelGroupFromDb(DEFAULT_OS_ACCOUNT, nullptr);
    ASSERT_NE(ret, HC_SUCCESS);
}

HWTEST_F(GroupOperationTest, GroupOperationTest034, TestSize.Level0)
{
    const char *groupId = "ABCD";
    int32_t ret = DelGroupFromDb(DEFAULT_OS_ACCOUNT, groupId);
    ASSERT_EQ(ret, HC_SUCCESS);
}

HWTEST_F(GroupOperationTest, GroupOperationTest035, TestSize.Level0)
{
    char *returnJsonStr = nullptr;
    int32_t ret = ConvertGroupIdToJsonStr(nullptr, &returnJsonStr);
    ASSERT_NE(ret, HC_SUCCESS);
}

HWTEST_F(GroupOperationTest, GroupOperationTest036, TestSize.Level0)
{
    int32_t ret = ConvertGroupIdToJsonStr(g_normalStr, nullptr);
    ASSERT_NE(ret, HC_SUCCESS);
}

HWTEST_F(GroupOperationTest, GroupOperationTest037, TestSize.Level0)
{
    char *returnJsonStr = nullptr;
    int32_t ret = GenerateBindSuccessData(nullptr, g_normalStr, g_normalStr, &returnJsonStr);
    ASSERT_NE(ret, HC_SUCCESS);
}

HWTEST_F(GroupOperationTest, GroupOperationTest038, TestSize.Level0)
{
    char *returnJsonStr = nullptr;
    int32_t ret = GenerateBindSuccessData(g_normalStr, nullptr, g_normalStr, &returnJsonStr);
    ASSERT_NE(ret, HC_SUCCESS);
}

HWTEST_F(GroupOperationTest, GroupOperationTest039, TestSize.Level0)
{
    int32_t ret = GenerateBindSuccessData(g_normalStr, g_normalStr, g_normalStr, nullptr);
    ASSERT_NE(ret, HC_SUCCESS);
}

HWTEST_F(GroupOperationTest, GroupOperationTest040, TestSize.Level0)
{
    char *returnJsonStr = nullptr;
    int32_t ret = GenerateUnbindSuccessData(nullptr, g_normalStr, &returnJsonStr);
    ASSERT_NE(ret, HC_SUCCESS);
}

HWTEST_F(GroupOperationTest, GroupOperationTest041, TestSize.Level0)
{
    char *returnJsonStr = nullptr;
    int32_t ret = GenerateUnbindSuccessData(g_normalStr, nullptr, &returnJsonStr);
    ASSERT_NE(ret, HC_SUCCESS);
}

HWTEST_F(GroupOperationTest, GroupOperationTest042, TestSize.Level0)
{
    int32_t ret = GenerateUnbindSuccessData(g_normalStr, g_normalStr, nullptr);
    ASSERT_NE(ret, HC_SUCCESS);
}


HWTEST_F(GroupOperationTest, GroupOperationTest043, TestSize.Level0)
{
    int32_t ret = ProcessKeyPair(CREATE_KEY_PAIR, nullptr, g_normalStr);
    ASSERT_NE(ret, HC_SUCCESS);
}

HWTEST_F(GroupOperationTest, GroupOperationTest044, TestSize.Level0)
{
    CJson *jsonParams = CreateJson();
    int32_t ret = ProcessKeyPair(CREATE_KEY_PAIR, jsonParams, nullptr);
    FreeJson(jsonParams);
    ASSERT_NE(ret, HC_SUCCESS);
}

HWTEST_F(GroupOperationTest, GroupOperationTest045, TestSize.Level0)
{
    int32_t groupType;
    int32_t ret = GetGroupTypeFromDb(DEFAULT_OS_ACCOUNT, nullptr, &groupType);
    ASSERT_NE(ret, HC_SUCCESS);
}

HWTEST_F(GroupOperationTest, GroupOperationTest046, TestSize.Level0)
{
    int32_t ret = GetGroupTypeFromDb(DEFAULT_OS_ACCOUNT, g_normalStr, nullptr);
    ASSERT_NE(ret, HC_SUCCESS);
}

HWTEST_F(GroupOperationTest, GroupOperationTest047, TestSize.Level0)
{
    int32_t groupType;
    int32_t ret = GetGroupTypeFromDb(DEFAULT_OS_ACCOUNT, g_normalStr, &groupType);
    ASSERT_NE(ret, HC_SUCCESS);
}

HWTEST_F(GroupOperationTest, GroupOperationTest048, TestSize.Level0)
{
    char *userId = nullptr;
    int32_t ret = GetUserIdFromJson(nullptr, &userId);
    ASSERT_NE(ret, HC_SUCCESS);
}

HWTEST_F(GroupOperationTest, GroupOperationTest049, TestSize.Level0)
{
    CJson *jsonParams = CreateJson();
    int32_t ret = GetUserIdFromJson(jsonParams, nullptr);
    FreeJson(jsonParams);
    ASSERT_NE(ret, HC_SUCCESS);
}

HWTEST_F(GroupOperationTest, GroupOperationTest050, TestSize.Level0)
{
    char *userId = nullptr;
    CJson *jsonParams = CreateJson();
    int32_t ret = GetUserIdFromJson(jsonParams, &userId);
    FreeJson(jsonParams);
    ASSERT_NE(ret, HC_SUCCESS);
}

HWTEST_F(GroupOperationTest, GroupOperationTest051, TestSize.Level0)
{
    char *sharedUserId = nullptr;
    int32_t ret = GetSharedUserIdFromJson(nullptr, &sharedUserId);
    ASSERT_NE(ret, HC_SUCCESS);
}

HWTEST_F(GroupOperationTest, GroupOperationTest052, TestSize.Level0)
{
    CJson *jsonParams = CreateJson();
    int32_t ret = GetSharedUserIdFromJson(jsonParams, nullptr);
    FreeJson(jsonParams);
    ASSERT_NE(ret, HC_SUCCESS);
}

HWTEST_F(GroupOperationTest, GroupOperationTest053, TestSize.Level0)
{
    char *sharedUserId = nullptr;
    CJson *jsonParams = CreateJson();
    int32_t ret = GetSharedUserIdFromJson(jsonParams, &sharedUserId);
    FreeJson(jsonParams);
    ASSERT_NE(ret, HC_SUCCESS);
}

HWTEST_F(GroupOperationTest, GroupOperationTest054, TestSize.Level0)
{
    const char *groupId = nullptr;
    int32_t ret = GetGroupIdFromJson(nullptr, &groupId);
    ASSERT_NE(ret, HC_SUCCESS);
}

HWTEST_F(GroupOperationTest, GroupOperationTest055, TestSize.Level0)
{
    CJson *jsonParams = CreateJson();
    int32_t ret = GetGroupIdFromJson(jsonParams, nullptr);
    FreeJson(jsonParams);
    ASSERT_NE(ret, HC_SUCCESS);
}

HWTEST_F(GroupOperationTest, GroupOperationTest056, TestSize.Level0)
{
    const char *groupId = nullptr;
    CJson *jsonParams = CreateJson();
    int32_t ret = GetGroupIdFromJson(jsonParams, &groupId);
    FreeJson(jsonParams);
    ASSERT_NE(ret, HC_SUCCESS);
}

HWTEST_F(GroupOperationTest, GroupOperationTest057, TestSize.Level0)
{
    const char *appId = nullptr;
    int32_t ret = GetAppIdFromJson(nullptr, &appId);
    ASSERT_NE(ret, HC_SUCCESS);
}

HWTEST_F(GroupOperationTest, GroupOperationTest058, TestSize.Level0)
{
    CJson *jsonParams = CreateJson();
    int32_t ret = GetAppIdFromJson(jsonParams, nullptr);
    FreeJson(jsonParams);
    ASSERT_NE(ret, HC_SUCCESS);
}

HWTEST_F(GroupOperationTest, GroupOperationTest059, TestSize.Level0)
{
    const char *appId = nullptr;
    CJson *jsonParams = CreateJson();
    int32_t ret = GetAppIdFromJson(jsonParams, &appId);
    FreeJson(jsonParams);
    ASSERT_NE(ret, HC_SUCCESS);
}

HWTEST_F(GroupOperationTest, GroupOperationTest060, TestSize.Level0)
{
    int32_t ret = AssertGroupTypeMatch(PEER_TO_PEER_GROUP, IDENTICAL_ACCOUNT_GROUP);
    ASSERT_NE(ret, HC_SUCCESS);
}

HWTEST_F(GroupOperationTest, GroupOperationTest061, TestSize.Level0)
{
    char *hash = nullptr;
    int32_t ret = GetHashResult(nullptr, SHA256_LEN, hash, SHA256_LEN);
    ASSERT_NE(ret, HC_SUCCESS);
}

HWTEST_F(GroupOperationTest, GroupOperationTest062, TestSize.Level0)
{
    const uint8_t *info;
    int32_t ret = GetHashResult(info, SHA256_LEN, nullptr, SHA256_LEN);
    ASSERT_NE(ret, HC_SUCCESS);
}
}
