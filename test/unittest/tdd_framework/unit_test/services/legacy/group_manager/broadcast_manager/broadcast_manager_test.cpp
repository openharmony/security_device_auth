/*
 * Copyright (C) 2026 Huawei Device Co., Ltd.
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

#include <gtest/gtest.h>
#include "broadcast_manager.h"
#include "device_auth_defines.h"
#include "hc_log.h"

using namespace std;
using namespace testing::ext;

namespace {
static int g_onGroupCreatedCount = 0;
static int g_onGroupDeletedCount = 0;
static int g_onDeviceBoundCount = 0;
static int g_onDeviceUnBoundCount = 0;
static int g_onDeviceNotTrustedCount = 0;
static int g_onLastGroupDeletedCount = 0;
static int g_onTrustedDeviceNumChangedCount = 0;
static int g_onGroupActiveInUserCount = 0;
static int g_onGroupInactiveInUserCount = 0;
static int g_onDeviceActiveInUserCount = 0;
static int g_onDeviceInactiveInUserCount = 0;
static int g_onDeviceNotTrustedInUserCount = 0;

static void ResetCallbackCounts(void)
{
    g_onGroupCreatedCount = 0;
    g_onGroupDeletedCount = 0;
    g_onDeviceBoundCount = 0;
    g_onDeviceUnBoundCount = 0;
    g_onDeviceNotTrustedCount = 0;
    g_onLastGroupDeletedCount = 0;
    g_onTrustedDeviceNumChangedCount = 0;
    g_onGroupActiveInUserCount = 0;
    g_onGroupInactiveInUserCount = 0;
    g_onDeviceActiveInUserCount = 0;
    g_onDeviceInactiveInUserCount = 0;
    g_onDeviceNotTrustedInUserCount = 0;
}

static void TestOnGroupCreated(const char *groupInfo)
{
    (void)groupInfo;
    g_onGroupCreatedCount++;
}

static void TestOnGroupDeleted(const char *groupInfo)
{
    (void)groupInfo;
    g_onGroupDeletedCount++;
}

static void TestOnDeviceBound(const char *peerUdid, const char *groupInfo)
{
    (void)peerUdid;
    (void)groupInfo;
    g_onDeviceBoundCount++;
}

static void TestOnDeviceUnBound(const char *peerUdid, const char *groupInfo)
{
    (void)peerUdid;
    (void)groupInfo;
    g_onDeviceUnBoundCount++;
}

static void TestOnDeviceNotTrusted(const char *peerUdid)
{
    (void)peerUdid;
    g_onDeviceNotTrustedCount++;
}

static void TestOnLastGroupDeleted(const char *peerUdid, int groupType)
{
    (void)peerUdid;
    (void)groupType;
    g_onLastGroupDeletedCount++;
}

static void TestOnTrustedDeviceNumChanged(int curTrustedDeviceNum)
{
    (void)curTrustedDeviceNum;
    g_onTrustedDeviceNumChangedCount++;
}

static void TestOnGroupActiveInUser(const char *returnInfo)
{
    (void)returnInfo;
    g_onGroupActiveInUserCount++;
}

static void TestOnGroupInactiveInUser(const char *returnInfo)
{
    (void)returnInfo;
    g_onGroupInactiveInUserCount++;
}

static void TestOnDeviceActiveInUser(const char *udid, const char *returnInfo)
{
    (void)udid;
    (void)returnInfo;
    g_onDeviceActiveInUserCount++;
}

static void TestOnDeviceInactiveInUser(const char *udid, const char *returnInfo)
{
    (void)udid;
    (void)returnInfo;
    g_onDeviceInactiveInUserCount++;
}

static void TestOnDeviceNotTrustedInUser(const char *udid, const char *returnInfo)
{
    (void)udid;
    (void)returnInfo;
    g_onDeviceNotTrustedInUserCount++;
}

static DataChangeListener g_fullListener = {
    .onGroupCreated = TestOnGroupCreated,
    .onGroupDeleted = TestOnGroupDeleted,
    .onDeviceBound = TestOnDeviceBound,
    .onDeviceUnBound = TestOnDeviceUnBound,
    .onDeviceNotTrusted = TestOnDeviceNotTrusted,
    .onLastGroupDeleted = TestOnLastGroupDeleted,
    .onTrustedDeviceNumChanged = TestOnTrustedDeviceNumChanged,
    .onGroupActiveInUser = TestOnGroupActiveInUser,
    .onGroupInactiveInUser = TestOnGroupInactiveInUser,
    .onDeviceActiveInUser = TestOnDeviceActiveInUser,
    .onDeviceInactiveInUser = TestOnDeviceInactiveInUser,
    .onDeviceNotTrustedInUser = TestOnDeviceNotTrustedInUser,
};

static DataChangeListener g_partialListener = {
    .onGroupCreated = TestOnGroupCreated,
    .onGroupDeleted = NULL,
    .onDeviceBound = NULL,
    .onDeviceUnBound = NULL,
    .onDeviceNotTrusted = NULL,
    .onLastGroupDeleted = NULL,
    .onTrustedDeviceNumChanged = NULL,
    .onGroupActiveInUser = NULL,
    .onGroupInactiveInUser = NULL,
    .onDeviceActiveInUser = NULL,
    .onDeviceInactiveInUser = NULL,
    .onDeviceNotTrustedInUser = NULL,
};

static DataChangeListener g_emptyListener = {
    .onGroupCreated = NULL,
    .onGroupDeleted = NULL,
    .onDeviceBound = NULL,
    .onDeviceUnBound = NULL,
    .onDeviceNotTrusted = NULL,
    .onLastGroupDeleted = NULL,
    .onTrustedDeviceNumChanged = NULL,
    .onGroupActiveInUser = NULL,
    .onGroupInactiveInUser = NULL,
    .onDeviceActiveInUser = NULL,
    .onDeviceInactiveInUser = NULL,
    .onDeviceNotTrustedInUser = NULL,
};
}

class BroadcastManagerTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void BroadcastManagerTest::SetUpTestCase()
{
    int32_t ret = InitBroadcastManager();
    ASSERT_EQ(ret, HC_SUCCESS);
}

void BroadcastManagerTest::TearDownTestCase()
{
    DestroyBroadcastManager();
}

void BroadcastManagerTest::SetUp()
{
    ResetCallbackCounts();
}

void BroadcastManagerTest::TearDown() {}

HWTEST_F(BroadcastManagerTest, BroadcastManagerTest_IsBroadcastSupported, TestSize.Level0)
{
    EXPECT_TRUE(IsBroadcastSupported());
}

HWTEST_F(BroadcastManagerTest, BroadcastManagerTest_GetBroadcaster, TestSize.Level0)
{
    const Broadcaster *broadcaster = GetBroadcaster();
    EXPECT_NE(broadcaster, nullptr);
    EXPECT_NE(broadcaster->postOnGroupCreated, nullptr);
    EXPECT_NE(broadcaster->postOnGroupDeleted, nullptr);
    EXPECT_NE(broadcaster->postOnDeviceBound, nullptr);
    EXPECT_NE(broadcaster->postOnDeviceUnBound, nullptr);
    EXPECT_NE(broadcaster->postOnDeviceNotTrusted, nullptr);
    EXPECT_NE(broadcaster->postOnLastGroupDeleted, nullptr);
    EXPECT_NE(broadcaster->postOnTrustedDeviceNumChanged, nullptr);
    EXPECT_NE(broadcaster->postOnGroupActiveInUser, nullptr);
    EXPECT_NE(broadcaster->postOnGroupInactiveInUser, nullptr);
    EXPECT_NE(broadcaster->postOnDeviceActiveInUser, nullptr);
    EXPECT_NE(broadcaster->postOnDeviceInactiveInUser, nullptr);
    EXPECT_NE(broadcaster->postOnDeviceNotTrustedInUser, nullptr);
}

HWTEST_F(BroadcastManagerTest, BroadcastManagerTest_AddListener_NullAppId, TestSize.Level0)
{
    int32_t ret = AddListener(NULL, &g_fullListener);
    EXPECT_EQ(ret, HC_ERR_INVALID_PARAMS);
}

HWTEST_F(BroadcastManagerTest, BroadcastManagerTest_AddListener_NullListener, TestSize.Level0)
{
    int32_t ret = AddListener("com.test.app", NULL);
    EXPECT_EQ(ret, HC_ERR_INVALID_PARAMS);
}

HWTEST_F(BroadcastManagerTest, BroadcastManagerTest_AddListener_NullBoth, TestSize.Level0)
{
    int32_t ret = AddListener(NULL, NULL);
    EXPECT_EQ(ret, HC_ERR_INVALID_PARAMS);
}

HWTEST_F(BroadcastManagerTest, BroadcastManagerTest_AddListener_Success, TestSize.Level0)
{
    int32_t ret = AddListener("com.test.add.success", &g_fullListener);
    EXPECT_EQ(ret, HC_SUCCESS);
    RemoveListener("com.test.add.success");
}

HWTEST_F(BroadcastManagerTest, BroadcastManagerTest_AddListener_UpdateExisting, TestSize.Level0)
{
    int32_t ret = AddListener("com.test.update.app", &g_fullListener);
    EXPECT_EQ(ret, HC_SUCCESS);
    ret = AddListener("com.test.update.app", &g_partialListener);
    EXPECT_EQ(ret, HC_SUCCESS);
    RemoveListener("com.test.update.app");
}

HWTEST_F(BroadcastManagerTest, BroadcastManagerTest_RemoveListener_NullAppId, TestSize.Level0)
{
    int32_t ret = RemoveListener(NULL);
    EXPECT_EQ(ret, HC_ERR_INVALID_PARAMS);
}

HWTEST_F(BroadcastManagerTest, BroadcastManagerTest_RemoveListener_NotExist, TestSize.Level0)
{
    int32_t ret = RemoveListener("com.test.not.exist");
    EXPECT_EQ(ret, HC_SUCCESS);
}

HWTEST_F(BroadcastManagerTest, BroadcastManagerTest_RemoveListener_Success, TestSize.Level0)
{
    int32_t ret = AddListener("com.test.remove.success", &g_fullListener);
    EXPECT_EQ(ret, HC_SUCCESS);
    ret = RemoveListener("com.test.remove.success");
    EXPECT_EQ(ret, HC_SUCCESS);
}

HWTEST_F(BroadcastManagerTest, BroadcastManagerTest_PostOnGroupCreated_NullMessage, TestSize.Level0)
{
    const Broadcaster *broadcaster = GetBroadcaster();
    broadcaster->postOnGroupCreated(NULL);
    EXPECT_EQ(g_onGroupCreatedCount, 0);
}

HWTEST_F(BroadcastManagerTest, BroadcastManagerTest_PostOnGroupCreated_NoListener, TestSize.Level0)
{
    const Broadcaster *broadcaster = GetBroadcaster();
    broadcaster->postOnGroupCreated("{\"groupId\":\"test\"}");
    EXPECT_EQ(g_onGroupCreatedCount, 0);
}

HWTEST_F(BroadcastManagerTest, BroadcastManagerTest_PostOnGroupCreated_WithFullListener, TestSize.Level0)
{
    AddListener("com.test.group.created", &g_fullListener);
    const Broadcaster *broadcaster = GetBroadcaster();
    broadcaster->postOnGroupCreated("{\"groupId\":\"test\"}");
    EXPECT_EQ(g_onGroupCreatedCount, 1);
    RemoveListener("com.test.group.created");
}

HWTEST_F(BroadcastManagerTest, BroadcastManagerTest_PostOnGroupCreated_WithPartialListener, TestSize.Level0)
{
    AddListener("com.test.group.created.partial", &g_partialListener);
    const Broadcaster *broadcaster = GetBroadcaster();
    broadcaster->postOnGroupCreated("{\"groupId\":\"test\"}");
    EXPECT_EQ(g_onGroupCreatedCount, 1);
    broadcaster->postOnGroupDeleted("{\"groupId\":\"test\"}");
    EXPECT_EQ(g_onGroupDeletedCount, 0);
    RemoveListener("com.test.group.created.partial");
}

HWTEST_F(BroadcastManagerTest, BroadcastManagerTest_PostOnGroupCreated_WithEmptyListener, TestSize.Level0)
{
    AddListener("com.test.group.created.empty", &g_emptyListener);
    const Broadcaster *broadcaster = GetBroadcaster();
    broadcaster->postOnGroupCreated("{\"groupId\":\"test\"}");
    EXPECT_EQ(g_onGroupCreatedCount, 0);
    RemoveListener("com.test.group.created.empty");
}

HWTEST_F(BroadcastManagerTest, BroadcastManagerTest_PostOnGroupCreated_MultipleListeners, TestSize.Level0)
{
    AddListener("com.test.group.created.multi1", &g_fullListener);
    AddListener("com.test.group.created.multi2", &g_fullListener);
    const Broadcaster *broadcaster = GetBroadcaster();
    broadcaster->postOnGroupCreated("{\"groupId\":\"test\"}");
    EXPECT_EQ(g_onGroupCreatedCount, 2);
    RemoveListener("com.test.group.created.multi1");
    RemoveListener("com.test.group.created.multi2");
}

HWTEST_F(BroadcastManagerTest, BroadcastManagerTest_PostOnGroupDeleted_NullMessage, TestSize.Level0)
{
    const Broadcaster *broadcaster = GetBroadcaster();
    broadcaster->postOnGroupDeleted(NULL);
    EXPECT_EQ(g_onGroupDeletedCount, 0);
}

HWTEST_F(BroadcastManagerTest, BroadcastManagerTest_PostOnGroupDeleted_WithListener, TestSize.Level0)
{
    AddListener("com.test.group.deleted", &g_fullListener);
    const Broadcaster *broadcaster = GetBroadcaster();
    broadcaster->postOnGroupDeleted("{\"groupId\":\"test\"}");
    EXPECT_EQ(g_onGroupDeletedCount, 1);
    RemoveListener("com.test.group.deleted");
}

HWTEST_F(BroadcastManagerTest, BroadcastManagerTest_PostOnDeviceBound_NullPeerUdid, TestSize.Level0)
{
    const Broadcaster *broadcaster = GetBroadcaster();
    broadcaster->postOnDeviceBound(NULL, "{\"groupId\":\"test\"}");
    EXPECT_EQ(g_onDeviceBoundCount, 0);
}

HWTEST_F(BroadcastManagerTest, BroadcastManagerTest_PostOnDeviceBound_NullMessage, TestSize.Level0)
{
    const Broadcaster *broadcaster = GetBroadcaster();
    broadcaster->postOnDeviceBound("peerUdid", NULL);
    EXPECT_EQ(g_onDeviceBoundCount, 0);
}

HWTEST_F(BroadcastManagerTest, BroadcastManagerTest_PostOnDeviceBound_WithListener, TestSize.Level0)
{
    AddListener("com.test.device.bound", &g_fullListener);
    const Broadcaster *broadcaster = GetBroadcaster();
    broadcaster->postOnDeviceBound("peerUdid", "{\"groupId\":\"test\"}");
    EXPECT_EQ(g_onDeviceBoundCount, 1);
    RemoveListener("com.test.device.bound");
}

HWTEST_F(BroadcastManagerTest, BroadcastManagerTest_PostOnDeviceUnBound_NullPeerUdid, TestSize.Level0)
{
    const Broadcaster *broadcaster = GetBroadcaster();
    broadcaster->postOnDeviceUnBound(NULL, "{\"groupId\":\"test\"}");
    EXPECT_EQ(g_onDeviceUnBoundCount, 0);
}

HWTEST_F(BroadcastManagerTest, BroadcastManagerTest_PostOnDeviceUnBound_NullMessage, TestSize.Level0)
{
    const Broadcaster *broadcaster = GetBroadcaster();
    broadcaster->postOnDeviceUnBound("peerUdid", NULL);
    EXPECT_EQ(g_onDeviceUnBoundCount, 0);
}

HWTEST_F(BroadcastManagerTest, BroadcastManagerTest_PostOnDeviceUnBound_WithListener, TestSize.Level0)
{
    AddListener("com.test.device.unbound", &g_fullListener);
    const Broadcaster *broadcaster = GetBroadcaster();
    broadcaster->postOnDeviceUnBound("peerUdid", "{\"groupId\":\"test\"}");
    EXPECT_EQ(g_onDeviceUnBoundCount, 1);
    RemoveListener("com.test.device.unbound");
}

HWTEST_F(BroadcastManagerTest, BroadcastManagerTest_PostOnDeviceNotTrusted_NullPeerUdid, TestSize.Level0)
{
    const Broadcaster *broadcaster = GetBroadcaster();
    broadcaster->postOnDeviceNotTrusted(NULL);
    EXPECT_EQ(g_onDeviceNotTrustedCount, 0);
}

HWTEST_F(BroadcastManagerTest, BroadcastManagerTest_PostOnDeviceNotTrusted_WithListener, TestSize.Level0)
{
    AddListener("com.test.device.not.trusted", &g_fullListener);
    const Broadcaster *broadcaster = GetBroadcaster();
    broadcaster->postOnDeviceNotTrusted("peerUdid");
    EXPECT_EQ(g_onDeviceNotTrustedCount, 1);
    RemoveListener("com.test.device.not.trusted");
}

HWTEST_F(BroadcastManagerTest, BroadcastManagerTest_PostOnLastGroupDeleted_NullPeerUdid, TestSize.Level0)
{
    const Broadcaster *broadcaster = GetBroadcaster();
    broadcaster->postOnLastGroupDeleted(NULL, 1);
    EXPECT_EQ(g_onLastGroupDeletedCount, 0);
}

HWTEST_F(BroadcastManagerTest, BroadcastManagerTest_PostOnLastGroupDeleted_WithListener, TestSize.Level0)
{
    AddListener("com.test.last.group.deleted", &g_fullListener);
    const Broadcaster *broadcaster = GetBroadcaster();
    broadcaster->postOnLastGroupDeleted("peerUdid", 1);
    EXPECT_EQ(g_onLastGroupDeletedCount, 1);
    RemoveListener("com.test.last.group.deleted");
}

HWTEST_F(BroadcastManagerTest, BroadcastManagerTest_PostOnTrustedDeviceNumChanged_WithListener, TestSize.Level0)
{
    AddListener("com.test.trusted.num.changed", &g_fullListener);
    const Broadcaster *broadcaster = GetBroadcaster();
    broadcaster->postOnTrustedDeviceNumChanged(5);
    EXPECT_EQ(g_onTrustedDeviceNumChangedCount, 1);
    RemoveListener("com.test.trusted.num.changed");
}

HWTEST_F(BroadcastManagerTest, BroadcastManagerTest_PostOnGroupActiveInUser_NullReturnInfo, TestSize.Level0)
{
    const Broadcaster *broadcaster = GetBroadcaster();
    broadcaster->postOnGroupActiveInUser(NULL);
    EXPECT_EQ(g_onGroupActiveInUserCount, 0);
}

HWTEST_F(BroadcastManagerTest, BroadcastManagerTest_PostOnGroupActiveInUser_WithListener, TestSize.Level0)
{
    AddListener("com.test.group.active", &g_fullListener);
    const Broadcaster *broadcaster = GetBroadcaster();
    broadcaster->postOnGroupActiveInUser("{\"groupId\":\"test\"}");
    EXPECT_EQ(g_onGroupActiveInUserCount, 1);
    RemoveListener("com.test.group.active");
}

HWTEST_F(BroadcastManagerTest, BroadcastManagerTest_PostOnGroupInactiveInUser_NullReturnInfo, TestSize.Level0)
{
    const Broadcaster *broadcaster = GetBroadcaster();
    broadcaster->postOnGroupInactiveInUser(NULL);
    EXPECT_EQ(g_onGroupInactiveInUserCount, 0);
}

HWTEST_F(BroadcastManagerTest, BroadcastManagerTest_PostOnGroupInactiveInUser_WithListener, TestSize.Level0)
{
    AddListener("com.test.group.inactive", &g_fullListener);
    const Broadcaster *broadcaster = GetBroadcaster();
    broadcaster->postOnGroupInactiveInUser("{\"groupId\":\"test\"}");
    EXPECT_EQ(g_onGroupInactiveInUserCount, 1);
    RemoveListener("com.test.group.inactive");
}

HWTEST_F(BroadcastManagerTest, BroadcastManagerTest_PostOnDeviceActiveInUser_NullUdid, TestSize.Level0)
{
    const Broadcaster *broadcaster = GetBroadcaster();
    broadcaster->postOnDeviceActiveInUser(NULL, "{\"groupId\":\"test\"}");
    EXPECT_EQ(g_onDeviceActiveInUserCount, 0);
}

HWTEST_F(BroadcastManagerTest, BroadcastManagerTest_PostOnDeviceActiveInUser_NullReturnInfo, TestSize.Level0)
{
    const Broadcaster *broadcaster = GetBroadcaster();
    broadcaster->postOnDeviceActiveInUser("udid", NULL);
    EXPECT_EQ(g_onDeviceActiveInUserCount, 0);
}

HWTEST_F(BroadcastManagerTest, BroadcastManagerTest_PostOnDeviceActiveInUser_WithListener, TestSize.Level0)
{
    AddListener("com.test.device.active", &g_fullListener);
    const Broadcaster *broadcaster = GetBroadcaster();
    broadcaster->postOnDeviceActiveInUser("udid", "{\"groupId\":\"test\"}");
    EXPECT_EQ(g_onDeviceActiveInUserCount, 1);
    RemoveListener("com.test.device.active");
}

HWTEST_F(BroadcastManagerTest, BroadcastManagerTest_PostOnDeviceInactiveInUser_NullUdid, TestSize.Level0)
{
    const Broadcaster *broadcaster = GetBroadcaster();
    broadcaster->postOnDeviceInactiveInUser(NULL, "{\"groupId\":\"test\"}");
    EXPECT_EQ(g_onDeviceInactiveInUserCount, 0);
}

HWTEST_F(BroadcastManagerTest, BroadcastManagerTest_PostOnDeviceInactiveInUser_NullReturnInfo, TestSize.Level0)
{
    const Broadcaster *broadcaster = GetBroadcaster();
    broadcaster->postOnDeviceInactiveInUser("udid", NULL);
    EXPECT_EQ(g_onDeviceInactiveInUserCount, 0);
}

HWTEST_F(BroadcastManagerTest, BroadcastManagerTest_PostOnDeviceInactiveInUser_WithListener, TestSize.Level0)
{
    AddListener("com.test.device.inactive", &g_fullListener);
    const Broadcaster *broadcaster = GetBroadcaster();
    broadcaster->postOnDeviceInactiveInUser("udid", "{\"groupId\":\"test\"}");
    EXPECT_EQ(g_onDeviceInactiveInUserCount, 1);
    RemoveListener("com.test.device.inactive");
}

HWTEST_F(BroadcastManagerTest, BroadcastManagerTest_PostDeviceNotTrustedInUser_NullUdid, TestSize.Level0)
{
    const Broadcaster *broadcaster = GetBroadcaster();
    broadcaster->postOnDeviceNotTrustedInUser(NULL, "{\"groupId\":\"test\"}");
    EXPECT_EQ(g_onDeviceNotTrustedInUserCount, 0);
}

HWTEST_F(BroadcastManagerTest, BroadcastManagerTest_PostDeviceNotTrustedInUser_NullReturnInfo, TestSize.Level0)
{
    const Broadcaster *broadcaster = GetBroadcaster();
    broadcaster->postOnDeviceNotTrustedInUser("udid", NULL);
    EXPECT_EQ(g_onDeviceNotTrustedInUserCount, 0);
}

HWTEST_F(BroadcastManagerTest, BroadcastManagerTest_PostDeviceNotTrustedInUser_WithListener, TestSize.Level0)
{
    AddListener("com.test.device.not.trusted.in.user", &g_fullListener);
    const Broadcaster *broadcaster = GetBroadcaster();
    broadcaster->postOnDeviceNotTrustedInUser("udid", "{\"groupId\":\"test\"}");
    EXPECT_EQ(g_onDeviceNotTrustedInUserCount, 1);
    RemoveListener("com.test.device.not.trusted.in.user");
}

HWTEST_F(BroadcastManagerTest, BroadcastManagerTest_AllPostFunctions_CallbackNullCheck, TestSize.Level0)
{
    AddListener("com.test.null.cb", &g_emptyListener);
    const Broadcaster *broadcaster = GetBroadcaster();
    broadcaster->postOnGroupCreated("{\"groupId\":\"test\"}");
    broadcaster->postOnGroupDeleted("{\"groupId\":\"test\"}");
    broadcaster->postOnDeviceBound("peerUdid", "{\"groupId\":\"test\"}");
    broadcaster->postOnDeviceUnBound("peerUdid", "{\"groupId\":\"test\"}");
    broadcaster->postOnDeviceNotTrusted("peerUdid");
    broadcaster->postOnLastGroupDeleted("peerUdid", 1);
    broadcaster->postOnTrustedDeviceNumChanged(5);
    broadcaster->postOnGroupActiveInUser("{\"groupId\":\"test\"}");
    broadcaster->postOnGroupInactiveInUser("{\"groupId\":\"test\"}");
    broadcaster->postOnDeviceActiveInUser("udid", "{\"groupId\":\"test\"}");
    broadcaster->postOnDeviceInactiveInUser("udid", "{\"groupId\":\"test\"}");
    broadcaster->postOnDeviceNotTrustedInUser("udid", "{\"groupId\":\"test\"}");
    EXPECT_EQ(g_onGroupCreatedCount, 0);
    EXPECT_EQ(g_onGroupDeletedCount, 0);
    EXPECT_EQ(g_onDeviceBoundCount, 0);
    EXPECT_EQ(g_onDeviceUnBoundCount, 0);
    EXPECT_EQ(g_onDeviceNotTrustedCount, 0);
    EXPECT_EQ(g_onLastGroupDeletedCount, 0);
    EXPECT_EQ(g_onTrustedDeviceNumChangedCount, 0);
    EXPECT_EQ(g_onGroupActiveInUserCount, 0);
    EXPECT_EQ(g_onGroupInactiveInUserCount, 0);
    EXPECT_EQ(g_onDeviceActiveInUserCount, 0);
    EXPECT_EQ(g_onDeviceInactiveInUserCount, 0);
    EXPECT_EQ(g_onDeviceNotTrustedInUserCount, 0);
    RemoveListener("com.test.null.cb");
}

HWTEST_F(BroadcastManagerTest, BroadcastManagerTest_AddRemoveAndBroadcast, TestSize.Level0)
{
    AddListener("com.test.addremove1", &g_fullListener);
    AddListener("com.test.addremove2", &g_fullListener);
    const Broadcaster *broadcaster = GetBroadcaster();
    broadcaster->postOnGroupCreated("{\"groupId\":\"test\"}");
    EXPECT_EQ(g_onGroupCreatedCount, 2);
    ResetCallbackCounts();
    RemoveListener("com.test.addremove1");
    broadcaster->postOnGroupCreated("{\"groupId\":\"test2\"}");
    EXPECT_EQ(g_onGroupCreatedCount, 1);
    RemoveListener("com.test.addremove2");
}

HWTEST_F(BroadcastManagerTest, BroadcastManagerTest_RemoveListenerAfterUpdate, TestSize.Level0)
{
    AddListener("com.test.remove.after.update", &g_fullListener);
    AddListener("com.test.remove.after.update", &g_partialListener);
    int32_t ret = RemoveListener("com.test.remove.after.update");
    EXPECT_EQ(ret, HC_SUCCESS);
}

HWTEST_F(BroadcastManagerTest, BroadcastManagerTest_InitBroadcastManager_ReInit, TestSize.Level0)
{
    int32_t ret = InitBroadcastManager();
    EXPECT_EQ(ret, HC_SUCCESS);
}
