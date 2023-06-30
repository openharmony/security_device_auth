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

#include <cinttypes>
#include <unistd.h>
#include <gtest/gtest.h>

#include "common_defs.h"
#include "device_auth.h"
#include "device_auth_defines.h"
#include "hc_log.h"
#include "json_utils.h"
#include "../../../../../services/group_manager/src/group_operation/peer_to_peer_group/peer_to_peer_group.c"

using namespace std;
using namespace testing::ext;

namespace {
class PeerToPeerGroupTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void PeerToPeerGroupTest::SetUpTestCase() {}
void PeerToPeerGroupTest::TearDownTestCase() {}
void PeerToPeerGroupTest::SetUp() {}
void PeerToPeerGroupTest::TearDown() {}

HWTEST_F(PeerToPeerGroupTest, PeerToPeerGroupTest001, TestSize.Level0)
{
    bool ret = IsSameNameGroupExist(DEFAULT_OS_ACCOUNT, nullptr, nullptr);
    EXPECT_EQ(ret, false);
}

HWTEST_F(PeerToPeerGroupTest, PeerToPeerGroupTest002, TestSize.Level0)
{
    int32_t ret = CheckGroupName(DEFAULT_OS_ACCOUNT, nullptr, nullptr);
    EXPECT_NE(ret, HC_SUCCESS);
}

HWTEST_F(PeerToPeerGroupTest, PeerToPeerGroupTest003, TestSize.Level0)
{
    int32_t ret = GenerateGroupId(nullptr, nullptr, nullptr);
    EXPECT_NE(ret, HC_SUCCESS);
}

HWTEST_F(PeerToPeerGroupTest, PeerToPeerGroupTest004, TestSize.Level0)
{
    int32_t ret = GeneratePeerToPeerGroupId(nullptr, nullptr);
    EXPECT_NE(ret, HC_SUCCESS);
}

HWTEST_F(PeerToPeerGroupTest, PeerToPeerGroupTest005, TestSize.Level0)
{
    int32_t ret = CheckCreateParams(DEFAULT_OS_ACCOUNT, nullptr);
    EXPECT_NE(ret, HC_SUCCESS);
}

HWTEST_F(PeerToPeerGroupTest, PeerToPeerGroupTest006, TestSize.Level0)
{
    TrustedGroupEntry groupParams;
    int32_t ret = GenerateGroupParams(nullptr, nullptr, &groupParams);
    EXPECT_NE(ret, HC_SUCCESS);
}

HWTEST_F(PeerToPeerGroupTest, PeerToPeerGroupTest007, TestSize.Level0)
{
    TrustedDeviceEntry devParams;
    int32_t ret = GenerateDevParams(nullptr, nullptr, &devParams);
    EXPECT_NE(ret, HC_SUCCESS);
}

HWTEST_F(PeerToPeerGroupTest, PeerToPeerGroupTest008, TestSize.Level0)
{
    int32_t ret = CreateGroupInner(DEFAULT_OS_ACCOUNT, nullptr, nullptr);
    EXPECT_NE(ret, HC_SUCCESS);
}

HWTEST_F(PeerToPeerGroupTest, PeerToPeerGroupTest009, TestSize.Level0)
{
    int32_t ret = GetPeerDevUserTypeFromDb(DEFAULT_OS_ACCOUNT, nullptr, nullptr);
    EXPECT_EQ(ret, DEVICE_TYPE_ACCESSORY);
}

HWTEST_F(PeerToPeerGroupTest, PeerToPeerGroupTest010, TestSize.Level0)
{
    int32_t ret = AddAuthIdAndUserTypeToParams(DEFAULT_OS_ACCOUNT, nullptr, nullptr);
    EXPECT_NE(ret, HC_SUCCESS);
}

HWTEST_F(PeerToPeerGroupTest, PeerToPeerGroupTest011, TestSize.Level0)
{
    DeviceAuthCallback callback;
    int32_t ret = HandleLocalUnbind(DEFAULT_REQUEST_ID, nullptr, &callback);
    EXPECT_NE(ret, HC_SUCCESS);
}

HWTEST_F(PeerToPeerGroupTest, PeerToPeerGroupTest012, TestSize.Level0)
{
    int32_t ret = CheckPeerDeviceStatus(DEFAULT_REQUEST_ID, nullptr, nullptr);
    EXPECT_NE(ret, HC_SUCCESS);
}

HWTEST_F(PeerToPeerGroupTest, PeerToPeerGroupTest015, TestSize.Level0)
{
    int32_t ret = CheckDeletePeerStatus(nullptr);
    EXPECT_NE(ret, HC_SUCCESS);
}

HWTEST_F(PeerToPeerGroupTest, PeerToPeerGroupTest021, TestSize.Level0)
{
    int32_t ret = CreateGroup(DEFAULT_OS_ACCOUNT, nullptr, nullptr);
    EXPECT_NE(ret, HC_SUCCESS);
}

HWTEST_F(PeerToPeerGroupTest, PeerToPeerGroupTest022, TestSize.Level0)
{
    int32_t ret = CreateGroup(DEFAULT_OS_ACCOUNT, nullptr, nullptr);
    EXPECT_NE(ret, HC_SUCCESS);
}

HWTEST_F(PeerToPeerGroupTest, PeerToPeerGroupTest023, TestSize.Level0)
{
    int32_t ret = DeleteGroup(DEFAULT_OS_ACCOUNT, nullptr, nullptr);
    EXPECT_NE(ret, HC_SUCCESS);
}

HWTEST_F(PeerToPeerGroupTest, PeerToPeerGroupTest025, TestSize.Level0)
{
    DeviceAuthCallback callback;
    int32_t ret = DeleteMemberFromGroup(DEFAULT_OS_ACCOUNT, DEFAULT_REQUEST_ID, nullptr, &callback);
    EXPECT_NE(ret, HC_SUCCESS);
}
}
