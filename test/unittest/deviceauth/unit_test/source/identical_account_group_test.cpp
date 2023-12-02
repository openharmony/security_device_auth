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
#include "../../../../../services/legacy/group_manager/src/group_operation/identical_account_group/identical_account_group.c"

using namespace std;
using namespace testing::ext;

namespace {
class IdenticalAccountGroupTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void IdenticalAccountGroupTest::SetUpTestCase() {}
void IdenticalAccountGroupTest::TearDownTestCase() {}
void IdenticalAccountGroupTest::SetUp() {}
void IdenticalAccountGroupTest::TearDown() {}

HWTEST_F(IdenticalAccountGroupTest, IdenticalAccountGroupTest001, TestSize.Level0)
{
    TrustedDeviceEntry trustedDeviceEntry;
    int32_t ret = GenerateDevParams(nullptr, nullptr, &trustedDeviceEntry);
    EXPECT_NE(ret, HC_SUCCESS);
}

HWTEST_F(IdenticalAccountGroupTest, IdenticalAccountGroupTest002, TestSize.Level0)
{
    TrustedGroupEntry trustedGroupEntry;
    int32_t ret = GenerateGroupParams(nullptr, nullptr, &trustedGroupEntry);
    EXPECT_NE(ret, HC_SUCCESS);
}

HWTEST_F(IdenticalAccountGroupTest, IdenticalAccountGroupTest003, TestSize.Level0)
{
    int32_t ret = GenerateGroupId(nullptr, nullptr);
    EXPECT_NE(ret, HC_SUCCESS);
}

HWTEST_F(IdenticalAccountGroupTest, IdenticalAccountGroupTest004, TestSize.Level0)
{
    int32_t ret = GenerateIdenticalGroupId(nullptr, nullptr);
    EXPECT_NE(ret, HC_SUCCESS);
}

HWTEST_F(IdenticalAccountGroupTest, IdenticalAccountGroupTest005, TestSize.Level0)
{
    int32_t ret = AssertCredentialExist(nullptr);
    EXPECT_NE(ret, HC_SUCCESS);
}

HWTEST_F(IdenticalAccountGroupTest, IdenticalAccountGroupTest006, TestSize.Level0)
{
    int32_t ret = CheckCreateParams(DEFAULT_OS_ACCOUNT, nullptr);
    EXPECT_NE(ret, HC_SUCCESS);
}

HWTEST_F(IdenticalAccountGroupTest, IdenticalAccountGroupTest008, TestSize.Level0)
{
    int32_t ret = ImportSelfToken(DEFAULT_OS_ACCOUNT, nullptr);
    EXPECT_NE(ret, HC_SUCCESS);
}

HWTEST_F(IdenticalAccountGroupTest, IdenticalAccountGroupTest009, TestSize.Level0)
{
    int32_t ret = DelSelfToken(DEFAULT_OS_ACCOUNT, nullptr);
    EXPECT_NE(ret, HC_SUCCESS);
}

HWTEST_F(IdenticalAccountGroupTest, IdenticalAccountGroupTest010, TestSize.Level0)
{
    int32_t ret = GenerateAddTokenParams(nullptr, nullptr);
    EXPECT_NE(ret, HC_SUCCESS);
}

HWTEST_F(IdenticalAccountGroupTest, IdenticalAccountGroupTest011, TestSize.Level0)
{
    TrustedDeviceEntry entry;
    int32_t ret = GenerateDelTokenParams(&entry, nullptr);
    EXPECT_NE(ret, HC_SUCCESS);
}

HWTEST_F(IdenticalAccountGroupTest, IdenticalAccountGroupTest012, TestSize.Level0)
{
    TrustedDeviceEntry entry;
    int32_t ret = DelDeviceToken(DEFAULT_OS_ACCOUNT, &entry, false);
    EXPECT_NE(ret, HC_SUCCESS);
}

HWTEST_F(IdenticalAccountGroupTest, IdenticalAccountGroupTest016, TestSize.Level0)
{
    GroupEntryVec vec;
    int32_t ret = GetRelatedAcrossAccountGroups(DEFAULT_OS_ACCOUNT, nullptr, &vec);
    EXPECT_NE(ret, HC_SUCCESS);
}

HWTEST_F(IdenticalAccountGroupTest, IdenticalAccountGroupTest017, TestSize.Level0)
{
    GroupEntryVec vec;
    int32_t ret = GetRelatedAcrossAccountGroups(DEFAULT_OS_ACCOUNT, nullptr, &vec);
    EXPECT_NE(ret, HC_SUCCESS);
}

HWTEST_F(IdenticalAccountGroupTest, IdenticalAccountGroupTest018, TestSize.Level0)
{
    int32_t ret = DelRelatedAcrossAccountGroups(DEFAULT_OS_ACCOUNT, nullptr);
    EXPECT_EQ(ret, HC_SUCCESS);
}

HWTEST_F(IdenticalAccountGroupTest, IdenticalAccountGroupTest020, TestSize.Level0)
{
    TrustedDeviceEntry devParams;
    int32_t ret = GenerateTrustedDevParams(nullptr, nullptr, &devParams);
    EXPECT_NE(ret, HC_SUCCESS);
}

HWTEST_F(IdenticalAccountGroupTest, IdenticalAccountGroupTest021, TestSize.Level0)
{
    int32_t ret = CheckPeerDeviceNotSelf(nullptr);
    EXPECT_NE(ret, HC_SUCCESS);
}

HWTEST_F(IdenticalAccountGroupTest, IdenticalAccountGroupTest022, TestSize.Level0)
{
    int32_t ret = AddDeviceAndToken(DEFAULT_OS_ACCOUNT, nullptr, nullptr);
    EXPECT_NE(ret, HC_SUCCESS);
}

HWTEST_F(IdenticalAccountGroupTest, IdenticalAccountGroupTest023, TestSize.Level0)
{
    int32_t ret = DelPeerDeviceAndToken(DEFAULT_OS_ACCOUNT, nullptr, nullptr);
    EXPECT_NE(ret, HC_SUCCESS);
}

HWTEST_F(IdenticalAccountGroupTest, IdenticalAccountGroupTest024, TestSize.Level0)
{
    int32_t ret = CheckChangeParams(DEFAULT_OS_ACCOUNT, nullptr, nullptr);
    EXPECT_NE(ret, HC_SUCCESS);
}

HWTEST_F(IdenticalAccountGroupTest, IdenticalAccountGroupTest025, TestSize.Level0)
{
    int32_t ret = AddGroupAndToken(DEFAULT_OS_ACCOUNT, nullptr, nullptr);
    EXPECT_NE(ret, HC_SUCCESS);
}

HWTEST_F(IdenticalAccountGroupTest, IdenticalAccountGroupTest026, TestSize.Level0)
{
    int32_t ret = CheckUserIdValid(DEFAULT_OS_ACCOUNT, nullptr, nullptr);
    EXPECT_NE(ret, HC_SUCCESS);
}

HWTEST_F(IdenticalAccountGroupTest, IdenticalAccountGroupTest027, TestSize.Level0)
{
    int32_t ret = CheckDeviceInfoValid(DEFAULT_OS_ACCOUNT, nullptr, nullptr);
    EXPECT_NE(ret, HC_SUCCESS);
}

HWTEST_F(IdenticalAccountGroupTest, IdenticalAccountGroupTest028, TestSize.Level0)
{
    int32_t ret = CreateGroup(DEFAULT_OS_ACCOUNT, nullptr, nullptr);
    EXPECT_NE(ret, HC_SUCCESS);
}

HWTEST_F(IdenticalAccountGroupTest, IdenticalAccountGroupTest029, TestSize.Level0)
{
    int32_t ret = DeleteGroup(DEFAULT_OS_ACCOUNT, nullptr, nullptr);
    EXPECT_NE(ret, HC_SUCCESS);
}

HWTEST_F(IdenticalAccountGroupTest, IdenticalAccountGroupTest030, TestSize.Level0)
{
    int32_t ret = AddMultiMembersToGroup(DEFAULT_OS_ACCOUNT, nullptr, nullptr);
    EXPECT_NE(ret, HC_SUCCESS);
}

HWTEST_F(IdenticalAccountGroupTest, IdenticalAccountGroupTest031, TestSize.Level0)
{
    int32_t ret = DelMultiMembersFromGroup(DEFAULT_OS_ACCOUNT, nullptr, nullptr);
    EXPECT_NE(ret, HC_SUCCESS);
}
}