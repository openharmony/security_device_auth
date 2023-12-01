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
#include "../../../../../services/legacy/group_manager/src/group_operation/across_account_group/across_account_group.c"

using namespace std;
using namespace testing::ext;

namespace {

class AcrossAccountGroupTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void AcrossAccountGroupTest::SetUpTestCase() {}
void AcrossAccountGroupTest::TearDownTestCase() {}
void AcrossAccountGroupTest::SetUp() {}
void AcrossAccountGroupTest::TearDown() {}

HWTEST_F(AcrossAccountGroupTest, AcrossAccountGroupTest001, TestSize.Level0)
{
    int32_t ret = CompareString(nullptr, nullptr);
    EXPECT_EQ(ret, 0);
}

HWTEST_F(AcrossAccountGroupTest, AcrossAccountGroupTest002, TestSize.Level0)
{
    int32_t ret = GenerateGroupId(nullptr, nullptr, nullptr);
    EXPECT_NE(ret, HC_SUCCESS);
}

HWTEST_F(AcrossAccountGroupTest, AcrossAccountGroupTest003, TestSize.Level0)
{
    int32_t ret = AddCredTypeToParamsFromIdenticalGroup(DEFAULT_OS_ACCOUNT, nullptr);
    EXPECT_NE(ret, HC_SUCCESS);
}

HWTEST_F(AcrossAccountGroupTest, AcrossAccountGroupTest004, TestSize.Level0)
{
    TrustedDeviceEntry devParams;
    int32_t ret = GenerateDevParams(nullptr, nullptr, &devParams);
    EXPECT_NE(ret, HC_SUCCESS);
}

HWTEST_F(AcrossAccountGroupTest, AcrossAccountGroupTest005, TestSize.Level0)
{
    TrustedGroupEntry groupParams;
    int32_t ret = GenerateGroupParams(nullptr, nullptr, &groupParams);
    EXPECT_NE(ret, HC_SUCCESS);
}

HWTEST_F(AcrossAccountGroupTest, AcrossAccountGroupTest006, TestSize.Level0)
{
    int32_t ret = GenerateAcrossAccountGroupId(nullptr, nullptr);
    EXPECT_NE(ret, HC_SUCCESS);
}

HWTEST_F(AcrossAccountGroupTest, AcrossAccountGroupTest007, TestSize.Level0)
{
    int32_t ret = AssertIdenticalGroupExist(DEFAULT_OS_ACCOUNT, nullptr);
    EXPECT_NE(ret, HC_SUCCESS);
}

HWTEST_F(AcrossAccountGroupTest, AcrossAccountGroupTest008, TestSize.Level0)
{
    int32_t ret = AssertSharedUserIdValid(nullptr);
    EXPECT_NE(ret, HC_SUCCESS);
}

HWTEST_F(AcrossAccountGroupTest, AcrossAccountGroupTest009, TestSize.Level0)
{
    int32_t ret = CheckCreateParams(DEFAULT_OS_ACCOUNT, nullptr);
    EXPECT_NE(ret, HC_SUCCESS);
}

HWTEST_F(AcrossAccountGroupTest, AcrossAccountGroupTest010, TestSize.Level0)
{
    int32_t ret = GenerateAddTokenParams(nullptr, nullptr);
    EXPECT_NE(ret, HC_SUCCESS);
}

HWTEST_F(AcrossAccountGroupTest, AcrossAccountGroupTest011, TestSize.Level0)
{
    TrustedDeviceEntry entry;
    int32_t ret = GenerateDelTokenParams(&entry, nullptr);
    EXPECT_NE(ret, HC_SUCCESS);
}

HWTEST_F(AcrossAccountGroupTest, AcrossAccountGroupTest012, TestSize.Level0)
{
    int32_t ret = CheckChangeParams(DEFAULT_OS_ACCOUNT, nullptr, nullptr);
    EXPECT_NE(ret, HC_SUCCESS);
}

HWTEST_F(AcrossAccountGroupTest, AcrossAccountGroupTest013, TestSize.Level0)
{
    TrustedDeviceEntry entry;
    int32_t ret = GenerateTrustedDevParams(nullptr, nullptr, &entry);
    EXPECT_NE(ret, HC_SUCCESS);
}

HWTEST_F(AcrossAccountGroupTest, AcrossAccountGroupTest014, TestSize.Level0)
{
    int32_t ret = CheckPeerDeviceNotSelf(nullptr);
    EXPECT_NE(ret, HC_SUCCESS);
}

HWTEST_F(AcrossAccountGroupTest, AcrossAccountGroupTest015, TestSize.Level0)
{
    int32_t ret = AddDeviceAndToken(DEFAULT_OS_ACCOUNT, nullptr, nullptr);
    EXPECT_NE(ret, HC_SUCCESS);
}

HWTEST_F(AcrossAccountGroupTest, AcrossAccountGroupTest016, TestSize.Level0)
{
    int32_t ret = AddGroupAndLocalDev(DEFAULT_OS_ACCOUNT, nullptr, nullptr);
    EXPECT_NE(ret, HC_SUCCESS);
}

HWTEST_F(AcrossAccountGroupTest, AcrossAccountGroupTest017, TestSize.Level0)
{
    int32_t ret = CheckUserIdValid(DEFAULT_OS_ACCOUNT, nullptr, nullptr);
    EXPECT_NE(ret, HC_SUCCESS);
}

HWTEST_F(AcrossAccountGroupTest, AcrossAccountGroupTest018, TestSize.Level0)
{
    int32_t ret = CheckDeviceInfoValid(DEFAULT_OS_ACCOUNT, nullptr, nullptr);
    EXPECT_NE(ret, HC_SUCCESS);
}

HWTEST_F(AcrossAccountGroupTest, AcrossAccountGroupTest020, TestSize.Level0)
{
    int32_t ret = CreateGroup(DEFAULT_OS_ACCOUNT, nullptr, nullptr);
    EXPECT_NE(ret, HC_SUCCESS);
}

HWTEST_F(AcrossAccountGroupTest, AcrossAccountGroupTest021, TestSize.Level0)
{
    int32_t ret = CreateGroup(DEFAULT_OS_ACCOUNT, nullptr, nullptr);
    EXPECT_NE(ret, HC_SUCCESS);
}

HWTEST_F(AcrossAccountGroupTest, AcrossAccountGroupTest022, TestSize.Level0)
{
    int32_t ret = DeleteGroup(DEFAULT_OS_ACCOUNT, nullptr, nullptr);
    EXPECT_NE(ret, HC_SUCCESS);
}

HWTEST_F(AcrossAccountGroupTest, AcrossAccountGroupTest023, TestSize.Level0)
{
    int32_t ret = AddMultiMembersToGroup(DEFAULT_OS_ACCOUNT, nullptr, nullptr);
    EXPECT_NE(ret, HC_SUCCESS);
}
}