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
#include "../../../../../services/group_manager/src/session/bind_session/bind_session_common.c"

using namespace std;
using namespace testing::ext;

namespace {
class BindSessionCommonTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void BindSessionCommonTest::SetUpTestCase() {}

void BindSessionCommonTest::TearDownTestCase() {}

void BindSessionCommonTest::SetUp()
{
    int32_t ret = InitDeviceAuthService();
    EXPECT_EQ(ret, HC_SUCCESS);
}

void BindSessionCommonTest::TearDown()
{
    DestroyDeviceAuthService();
}

HWTEST_F(BindSessionCommonTest, BindSessionCommonTest0101, TestSize.Level0)
{
    int32_t ret = HC_SUCCESS;
    BindSession session;
    session.params = nullptr;
    session.opCode = MEMBER_DELETE;  // For unit test.
    (void)AddPeerAuthIdAndUserTypeToParamsIfNeed(&session, nullptr);
    EXPECT_EQ(ret, HC_SUCCESS);
}

HWTEST_F(BindSessionCommonTest, BindSessionCommonTest0102, TestSize.Level0)
{
    int32_t ret = HC_SUCCESS;
    (void)AddGroupInfoByDatabase(ANY_OS_ACCOUNT, nullptr, nullptr);
    EXPECT_EQ(ret, HC_SUCCESS);
}

HWTEST_F(BindSessionCommonTest, BindSessionCommonTest0103, TestSize.Level0)
{
    int32_t ret = HC_SUCCESS;
    (void)AddGroupName(nullptr, nullptr);
    EXPECT_EQ(ret, HC_SUCCESS);
}

HWTEST_F(BindSessionCommonTest, BindSessionCommonTest0104, TestSize.Level0)
{
    int32_t ret = HC_SUCCESS;
    (void)AddGroupOwnerIfExist(nullptr, nullptr);
    EXPECT_EQ(ret, HC_SUCCESS);
}

HWTEST_F(BindSessionCommonTest, BindSessionCommonTest0105, TestSize.Level0)
{
    int32_t ret = HC_SUCCESS;
    (void)AddGroupTypeIfValid(nullptr, nullptr);
    EXPECT_EQ(ret, HC_SUCCESS);
}

HWTEST_F(BindSessionCommonTest, BindSessionCommonTest0106, TestSize.Level0)
{
    int32_t ret = HC_SUCCESS;
    (void)AddGroupVisibilityIfValidOrDefault(nullptr, nullptr);
    EXPECT_EQ(ret, HC_SUCCESS);
}

HWTEST_F(BindSessionCommonTest, BindSessionCommonTest0107, TestSize.Level0)
{
    int32_t ret = HC_SUCCESS;
    (void)AddExpireTimeIfValidOrDefault(nullptr, nullptr);
    EXPECT_EQ(ret, HC_SUCCESS);
}

HWTEST_F(BindSessionCommonTest, BindSessionCommonTest0108, TestSize.Level0)
{
    int32_t ret = HC_SUCCESS;
    (void)AddAuthIdAndUserTypeIfValidOrDefault(ANY_OS_ACCOUNT, nullptr, nullptr, nullptr);
    EXPECT_EQ(ret, HC_SUCCESS);
}

HWTEST_F(BindSessionCommonTest, BindSessionCommonTest0109, TestSize.Level0)
{
    int32_t ret = HC_SUCCESS;
    BindSession session;
    session.params = nullptr;
    (void)AddDevInfoToSendData(&session, nullptr);
    EXPECT_EQ(ret, HC_SUCCESS);
}

HWTEST_F(BindSessionCommonTest, BindSessionCommonTest0110, TestSize.Level0)
{
    int32_t ret = HC_SUCCESS;
    BindSession session;
    session.params = nullptr;
    (void)AddGroupInfoToSendData(&session, nullptr);
    EXPECT_EQ(ret, HC_SUCCESS);
}

HWTEST_F(BindSessionCommonTest, BindSessionCommonTest0111, TestSize.Level0)
{
    int32_t ret = HC_SUCCESS;
    (void)GenerateCompatibleInfo(nullptr);
    EXPECT_EQ(ret, HC_SUCCESS);
}

HWTEST_F(BindSessionCommonTest, BindSessionCommonTest0112, TestSize.Level0)
{
    int32_t ret = HC_SUCCESS;
    (void)AddCompatibleInfoToSendData(true, nullptr); // For unit test.
    EXPECT_EQ(ret, HC_SUCCESS);
}

HWTEST_F(BindSessionCommonTest, BindSessionCommonTest0113, TestSize.Level0)
{
    int32_t ret = HC_SUCCESS;
    BindSession session;
    session.params = nullptr;
    (void)AddGroupAndDevInfoToParams(&session, nullptr);
    EXPECT_EQ(ret, HC_SUCCESS);
}

HWTEST_F(BindSessionCommonTest, BindSessionCommonTest0114, TestSize.Level0)
{
    int32_t ret = HC_SUCCESS;
    BindSession session;
    session.params = nullptr;
    session.opCode = MEMBER_JOIN;  // For unit test.
    (void)AddPinCodeToParamsIfNeed(&session, nullptr);
    EXPECT_EQ(ret, HC_SUCCESS);
}

HWTEST_F(BindSessionCommonTest, BindSessionCommonTest0115, TestSize.Level0)
{
    int32_t ret = HC_SUCCESS;
    BindSession session;
    session.params = nullptr;
    session.opCode = MEMBER_JOIN;  // For unit test.
    (void)AddPeerAuthIdToParams(&session, nullptr);
    EXPECT_EQ(ret, HC_SUCCESS);
}

HWTEST_F(BindSessionCommonTest, BindSessionCommonTest0116, TestSize.Level0)
{
    int32_t ret = HC_SUCCESS;
    BindSession session;
    session.params = nullptr;
    session.opCode = MEMBER_JOIN;  // For unit test.
    (void)AddPeerUserTypeToParams(&session, nullptr);
    EXPECT_EQ(ret, HC_SUCCESS);
}

HWTEST_F(BindSessionCommonTest, BindSessionCommonTest0117, TestSize.Level0)
{
    int32_t ret = HC_SUCCESS;
    (void)AddUserTypeIfValidOrDefault(nullptr, nullptr);
    EXPECT_EQ(ret, HC_SUCCESS);
}

HWTEST_F(BindSessionCommonTest, BindSessionCommonTest0118, TestSize.Level0)
{
    int32_t ret = HC_SUCCESS;
    (void)AddGroupInfoToSessionParams(nullptr, nullptr, nullptr);
    EXPECT_EQ(ret, HC_SUCCESS);
}

HWTEST_F(BindSessionCommonTest, BindSessionCommonTest0119, TestSize.Level0)
{
    int32_t ret = HC_SUCCESS;
    (void)AddDevInfoToSessionParams(ANY_OS_ACCOUNT, nullptr, nullptr, nullptr);
    EXPECT_EQ(ret, HC_SUCCESS);
}

HWTEST_F(BindSessionCommonTest, BindSessionCommonTest0120, TestSize.Level0)
{
    int32_t ret = HC_SUCCESS;
    (void)GenerateParamsByInput(ANY_OS_ACCOUNT, nullptr, nullptr, nullptr);
    EXPECT_EQ(ret, HC_SUCCESS);
}

HWTEST_F(BindSessionCommonTest, BindSessionCommonTest0121, TestSize.Level0)
{
    int32_t ret = HC_SUCCESS;
    (void)GenerateParamsByDatabase(ANY_OS_ACCOUNT, nullptr, nullptr);
    EXPECT_EQ(ret, HC_SUCCESS);
}

HWTEST_F(BindSessionCommonTest, BindSessionCommonTest0122, TestSize.Level0)
{
    int32_t ret = HC_SUCCESS;
    BindSession session;
    session.params = nullptr;
    session.opCode = MEMBER_DELETE;  // For unit test.
    (void)AddChannelIdIfNeed(CLIENT, nullptr, &session);
    EXPECT_EQ(ret, HC_SUCCESS);
}

HWTEST_F(BindSessionCommonTest, BindSessionCommonTest0123, TestSize.Level0)
{
    int32_t ret = HC_SUCCESS;
    BindSession session;
    session.params = nullptr;
    session.opCode = MEMBER_DELETE;  // For unit test.
    (void)AddPinCodeIfNeed(nullptr, &session);
    EXPECT_EQ(ret, HC_SUCCESS);
}

HWTEST_F(BindSessionCommonTest, BindSessionCommonTest0124, TestSize.Level0)
{
    int32_t ret = HC_SUCCESS;
    BindSession session;
    session.params = nullptr;
    session.opCode = MEMBER_DELETE;  // For unit test.
    (void)AddPeerAuthIdIfDelete(true, nullptr, &session);
    EXPECT_EQ(ret, HC_SUCCESS);
}

HWTEST_F(BindSessionCommonTest, BindSessionCommonTest0125, TestSize.Level0)
{
    int32_t ret = HC_SUCCESS;
    BindSession session;
    session.params = nullptr;
    session.opCode = MEMBER_DELETE;  // For unit test.
    (void)AddPeerUserTypeIfDelete(&session);
    EXPECT_EQ(ret, HC_SUCCESS);
}

HWTEST_F(BindSessionCommonTest, BindSessionCommonTest0126, TestSize.Level0)
{
    int32_t ret = HC_SUCCESS;
    BindSession session;
    session.params = nullptr;
    session.opCode = MEMBER_DELETE;  // For unit test.
    (void)AddPeerDevInfoIfNeed(CLIENT, nullptr, &session);
    EXPECT_EQ(ret, HC_SUCCESS);
}

HWTEST_F(BindSessionCommonTest, BindSessionCommonTest0127, TestSize.Level0)
{
    int32_t ret = HC_SUCCESS;
    BindSession session;
    session.params = nullptr;
    session.opCode = MEMBER_DELETE;  // For unit test.
    (void)AddGroupAndDevInfo(ANY_OS_ACCOUNT, CLIENT, nullptr, &session);
    EXPECT_EQ(ret, HC_SUCCESS);
}

HWTEST_F(BindSessionCommonTest, BindSessionCommonTest0128, TestSize.Level0)
{
    int32_t ret = HC_SUCCESS;
    BindSession session;
    session.params = nullptr;
    session.opCode = MEMBER_DELETE;  // For unit test.
    (void)InteractWithPeer(&session, nullptr);
    EXPECT_EQ(ret, HC_SUCCESS);
}

HWTEST_F(BindSessionCommonTest, BindSessionCommonTest0129, TestSize.Level0)
{
    int32_t ret = HC_SUCCESS;
    BindSession session;
    session.params = nullptr;
    session.opCode = MEMBER_DELETE;  // For unit test.
    (void)InformSelfUnbindSuccess(nullptr, nullptr, &session);
    EXPECT_EQ(ret, HC_SUCCESS);
}

HWTEST_F(BindSessionCommonTest, BindSessionCommonTest0130, TestSize.Level0)
{
    int32_t ret = HC_SUCCESS;

    (void)SetGroupId(nullptr, nullptr);
    EXPECT_EQ(ret, HC_SUCCESS);
}

HWTEST_F(BindSessionCommonTest, BindSessionCommonTest0131, TestSize.Level0)
{
    int32_t ret = HC_SUCCESS;
    (void)SetGroupName(nullptr, nullptr);
    EXPECT_EQ(ret, HC_SUCCESS);
}

HWTEST_F(BindSessionCommonTest, BindSessionCommonTest0132, TestSize.Level0)
{
    int32_t ret = HC_SUCCESS;
    (void)ForceDeletePeerKey(nullptr);
    EXPECT_EQ(ret, HC_SUCCESS);
}

HWTEST_F(BindSessionCommonTest, BindSessionCommonTest0133, TestSize.Level0)
{
    int32_t ret = HC_SUCCESS;
    BindSession session;
    session.params = nullptr;
    session.opCode = MEMBER_DELETE;  // For unit test.
    (void)GenerateGroupParams(&session, nullptr);
    EXPECT_EQ(ret, HC_SUCCESS);
}

HWTEST_F(BindSessionCommonTest, BindSessionCommonTest0134, TestSize.Level0)
{
    int32_t ret = HC_SUCCESS;
    BindSession session;
    session.params = nullptr;
    session.opCode = MEMBER_DELETE;  // For unit test.
    (void)AddPeerDevToGroup(nullptr, nullptr, nullptr, &session);
    EXPECT_EQ(ret, HC_SUCCESS);
}

HWTEST_F(BindSessionCommonTest, BindSessionCommonTest0135, TestSize.Level0)
{
    int32_t ret = HC_SUCCESS;
    BindSession session;
    session.params = nullptr;
    session.opCode = MEMBER_DELETE;  // For unit test.
    (void)AddGroupAndDev(nullptr, nullptr, nullptr, &session);
    EXPECT_EQ(ret, HC_SUCCESS);
}

HWTEST_F(BindSessionCommonTest, BindSessionCommonTest0136, TestSize.Level0)
{
    int32_t ret = HC_SUCCESS;
    BindSession session;
    session.params = nullptr;
    session.opCode = MEMBER_DELETE;  // For unit test.
    (void)HandleBindSuccess(nullptr, nullptr, nullptr, &session, nullptr);
    EXPECT_EQ(ret, HC_SUCCESS);
}

HWTEST_F(BindSessionCommonTest, BindSessionCommonTest0137, TestSize.Level0)
{
    int32_t ret = HC_SUCCESS;
    BindSession session;
    session.params = nullptr;
    session.opCode = MEMBER_DELETE;  // For unit test.
    (void)OnBindOrUnbindFinish(&session, nullptr, nullptr);
    EXPECT_EQ(ret, HC_SUCCESS);
}

HWTEST_F(BindSessionCommonTest, BindSessionCommonTest0138, TestSize.Level0)
{
    int32_t ret = HC_SUCCESS;
    BindSession session;
    session.params = nullptr;
    session.opCode = MEMBER_DELETE;  // For unit test.
    bool isNeedInform = false;
    int32_t status = IGNORE_MSG;
    (void)ProcessBindSessionInner(&session, nullptr, &status, &isNeedInform);
    EXPECT_EQ(ret, HC_SUCCESS);
}

HWTEST_F(BindSessionCommonTest, BindSessionCommonTest0139, TestSize.Level0)
{
    int32_t ret = HC_SUCCESS;
    (void)ProcessBindSession(nullptr, nullptr);
    EXPECT_EQ(ret, HC_SUCCESS);
}

HWTEST_F(BindSessionCommonTest, BindSessionCommonTest0140, TestSize.Level0)
{
    int32_t ret = HC_SUCCESS;
    BindSession session;
    session.params = nullptr;
    session.opCode = MEMBER_DELETE;  // For unit test.
    (void)ForceUnbindDevice(&session);
    EXPECT_EQ(ret, HC_SUCCESS);
}

HWTEST_F(BindSessionCommonTest, BindSessionCommonTest0141, TestSize.Level0)
{
    int32_t ret = HC_SUCCESS;
    BindSession session;
    session.params = nullptr;
    session.opCode = MEMBER_DELETE;  // For unit test.
    (void)AddInfoToSendData(false, &session, nullptr);
    EXPECT_EQ(ret, HC_SUCCESS);
}

HWTEST_F(BindSessionCommonTest, BindSessionCommonTest0142, TestSize.Level0)
{
    int32_t ret = HC_SUCCESS;
    BindSession session;
    session.params = nullptr;
    session.opCode = MEMBER_DELETE;  // For unit test.
    (void)GenerateBasicModuleParams(true, &session, nullptr);
    EXPECT_EQ(ret, HC_SUCCESS);
}
}