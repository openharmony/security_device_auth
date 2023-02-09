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
#include "../../../../../services/group_manager/src/session/bind_session/bind_session_server.c"

using namespace std;
using namespace testing::ext;

namespace {
class BindSessionServerTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void BindSessionServerTest::SetUpTestCase() {}

void BindSessionServerTest::TearDownTestCase() {}

void BindSessionServerTest::SetUp()
{
    int ret = InitDeviceAuthService();
    EXPECT_EQ(ret, HC_SUCCESS);
}

void BindSessionServerTest::TearDown()
{
    DestroyDeviceAuthService();
}

HWTEST_F(BindSessionServerTest, BindSessionServerTest0101, TestSize.Level0)
{
    int32_t ret = HC_SUCCESS;
    (void)AddRecvModuleDataToParams(nullptr, nullptr);
    EXPECT_EQ(ret, HC_SUCCESS);
}

HWTEST_F(BindSessionServerTest, BindSessionServerTest0102, TestSize.Level0)
{
    int32_t ret = HC_SUCCESS;
    BindSession session;
    (void)GenerateServerModuleParams(&session, nullptr, nullptr);
    EXPECT_EQ(ret, HC_SUCCESS);
}

HWTEST_F(BindSessionServerTest, BindSessionServerTest0103, TestSize.Level0)
{
    int32_t ret = HC_SUCCESS;
    BindSession session;
    (void)GetServerModuleReturnData(&session, nullptr, nullptr, nullptr);
    EXPECT_EQ(ret, HC_SUCCESS);
}

HWTEST_F(BindSessionServerTest, BindSessionServerTest0104, TestSize.Level0)
{
    int32_t ret = HC_SUCCESS;
    (void)GenerateRequestParams(nullptr, nullptr);
    EXPECT_EQ(ret, HC_SUCCESS);
}

HWTEST_F(BindSessionServerTest, BindSessionServerTest0105, TestSize.Level0)
{
    int32_t ret = HC_SUCCESS;
    BindSession session;
    (void)RequestConfirmation(nullptr, &session, nullptr);
    EXPECT_EQ(ret, HC_SUCCESS);
}

HWTEST_F(BindSessionServerTest, BindSessionServerTest0106, TestSize.Level0)
{
    int32_t ret = HC_SUCCESS;
    (void)AddAuthIdIfExist(nullptr, nullptr);
    EXPECT_EQ(ret, HC_SUCCESS);
}

HWTEST_F(BindSessionServerTest, BindSessionServerTest0107, TestSize.Level0)
{
    int32_t ret = HC_SUCCESS;
    (void)AddUserTypeIfExistAndValid(nullptr, nullptr);
    EXPECT_EQ(ret, HC_SUCCESS);
}

HWTEST_F(BindSessionServerTest, BindSessionServerTest0108, TestSize.Level0)
{
    int32_t ret = HC_SUCCESS;
    (void)AddGroupVisibilityIfExistAndValid(nullptr, nullptr);
    EXPECT_EQ(ret, HC_SUCCESS);
}

HWTEST_F(BindSessionServerTest, BindSessionServerTest0109, TestSize.Level0)
{
    int32_t ret = HC_SUCCESS;
    (void)AddExpireTimeIfExistAndValid(nullptr, nullptr);
    EXPECT_EQ(ret, HC_SUCCESS);
}


HWTEST_F(BindSessionServerTest, BindSessionServerTest0110, TestSize.Level0)
{
    int32_t ret = HC_SUCCESS;
    (void)AddPinCode(nullptr, nullptr);
    EXPECT_EQ(ret, HC_SUCCESS);
}

HWTEST_F(BindSessionServerTest, BindSessionServerTest0111, TestSize.Level0)
{
    int32_t ret = HC_SUCCESS;
    (void)CombineInputData(MEMBER_JOIN, nullptr, nullptr);
    EXPECT_EQ(ret, HC_SUCCESS);
}

HWTEST_F(BindSessionServerTest, BindSessionServerTest0112, TestSize.Level0)
{
    int32_t ret = HC_SUCCESS;
    (void)CheckServerStatusIfNotInvite(ANY_OS_ACCOUNT, MEMBER_DELETE, nullptr);
    EXPECT_EQ(ret, HC_SUCCESS);
}

HWTEST_F(BindSessionServerTest, BindSessionServerTest0113, TestSize.Level0)
{
    int32_t ret = HC_SUCCESS;
    BindSession session;
    (void)PrepareServer(&session, nullptr, nullptr);
    EXPECT_EQ(ret, HC_SUCCESS);
}

HWTEST_F(BindSessionServerTest, BindSessionServerTest0114, TestSize.Level0)
{
    int32_t ret = HC_SUCCESS;
    BindSession session;
    (void)JudgeConfirmation(nullptr, nullptr, &session, nullptr);
    EXPECT_EQ(ret, HC_SUCCESS);
}

HWTEST_F(BindSessionServerTest, BindSessionServerTest0115, TestSize.Level0)
{
    int32_t ret = HC_SUCCESS;
    (void)CreateServerBindSession(nullptr, nullptr);
    EXPECT_EQ(ret, HC_SUCCESS);
}
}