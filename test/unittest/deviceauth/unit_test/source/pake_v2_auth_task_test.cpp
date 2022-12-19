/*
 * Copyright (C) 2021-2022 Huawei Device Co., Ltd.
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

#include "pake_v2_auth_task_test.h"
#include <cinttypes>
#include <unistd.h>
#include <gtest/gtest.h>

using namespace std;
using namespace testing::ext;

namespace {
// Beginning for pake_v2_auth_client_task.c test.
class PakeV2AuthClientTaskTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void PakeV2AuthClientTaskTest::SetUpTestCase() {}

void PakeV2AuthClientTaskTest::TearDownTestCase() {}

void PakeV2AuthClientTaskTest::SetUp() {}

void PakeV2AuthClientTaskTest::TearDown() {}

HWTEST_F(PakeV2AuthClientTaskTest, PakeV2AuthClientTaskTest001, TestSize.Level0)
{
    CJson *in = nullptr;
    CJson *out = nullptr;
    AccountVersionInfo *verInfo = nullptr;
    TaskBase *retPtr = CreatePakeV2AuthClientTask(in, out, verInfo);
    EXPECT_EQ(retPtr, nullptr);
}

HWTEST_F(PakeV2AuthClientTaskTest, PakeV2AuthClientTaskTest002, TestSize.Level0)
{
    CJson *in = CreateJson();
    CJson *out = nullptr;
    AccountVersionInfo *verInfo = nullptr;
    TaskBase *retPtr = CreatePakeV2AuthClientTask(in, out, verInfo);
    EXPECT_EQ(retPtr, nullptr);
    FreeJson(in);
}

HWTEST_F(PakeV2AuthClientTaskTest, PakeV2AuthClientTaskTest003, TestSize.Level0)
{
    CJson *in = CreateJson();
    CJson *out = CreateJson();
    AccountVersionInfo *verInfo = nullptr;
    TaskBase *retPtr = CreatePakeV2AuthClientTask(in, out, verInfo);
    EXPECT_EQ(retPtr, nullptr);
    FreeJson(in);
    FreeJson(out);
}

HWTEST_F(PakeV2AuthClientTaskTest, PakeV2AuthClientTaskTest004, TestSize.Level0)
{
    CJson *in = CreateJson();
    CJson *out = CreateJson();
    AccountVersionInfo verInfo;
    TaskBase *retPtr = CreatePakeV2AuthClientTask(in, out, &verInfo);
    EXPECT_EQ(retPtr, nullptr);
    FreeJson(in);
    FreeJson(out);
}
// Ending for pake_v2_auth_client_task.c test.

// Beginning for pake_v2_auth_server_task.c test.
class PakeV2AuthServerTaskTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void PakeV2AuthServerTaskTest::SetUpTestCase() {}

void PakeV2AuthServerTaskTest::TearDownTestCase() {}

void PakeV2AuthServerTaskTest::SetUp() {}

void PakeV2AuthServerTaskTest::TearDown() {}

HWTEST_F(PakeV2AuthServerTaskTest, PakeV2AuthServerTaskTest001, TestSize.Level0)
{
    CJson *in = nullptr;
    CJson *out = nullptr;
    AccountVersionInfo *verInfo = nullptr;
    TaskBase *retPtr = CreatePakeV2AuthServerTask(in, out, verInfo);
    EXPECT_EQ(retPtr, nullptr);
}

HWTEST_F(PakeV2AuthServerTaskTest, PakeV2AuthServerTaskTest002, TestSize.Level0)
{
    CJson *in = CreateJson();
    CJson *out = nullptr;
    AccountVersionInfo *verInfo = nullptr;
    TaskBase *retPtr = CreatePakeV2AuthServerTask(in, out, verInfo);
    EXPECT_EQ(retPtr, nullptr);
    FreeJson(in);
}

HWTEST_F(PakeV2AuthServerTaskTest, PakeV2AuthServerTaskTest003, TestSize.Level0)
{
    CJson *in = CreateJson();
    CJson *out = CreateJson();
    AccountVersionInfo *verInfo = nullptr;
    TaskBase *retPtr = CreatePakeV2AuthServerTask(in, out, verInfo);
    EXPECT_EQ(retPtr, nullptr);
    FreeJson(in);
    FreeJson(out);
}

HWTEST_F(PakeV2AuthServerTaskTest, PakeV2AuthServerTaskTest004, TestSize.Level0)
{
    CJson *in = CreateJson();
    CJson *out = CreateJson();
    AccountVersionInfo verInfo;
    TaskBase *retPtr = CreatePakeV2AuthServerTask(in, out, &verInfo);
    EXPECT_EQ(retPtr, nullptr);
    FreeJson(in);
    FreeJson(out);
}
// Ending for pake_v2_auth_server_task.c test.

// Beginning for pake_v2_auth_task_common.c test.
class PakeV2AuthTaskCommonTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void PakeV2AuthTaskCommonTest::SetUpTestCase() {}

void PakeV2AuthTaskCommonTest::TearDownTestCase() {}

void PakeV2AuthTaskCommonTest::SetUp() {}

void PakeV2AuthTaskCommonTest::TearDown() {}

HWTEST_F(PakeV2AuthTaskCommonTest, PakeV2AuthTaskCommonTest001, TestSize.Level0)
{
    CJson *in = nullptr;
    PakeAuthParams *params = nullptr;
    AccountVersionInfo *verInfo = nullptr;
    int32_t ret = InitPakeAuthParams(in, params, verInfo);
    EXPECT_NE(ret, 0);
}

HWTEST_F(PakeV2AuthTaskCommonTest, PakeV2AuthTaskCommonTest002, TestSize.Level0)
{
    CJson *in = CreateJson();
    PakeAuthParams *params = nullptr;
    AccountVersionInfo *verInfo = nullptr;
    int32_t ret = InitPakeAuthParams(in, params, verInfo);
    EXPECT_NE(ret, 0);
    FreeJson(in);
}

HWTEST_F(PakeV2AuthTaskCommonTest, PakeV2AuthTaskCommonTest003, TestSize.Level0)
{
    CJson *in = CreateJson();
    PakeAuthParams params;
    AccountVersionInfo *verInfo = nullptr;
    int32_t ret = InitPakeAuthParams(in, &params, verInfo);
    EXPECT_NE(ret, 0);
    FreeJson(in);
}

HWTEST_F(PakeV2AuthTaskCommonTest, PakeV2AuthTaskCommonTest004, TestSize.Level0)
{
    CJson *in = CreateJson();
    PakeAuthParams params;
    AccountVersionInfo verInfo;
    int32_t ret = InitPakeAuthParams(in, &params, &verInfo);
    EXPECT_NE(ret, 0);
    FreeJson(in);
}

HWTEST_F(PakeV2AuthTaskCommonTest, PakeV2AuthTaskCommonTest005, TestSize.Level0)
{
    CJson *in = CreateJson();
    PakeAuthParams params;
    AccountVersionInfo verInfo;
    int32_t ret = AddStringToJson(in, FIELD_SELF_DEVICE_ID, "device_id_unit_test");
    EXPECT_EQ(ret, 0);
    ret = InitPakeAuthParams(in, &params, &verInfo);
    EXPECT_NE(ret, 0);
    FreeJson(in);
}

HWTEST_F(PakeV2AuthTaskCommonTest, PakeV2AuthTaskCommonTest006, TestSize.Level0)
{
    CJson *in = CreateJson();
    PakeAuthParams params;
    AccountVersionInfo verInfo;
    int32_t ret = AddStringToJson(in, FIELD_SELF_DEVICE_ID, "device_id_unit_test");
    EXPECT_EQ(ret, 0);
    ret = AddIntToJson(in, FIELD_OS_ACCOUNT_ID, 0);
    EXPECT_EQ(ret, 0);
    ret = InitPakeAuthParams(in, &params, &verInfo);
    EXPECT_NE(ret, 0);
    FreeJson(in);
    DestroyPakeAuthParams(&params);
}

HWTEST_F(PakeV2AuthTaskCommonTest, PakeV2AuthTaskCommonTest007, TestSize.Level0)
{
    CJson *in = CreateJson();
    PakeAuthParams params;
    AccountVersionInfo verInfo;
    int32_t ret = AddStringToJson(in, FIELD_SELF_DEVICE_ID, "device_id_unit_test");
    EXPECT_EQ(ret, 0);
    ret = AddIntToJson(in, FIELD_OS_ACCOUNT_ID, 0);
    EXPECT_EQ(ret, 0);
    ret = AddStringToJson(in, FIELD_SELF_USER_ID, "self_user_id_unit_test");
    EXPECT_EQ(ret, 0);
    ret = InitPakeAuthParams(in, &params, &verInfo);
    EXPECT_NE(ret, 0);
    FreeJson(in);
    DestroyPakeAuthParams(&params);
}

HWTEST_F(PakeV2AuthTaskCommonTest, PakeV2AuthTaskCommonTest008, TestSize.Level0)
{
    CJson *in = CreateJson();
    PakeAuthParams params;
    AccountVersionInfo verInfo;
    int32_t ret = AddStringToJson(in, FIELD_SELF_DEVICE_ID, "device_id_unit_test");
    EXPECT_EQ(ret, 0);
    ret = AddIntToJson(in, FIELD_OS_ACCOUNT_ID, 0);
    EXPECT_EQ(ret, 0);
    ret = AddStringToJson(in, FIELD_SELF_USER_ID, "self_user_id_unit_test");
    EXPECT_EQ(ret, 0);
    ret = AddBoolToJson(in, FIELD_IS_CLIENT, true);
    EXPECT_EQ(ret, 0);
    ret = InitPakeAuthParams(in, &params, &verInfo);
    EXPECT_NE(ret, 0);
    FreeJson(in);
    DestroyPakeAuthParams(&params);
}

HWTEST_F(PakeV2AuthTaskCommonTest, PakeV2AuthTaskCommonTest100, TestSize.Level0)
{
    bool ret = IsPakeV2AuthTaskSupported();
    EXPECT_EQ(ret, true);
}

HWTEST_F(PakeV2AuthTaskCommonTest, PakeV2AuthTaskCommonTest101, TestSize.Level0)
{
    CJson *in = nullptr;
    CJson *out = nullptr;
    AccountVersionInfo *verInfo = nullptr;
    TaskBase *retPtr = CreatePakeV2AuthTask(in, out, verInfo);
    EXPECT_EQ(retPtr, nullptr);
}

HWTEST_F(PakeV2AuthTaskCommonTest, PakeV2AuthTaskCommonTest102, TestSize.Level0)
{
    CJson *in = CreateJson();
    int32_t ret = AddBoolToJson(in, FIELD_IS_CLIENT, true);
    EXPECT_EQ(ret, 0);
    CJson *out = nullptr;
    AccountVersionInfo *verInfo = nullptr;
    TaskBase *retPtr = CreatePakeV2AuthTask(in, out, verInfo);
    EXPECT_EQ(retPtr, nullptr);
    FreeJson(in);
}

// This test is blocked by no token.
HWTEST_F(PakeV2AuthTaskCommonTest, PakeV2AuthTaskCommonTest103, TestSize.Level0)
{
    PakeAuthParams params;
    InitTokenManager();
    int32_t ret = VerifyPkSignPeer(&params);
    EXPECT_NE(ret, 0);
    DestroyTokenManager();
}

HWTEST_F(PakeV2AuthTaskCommonTest, PakeV2AuthTaskCommonTest104, TestSize.Level0)
{
    PakeAuthParams params;
    InitTokenManager();
    int32_t ret = GenerateEcdhSharedKey(&params);
    EXPECT_NE(ret, 0);
    DestroyTokenManager();
}

HWTEST_F(PakeV2AuthTaskCommonTest, PakeV2AuthTaskCommonTest105, TestSize.Level0)
{
    PakeAuthParams *params = nullptr;
    CJson *in = nullptr;
    InitTokenManager();
    int32_t ret = GetPkInfoPeer(params, in);
    EXPECT_NE(ret, 0);
    DestroyTokenManager();
}

HWTEST_F(PakeV2AuthTaskCommonTest, PakeV2AuthTaskCommonTest106, TestSize.Level0)
{
    PakeAuthParams params;
    CJson *in = nullptr;
    InitTokenManager();
    int32_t ret = GetPkInfoPeer(&params, in);
    EXPECT_NE(ret, 0);
    in = CreateJson();
    ret = GetPkInfoPeer(&params, in);
    EXPECT_NE(ret, 0);
    ret = AddStringToJson(in, FIELD_AUTH_PK_INFO, "auth_pk_info");
    ret = GetPkInfoPeer(&params, in);
    EXPECT_NE(ret, 0);
    FreeJson(in);
    DestroyPakeAuthParams(&params);
    DestroyTokenManager();
}

HWTEST_F(PakeV2AuthTaskCommonTest, PakeV2AuthTaskCommonTest107, TestSize.Level0)
{
    PakeAuthParams *params = nullptr;
    InitTokenManager();
    DestroyPakeAuthParams(params);
    DestroyTokenManager();
}

HWTEST_F(PakeV2AuthTaskCommonTest, PakeV2AuthTaskCommonTest108, TestSize.Level0)
{
    PakeAuthParams *params = nullptr;
    CJson *in = nullptr;
    InitTokenManager();
    int32_t ret = ExtractPakePeerId(params, in);
    EXPECT_NE(ret, 0);
    DestroyTokenManager();
}

HWTEST_F(PakeV2AuthTaskCommonTest, PakeV2AuthTaskCommonTest109, TestSize.Level0)
{
    PakeAuthParams params;
    CJson *in = nullptr;
    InitTokenManager();
    int32_t ret = ExtractPakePeerId(&params, in);
    EXPECT_NE(ret, 0);
    DestroyPakeAuthParams(&params);
    DestroyTokenManager();
}

HWTEST_F(PakeV2AuthTaskCommonTest, PakeV2AuthTaskCommonTest110, TestSize.Level0)
{
    PakeAuthParams params;
    CJson *in = CreateJson();
    InitTokenManager();
    int32_t ret = ExtractPakePeerId(&params, in);
    EXPECT_NE(ret, 0);
    FreeJson(in);
    DestroyPakeAuthParams(&params);
    DestroyTokenManager();
}

HWTEST_F(PakeV2AuthTaskCommonTest, PakeV2AuthTaskCommonTest111, TestSize.Level0)
{
    PakeAuthParams *params = nullptr;
    InitTokenManager();
    int32_t ret = ExtractPakeSelfId(params);
    EXPECT_NE(ret, 0);
    DestroyTokenManager();
}

HWTEST_F(PakeV2AuthTaskCommonTest, PakeV2AuthTaskCommonTest112, TestSize.Level0)
{
    PakeAuthParams params;
    InitTokenManager();
    int32_t ret = ExtractPakeSelfId(&params);
    EXPECT_NE(ret, 0);
    DestroyPakeAuthParams(&params);
    DestroyTokenManager();
}

HWTEST_F(PakeV2AuthTaskCommonTest, PakeV2AuthTaskCommonTest113, TestSize.Level0)
{
    PakeAuthParams *params = nullptr;
    CJson *in = nullptr;
    InitTokenManager();
    int32_t ret = ExtractPeerDeviceId(params, in);
    EXPECT_NE(ret, 0);
    DestroyTokenManager();
}

HWTEST_F(PakeV2AuthTaskCommonTest, PakeV2AuthTaskCommonTest114, TestSize.Level0)
{
    PakeAuthParams params;
    CJson *in = nullptr;
    InitTokenManager();
    int32_t ret = ExtractPeerDeviceId(&params, in);
    EXPECT_NE(ret, 0);
    DestroyPakeAuthParams(&params);
    DestroyTokenManager();
}

HWTEST_F(PakeV2AuthTaskCommonTest, PakeV2AuthTaskCommonTest115, TestSize.Level0)
{
    PakeAuthParams params;
    CJson *in = CreateJson();
    InitTokenManager();
    int32_t ret = ExtractPeerDeviceId(&params, in);
    EXPECT_NE(ret, 0);
    ret = AddStringToJson(in, FIELD_DEVICE_ID, "device_id_unit_test");
    EXPECT_EQ(ret, 0);
    ret = ExtractPeerDeviceId(&params, in);
    EXPECT_EQ(ret, 0);
    FreeJson(in);
    DestroyPakeAuthParams(&params);
    DestroyTokenManager();
}

HWTEST_F(PakeV2AuthTaskCommonTest, PakeV2AuthTaskCommonTest116, TestSize.Level0)
{
    PakeAuthParams *params = nullptr;
    CJson *in = nullptr;
    InitTokenManager();
    int32_t ret = ExtractPeerDevId(params, in);
    EXPECT_NE(ret, 0);
    DestroyTokenManager();
}

HWTEST_F(PakeV2AuthTaskCommonTest, PakeV2AuthTaskCommonTest117, TestSize.Level0)
{
    PakeAuthParams params;
    CJson *in = nullptr;
    InitTokenManager();
    int32_t ret = ExtractPeerDevId(&params, in);
    EXPECT_NE(ret, 0);
    DestroyPakeAuthParams(&params);
    DestroyTokenManager();
}

HWTEST_F(PakeV2AuthTaskCommonTest, PakeV2AuthTaskCommonTest118, TestSize.Level0)
{
    PakeAuthParams params;
    CJson *in = CreateJson();
    InitTokenManager();
    int32_t ret = ExtractPeerDevId(&params, in);
    EXPECT_NE(ret, 0);
    ret = AddStringToJson(in, FIELD_DEV_ID, "dev_id_unit_test");
    EXPECT_EQ(ret, 0);
    ret = ExtractPeerDevId(&params, in);
    EXPECT_EQ(ret, 0);
    FreeJson(in);
    DestroyPakeAuthParams(&params);
    DestroyTokenManager();
}

// Ending for pake_v2_auth_task_common.c test.
} // NAMESPACE