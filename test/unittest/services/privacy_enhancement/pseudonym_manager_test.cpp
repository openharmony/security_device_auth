/*
 * Copyright (C) 2024 Huawei Device Co., Ltd.
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
#include <gmock/gmock.h>
#include "device_auth_defines.h"
#include "pseudonym_manager.h"
#include "hc_file_mock.h"
#include "hc_dev_info_mock.h"
#include "os_account_adapter_mock.h"

using namespace std;
using namespace testing;
using namespace testing::ext;

namespace {
#define TEST_PSEUDONYM_ID "1234ABCD"
#define TEST_PSEUDONYM_ID2 "4567ABCD"
#define TEST_DEVICE_ID "TestAuthId"
#define TEST_DEVICE_ID2 "TestAuthId2"
#define TEST_REAL_INFO "37364761534f454d33567a73424e794f33573330507069434b31676f7254706b"
#define TEST_REAL_INFO2 "87364761534f454d33567a73424e794f33573330507069434b31676f72547068"
#define TEST_INDEX_KEY "DCBA4321"
#define TEST_INDEX_KEY2 "DCBA6789"

static const char *MOCK_PSEUDONYM_PATH = "/data/service/el1/public/deviceauth/pseudonym";
static const int MOCK_FILE_OPEN_SUCCESS = 0;
static const int MOCK_FILE_OPEN_FAIL = -1;
static const int MOCK_FILE_WRITE_SIZE_ARG_INDEX = 2;

static void ExpectDbWriteSuccess(NiceMock<MockHcFile> &mock)
{
    EXPECT_CALL(mock, HcFileOpen(_, MODE_FILE_WRITE, _)).WillOnce(Return(MOCK_FILE_OPEN_SUCCESS));
    EXPECT_CALL(mock, HcFileWrite(_, _, _)).WillOnce(ReturnArg<MOCK_FILE_WRITE_SIZE_ARG_INDEX>());
    EXPECT_CALL(mock, HcFileClose(_));
}

static void ExpectDbWriteFail(NiceMock<MockHcFile> &mock)
{
    EXPECT_CALL(mock, HcFileOpen(_, MODE_FILE_WRITE, _)).WillOnce(Return(MOCK_FILE_OPEN_FAIL));
}

class PseudonymManagerTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();

protected:
    static NiceMock<MockHcFile> g_mockHcFile;
    static NiceMock<MockHcDevInfo> g_mockHcDevInfo;
    static NiceMock<MockOsAccountAdapter> g_mockOsAccountAdapter;
};

NiceMock<MockHcFile> PseudonymManagerTest::g_mockHcFile;
NiceMock<MockHcDevInfo> PseudonymManagerTest::g_mockHcDevInfo;
NiceMock<MockOsAccountAdapter> PseudonymManagerTest::g_mockOsAccountAdapter;

void PseudonymManagerTest::SetUpTestCase()
{
    SetMockHcFile(&g_mockHcFile);
    SetMockHcDevInfo(&g_mockHcDevInfo);
    SetMockOsAccountAdapter(&g_mockOsAccountAdapter);
}

void PseudonymManagerTest::TearDownTestCase()
{
    SetMockHcFile(nullptr);
    SetMockHcDevInfo(nullptr);
    SetMockOsAccountAdapter(nullptr);
}

void PseudonymManagerTest::SetUp()
{
    ON_CALL(g_mockOsAccountAdapter, IsOsAccountSupported())
        .WillByDefault(Return(false));
    ON_CALL(g_mockOsAccountAdapter, GetCurrentActiveOsAccountId())
        .WillByDefault(Return(DEFAULT_OS_ACCOUNT));
    ON_CALL(g_mockOsAccountAdapter, DevAuthGetRealOsAccountLocalId(_))
        .WillByDefault(ReturnArg<0>());
    ON_CALL(g_mockOsAccountAdapter, IsOsAccountUnlocked(_))
        .WillByDefault(Return(true));
    ON_CALL(g_mockOsAccountAdapter, CheckIsForegroundOsAccountId(_))
        .WillByDefault(Return(true));
    ON_CALL(g_mockOsAccountAdapter, AddOsAccountEventCallback(_, _, _))
        .WillByDefault(Return());
    ON_CALL(g_mockHcDevInfo, GetPseudonymStoragePath())
        .WillByDefault(Return(MOCK_PSEUDONYM_PATH));

    PseudonymManager *manager = GetPseudonymInstance();
    ASSERT_NE(manager, nullptr);
    manager->loadPseudonymData();
}

void PseudonymManagerTest::TearDown()
{
    DestroyPseudonymManager();
}

HWTEST_F(PseudonymManagerTest, PseudonymManager_SaveDbFailRollback001, TestSize.Level0)
{
    PseudonymManager *manager = GetPseudonymInstance();
    ASSERT_NE(manager, nullptr);

    InSequence seq;
    ExpectDbWriteSuccess(g_mockHcFile);
    ExpectDbWriteFail(g_mockHcFile);
    ExpectDbWriteSuccess(g_mockHcFile);

    int32_t ret = manager->savePseudonymId(
        DEFAULT_OS_ACCOUNT, TEST_PSEUDONYM_ID, TEST_REAL_INFO, TEST_DEVICE_ID, TEST_INDEX_KEY);
    EXPECT_EQ(ret, HC_SUCCESS);

    ret = manager->savePseudonymId(
        DEFAULT_OS_ACCOUNT, TEST_PSEUDONYM_ID2, TEST_REAL_INFO2, TEST_DEVICE_ID2, TEST_INDEX_KEY2);
    EXPECT_NE(ret, HC_SUCCESS);

    char *realInfo = nullptr;
    ret = manager->getRealInfo(DEFAULT_OS_ACCOUNT, TEST_PSEUDONYM_ID2, &realInfo);
    EXPECT_NE(ret, HC_SUCCESS);

    char *realInfo2 = nullptr;
    ret = manager->getRealInfo(DEFAULT_OS_ACCOUNT, TEST_PSEUDONYM_ID, &realInfo2);
    EXPECT_EQ(ret, HC_SUCCESS);
    HcFree(realInfo2);

    ret = manager->deletePseudonymId(DEFAULT_OS_ACCOUNT, TEST_INDEX_KEY);
    EXPECT_EQ(ret, HC_SUCCESS);
}

HWTEST_F(PseudonymManagerTest, PseudonymManager_SaveDbFailRollback002, TestSize.Level0)
{
    PseudonymManager *manager = GetPseudonymInstance();
    ASSERT_NE(manager, nullptr);

    InSequence seq;
    ExpectDbWriteSuccess(g_mockHcFile);
    ExpectDbWriteFail(g_mockHcFile);
    ExpectDbWriteSuccess(g_mockHcFile);

    int32_t ret = manager->savePseudonymId(
        DEFAULT_OS_ACCOUNT, TEST_PSEUDONYM_ID, TEST_REAL_INFO, TEST_DEVICE_ID, TEST_INDEX_KEY);
    EXPECT_EQ(ret, HC_SUCCESS);

    ret = manager->savePseudonymId(
        DEFAULT_OS_ACCOUNT, TEST_PSEUDONYM_ID2, TEST_REAL_INFO2, TEST_DEVICE_ID2, TEST_INDEX_KEY2);
    EXPECT_NE(ret, HC_SUCCESS);

    char *pseudonymId = nullptr;
    ret = manager->getPseudonymId(DEFAULT_OS_ACCOUNT, TEST_INDEX_KEY2, &pseudonymId);
    EXPECT_NE(ret, HC_SUCCESS);

    char *pseudonymId2 = nullptr;
    ret = manager->getPseudonymId(DEFAULT_OS_ACCOUNT, TEST_INDEX_KEY, &pseudonymId2);
    EXPECT_EQ(ret, HC_SUCCESS);
    HcFree(pseudonymId2);

    ret = manager->deletePseudonymId(DEFAULT_OS_ACCOUNT, TEST_INDEX_KEY);
    EXPECT_EQ(ret, HC_SUCCESS);
}

HWTEST_F(PseudonymManagerTest, PseudonymManager_SaveDbFailRollback003, TestSize.Level0)
{
    PseudonymManager *manager = GetPseudonymInstance();
    ASSERT_NE(manager, nullptr);

    InSequence seq;
    ExpectDbWriteSuccess(g_mockHcFile);
    ExpectDbWriteFail(g_mockHcFile);
    ExpectDbWriteSuccess(g_mockHcFile);

    int32_t ret = manager->savePseudonymId(
        DEFAULT_OS_ACCOUNT, TEST_PSEUDONYM_ID, TEST_REAL_INFO, TEST_DEVICE_ID, TEST_INDEX_KEY);
    EXPECT_EQ(ret, HC_SUCCESS);

    ret = manager->savePseudonymId(
        DEFAULT_OS_ACCOUNT, TEST_PSEUDONYM_ID2, TEST_REAL_INFO2, TEST_DEVICE_ID2, TEST_INDEX_KEY2);
    EXPECT_NE(ret, HC_SUCCESS);

    ret = manager->deleteAllPseudonymId(DEFAULT_OS_ACCOUNT, TEST_DEVICE_ID2);
    EXPECT_NE(ret, HC_SUCCESS);

    ret = manager->deleteAllPseudonymId(DEFAULT_OS_ACCOUNT, TEST_DEVICE_ID);
    EXPECT_EQ(ret, HC_SUCCESS);
}

HWTEST_F(PseudonymManagerTest, PseudonymManager_SaveDbFailRollback004, TestSize.Level0)
{
    PseudonymManager *manager = GetPseudonymInstance();
    ASSERT_NE(manager, nullptr);

    InSequence seq;
    ExpectDbWriteSuccess(g_mockHcFile);
    ExpectDbWriteSuccess(g_mockHcFile);
    ExpectDbWriteFail(g_mockHcFile);
    ExpectDbWriteSuccess(g_mockHcFile);
    ExpectDbWriteSuccess(g_mockHcFile);

    int32_t ret = manager->savePseudonymId(
        DEFAULT_OS_ACCOUNT, TEST_PSEUDONYM_ID, TEST_REAL_INFO, TEST_DEVICE_ID, TEST_INDEX_KEY);
    EXPECT_EQ(ret, HC_SUCCESS);

    ret = manager->savePseudonymId(
        DEFAULT_OS_ACCOUNT, TEST_PSEUDONYM_ID2, TEST_REAL_INFO2, TEST_DEVICE_ID2, TEST_INDEX_KEY2);
    EXPECT_EQ(ret, HC_SUCCESS);

    ret = manager->savePseudonymId(
        DEFAULT_OS_ACCOUNT, "NEWPSDID", "NEWWREALINFO", TEST_DEVICE_ID2, "NEWKEY");
    EXPECT_NE(ret, HC_SUCCESS);

    char *pseudonymId = nullptr;
    ret = manager->getPseudonymId(DEFAULT_OS_ACCOUNT, "NEWKEY", &pseudonymId);
    EXPECT_NE(ret, HC_SUCCESS);

    char *pseudonymId1 = nullptr;
    ret = manager->getPseudonymId(DEFAULT_OS_ACCOUNT, TEST_INDEX_KEY, &pseudonymId1);
    EXPECT_EQ(ret, HC_SUCCESS);
    HcFree(pseudonymId1);

    char *pseudonymId2 = nullptr;
    ret = manager->getPseudonymId(DEFAULT_OS_ACCOUNT, TEST_INDEX_KEY2, &pseudonymId2);
    EXPECT_EQ(ret, HC_SUCCESS);
    HcFree(pseudonymId2);

    ret = manager->deletePseudonymId(DEFAULT_OS_ACCOUNT, TEST_INDEX_KEY);
    EXPECT_EQ(ret, HC_SUCCESS);

    ret = manager->deletePseudonymId(DEFAULT_OS_ACCOUNT, TEST_INDEX_KEY2);
    EXPECT_EQ(ret, HC_SUCCESS);
}
}
