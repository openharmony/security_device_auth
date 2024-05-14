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
#include "device_auth_defines.h"
#include "hc_dev_info_mock.h"
#include "pseudonym_manager.h"

using namespace std;
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

static const std::string TEST_GROUP_DATA_PATH = "/data/service/el1/public/deviceauthMock";
static const int TEST_DEV_AUTH_BUFFER_SIZE = 128;

class PrivacyEnhancementTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void PrivacyEnhancementTest::SetUpTestCase() {}
void PrivacyEnhancementTest::TearDownTestCase() {}

static void RemoveDir(const char *path)
{
    char strBuf[TEST_DEV_AUTH_BUFFER_SIZE] = { 0 };
    if (path == nullptr) {
        return;
    }
    if (sprintf_s(strBuf, sizeof(strBuf) - 1, "rm -rf %s", path) < 0) {
        return;
    }
    system(strBuf);
}

static void DeleteDatabase()
{
    RemoveDir(TEST_GROUP_DATA_PATH.c_str());
}

void PrivacyEnhancementTest::SetUp()
{
    DeleteDatabase();
    PseudonymManager *manager = GetPseudonymInstance();
    ASSERT_NE(manager, nullptr);
    manager->loadPseudonymData();
}

void PrivacyEnhancementTest::TearDown()
{
    DestroyPseudonymManager();
}

HWTEST_F(PrivacyEnhancementTest, GetRealInfoTest001, TestSize.Level0)
{
    PseudonymManager *manager = GetPseudonymInstance();
    ASSERT_NE(manager, nullptr);
    char *pdid1 = nullptr;
    char *peerInfo1 = nullptr;
    int32_t ret = manager->getRealInfo(DEFAULT_OS_ACCOUNT, pdid1, &peerInfo1);
    EXPECT_NE(ret, HC_SUCCESS);

    char *peerInfo2 = nullptr;
    ret = manager->getRealInfo(DEFAULT_OS_ACCOUNT, TEST_PSEUDONYM_ID, &peerInfo2);
    EXPECT_EQ(ret, HC_SUCCESS);
}

HWTEST_F(PrivacyEnhancementTest, GetRealInfoTest002, TestSize.Level0)
{
    PseudonymManager *manager = GetPseudonymInstance();
    ASSERT_NE(manager, nullptr);

    int32_t ret = manager->savePseudonymId(
        DEFAULT_OS_ACCOUNT, TEST_PSEUDONYM_ID, TEST_REAL_INFO, TEST_DEVICE_ID, TEST_INDEX_KEY);
    EXPECT_EQ(ret, HC_SUCCESS);

    char *realInfo1 = nullptr;
    ret = manager->getRealInfo(DEFAULT_OS_ACCOUNT, TEST_PSEUDONYM_ID, &realInfo1);
    EXPECT_EQ(ret, HC_SUCCESS);
    EXPECT_EQ(*realInfo1, *(TEST_REAL_INFO));
    HcFree(realInfo1);

    char *realInfo2 = nullptr;
    ret = manager->getRealInfo(DEFAULT_OS_ACCOUNT, TEST_PSEUDONYM_ID2, &realInfo2);
    EXPECT_EQ(ret, HC_SUCCESS);
    HcFree(realInfo2);

    ret = manager->deletePseudonymId(DEFAULT_OS_ACCOUNT, TEST_INDEX_KEY);
    EXPECT_EQ(ret, HC_SUCCESS);
}

HWTEST_F(PrivacyEnhancementTest, GetPseudonymIdTest001, TestSize.Level0)
{
    PseudonymManager *manager = GetPseudonymInstance();
    ASSERT_NE(manager, nullptr);

    int32_t ret = manager->savePseudonymId(
        DEFAULT_OS_ACCOUNT, TEST_PSEUDONYM_ID, TEST_REAL_INFO, TEST_DEVICE_ID, TEST_INDEX_KEY);
    EXPECT_EQ(ret, HC_SUCCESS);

    char *indexKey1 = nullptr;
    char *pseudonymId1 = nullptr;
    ret = manager->getPseudonymId(DEFAULT_OS_ACCOUNT, indexKey1, &pseudonymId1);
    EXPECT_NE(ret, HC_SUCCESS);

    char *pseudonymId2 = nullptr;
    ret = manager->getPseudonymId(DEFAULT_OS_ACCOUNT, TEST_INDEX_KEY, &pseudonymId2);
    EXPECT_EQ(ret, HC_SUCCESS);
    HcFree(pseudonymId2);

    char *pseudonymId3 = nullptr;
    ret = manager->getPseudonymId(DEFAULT_OS_ACCOUNT, TEST_INDEX_KEY2, &pseudonymId3);
    EXPECT_EQ(ret, HC_SUCCESS);
    HcFree(pseudonymId3);

    ret = manager->deletePseudonymId(DEFAULT_OS_ACCOUNT, TEST_INDEX_KEY);
    EXPECT_EQ(ret, HC_SUCCESS);
}

HWTEST_F(PrivacyEnhancementTest, GetPseudonymIdTest002, TestSize.Level0)
{
    PseudonymManager *manager = GetPseudonymInstance();
    ASSERT_NE(manager, nullptr);

    char *indexKey1 = nullptr;
    char *pseudonymId1 = nullptr;
    int32_t ret = manager->getPseudonymId(DEFAULT_OS_ACCOUNT, indexKey1, &pseudonymId1);
    EXPECT_NE(ret, HC_SUCCESS);

    ret = manager->savePseudonymId(
        DEFAULT_OS_ACCOUNT, TEST_PSEUDONYM_ID, TEST_REAL_INFO, TEST_DEVICE_ID, TEST_INDEX_KEY);
    EXPECT_EQ(ret, HC_SUCCESS);

    char *pseudonymId2 = nullptr;
    ret = manager->getPseudonymId(DEFAULT_OS_ACCOUNT, TEST_INDEX_KEY, &pseudonymId2);
    EXPECT_EQ(*pseudonymId2, *(TEST_PSEUDONYM_ID));
    EXPECT_EQ(ret, HC_SUCCESS);
    HcFree(pseudonymId2);

    ret = manager->deletePseudonymId(DEFAULT_OS_ACCOUNT, TEST_INDEX_KEY);
    EXPECT_EQ(ret, HC_SUCCESS);
}

HWTEST_F(PrivacyEnhancementTest, SavePseudonymIdTest001, TestSize.Level0)
{
    PseudonymManager *manager = GetPseudonymInstance();
    ASSERT_NE(manager, nullptr);

    int32_t ret = manager->savePseudonymId(
        DEFAULT_OS_ACCOUNT, nullptr, TEST_REAL_INFO, TEST_DEVICE_ID, TEST_INDEX_KEY);
    EXPECT_NE(ret, HC_SUCCESS);

    ret = manager->savePseudonymId(DEFAULT_OS_ACCOUNT, TEST_PSEUDONYM_ID, nullptr, TEST_DEVICE_ID, TEST_INDEX_KEY);
    EXPECT_NE(ret, HC_SUCCESS);

    ret = manager->savePseudonymId(DEFAULT_OS_ACCOUNT, TEST_PSEUDONYM_ID, TEST_REAL_INFO, nullptr, TEST_INDEX_KEY);
    EXPECT_NE(ret, HC_SUCCESS);

    ret = manager->savePseudonymId(DEFAULT_OS_ACCOUNT, TEST_PSEUDONYM_ID, TEST_REAL_INFO, TEST_DEVICE_ID, nullptr);
    EXPECT_NE(ret, HC_SUCCESS);
}

HWTEST_F(PrivacyEnhancementTest, SavePseudonymIdTest002, TestSize.Level0)
{
    PseudonymManager *manager = GetPseudonymInstance();
    ASSERT_NE(manager, nullptr);

    int32_t ret = manager->savePseudonymId(
        DEFAULT_OS_ACCOUNT, TEST_PSEUDONYM_ID, TEST_REAL_INFO, TEST_DEVICE_ID, TEST_INDEX_KEY);
    EXPECT_EQ(ret, HC_SUCCESS);

    ret = manager->savePseudonymId(
        DEFAULT_OS_ACCOUNT, TEST_PSEUDONYM_ID2, TEST_REAL_INFO2, TEST_DEVICE_ID2, TEST_INDEX_KEY2);
    EXPECT_EQ(ret, HC_SUCCESS);

    ret = manager->savePseudonymId(
        DEFAULT_OS_ACCOUNT, TEST_PSEUDONYM_ID, TEST_REAL_INFO, TEST_DEVICE_ID, TEST_INDEX_KEY2);
    EXPECT_EQ(ret, HC_SUCCESS);

    ret = manager->savePseudonymId(
        DEFAULT_OS_ACCOUNT, TEST_PSEUDONYM_ID2, TEST_REAL_INFO2, TEST_DEVICE_ID2, TEST_INDEX_KEY);
    EXPECT_EQ(ret, HC_SUCCESS);

    ret = manager->deletePseudonymId(DEFAULT_OS_ACCOUNT, TEST_INDEX_KEY);
    EXPECT_EQ(ret, HC_SUCCESS);

    ret = manager->deletePseudonymId(DEFAULT_OS_ACCOUNT, TEST_INDEX_KEY2);
    EXPECT_EQ(ret, HC_SUCCESS);
}

HWTEST_F(PrivacyEnhancementTest, DeleteAllPseudonymIdTest001, TestSize.Level0)
{
    PseudonymManager *manager = GetPseudonymInstance();
    ASSERT_NE(manager, nullptr);

    int32_t ret = manager->deleteAllPseudonymId(DEFAULT_OS_ACCOUNT, nullptr);
    EXPECT_NE(ret, HC_SUCCESS);

    ret = manager->savePseudonymId(
        DEFAULT_OS_ACCOUNT, TEST_PSEUDONYM_ID, TEST_REAL_INFO, TEST_DEVICE_ID, TEST_INDEX_KEY);
    EXPECT_EQ(ret, HC_SUCCESS);

    ret = manager->savePseudonymId(
        DEFAULT_OS_ACCOUNT, TEST_PSEUDONYM_ID2, TEST_REAL_INFO2, TEST_DEVICE_ID, TEST_INDEX_KEY2);
    EXPECT_EQ(ret, HC_SUCCESS);

    ret = manager->deleteAllPseudonymId(DEFAULT_OS_ACCOUNT, TEST_DEVICE_ID);
    EXPECT_EQ(ret, HC_SUCCESS);
}

HWTEST_F(PrivacyEnhancementTest, DeletePseudonymIdTest001, TestSize.Level0)
{
    PseudonymManager *manager = GetPseudonymInstance();
    ASSERT_NE(manager, nullptr);

    int32_t ret = manager->deletePseudonymId(DEFAULT_OS_ACCOUNT, nullptr);
    EXPECT_NE(ret, HC_SUCCESS);

    ret = manager->savePseudonymId(
        DEFAULT_OS_ACCOUNT, TEST_PSEUDONYM_ID, TEST_REAL_INFO, TEST_DEVICE_ID, TEST_INDEX_KEY);
    EXPECT_EQ(ret, HC_SUCCESS);

    ret = manager->deletePseudonymId(DEFAULT_OS_ACCOUNT, TEST_INDEX_KEY);
    EXPECT_EQ(ret, HC_SUCCESS);
}

HWTEST_F(PrivacyEnhancementTest, IsNeedRefreshPseudonymIdTest001, TestSize.Level0)
{
    PseudonymManager *manager = GetPseudonymInstance();
    ASSERT_NE(manager, nullptr);

    int32_t ret = manager->isNeedRefreshPseudonymId(DEFAULT_OS_ACCOUNT, nullptr);
    EXPECT_NE(ret, HC_SUCCESS);

    ret = manager->savePseudonymId(
        DEFAULT_OS_ACCOUNT, TEST_PSEUDONYM_ID, TEST_REAL_INFO, TEST_DEVICE_ID, TEST_INDEX_KEY);
    EXPECT_EQ(ret, HC_SUCCESS);

    ret = manager->isNeedRefreshPseudonymId(DEFAULT_OS_ACCOUNT, TEST_INDEX_KEY);
    EXPECT_EQ(ret, HC_SUCCESS);

    ret = manager->deletePseudonymId(DEFAULT_OS_ACCOUNT, TEST_INDEX_KEY);
    EXPECT_EQ(ret, HC_SUCCESS);
}
}