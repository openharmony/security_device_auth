/*
 * Copyright (C) 2026 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <gtest/gtest.h>
#include <cstring>
#include "hc_dev_info.h"

using namespace std;
using namespace testing::ext;
namespace {
class HcDevInfoTest : public testing::Test {};

HWTEST_F(HcDevInfoTest, HcGetUdidNullTest001, TestSize.Level0)
{
    int32_t res = HcGetUdid(NULL, 65);
    EXPECT_NE(res, 0);
}

HWTEST_F(HcDevInfoTest, HcGetUdidLenTooSmallTest001, TestSize.Level0)
{
    uint8_t udid[64] = {0};
    int32_t res = HcGetUdid(udid, 64);
    EXPECT_NE(res, 0);
}

HWTEST_F(HcDevInfoTest, HcGetUdidLenTooLargeTest001, TestSize.Level0)
{
    uint8_t udid[201] = {0};
    int32_t res = HcGetUdid(udid, 201);
    EXPECT_NE(res, 0);
}

HWTEST_F(HcDevInfoTest, HcGetUdidValidTest001, TestSize.Level0)
{
    uint8_t udid[65] = {0};
    int32_t res = HcGetUdid(udid, 65);
    EXPECT_EQ(res, 0);
}

HWTEST_F(HcDevInfoTest, HcGetUdidValidLen200Test001, TestSize.Level0)
{
    uint8_t udid[200] = {0};
    int32_t res = HcGetUdid(udid, 200);
    EXPECT_EQ(res, 0);
}

HWTEST_F(HcDevInfoTest, GetStoragePathTest001, TestSize.Level0)
{
    const char *path = GetStoragePath();
    EXPECT_NE(path, nullptr);
    EXPECT_STRNE(path, "");
}

HWTEST_F(HcDevInfoTest, GetStorageDirPathCeTest001, TestSize.Level0)
{
    const char *path = GetStorageDirPathCe();
    EXPECT_NE(path, nullptr);
    EXPECT_STRNE(path, "");
}

HWTEST_F(HcDevInfoTest, GetStorageDirPathTest001, TestSize.Level0)
{
    const char *path = GetStorageDirPath();
    EXPECT_NE(path, nullptr);
    EXPECT_STRNE(path, "");
}

HWTEST_F(HcDevInfoTest, GetAccountStoragePathTest001, TestSize.Level0)
{
    const char *path = GetAccountStoragePath();
    EXPECT_NE(path, nullptr);
    EXPECT_STRNE(path, "");
}

HWTEST_F(HcDevInfoTest, GetPseudonymStoragePathTest001, TestSize.Level0)
{
    const char *path = GetPseudonymStoragePath();
    EXPECT_NE(path, nullptr);
    EXPECT_STRNE(path, "");
}
}
