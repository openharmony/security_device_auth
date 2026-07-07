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

#include <gtest/gtest.h>
#include "dev_auth_dynamic_load.h"
#include "hc_log.h"

using namespace std;
using namespace testing::ext;

class DevAuthDynamicLoadTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void DevAuthDynamicLoadTest::SetUpTestCase()
{
}

void DevAuthDynamicLoadTest::TearDownTestCase()
{
}

void DevAuthDynamicLoadTest::SetUp()
{
}

void DevAuthDynamicLoadTest::TearDown()
{
}

HWTEST_F(DevAuthDynamicLoadTest, DevAuthDlopenTest001, TestSize.Level0)
{
    void *handle = DevAuthDlopen("/system/lib/platformsdk/libdeviceauth_sdk.z.so");
    if (handle != nullptr) {
        DevAuthDlclose(handle);
    }
}

HWTEST_F(DevAuthDynamicLoadTest, DevAuthDlopenTest002, TestSize.Level0)
{
    void *handle = DevAuthDlopen("/invalid/path/library.so");
    EXPECT_EQ(handle, nullptr);
}

HWTEST_F(DevAuthDynamicLoadTest, DevAuthDlsymTest001, TestSize.Level0)
{
    void *sym = DevAuthDlsym(NULL, "test");
    EXPECT_EQ(sym, nullptr);
}

HWTEST_F(DevAuthDynamicLoadTest, DevAuthDlsymTest002, TestSize.Level0)
{
    void *handle = DevAuthDlopen("/system/lib/platformsdk/libdeviceauth_sdk.z.so");
    if (handle != nullptr) {
        void *sym = DevAuthDlsym(handle, "InitDeviceAuth");
        if (sym != nullptr) {
            EXPECT_NE(sym, nullptr);
        }
        DevAuthDlclose(handle);
    }
}

HWTEST_F(DevAuthDynamicLoadTest, DevAuthDlsymTest003, TestSize.Level0)
{
    void *handle = DevAuthDlopen("/system/lib/platformsdk/libdeviceauth_sdk.z.so");
    if (handle != nullptr) {
        void *sym = DevAuthDlsym(handle, "InvalidSymbol");
        EXPECT_EQ(sym, nullptr);
        DevAuthDlclose(handle);
    }
}

HWTEST_F(DevAuthDynamicLoadTest, DevAuthDlcloseTest001, TestSize.Level0)
{
    DevAuthDlclose(NULL);
}
