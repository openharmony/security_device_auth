/*
 * Copyright (C) 2026 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <gtest/gtest.h>
#include "hc_init_protection.h"

using namespace testing::ext;

class HcInitProtectionTest : public testing::Test {
public:
    static void SetUpTestCase() {}
    static void TearDownTestCase() {}
    void SetUp() {}
    void TearDown() {}
};

HWTEST_F(HcInitProtectionTest, CheckInitTest001, TestSize.Level0)
{
    int ret = CheckInit();
    EXPECT_EQ(ret, CONTINUE_INIT);
}

HWTEST_F(HcInitProtectionTest, CheckDestroyTest001, TestSize.Level0)
{
    int ret = CheckDestroy();
    EXPECT_EQ(ret, FINISH_DESTROY);
}

HWTEST_F(HcInitProtectionTest, SetInitStatusTest001, TestSize.Level0)
{
    SetInitStatus();
    int ret = CheckInit();
    EXPECT_EQ(ret, FINISH_INIT);
    ret = CheckDestroy();
    EXPECT_EQ(ret, CONTINUE_DESTROY);
}

HWTEST_F(HcInitProtectionTest, SetDeInitStatusTest001, TestSize.Level0)
{
    SetInitStatus();
    SetDeInitStatus();
    int ret = CheckInit();
    EXPECT_EQ(ret, CONTINUE_INIT);
    ret = CheckDestroy();
    EXPECT_EQ(ret, FINISH_DESTROY);
}

HWTEST_F(HcInitProtectionTest, StateTransitionTest001, TestSize.Level0)
{
    SetDeInitStatus();
    EXPECT_EQ(CheckInit(), CONTINUE_INIT);
    EXPECT_EQ(CheckDestroy(), FINISH_DESTROY);
    SetInitStatus();
    EXPECT_EQ(CheckInit(), FINISH_INIT);
    EXPECT_EQ(CheckDestroy(), CONTINUE_DESTROY);
    SetDeInitStatus();
    EXPECT_EQ(CheckInit(), CONTINUE_INIT);
    EXPECT_EQ(CheckDestroy(), FINISH_DESTROY);
}
