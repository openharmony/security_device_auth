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
#include "hc_condition.h"

using namespace testing::ext;

class HcConditionTest : public testing::Test {
public:
    static void SetUpTestCase() {}
    static void TearDownTestCase() {}
    void SetUp() {}
    void TearDown() {}
};

HWTEST_F(HcConditionTest, InitHcCondNullTest001, TestSize.Level0)
{
    int32_t ret = InitHcCond(nullptr, nullptr);
    EXPECT_EQ(ret, -1);
}

HWTEST_F(HcConditionTest, InitHcCondWithExternalMutexTest001, TestSize.Level0)
{
    HcMutex mutex;
    int32_t mutexRet = InitHcMutex(&mutex, false);
    EXPECT_EQ(mutexRet, 0);

    HcCondition cond;
    int32_t ret = InitHcCond(&cond, &mutex);
    EXPECT_EQ(ret, 0);
    EXPECT_EQ(cond.innerMutex, HC_FALSE);
    EXPECT_EQ(cond.mutex, &mutex);

    DestroyHcCond(&cond);
    DestroyHcMutex(&mutex);
}

HWTEST_F(HcConditionTest, InitHcCondWithNullMutexTest001, TestSize.Level0)
{
    HcCondition cond;
    int32_t ret = InitHcCond(&cond, nullptr);
    EXPECT_EQ(ret, 0);
    EXPECT_EQ(cond.innerMutex, HC_TRUE);
    EXPECT_NE(cond.mutex, nullptr);

    DestroyHcCond(&cond);
}

HWTEST_F(HcConditionTest, DestroyHcCondNullTest001, TestSize.Level0)
{
    DestroyHcCond(nullptr);
    SUCCEED();
}

HWTEST_F(HcConditionTest, NotifyWithoutLockTest001, TestSize.Level0)
{
    HcCondition cond;
    int32_t ret = InitHcCond(&cond, nullptr);
    EXPECT_EQ(ret, 0);

    (void)LockHcMutex(cond.mutex);
    cond.notifyWithoutLock(&cond);
    UnlockHcMutex(cond.mutex);
    EXPECT_EQ(cond.notified, HC_TRUE);

    DestroyHcCond(&cond);
}

HWTEST_F(HcConditionTest, WaitWithoutLockNotifiedTest001, TestSize.Level0)
{
    HcCondition cond;
    int32_t ret = InitHcCond(&cond, nullptr);
    EXPECT_EQ(ret, 0);

    (void)LockHcMutex(cond.mutex);
    cond.notifyWithoutLock(&cond);
    EXPECT_EQ(cond.notified, HC_TRUE);

    int waitRet = cond.waitWithoutLock(&cond);
    EXPECT_EQ(waitRet, 0);

    UnlockHcMutex(cond.mutex);
    DestroyHcCond(&cond);
}

HWTEST_F(HcConditionTest, NotifyAndWaitTest001, TestSize.Level0)
{
    HcCondition cond;
    int32_t ret = InitHcCond(&cond, nullptr);
    EXPECT_EQ(ret, 0);

    cond.notify(&cond);
    EXPECT_EQ(cond.notified, HC_TRUE);

    int waitRet = cond.wait(&cond);
    EXPECT_EQ(waitRet, 0);

    DestroyHcCond(&cond);
}

HWTEST_F(HcConditionTest, CondWaitNullCondTest001, TestSize.Level0)
{
    HcCondition cond;
    int32_t ret = InitHcCond(&cond, nullptr);
    EXPECT_EQ(ret, 0);

    HcMutex *savedMutex = cond.mutex;
    cond.mutex = nullptr;
    int waitRet = cond.wait(&cond);
    EXPECT_EQ(waitRet, -1);
    cond.mutex = savedMutex;

    DestroyHcCond(&cond);
}

HWTEST_F(HcConditionTest, CondNotifyNullMutexTest001, TestSize.Level0)
{
    HcCondition cond;
    int32_t ret = InitHcCond(&cond, nullptr);
    EXPECT_EQ(ret, 0);

    HcMutex *savedMutex = cond.mutex;
    cond.mutex = nullptr;
    cond.notify(&cond);
    cond.mutex = savedMutex;

    DestroyHcCond(&cond);
}

HWTEST_F(HcConditionTest, WaitWithoutLockNullCondTest001, TestSize.Level0)
{
    HcCondition cond;
    int32_t ret = InitHcCond(&cond, nullptr);
    EXPECT_EQ(ret, 0);
    int waitRet = cond.waitWithoutLock(nullptr);
    EXPECT_EQ(waitRet, -1);
    DestroyHcCond(&cond);
}

HWTEST_F(HcConditionTest, NotifyWithoutLockNullCondTest001, TestSize.Level0)
{
    HcCondition cond;
    int32_t ret = InitHcCond(&cond, nullptr);
    EXPECT_EQ(ret, 0);
    cond.notifyWithoutLock(nullptr);
    DestroyHcCond(&cond);
}

HWTEST_F(HcConditionTest, DestroyHcCondWithInnerMutexTest001, TestSize.Level0)
{
    HcCondition cond;
    int32_t ret = InitHcCond(&cond, nullptr);
    EXPECT_EQ(ret, 0);
    EXPECT_EQ(cond.innerMutex, HC_TRUE);
    EXPECT_NE(cond.mutex, nullptr);

    DestroyHcCond(&cond);
}
