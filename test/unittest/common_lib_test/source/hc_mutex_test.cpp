/*
 * Copyright (C) 2025 Huawei Device Co., Ltd.
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
#include <pthread.h>
#include "hc_mutex.h"
#include "hc_mutex_mock.h"
#include "securec.h"

using namespace testing::ext;

namespace {
static const int TEST_ITERATION_COUNT = 10;
static const int TEST_THREAD_COUNT = 5;

struct ThreadTestData {
    HcMutex *mutex;
    int *counter;
    int iterationCount;
};

void *ThreadLockUnlockRoutine(void *arg)
{
    ThreadTestData *data = static_cast<ThreadTestData *>(arg);
    for (int i = 0; i < data->iterationCount; i++) {
        LockHcMutex(data->mutex);
        (*data->counter)++;
        UnlockHcMutex(data->mutex);
    }
    return nullptr;
}

void *ThreadReentrantLockRoutine(void *arg)
{
    ThreadTestData *data = static_cast<ThreadTestData *>(arg);
    for (int i = 0; i < data->iterationCount; i++) {
        LockHcMutex(data->mutex);
        LockHcMutex(data->mutex);
        (*data->counter)++;
        UnlockHcMutex(data->mutex);
        UnlockHcMutex(data->mutex);
    }
    return nullptr;
}

class HcMutexTest : public testing::Test {
};

HWTEST_F(HcMutexTest, InitHcMutexTest001, TestSize.Level0)
{
    HcMutex mutex;
    int32_t ret = InitHcMutex(&mutex, false);
    EXPECT_EQ(ret, 0);
    EXPECT_NE(mutex.lock, nullptr);
    EXPECT_NE(mutex.unlock, nullptr);
    DestroyHcMutex(&mutex);
}

HWTEST_F(HcMutexTest, InitHcMutexTest002, TestSize.Level0)
{
    HcMutex mutex;
    int32_t ret = InitHcMutex(&mutex, true);
    EXPECT_EQ(ret, 0);
    EXPECT_NE(mutex.lock, nullptr);
    EXPECT_NE(mutex.unlock, nullptr);
    EXPECT_TRUE(mutex.isReentrant);
    DestroyHcMutex(&mutex);
}

HWTEST_F(HcMutexTest, InitHcMutexTest003, TestSize.Level0)
{
    int32_t ret = InitHcMutex(nullptr, false);
    EXPECT_EQ(ret, -1);
}

HWTEST_F(HcMutexTest, DestroyHcMutexTest001, TestSize.Level0)
{
    HcMutex mutex;
    InitHcMutex(&mutex, false);
    DestroyHcMutex(&mutex);
    EXPECT_EQ(mutex.count, 0);
    EXPECT_FALSE(mutex.isReentrant);
}

HWTEST_F(HcMutexTest, DestroyHcMutexTest002, TestSize.Level0)
{
    DestroyHcMutex(nullptr);
}

HWTEST_F(HcMutexTest, LockHcMutexTest001, TestSize.Level0)
{
    HcMutex mutex;
    InitHcMutex(&mutex, false);
    int32_t ret = LockHcMutex(&mutex);
    EXPECT_EQ(ret, 0);
    UnlockHcMutex(&mutex);
    DestroyHcMutex(&mutex);
}

HWTEST_F(HcMutexTest, LockHcMutexTest002, TestSize.Level0)
{
    int32_t ret = LockHcMutex(nullptr);
    EXPECT_EQ(ret, -1);
}

HWTEST_F(HcMutexTest, UnlockHcMutexTest001, TestSize.Level0)
{
    HcMutex mutex;
    InitHcMutex(&mutex, false);
    LockHcMutex(&mutex);
    UnlockHcMutex(&mutex);
    DestroyHcMutex(&mutex);
}

HWTEST_F(HcMutexTest, UnlockHcMutexTest002, TestSize.Level0)
{
    UnlockHcMutex(nullptr);
}

HWTEST_F(HcMutexTest, ReentrantLockTest001, TestSize.Level0)
{
    HcMutex mutex;
    InitHcMutex(&mutex, true);
    int32_t ret = LockHcMutex(&mutex);
    EXPECT_EQ(ret, 0);
    EXPECT_EQ(mutex.count, 1);
    
    ret = LockHcMutex(&mutex);
    EXPECT_EQ(ret, 0);
    EXPECT_EQ(mutex.count, 2);
    
    UnlockHcMutex(&mutex);
    EXPECT_EQ(mutex.count, 1);
    
    UnlockHcMutex(&mutex);
    EXPECT_EQ(mutex.count, 0);
    
    DestroyHcMutex(&mutex);
}

HWTEST_F(HcMutexTest, ReentrantLockTest002, TestSize.Level0)
{
    HcMutex mutex;
    InitHcMutex(&mutex, true);
    
    for (int i = 0; i < TEST_ITERATION_COUNT; i++) {
        LockHcMutex(&mutex);
    }
    EXPECT_EQ(mutex.count, TEST_ITERATION_COUNT);
    
    for (int i = 0; i < TEST_ITERATION_COUNT; i++) {
        UnlockHcMutex(&mutex);
    }
    EXPECT_EQ(mutex.count, 0);
    
    DestroyHcMutex(&mutex);
}

HWTEST_F(HcMutexTest, NonReentrantLockTest001, TestSize.Level0)
{
    HcMutex mutex;
    InitHcMutex(&mutex, false);
    
    LockHcMutex(&mutex);
    UnlockHcMutex(&mutex);
    
    LockHcMutex(&mutex);
    UnlockHcMutex(&mutex);
    
    DestroyHcMutex(&mutex);
}

HWTEST_F(HcMutexTest, MultiThreadTest001, TestSize.Level0)
{
    HcMutex mutex;
    int counter = 0;
    ThreadTestData data = { &mutex, &counter, TEST_ITERATION_COUNT };
    
    InitHcMutex(&mutex, false);
    
    pthread_t threads[TEST_THREAD_COUNT];
    for (int i = 0; i < TEST_THREAD_COUNT; i++) {
        pthread_create(&threads[i], nullptr, ThreadLockUnlockRoutine, &data);
    }
    
    for (int i = 0; i < TEST_THREAD_COUNT; i++) {
        pthread_join(threads[i], nullptr);
    }
    
    EXPECT_EQ(counter, TEST_THREAD_COUNT * TEST_ITERATION_COUNT);
    
    DestroyHcMutex(&mutex);
}

HWTEST_F(HcMutexTest, MultiThreadTest002, TestSize.Level0)
{
    HcMutex mutex;
    int counter = 0;
    ThreadTestData data = { &mutex, &counter, TEST_ITERATION_COUNT };
    
    InitHcMutex(&mutex, true);
    
    pthread_t threads[TEST_THREAD_COUNT];
    for (int i = 0; i < TEST_THREAD_COUNT; i++) {
        pthread_create(&threads[i], nullptr, ThreadReentrantLockRoutine, &data);
    }
    
    for (int i = 0; i < TEST_THREAD_COUNT; i++) {
        pthread_join(threads[i], nullptr);
    }
    
    EXPECT_EQ(counter, TEST_THREAD_COUNT * TEST_ITERATION_COUNT);
    
    DestroyHcMutex(&mutex);
}

HWTEST_F(HcMutexTest, FunctionPointerTest001, TestSize.Level0)
{
    HcMutex mutex;
    InitHcMutex(&mutex, false);
    
    EXPECT_NE(mutex.lock, nullptr);
    EXPECT_NE(mutex.unlock, nullptr);
    
    int32_t ret = mutex.lock(&mutex);
    EXPECT_EQ(ret, 0);
    
    mutex.unlock(&mutex);
    
    DestroyHcMutex(&mutex);
}

HWTEST_F(HcMutexTest, StressTest001, TestSize.Level0)
{
    HcMutex mutex;
    int counter = 0;
    const int stressThreadCount = 10;
    const int stressIterationCount = 100;
    ThreadTestData data = { &mutex, &counter, stressIterationCount };
    
    InitHcMutex(&mutex, false);
    
    pthread_t threads[stressThreadCount];
    
    for (int i = 0; i < stressThreadCount; i++) {
        pthread_create(&threads[i], nullptr, ThreadLockUnlockRoutine, &data);
    }
    
    for (int i = 0; i < stressThreadCount; i++) {
        pthread_join(threads[i], nullptr);
    }
    
    EXPECT_EQ(counter, stressThreadCount * stressIterationCount);
    
    DestroyHcMutex(&mutex);
}

HWTEST_F(HcMutexTest, ReentrantCountToZeroTest001, TestSize.Level0)
{
    HcMutex mutex;
    InitHcMutex(&mutex, true);
    
    LockHcMutex(&mutex);
    LockHcMutex(&mutex);
    LockHcMutex(&mutex);
    EXPECT_EQ(mutex.count, 3);
    
    UnlockHcMutex(&mutex);
    EXPECT_EQ(mutex.count, 2);
    EXPECT_NE(mutex.owner, 0);
    
    UnlockHcMutex(&mutex);
    EXPECT_EQ(mutex.count, 1);
    EXPECT_NE(mutex.owner, 0);
    
    UnlockHcMutex(&mutex);
    EXPECT_EQ(mutex.count, 0);
    EXPECT_EQ(mutex.owner, 0);
    
    DestroyHcMutex(&mutex);
}

HWTEST_F(HcMutexTest, InitDestroyCycleTest001, TestSize.Level0)
{
    HcMutex mutex;
    
    for (int i = 0; i < TEST_ITERATION_COUNT; i++) {
        InitHcMutex(&mutex, false);
        LockHcMutex(&mutex);
        UnlockHcMutex(&mutex);
        DestroyHcMutex(&mutex);
    }
}

HWTEST_F(HcMutexTest, InitDestroyCycleTest002, TestSize.Level0)
{
    HcMutex mutex;
    
    for (int i = 0; i < TEST_ITERATION_COUNT; i++) {
        InitHcMutex(&mutex, true);
        LockHcMutex(&mutex);
        LockHcMutex(&mutex);
        UnlockHcMutex(&mutex);
        UnlockHcMutex(&mutex);
        DestroyHcMutex(&mutex);
    }
}

HWTEST_F(HcMutexTest, LockHcMutexTest003, TestSize.Level0)
{
    HcMutex mutex;
    mutex.lock = nullptr;
    int32_t ret = LockHcMutex(&mutex);
    EXPECT_EQ(ret, -1);
}

HWTEST_F(HcMutexTest, UnlockHcMutexTest003, TestSize.Level0)
{
    HcMutex mutex;
    mutex.unlock = nullptr;
    UnlockHcMutex(&mutex);
}

HWTEST_F(HcMutexTest, PthreadMutexInitFailTest001, TestSize.Level0)
{
    HcMutex mutex;
    SetPthreadMockFlags(true, false, false, false);
    
    int32_t ret = InitHcMutex(&mutex, false);
    EXPECT_NE(ret, 0);
    
    SetPthreadMockFlags(false, false, false, false);
}

HWTEST_F(HcMutexTest, PthreadMutexLockFailTest001, TestSize.Level0)
{
    HcMutex mutex;
    InitHcMutex(&mutex, false);
    
    SetPthreadMockFlags(false, true, false, false);
    int32_t ret = LockHcMutex(&mutex);
    EXPECT_NE(ret, 0);
    
    SetPthreadMockFlags(false, false, false, false);
    DestroyHcMutex(&mutex);
}

HWTEST_F(HcMutexTest, PthreadMutexUnlockFailTest001, TestSize.Level0)
{
    HcMutex mutex;
    InitHcMutex(&mutex, false);
    LockHcMutex(&mutex);
    
    SetPthreadMockFlags(false, false, true, false);
    UnlockHcMutex(&mutex);
    
    SetPthreadMockFlags(false, false, false, false);
    DestroyHcMutex(&mutex);
}

HWTEST_F(HcMutexTest, PthreadMutexDestroyFailTest001, TestSize.Level0)
{
    HcMutex mutex;
    InitHcMutex(&mutex, false);
    
    SetPthreadMockFlags(false, false, false, true);
    DestroyHcMutex(&mutex);
    
    SetPthreadMockFlags(false, false, false, false);
}

HWTEST_F(HcMutexTest, ReentrantLockFailTest001, TestSize.Level0)
{
    HcMutex mutex;
    InitHcMutex(&mutex, true);
    
    SetPthreadMockFlags(false, true, false, false);
    int32_t ret = LockHcMutex(&mutex);
    EXPECT_NE(ret, 0);
    
    SetPthreadMockFlags(false, false, false, false);
    DestroyHcMutex(&mutex);
}

HWTEST_F(HcMutexTest, ReentrantUnlockFailTest001, TestSize.Level0)
{
    HcMutex mutex;
    InitHcMutex(&mutex, true);
    LockHcMutex(&mutex);
    LockHcMutex(&mutex);
    
    SetPthreadMockFlags(false, false, true, false);
    UnlockHcMutex(&mutex);
    UnlockHcMutex(&mutex);
    
    SetPthreadMockFlags(false, false, false, false);
    DestroyHcMutex(&mutex);
}
}
