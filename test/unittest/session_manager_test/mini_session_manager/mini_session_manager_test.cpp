/*
 * Copyright (C) 2026 Huawei Device Co., Ltd.
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
#include <gmock/gmock.h>
#include <unistd.h>
#include "mini_session_manager.h"
#include "hc_log.h"
#include "hc_types.h"
#include "common_defs.h"
#include "callback_manager.h"
#include "clib_error.h"
#include "hc_types_mock.h"
#include "hc_mutex_mock.h"
#include "string_util_mock.h"
#include "hc_time_mock.h"
extern "C" void ProcessErrorCallback(int64_t reqId, int operationCode, int errorCode,
    const char *errorReturn, const DeviceAuthCallback *callback)
{
}

using testing::_;
using testing::Return;
using testing::Invoke;
using testing::AnyNumber;
using namespace testing::ext;

static const int64_t TEST_REQUEST_ID = 12345;
static const int32_t TEST_OS_ACCOUNT_ID = 100;
static const char *TEST_SERVICE_ID = "testServiceId";
static const int32_t TEST_OP_CODE = 1;
static const int32_t MAX_SESSION_NUM = 30;

static void FillRandomBuff(DataBuff *buff, uint32_t len)
{
    buff->length = len;
    buff->data = (uint8_t *)HcMalloc(len, 0);
    for (uint32_t i = 0; i < len; i++) {
        buff->data[i] = (uint8_t)(i % 256);
    }
}

static void FreeRandomBuff(DataBuff *buff)
{
    if (buff->data != nullptr) {
        HcFree(buff->data);
        buff->data = nullptr;
    }
    buff->length = 0;
}

static void FillTestCallback(DeviceAuthCallback *callback)
{
    callback->onTransmit = nullptr;
    callback->onFinish = nullptr;
    callback->onError = nullptr;
    callback->onSessionKeyReturned = nullptr;
    callback->onRequest = nullptr;
}

static int32_t CreateValidInitParams(LightSessionInitParams *params)
{
    params->requestId = TEST_REQUEST_ID;
    params->osAccountId = TEST_OS_ACCOUNT_ID;
    params->serviceId = TEST_SERVICE_ID;
    params->opCode = TEST_OP_CODE;
    FillRandomBuff(&params->randomBuff, 32);
    DeviceAuthCallback *cb = (DeviceAuthCallback *)HcMalloc(sizeof(DeviceAuthCallback), 0);
    if (cb == nullptr) {
        FreeRandomBuff(&params->randomBuff);
        return HC_ERR_ALLOC_MEMORY;
    }
    FillTestCallback(cb);
    params->callback = cb;
    return HC_SUCCESS;
}

static void DestroyInitParams(LightSessionInitParams *params)
{
    FreeRandomBuff(&params->randomBuff);
    if (params->callback != nullptr) {
        HcFree((void *)params->callback);
        params->callback = nullptr;
    }
}

class MiniSessionManagerTest : public testing::Test {
public:
    void SetUp() override
    {
        InitLightSessionManager();
    }
    void TearDown() override
    {
        DestroyLightSessionManager();
    }
};

HWTEST_F(MiniSessionManagerTest, InitAndDestroyTest001, TestSize.Level0)
{
    SUCCEED();
}

HWTEST_F(MiniSessionManagerTest, AddLightSessionNullParamsTest001, TestSize.Level0)
{
    int32_t ret = AddLightSession(nullptr);
    EXPECT_EQ(ret, HC_ERR_INVALID_PARAMS);
}

HWTEST_F(MiniSessionManagerTest, AddLightSessionNullCallbackTest001, TestSize.Level0)
{
    LightSessionInitParams params = {0};
    params.requestId = TEST_REQUEST_ID;
    params.osAccountId = TEST_OS_ACCOUNT_ID;
    params.serviceId = TEST_SERVICE_ID;
    params.callback = nullptr;
    int32_t ret = AddLightSession(&params);
    EXPECT_EQ(ret, HC_ERR_INVALID_PARAMS);
}

HWTEST_F(MiniSessionManagerTest, AddLightSessionNullServiceIdTest001, TestSize.Level0)
{
    LightSessionInitParams params = {0};
    params.requestId = TEST_REQUEST_ID;
    params.osAccountId = TEST_OS_ACCOUNT_ID;
    params.serviceId = nullptr;
    DeviceAuthCallback cb = {0};
    params.callback = &cb;
    int32_t ret = AddLightSession(&params);
    EXPECT_EQ(ret, HC_ERR_INVALID_PARAMS);
}

HWTEST_F(MiniSessionManagerTest, AddAndQueryLightSessionTest001, TestSize.Level0)
{
    LightSessionInitParams params = {0};
    int32_t ret = CreateValidInitParams(&params);
    ASSERT_EQ(ret, HC_SUCCESS);

    ret = AddLightSession(&params);
    EXPECT_EQ(ret, HC_SUCCESS);

    uint8_t *randomVal = nullptr;
    uint32_t randomLen = 0;
    char *serviceId = nullptr;
    ret = QueryLightSession(TEST_REQUEST_ID, TEST_OS_ACCOUNT_ID, &randomVal, &randomLen, &serviceId);
    EXPECT_EQ(ret, HC_SUCCESS);
    EXPECT_NE(randomVal, nullptr);
    EXPECT_NE(serviceId, nullptr);
    if (randomVal != nullptr) {
        HcFree(randomVal);
    }
    if (serviceId != nullptr) {
        HcFree(serviceId);
    }

    DestroyInitParams(&params);
}

HWTEST_F(MiniSessionManagerTest, QueryLightSessionNotExistTest001, TestSize.Level0)
{
    uint8_t *randomVal = nullptr;
    uint32_t randomLen = 0;
    char *serviceId = nullptr;
    int32_t ret = QueryLightSession(99999, TEST_OS_ACCOUNT_ID, &randomVal, &randomLen, &serviceId);
    EXPECT_EQ(ret, HC_ERR_SESSION_NOT_EXIST);
}

HWTEST_F(MiniSessionManagerTest, DeleteLightSessionTest001, TestSize.Level0)
{
    LightSessionInitParams params = {0};
    int32_t ret = CreateValidInitParams(&params);
    ASSERT_EQ(ret, HC_SUCCESS);

    ret = AddLightSession(&params);
    EXPECT_EQ(ret, HC_SUCCESS);

    ret = DeleteLightSession(TEST_REQUEST_ID, TEST_OS_ACCOUNT_ID);
    EXPECT_EQ(ret, HC_SUCCESS);

    uint8_t *randomVal = nullptr;
    uint32_t randomLen = 0;
    char *serviceId = nullptr;
    ret = QueryLightSession(TEST_REQUEST_ID, TEST_OS_ACCOUNT_ID, &randomVal, &randomLen, &serviceId);
    EXPECT_EQ(ret, HC_ERR_SESSION_NOT_EXIST);

    DestroyInitParams(&params);
}

HWTEST_F(MiniSessionManagerTest, DeleteLightSessionNotExistTest001, TestSize.Level0)
{
    int32_t ret = DeleteLightSession(99999, TEST_OS_ACCOUNT_ID);
    EXPECT_EQ(ret, HC_SUCCESS);
}

HWTEST_F(MiniSessionManagerTest, AddAndDeleteMultipleSessionsTest001, TestSize.Level0)
{
    LightSessionInitParams params1 = {0};
    params1.requestId = 100;
    params1.osAccountId = TEST_OS_ACCOUNT_ID;
    params1.serviceId = "service1";
    params1.opCode = TEST_OP_CODE;
    FillRandomBuff(&params1.randomBuff, 16);
    DeviceAuthCallback cb1 = {0};
    params1.callback = &cb1;

    LightSessionInitParams params2 = {0};
    params2.requestId = 200;
    params2.osAccountId = TEST_OS_ACCOUNT_ID;
    params2.serviceId = "service2";
    params2.opCode = TEST_OP_CODE;
    FillRandomBuff(&params2.randomBuff, 16);
    DeviceAuthCallback cb2 = {0};
    params2.callback = &cb2;

    int32_t ret = AddLightSession(&params1);
    EXPECT_EQ(ret, HC_SUCCESS);
    ret = AddLightSession(&params2);
    EXPECT_EQ(ret, HC_SUCCESS);

    ret = DeleteLightSession(100, TEST_OS_ACCOUNT_ID);
    EXPECT_EQ(ret, HC_SUCCESS);

    uint8_t *randomVal = nullptr;
    uint32_t randomLen = 0;
    char *serviceId = nullptr;
    ret = QueryLightSession(200, TEST_OS_ACCOUNT_ID, &randomVal, &randomLen, &serviceId);
    EXPECT_EQ(ret, HC_SUCCESS);
    if (randomVal != nullptr) {
        HcFree(randomVal);
    }
    if (serviceId != nullptr) {
        HcFree(serviceId);
    }

    ret = QueryLightSession(100, TEST_OS_ACCOUNT_ID, &randomVal, &randomLen, &serviceId);
    EXPECT_EQ(ret, HC_ERR_SESSION_NOT_EXIST);

    FreeRandomBuff(&params1.randomBuff);
    FreeRandomBuff(&params2.randomBuff);
}

HWTEST_F(MiniSessionManagerTest, AddLightSessionMaxLimitTest001, TestSize.Level0)
{
    LightSessionInitParams params[MAX_SESSION_NUM] = {{0}};
    DeviceAuthCallback cbs[MAX_SESSION_NUM] = {{0}};
    int32_t ret;

    for (int32_t i = 0; i < MAX_SESSION_NUM; i++) {
        params[i].requestId = 1000 + i;
        params[i].osAccountId = TEST_OS_ACCOUNT_ID;
        params[i].serviceId = "maxLimitSvc";
        params[i].opCode = TEST_OP_CODE;
        FillRandomBuff(&params[i].randomBuff, 8);
        FillTestCallback(&cbs[i]);
        params[i].callback = &cbs[i];
        ret = AddLightSession(&params[i]);
        ASSERT_EQ(ret, HC_SUCCESS);
    }

    LightSessionInitParams extraParams = {0};
    extraParams.requestId = 9999;
    extraParams.osAccountId = TEST_OS_ACCOUNT_ID;
    extraParams.serviceId = "extraSvc";
    extraParams.opCode = TEST_OP_CODE;
    FillRandomBuff(&extraParams.randomBuff, 8);
    DeviceAuthCallback extraCb = {0};
    FillTestCallback(&extraCb);
    extraParams.callback = &extraCb;
    ret = AddLightSession(&extraParams);
    EXPECT_EQ(ret, HC_ERR_OUT_OF_LIMIT);

    FreeRandomBuff(&extraParams.randomBuff);

    for (int32_t i = 0; i < MAX_SESSION_NUM; i++) {
        DeleteLightSession(1000 + i, TEST_OS_ACCOUNT_ID);
        FreeRandomBuff(&params[i].randomBuff);
    }
}

HWTEST_F(MiniSessionManagerTest, TimeoutSessionTest001, TestSize.Level0)
{
    LightSessionInitParams params = {0};
    int32_t ret = CreateValidInitParams(&params);
    ASSERT_EQ(ret, HC_SUCCESS);

    ret = AddLightSession(&params);
    ASSERT_EQ(ret, HC_SUCCESS);

    SetForceTimeout(true);
    ret = QueryLightSession(TEST_REQUEST_ID, TEST_OS_ACCOUNT_ID, nullptr, nullptr, nullptr);
    SetForceTimeout(false);

    DestroyInitParams(&params);
}

HWTEST_F(MiniSessionManagerTest, TimeoutSessionDeleteTest001, TestSize.Level0)
{
    LightSessionInitParams params = {0};
    int32_t ret = CreateValidInitParams(&params);
    ASSERT_EQ(ret, HC_SUCCESS);

    ret = AddLightSession(&params);
    ASSERT_EQ(ret, HC_SUCCESS);

    SetForceTimeout(true);
    ret = DeleteLightSession(TEST_REQUEST_ID, TEST_OS_ACCOUNT_ID);
    SetForceTimeout(false);
    EXPECT_EQ(ret, HC_SUCCESS);

    DestroyInitParams(&params);
}

HWTEST_F(MiniSessionManagerTest, CreateSessionMallocFailTest001, TestSize.Level0)
{
    static int32_t mallocFailAt = 2;
    static int32_t mallocCallCount = 0;
    mallocFailAt = 2;
    mallocCallCount = 0;

    MockHcTypes mockHcTypes;
    SetMockHcTypes(&mockHcTypes);
    EXPECT_CALL(mockHcTypes, Malloc(_, _)).Times(AnyNumber())
        .WillRepeatedly(Invoke([&](uint32_t size, char val) {
            mallocCallCount++;
            if (mallocCallCount == mallocFailAt) return (void*)nullptr;
            void *p = malloc(size);
            if (p) memset(p, 0, size);
            if (p && val) memset(p, val, size);
            return p;
        }));
    EXPECT_CALL(mockHcTypes, Free(_)).Times(AnyNumber())
        .WillRepeatedly(Invoke([](void *p) { free(p); }));

    LightSessionInitParams params = {0};
    params.requestId = TEST_REQUEST_ID + 5000;
    params.osAccountId = TEST_OS_ACCOUNT_ID;
    params.serviceId = "failSvc";
    params.opCode = TEST_OP_CODE;
    FillRandomBuff(&params.randomBuff, 8);
    DeviceAuthCallback cb = {0};
    FillTestCallback(&cb);
    params.callback = &cb;

    int32_t ret = AddLightSession(&params);
    EXPECT_EQ(ret, HC_ERR_MEMORY_COPY);

    FreeRandomBuff(&params.randomBuff);
    SetMockHcTypes(nullptr);
}

HWTEST_F(MiniSessionManagerTest, CopyRandomMallocFailTest001, TestSize.Level0)
{
    static int32_t mallocCallCount = 0;
    static int32_t mallocFailAt = 3;
    mallocFailAt = 3;
    mallocCallCount = 0;

    MockHcTypes mockHcTypes;
    SetMockHcTypes(&mockHcTypes);
    EXPECT_CALL(mockHcTypes, Malloc(_, _)).Times(AnyNumber())
        .WillRepeatedly(Invoke([&](uint32_t size, char val) {
            mallocCallCount++;
            if (mallocCallCount == mallocFailAt) return (void*)nullptr;
            void *p = malloc(size);
            if (p) memset(p, 0, size);
            if (p && val) memset(p, val, size);
            return p;
        }));
    EXPECT_CALL(mockHcTypes, Free(_)).Times(AnyNumber())
        .WillRepeatedly(Invoke([](void *p) { free(p); }));

    LightSessionInitParams params = {0};
    params.requestId = TEST_REQUEST_ID + 5001;
    params.osAccountId = TEST_OS_ACCOUNT_ID;
    params.serviceId = "failSvc";
    params.opCode = TEST_OP_CODE;
    FillRandomBuff(&params.randomBuff, 8);
    DeviceAuthCallback cb = {0};
    FillTestCallback(&cb);
    params.callback = &cb;

    int32_t ret = AddLightSession(&params);
    EXPECT_EQ(ret, HC_ERR_MEMORY_COPY);

    FreeRandomBuff(&params.randomBuff);
    SetMockHcTypes(nullptr);
}

HWTEST_F(MiniSessionManagerTest, CopyServiceIdMallocFailTest001, TestSize.Level0)
{
    static int32_t mallocCallCount = 0;
    static int32_t mallocFailAt = 4;
    mallocFailAt = 4;
    mallocCallCount = 0;

    MockHcTypes mockHcTypes;
    SetMockHcTypes(&mockHcTypes);
    EXPECT_CALL(mockHcTypes, Malloc(_, _)).Times(AnyNumber())
        .WillRepeatedly(Invoke([&](uint32_t size, char val) {
            mallocCallCount++;
            if (mallocCallCount == mallocFailAt) return (void*)nullptr;
            void *p = malloc(size);
            if (p) memset(p, 0, size);
            if (p && val) memset(p, val, size);
            return p;
        }));
    EXPECT_CALL(mockHcTypes, Free(_)).Times(AnyNumber())
        .WillRepeatedly(Invoke([](void *p) { free(p); }));

    LightSessionInitParams params = {0};
    params.requestId = TEST_REQUEST_ID + 5002;
    params.osAccountId = TEST_OS_ACCOUNT_ID;
    params.serviceId = "failSvc";
    params.opCode = TEST_OP_CODE;
    FillRandomBuff(&params.randomBuff, 8);
    DeviceAuthCallback cb = {0};
    FillTestCallback(&cb);
    params.callback = &cb;

    int32_t ret = AddLightSession(&params);
    EXPECT_EQ(ret, HC_ERR_MEMORY_COPY);

    FreeRandomBuff(&params.randomBuff);
    SetMockHcTypes(nullptr);
}

HWTEST_F(MiniSessionManagerTest, InitMutexFailTest001, TestSize.Level0)
{
    DestroyLightSessionManager();

    MockHcMutex mockHcMutex;
    SetMockHcMutex(&mockHcMutex);
    EXPECT_CALL(mockHcMutex, InitHcMutex(_, _)).WillOnce(Return(-1));
    EXPECT_CALL(mockHcMutex, DestroyHcMutex(_)).Times(AnyNumber());
    EXPECT_CALL(mockHcMutex, LockHcMutex(_)).Times(AnyNumber());
    EXPECT_CALL(mockHcMutex, UnlockHcMutex(_)).Times(AnyNumber());

    int32_t ret = InitLightSessionManager();
    EXPECT_EQ(ret, -1);

    SetMockHcMutex(nullptr);
    InitLightSessionManager();
}

HWTEST_F(MiniSessionManagerTest, QueryDeepCopyStringFailTest001, TestSize.Level0)
{
    MockStringUtil mockStringUtil;
    SetMockStringUtil(&mockStringUtil);
    EXPECT_CALL(mockStringUtil, DeepCopyString(_, _)).Times(AnyNumber())
        .WillRepeatedly(Return(CLIB_ERR_BAD_ALLOC));

    LightSessionInitParams params = {0};
    int32_t ret = CreateValidInitParams(&params);
    ASSERT_EQ(ret, HC_SUCCESS);
    ret = AddLightSession(&params);
    ASSERT_EQ(ret, HC_SUCCESS);

    uint8_t *randomVal = nullptr;
    uint32_t randomLen = 0;
    char *serviceId = nullptr;
    ret = QueryLightSession(TEST_REQUEST_ID, TEST_OS_ACCOUNT_ID, &randomVal, &randomLen, &serviceId);
    EXPECT_EQ(ret, HC_ERR_MEMORY_COPY);
    if (randomVal != nullptr) {
        HcFree(randomVal);
    }

    DestroyInitParams(&params);
    SetMockStringUtil(nullptr);
}

HWTEST_F(MiniSessionManagerTest, DeleteLightSessionMismatchTest001, TestSize.Level0)
{
    LightSessionInitParams params = {0};
    int32_t ret = CreateValidInitParams(&params);
    ASSERT_EQ(ret, HC_SUCCESS);

    ret = AddLightSession(&params);
    ASSERT_EQ(ret, HC_SUCCESS);

    ret = DeleteLightSession(99999, TEST_OS_ACCOUNT_ID);
    EXPECT_EQ(ret, HC_SUCCESS);

    uint8_t *randomVal = nullptr;
    uint32_t randomLen = 0;
    char *serviceId = nullptr;
    ret = QueryLightSession(TEST_REQUEST_ID, TEST_OS_ACCOUNT_ID, &randomVal, &randomLen, &serviceId);
    EXPECT_EQ(ret, HC_SUCCESS);
    if (randomVal != nullptr) {
        HcFree(randomVal);
    }
    if (serviceId != nullptr) {
        HcFree(serviceId);
    }

    DestroyInitParams(&params);
}

HWTEST_F(MiniSessionManagerTest, QueryLightSessionSecondInListTest001, TestSize.Level0)
{
    LightSessionInitParams params1 = {0};
    params1.requestId = 100;
    params1.osAccountId = TEST_OS_ACCOUNT_ID;
    params1.serviceId = "svc1";
    params1.opCode = TEST_OP_CODE;
    FillRandomBuff(&params1.randomBuff, 16);
    DeviceAuthCallback cb1 = {0};
    FillTestCallback(&cb1);
    params1.callback = &cb1;

    LightSessionInitParams params2 = {0};
    params2.requestId = 200;
    params2.osAccountId = TEST_OS_ACCOUNT_ID;
    params2.serviceId = "svc2";
    params2.opCode = TEST_OP_CODE;
    FillRandomBuff(&params2.randomBuff, 16);
    DeviceAuthCallback cb2 = {0};
    FillTestCallback(&cb2);
    params2.callback = &cb2;

    int32_t ret = AddLightSession(&params1);
    ASSERT_EQ(ret, HC_SUCCESS);
    ret = AddLightSession(&params2);
    ASSERT_EQ(ret, HC_SUCCESS);

    uint8_t *randomVal = nullptr;
    uint32_t randomLen = 0;
    char *serviceId = nullptr;
    ret = QueryLightSession(200, TEST_OS_ACCOUNT_ID, &randomVal, &randomLen, &serviceId);
    EXPECT_EQ(ret, HC_SUCCESS);
    EXPECT_NE(randomVal, nullptr);
    EXPECT_NE(serviceId, nullptr);
    if (randomVal != nullptr) {
        HcFree(randomVal);
    }
    if (serviceId != nullptr) {
        HcFree(serviceId);
    }

    FreeRandomBuff(&params1.randomBuff);
    FreeRandomBuff(&params2.randomBuff);
}

HWTEST_F(MiniSessionManagerTest, PushBackMallocFailTest001, TestSize.Level0)
{
    static int32_t mallocCallCount = 0;
    static int32_t mallocFailAt = 5;
    mallocFailAt = 5;
    mallocCallCount = 0;

    MockHcTypes mockHcTypes;
    SetMockHcTypes(&mockHcTypes);
    EXPECT_CALL(mockHcTypes, Malloc(_, _)).Times(AnyNumber())
        .WillRepeatedly(Invoke([&](uint32_t size, char val) {
            mallocCallCount++;
            if (mallocCallCount == mallocFailAt) return (void*)nullptr;
            void *p = malloc(size);
            if (p) memset(p, 0, size);
            if (p && val) memset(p, val, size);
            return p;
        }));
    EXPECT_CALL(mockHcTypes, Free(_)).Times(AnyNumber())
        .WillRepeatedly(Invoke([](void *p) { free(p); }));

    LightSessionInitParams params = {0};
    params.requestId = TEST_REQUEST_ID + 5003;
    params.osAccountId = TEST_OS_ACCOUNT_ID;
    params.serviceId = "failSvc";
    params.opCode = TEST_OP_CODE;
    FillRandomBuff(&params.randomBuff, 8);
    DeviceAuthCallback cb = {0};
    FillTestCallback(&cb);
    params.callback = &cb;

    int32_t ret = AddLightSession(&params);
    EXPECT_EQ(ret, HC_ERR_MEMORY_COPY);

    FreeRandomBuff(&params.randomBuff);
    SetMockHcTypes(nullptr);
}

HWTEST_F(MiniSessionManagerTest, DeleteLightSessionMismatchWithTwoSessionsTest001, TestSize.Level0)
{
    LightSessionInitParams params1 = {0};
    params1.requestId = 100;
    params1.osAccountId = TEST_OS_ACCOUNT_ID;
    params1.serviceId = "svc1";
    params1.opCode = TEST_OP_CODE;
    FillRandomBuff(&params1.randomBuff, 16);
    DeviceAuthCallback cb1 = {0};
    FillTestCallback(&cb1);
    params1.callback = &cb1;

    LightSessionInitParams params2 = {0};
    params2.requestId = 200;
    params2.osAccountId = TEST_OS_ACCOUNT_ID;
    params2.serviceId = "svc2";
    params2.opCode = TEST_OP_CODE;
    FillRandomBuff(&params2.randomBuff, 16);
    DeviceAuthCallback cb2 = {0};
    FillTestCallback(&cb2);
    params2.callback = &cb2;

    int32_t ret = AddLightSession(&params1);
    ASSERT_EQ(ret, HC_SUCCESS);
    ret = AddLightSession(&params2);
    ASSERT_EQ(ret, HC_SUCCESS);

    ret = DeleteLightSession(99999, TEST_OS_ACCOUNT_ID);
    EXPECT_EQ(ret, HC_SUCCESS);

    FreeRandomBuff(&params1.randomBuff);
    FreeRandomBuff(&params2.randomBuff);
}

HWTEST_F(MiniSessionManagerTest, DeleteLightSessionOsAccountIdMismatchTest001, TestSize.Level0)
{
    LightSessionInitParams params = {0};
    int32_t ret = CreateValidInitParams(&params);
    ASSERT_EQ(ret, HC_SUCCESS);

    ret = AddLightSession(&params);
    ASSERT_EQ(ret, HC_SUCCESS);

    ret = DeleteLightSession(TEST_REQUEST_ID, 99999);
    EXPECT_EQ(ret, HC_SUCCESS);

    uint8_t *randomVal = nullptr;
    uint32_t randomLen = 0;
    char *serviceId = nullptr;
    ret = QueryLightSession(TEST_REQUEST_ID, TEST_OS_ACCOUNT_ID, &randomVal, &randomLen, &serviceId);
    EXPECT_EQ(ret, HC_SUCCESS);
    if (randomVal != nullptr) {
        HcFree(randomVal);
    }
    if (serviceId != nullptr) {
        HcFree(serviceId);
    }

    DestroyInitParams(&params);
}

HWTEST_F(MiniSessionManagerTest, QueryLightSessionOsAccountIdMismatchTest001, TestSize.Level0)
{
    LightSessionInitParams params = {0};
    int32_t ret = CreateValidInitParams(&params);
    ASSERT_EQ(ret, HC_SUCCESS);

    ret = AddLightSession(&params);
    ASSERT_EQ(ret, HC_SUCCESS);

    uint8_t *randomVal = nullptr;
    uint32_t randomLen = 0;
    char *serviceId = nullptr;
    ret = QueryLightSession(TEST_REQUEST_ID, 99999, &randomVal, &randomLen, &serviceId);
    EXPECT_EQ(ret, HC_ERR_SESSION_NOT_EXIST);

    DestroyInitParams(&params);
}
