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
#include "device_auth_defines.h"
#include "ipc_sdk_defines.h"
#include "ipc_adapt.h"

using namespace testing::ext;

namespace {
class IpcAdaptParamTest : public testing::Test {
public:
    IpcAdaptParamTest() = default;  // 显式声明默认构造函数
    ~IpcAdaptParamTest() = default; // 显式声明默认析构函数
};
// 测试 GetAndValSize32Param 函数
HWTEST_F(IpcAdaptParamTest, GetAndValSize32Param_ValidParam, TestSize.Level0)
{
    int32_t testValue = 12345;
    IpcDataInfo testParams[1];
    testParams[0].type = PARAM_TYPE_REQID;
    testParams[0].val = reinterpret_cast<uint8_t *>(&testValue);
    testParams[0].valSz = sizeof(testValue);
    testParams[0].idx = 0;

    int32_t result;
    int32_t size = sizeof(result);
    EXPECT_EQ(HC_SUCCESS,
        GetAndValSize32Param(testParams, 1, PARAM_TYPE_REQID, reinterpret_cast<uint8_t *>(&result), &size));
    EXPECT_EQ(testValue, result);
}

HWTEST_F(IpcAdaptParamTest, GetAndValSize32Param_InvalidSize, TestSize.Level0)
{
    int64_t testValue = 12345;
    IpcDataInfo testParams[1];
    testParams[0].type = PARAM_TYPE_REQID;
    testParams[0].val = reinterpret_cast<uint8_t *>(&testValue);
    testParams[0].valSz = sizeof(testValue);
    testParams[0].idx = 0;

    int32_t result;
    int32_t size = sizeof(result);
    EXPECT_EQ(HC_ERR_IPC_BAD_PARAM,
        GetAndValSize32Param(testParams, 1, PARAM_TYPE_REQID, reinterpret_cast<uint8_t *>(&result), &size));
}

HWTEST_F(IpcAdaptParamTest, GetAndValSize32Param_NotFound, TestSize.Level0)
{
    int32_t testValue = 12345;
    IpcDataInfo testParams[1];
    testParams[0].type = PARAM_TYPE_REQID;
    testParams[0].val = reinterpret_cast<uint8_t *>(&testValue);
    testParams[0].valSz = sizeof(testValue);
    testParams[0].idx = 0;

    int32_t result;
    int32_t size = sizeof(result);
    EXPECT_EQ(HC_ERR_IPC_BAD_PARAM,
        GetAndValSize32Param(testParams, 1, PARAM_TYPE_OPCODE, reinterpret_cast<uint8_t *>(&result), &size));
}

// 测试 GetAndValSize64Param 函数
HWTEST_F(IpcAdaptParamTest, GetAndValSize64Param_ValidParam, TestSize.Level0)
{
    int64_t testValue = 1234567890LL;
    IpcDataInfo testParams[1];
    testParams[0].type = PARAM_TYPE_REQID;
    testParams[0].val = reinterpret_cast<uint8_t *>(&testValue);
    testParams[0].valSz = sizeof(testValue);
    testParams[0].idx = 0;

    int64_t result;
    int32_t size = sizeof(result);
    EXPECT_EQ(HC_SUCCESS,
        GetAndValSize64Param(testParams, 1, PARAM_TYPE_REQID, reinterpret_cast<uint8_t *>(&result), &size));
    EXPECT_EQ(testValue, result);
}

HWTEST_F(IpcAdaptParamTest, GetAndValSize64Param_InvalidSize, TestSize.Level0)
{
    int32_t testValue = 12345;
    IpcDataInfo testParams[1];
    testParams[0].type = PARAM_TYPE_REQID;
    testParams[0].val = reinterpret_cast<uint8_t *>(&testValue);
    testParams[0].valSz = sizeof(testValue);
    testParams[0].idx = 0;

    int64_t result;
    int32_t size = sizeof(result);
    EXPECT_EQ(HC_ERR_IPC_BAD_PARAM,
        GetAndValSize64Param(testParams, 1, PARAM_TYPE_REQID, reinterpret_cast<uint8_t *>(&result), &size));
}

HWTEST_F(IpcAdaptParamTest, GetAndValSize64Param_NotFound, TestSize.Level0)
{
    int64_t testValue = 1234567890LL;
    IpcDataInfo testParams[1];
    testParams[0].type = PARAM_TYPE_REQID;
    testParams[0].val = reinterpret_cast<uint8_t *>(&testValue);
    testParams[0].valSz = sizeof(testValue);
    testParams[0].idx = 0;

    int64_t result;
    int32_t size = sizeof(result);
    EXPECT_EQ(HC_ERR_IPC_BAD_PARAM,
        GetAndValSize64Param(testParams, 1, PARAM_TYPE_OPCODE, reinterpret_cast<uint8_t *>(&result), &size));
}

// 测试 GetAndValSizeCbParam 函数
HWTEST_F(IpcAdaptParamTest, GetAndValSizeCbParam_ValidParam, TestSize.Level0)
{
    DeviceAuthCallback testCallback = {
        .onTransmit = nullptr,
        .onSessionKeyReturned = nullptr,
        .onFinish = nullptr,
        .onError = nullptr,
        .onRequest = nullptr
    };
    IpcDataInfo testParams[1];
    testParams[0].type = PARAM_TYPE_DEV_AUTH_CB;
    testParams[0].val = reinterpret_cast<uint8_t *>(&testCallback);
    testParams[0].valSz = sizeof(testCallback);
    testParams[0].idx = 0;

    DeviceAuthCallback result;
    int32_t size = sizeof(result);
    EXPECT_EQ(HC_SUCCESS,
        GetAndValSizeCbParam(testParams, 1, PARAM_TYPE_DEV_AUTH_CB, reinterpret_cast<uint8_t *>(&result), &size));
}

HWTEST_F(IpcAdaptParamTest, GetAndValSizeCbParam_InvalidSize, TestSize.Level0)
{
    int32_t testValue = 12345;
    IpcDataInfo testParams[1];
    testParams[0].type = PARAM_TYPE_DEV_AUTH_CB;
    testParams[0].val = reinterpret_cast<uint8_t *>(&testValue);
    testParams[0].valSz = sizeof(testValue);
    testParams[0].idx = 0;

    DeviceAuthCallback result;
    int32_t size = sizeof(result);
    EXPECT_EQ(HC_ERR_IPC_BAD_PARAM,
        GetAndValSizeCbParam(testParams, 1, PARAM_TYPE_DEV_AUTH_CB, reinterpret_cast<uint8_t *>(&result), &size));
}

HWTEST_F(IpcAdaptParamTest, GetAndValSizeCbParam_NotFound, TestSize.Level0)
{
    DeviceAuthCallback testCallback = {
        .onTransmit = nullptr,
        .onSessionKeyReturned = nullptr,
        .onFinish = nullptr,
        .onError = nullptr,
        .onRequest = nullptr
    };
    IpcDataInfo testParams[1];
    testParams[0].type = PARAM_TYPE_DEV_AUTH_CB;
    testParams[0].val = reinterpret_cast<uint8_t *>(&testCallback);
    testParams[0].valSz = sizeof(testCallback);
    testParams[0].idx = 0;

    DeviceAuthCallback result;
    int32_t size = sizeof(result);
    EXPECT_EQ(HC_ERR_IPC_BAD_PARAM,
        GetAndValSizeCbParam(testParams, 1, PARAM_TYPE_OPCODE, reinterpret_cast<uint8_t *>(&result), &size));
}

// 测试 GetAndValNullParam 函数
HWTEST_F(IpcAdaptParamTest, GetAndValNullParam_ValidString, TestSize.Level0)
{
    char testString[] = "test_string";

    IpcDataInfo testParams[1];
    testParams[0].type = PARAM_TYPE_APPID;
    testParams[0].val = reinterpret_cast<uint8_t *>(testString);
    testParams[0].valSz = static_cast<int32_t>(strlen(testString)) + 1;
    testParams[0].idx = 0;

    char *result;
    EXPECT_EQ(HC_SUCCESS,
        GetAndValNullParam(testParams, 1, PARAM_TYPE_APPID, reinterpret_cast<uint8_t *>(&result), nullptr));
    EXPECT_STREQ("test_string", result);
}

HWTEST_F(IpcAdaptParamTest, GetAndValNullParam_NullParam, TestSize.Level0)
{
    IpcDataInfo testParams[1];
    testParams[0].type = PARAM_TYPE_APPID;
    testParams[0].val = nullptr;
    testParams[0].valSz = 0;
    testParams[0].idx = 0;

    char *result;
    EXPECT_EQ(HC_ERR_IPC_BAD_PARAM,
        GetAndValNullParam(testParams, 1, PARAM_TYPE_APPID, reinterpret_cast<uint8_t *>(&result), nullptr));
}

HWTEST_F(IpcAdaptParamTest, GetAndValNullParam_EmptyString, TestSize.Level0)
{
    char emptyString[] = "";

    IpcDataInfo testParams[1];
    testParams[0].type = PARAM_TYPE_APPID;
    testParams[0].val = reinterpret_cast<uint8_t *>(emptyString);
    testParams[0].valSz = 1;
    testParams[0].idx = 0;

    char *result;
    EXPECT_EQ(HC_SUCCESS,
        GetAndValNullParam(testParams, 1, PARAM_TYPE_APPID, reinterpret_cast<uint8_t *>(&result), nullptr));
}

HWTEST_F(IpcAdaptParamTest, GetAndValNullParam_InvalidStringNoNullTerminator, TestSize.Level0)
{
    char testString[] = {'t', 'e', 's', 't'}; // 没有null终止符

    IpcDataInfo testParams[1];
    testParams[0].type = PARAM_TYPE_APPID;
    testParams[0].val = reinterpret_cast<uint8_t *>(testString);
    testParams[0].valSz = sizeof(testString);
    testParams[0].idx = 0;

    char *result;
    EXPECT_EQ(HC_ERR_IPC_BAD_PARAM,
        GetAndValNullParam(testParams, 1, PARAM_TYPE_APPID, reinterpret_cast<uint8_t *>(&result), nullptr));
}

HWTEST_F(IpcAdaptParamTest, GetAndValNullParam_NotFound, TestSize.Level0)
{
    char testString[] = "test_string";

    IpcDataInfo testParams[1];
    testParams[0].type = PARAM_TYPE_APPID;
    testParams[0].val = reinterpret_cast<uint8_t *>(testString);
    testParams[0].valSz = static_cast<int32_t>(strlen(testString)) + 1;
    testParams[0].idx = 0;

    char *result;
    EXPECT_EQ(HC_ERR_IPC_BAD_PARAM,
        GetAndValNullParam(testParams, 1, PARAM_TYPE_OPCODE, reinterpret_cast<uint8_t *>(&result), nullptr));
}

HWTEST_F(IpcAdaptParamTest, GetAndValNullParam_ZeroSize, TestSize.Level0)
{
    char testString[] = "test";

    IpcDataInfo testParams[1];
    testParams[0].type = PARAM_TYPE_APPID;
    testParams[0].val = reinterpret_cast<uint8_t *>(testString);
    testParams[0].valSz = 0;
    testParams[0].idx = 0;

    char *result;
    EXPECT_EQ(HC_ERR_IPC_BAD_PARAM,
        GetAndValNullParam(testParams, 1, PARAM_TYPE_APPID, reinterpret_cast<uint8_t *>(&result), nullptr));
}

class IpcDevAuthCredListenerTest : public testing::Test {
public:
    IpcDevAuthCredListenerTest() = default;  // 显式声明默认构造函数
    ~IpcDevAuthCredListenerTest() = default; // 显式声明默认析构函数
    void SetUp();
    void TearDown();
};

void IpcDevAuthCredListenerTest::SetUp()
{
    // 初始化回调列表
    ASSERT_EQ(HC_SUCCESS, InitIpcCallBackList());
}

void IpcDevAuthCredListenerTest::TearDown()
{
    // 清理回调列表
    DeInitIpcCallBackList();
}

// 添加凭据监听器回调
static void AddCredListenerCallback()
{
    CredChangeListener credListener = {
        .onCredAdd = nullptr,
        .onCredDelete = nullptr,
        .onCredUpdate = nullptr
    };

    IpcDataInfo testParams[1];
    testParams[0].type = CB_TYPE_CRED_LISTENER;
    testParams[0].val = reinterpret_cast<uint8_t *>(&credListener);
    testParams[0].valSz = sizeof(credListener);
    testParams[0].idx = 0;

    // 添加凭据监听器
    ASSERT_EQ(HC_SUCCESS, AddIpcCallBackByAppId("test.app.id", reinterpret_cast<const uint8_t *>(&credListener),
        sizeof(credListener), CB_TYPE_CRED_LISTENER));
}

// 测试 InitDevAuthCredListenerCbCtx 函数
HWTEST_F(IpcDevAuthCredListenerTest, InitDevAuthCredListenerCbCtx_Valid, TestSize.Level0)
{
    CredChangeListener credListener;

    // 初始化凭据监听器回调上下文
    InitDevAuthCredListenerCbCtx(nullptr);
    InitDevAuthCredListenerCbCtx(&credListener);

    // 验证所有回调函数都已正确设置
    EXPECT_NE(credListener.onCredAdd, nullptr);
    EXPECT_NE(credListener.onCredDelete, nullptr);
    EXPECT_NE(credListener.onCredUpdate, nullptr);
}


// 测试通过 credListener 调用 IpcOnCredAdd
HWTEST_F(IpcDevAuthCredListenerTest, CredListenerOnCredAdd_Valid, TestSize.Level0)
{
    // 添加凭据监听器回调
    AddCredListenerCallback();

    // 设置回调函数
    CredChangeListener credListener;
    InitDevAuthCredListenerCbCtx(&credListener);

    // 更新回调
    ASSERT_EQ(HC_SUCCESS, AddIpcCallBackByAppId("test.app.id", reinterpret_cast<const uint8_t *>(&credListener),
        sizeof(credListener), CB_TYPE_CRED_LISTENER));

    // 添加回调对象
    AddIpcCbObjByAppId("test.app.id", 0, CB_TYPE_CRED_LISTENER);

    // 通过 credListener 调用 onCredAdd
    char credId[] = "test_cred_id";
    char credInfo[] = "test_cred_info";
    if (credListener.onCredAdd != nullptr) {
        credListener.onCredAdd(credId, credInfo);
    }
}

HWTEST_F(IpcDevAuthCredListenerTest, CredListenerOnCredAdd_NullCredId, TestSize.Level0)
{
    // 添加凭据监听器回调
    AddCredListenerCallback();

    // 设置回调函数
    CredChangeListener credListener;
    InitDevAuthCredListenerCbCtx(&credListener);

    // 更新回调
    ASSERT_EQ(HC_SUCCESS, AddIpcCallBackByAppId("test.app.id", reinterpret_cast<const uint8_t *>(&credListener),
        sizeof(credListener), CB_TYPE_CRED_LISTENER));

    // 添加回调对象
    AddIpcCbObjByAppId("test.app.id", 0, CB_TYPE_CRED_LISTENER);

    // 通过 credListener 调用 onCredAdd，使用空 credId
    if (credListener.onCredAdd != nullptr) {
        credListener.onCredAdd(nullptr, "test_cred_info");
    }
}

// 测试通过 credListener 调用 IpcOnCredDelete
HWTEST_F(IpcDevAuthCredListenerTest, CredListenerOnCredDelete_Valid, TestSize.Level0)
{
    // 添加凭据监听器回调
    AddCredListenerCallback();

    // 设置回调函数
    CredChangeListener credListener;
    InitDevAuthCredListenerCbCtx(&credListener);

    // 更新回调
    ASSERT_EQ(HC_SUCCESS, AddIpcCallBackByAppId("test.app.id", reinterpret_cast<const uint8_t *>(&credListener),
        sizeof(credListener), CB_TYPE_CRED_LISTENER));

    // 添加回调对象
    AddIpcCbObjByAppId("test.app.id", 0, CB_TYPE_CRED_LISTENER);

    // 通过 credListener 调用 onCredDelete
    char credId[] = "test_cred_id";
    char credInfo[] = "test_cred_info";
    if (credListener.onCredDelete != nullptr) {
        credListener.onCredDelete(credId, credInfo);
    }
}

HWTEST_F(IpcDevAuthCredListenerTest, CredListenerOnCredDelete_NullCredId, TestSize.Level0)
{
    // 添加凭据监听器回调
    AddCredListenerCallback();

    // 设置回调函数
    CredChangeListener credListener;
    InitDevAuthCredListenerCbCtx(&credListener);

    // 更新回调
    ASSERT_EQ(HC_SUCCESS, AddIpcCallBackByAppId("test.app.id", reinterpret_cast<const uint8_t *>(&credListener),
        sizeof(credListener), CB_TYPE_CRED_LISTENER));

    // 添加回调对象
    AddIpcCbObjByAppId("test.app.id", 0, CB_TYPE_CRED_LISTENER);

    // 通过 credListener 调用 onCredDelete，使用空 credId
    if (credListener.onCredDelete != nullptr) {
        credListener.onCredDelete(nullptr, "test_cred_info");
    }
}

// 测试通过 credListener 调用 IpcOnCredUpdate
HWTEST_F(IpcDevAuthCredListenerTest, CredListenerOnCredUpdate_Valid, TestSize.Level0)
{
    // 添加凭据监听器回调
    AddCredListenerCallback();

    // 设置回调函数
    CredChangeListener credListener;
    InitDevAuthCredListenerCbCtx(&credListener);

    // 更新回调
    ASSERT_EQ(HC_SUCCESS, AddIpcCallBackByAppId("test.app.id", reinterpret_cast<const uint8_t *>(&credListener),
        sizeof(credListener), CB_TYPE_CRED_LISTENER));

    // 添加回调对象
    AddIpcCbObjByAppId("test.app.id", 0, CB_TYPE_CRED_LISTENER);

    // 通过 credListener 调用 onCredUpdate
    char credId[] = "test_cred_id";
    char credInfo[] = "test_cred_info";
    if (credListener.onCredUpdate != nullptr) {
        credListener.onCredUpdate(credId, credInfo);
    }
}

HWTEST_F(IpcDevAuthCredListenerTest, CredListenerOnCredUpdate_NullCredId, TestSize.Level0)
{
    // 添加凭据监听器回调
    AddCredListenerCallback();

    // 设置回调函数
    CredChangeListener credListener;
    InitDevAuthCredListenerCbCtx(&credListener);

    // 更新回调
    ASSERT_EQ(HC_SUCCESS, AddIpcCallBackByAppId("test.app.id", reinterpret_cast<const uint8_t *>(&credListener),
        sizeof(credListener), CB_TYPE_CRED_LISTENER));

    // 添加回调对象
    AddIpcCbObjByAppId("test.app.id", 0, CB_TYPE_CRED_LISTENER);

    // 通过 credListener 调用 onCredUpdate，使用空 credId
    if (credListener.onCredUpdate != nullptr) {
        credListener.onCredUpdate(nullptr, "test_cred_info");
    }
}
}