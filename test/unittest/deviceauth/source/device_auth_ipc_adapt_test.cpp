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
#include <string>
#include "message_parcel.h"
#include "ipc_adapt.h"
#include "ipc_sdk_defines.h"
#include "device_auth_defines.h"
#include "ipc_service_common.h"
#include "device_auth.h"
using namespace testing::ext;

namespace {
class DeviceAuthIpcAdaptTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
    ~DeviceAuthIpcAdaptTest() = default;
};

const std::string COM_STR = "test";

void DeviceAuthIpcAdaptTest::SetUpTestCase(void)
{
    InitDeviceAuthService();
    MainRescInit();
}

void DeviceAuthIpcAdaptTest::TearDownTestCase(void)
{
    DeMainRescInit();
    DestroyDeviceAuthService();
}

void DeviceAuthIpcAdaptTest::SetUp(void) {}

void DeviceAuthIpcAdaptTest::TearDown(void) {}

static IpcDataInfo GenerateIpcDataInforOpCode()
{
    int32_t reqId = 0;
    IpcDataInfo ipcParams;
    ipcParams.val = reinterpret_cast<uint8_t *>(&reqId);
    ipcParams.valSz = sizeof(reqId);
    ipcParams.type = PARAM_TYPE_OPCODE;
    return ipcParams;
}

static IpcDataInfo GenerateIpcDataInforOsAccountId()
{
    int32_t reqId = 100;
    IpcDataInfo ipcParams;
    ipcParams.val = reinterpret_cast<uint8_t *>(&reqId);
    ipcParams.valSz = sizeof(reqId);
    ipcParams.type = PARAM_TYPE_OS_ACCOUNT_ID;
    return ipcParams;
}

static IpcDataInfo GenerateIpcDataInforGroupType()
{
    int32_t reqId = 256;
    IpcDataInfo ipcParams;
    ipcParams.val = reinterpret_cast<uint8_t *>(&reqId);
    ipcParams.valSz = sizeof(reqId);
    ipcParams.type = PARAM_TYPE_GROUP_TYPE;
    return ipcParams;
}

static IpcDataInfo GenerateIpcDataInforReqId()
{
    int64_t reqId = 123456789;
    IpcDataInfo ipcParams;
    ipcParams.val = reinterpret_cast<uint8_t *>(&reqId);
    ipcParams.valSz = sizeof(reqId);
    ipcParams.type = PARAM_TYPE_REQID;
    return ipcParams;
}

static IpcDataInfo GenerateIpcDataInforCBObject()
{
    int32_t reqId = 0;
    IpcDataInfo ipcParams;
    ipcParams.val = reinterpret_cast<uint8_t *>(&reqId);
    ipcParams.valSz = sizeof(reqId);
    ipcParams.type = PARAM_TYPE_CB_OBJECT;
    ipcParams.idx = 0;
    return ipcParams;
}

static IpcDataInfo GenerateIpcDataInforAppId()
{
    IpcDataInfo ipcParams;
    ipcParams.val = reinterpret_cast<uint8_t *>(const_cast<char *>(COM_STR.data()));
    ipcParams.valSz = strlen(COM_STR.c_str()) + 1;
    ipcParams.idx = 0;
    ipcParams.type = PARAM_TYPE_APPID;
    return ipcParams;
}

static IpcDataInfo GenerateIpcDataInforAuthParams()
{
    IpcDataInfo ipcParams = GenerateIpcDataInforAppId();
    ipcParams.type = PARAM_TYPE_AUTH_PARAMS;
    return ipcParams;
}
static IpcDataInfo GenerateIpcDataInforListener()
{
    DataChangeListener listener = {

    };
    IpcDataInfo ipcParams;
    ipcParams.val = reinterpret_cast<uint8_t *>(&listener);
    ipcParams.valSz = sizeof(DataChangeListener);
    ipcParams.type = PARAM_TYPE_LISTENER;
    ipcParams.idx = 0;
    return ipcParams;
}

static IpcDataInfo GenerateIpcDataInforDevAuthCB()
{
    DevAuthCallbackInfo cb;
    IpcDataInfo ipcParams;
    ipcParams.val = reinterpret_cast<uint8_t *>(&cb);
    ipcParams.valSz = sizeof(cb);
    ipcParams.type = PARAM_TYPE_DEV_AUTH_CB;
    ipcParams.idx = 0;
    return ipcParams;
}

static IpcDataInfo GenerateIpcDataInforCommonData()
{
    IpcDataInfo ipcParams = GenerateIpcDataInforAppId();
    ipcParams.type = PARAM_TYPE_COMM_DATA;
    return ipcParams;
}

static IpcDataInfo GenerateIpcDataInforSessionKey()
{
    IpcDataInfo ipcParams = GenerateIpcDataInforAppId();
    ipcParams.type = PARAM_TYPE_SESS_KEY;
    return ipcParams;
}

HWTEST_F(DeviceAuthIpcAdaptTest, GetAndValSize32ParamTest001, TestSize.Level1)
{
    int32_t testInt = 4;
    int32_t *param = &testInt;
    IpcDataInfo ipcParams = GenerateIpcDataInforOpCode();
    int32_t paramNum = 1;
    int32_t paramType = PARAM_TYPE_OPCODE;
    int32_t res = GetAndValSize32Param(&ipcParams, paramNum, paramType, param);
    EXPECT_EQ(res, HC_SUCCESS);
    EXPECT_EQ(*param, testInt);
    ipcParams.valSz = 0;
    res = GetAndValSize32Param(&ipcParams, paramNum, paramType, param);
    EXPECT_EQ(res, HC_ERR_IPC_BAD_PARAM);
    ipcParams.valSz = 6;
    res = GetAndValSize32Param(&ipcParams, paramNum, paramType, param);
    EXPECT_EQ(res, HC_ERR_IPC_BAD_PARAM);
    ipcParams.valSz = 2;
    res = GetAndValSize32Param(&ipcParams, paramNum, paramType, param);
    EXPECT_EQ(res, HC_ERR_IPC_BAD_PARAM);
}

HWTEST_F(DeviceAuthIpcAdaptTest, GetAndValSize64ParamTest001, TestSize.Level1)
{
    int64_t testInt = 4;
    int64_t *param = &testInt;
    IpcDataInfo ipcParams = GenerateIpcDataInforReqId();
    int64_t paramNum = 1;
    int64_t paramType = PARAM_TYPE_REQID;
    int64_t res = GetAndValSize64Param(&ipcParams, paramNum, paramType, param);
    EXPECT_EQ(res, HC_SUCCESS);
    EXPECT_EQ(*param, testInt);
    ipcParams.valSz = 0;
    res = GetAndValSize64Param(&ipcParams, paramNum, paramType, param);
    EXPECT_EQ(res, HC_ERR_IPC_BAD_PARAM);
    ipcParams.valSz = 6;
    res = GetAndValSize64Param(&ipcParams, paramNum, paramType, param);
    EXPECT_EQ(res, HC_ERR_IPC_BAD_PARAM);
    ipcParams.valSz = 2;
    res = GetAndValSize64Param(&ipcParams, paramNum, paramType, param);
    EXPECT_EQ(res, HC_ERR_IPC_BAD_PARAM);
}

HWTEST_F(DeviceAuthIpcAdaptTest, GetAndValStringParamTest001, TestSize.Level1)
{
    IpcDataInfo ipcParams = GenerateIpcDataInforAppId();
    int32_t paramNum = 1;
    int32_t paramType = PARAM_TYPE_APPID;
    const char *param = nullptr;
    int32_t res = GetAndValStringParam(&ipcParams, paramNum, paramType, &param);
    EXPECT_EQ(res, HC_SUCCESS);
    ipcParams.valSz = 0;
    res = GetAndValStringParam(&ipcParams, paramNum, paramType, &param);
    EXPECT_EQ(res, HC_ERR_IPC_BAD_PARAM);
    ipcParams.valSz = 2;
    res = GetAndValStringParam(&ipcParams, paramNum, paramType, &param);
    EXPECT_EQ(res, HC_ERR_IPC_BAD_PARAM);
    ipcParams.valSz = strnlen((const char *)ipcParams.val, 10);
    ipcParams.val = nullptr;
    res = GetAndValStringParam(&ipcParams, paramNum, paramType, &param);
    EXPECT_EQ(res, HC_ERR_IPC_BAD_PARAM);
}

HWTEST_F(DeviceAuthIpcAdaptTest, GetAndValSizeStructParam001, TestSize.Level1)
{
    DeviceAuthCallback cb;
    IpcDataInfo ipcParams;
    ipcParams.val = reinterpret_cast<uint8_t *>(&cb);
    ipcParams.valSz = sizeof(DeviceAuthCallback);
    ipcParams.idx = 0;
    ipcParams.type = PARAM_TYPE_DEV_AUTH_CB;
    int32_t paramNum = 1;
    int32_t paramType = PARAM_TYPE_DEV_AUTH_CB;
    DeviceAuthCallback *param = nullptr;
    int32_t res = GetAndValSizeStructParam(&ipcParams, paramNum, paramType, reinterpret_cast<uint8_t *>(&param),
        sizeof(DeviceAuthCallback));
    EXPECT_EQ(res, HC_SUCCESS);
    ipcParams.valSz = sizeof(DeviceAuthCallback) + 1;
    res = GetAndValSizeStructParam(&ipcParams, paramNum, paramType, reinterpret_cast<uint8_t *>(&param),
        sizeof(DeviceAuthCallback));
    EXPECT_EQ(res, HC_ERR_IPC_BAD_PARAM);
    ipcParams.valSz = sizeof(DeviceAuthCallback);
    ipcParams.val = nullptr;
    res = GetAndValSizeStructParam(&ipcParams, paramNum, paramType, reinterpret_cast<uint8_t *>(&param),
        sizeof(DeviceAuthCallback));
    EXPECT_EQ(res, HC_ERR_IPC_BAD_PARAM);
}

HWTEST_F(DeviceAuthIpcAdaptTest, GetAndValParamTest001, TestSize.Level1)
{
    IpcDataInfo ipcParams = GenerateIpcDataInforSessionKey();
    int32_t paramNum = 1;
    int32_t paramSize = 0;
    int32_t paramType = PARAM_TYPE_SESS_KEY;
    const char *param = nullptr;
    int32_t res = GetAndValParam(&ipcParams, paramNum, paramType, reinterpret_cast<u_int8_t *>(&param), &paramSize);
    EXPECT_EQ(res, HC_SUCCESS);
    EXPECT_EQ(paramSize, strlen(COM_STR.c_str()) + 1);
    ipcParams.valSz = 0;
    res = GetAndValParam(&ipcParams, paramNum, paramType, reinterpret_cast<u_int8_t *>(&param), &paramSize);
    EXPECT_EQ(res, HC_ERR_IPC_BAD_PARAM);
    ipcParams.valSz = strlen(COM_STR.c_str()) + 1;
    ipcParams.val = nullptr;
    res = GetAndValParam(&ipcParams, paramNum, paramType, reinterpret_cast<u_int8_t *>(&param), &paramSize);
    EXPECT_EQ(res, HC_ERR_IPC_BAD_PARAM);
}

HWTEST_F(DeviceAuthIpcAdaptTest, IpcServiceGmRegDataChangeListenerTest001, TestSize.Level1)
{
    OHOS::MessageParcel reply;
    uintptr_t out = reinterpret_cast<uintptr_t>(&reply);
    IpcDataInfo ipcParams [] = {GenerateIpcDataInforAppId(), GenerateIpcDataInforListener()};
    int32_t res = IpcServiceGmRegDataChangeListener(ipcParams, 2, out);
    EXPECT_EQ(res, HC_ERR_IPC_BAD_PARAM);
    ipcParams[1].valSz = 0;
    res = IpcServiceGmRegDataChangeListener(ipcParams, 2, out);
    EXPECT_EQ(res, HC_ERR_IPC_BAD_PARAM);
}

HWTEST_F(DeviceAuthIpcAdaptTest, IpcServiceGmProcessDataTest001, TestSize.Level1)
{
    OHOS::MessageParcel reply;
    uintptr_t out = reinterpret_cast<uintptr_t>(&reply);
    IpcDataInfo ipcParams [] = {GenerateIpcDataInforReqId(), GenerateIpcDataInforCommonData()};
    int32_t res = IpcServiceGmProcessData(ipcParams, 2, out);
    EXPECT_NE(res, HC_ERR_IPC_BAD_PARAM);
    ipcParams[1].valSz = 0;
    res = IpcServiceGmProcessData(ipcParams, 2, out);
    EXPECT_EQ(res, HC_ERR_IPC_BAD_PARAM);
}

HWTEST_F(DeviceAuthIpcAdaptTest, IpcServiceGmGetJoinedGroupsTest001, TestSize.Level1)
{
    OHOS::MessageParcel reply;
    uintptr_t out = reinterpret_cast<uintptr_t>(&reply);
    IpcDataInfo ipcParams [] = {GenerateIpcDataInforOsAccountId(), GenerateIpcDataInforAppId(),
        GenerateIpcDataInforGroupType()};
    int32_t res = IpcServiceGmGetJoinedGroups(ipcParams, 3, out);
    EXPECT_EQ(res, HC_SUCCESS);
    ipcParams[2].valSz = 0;
    res = IpcServiceGmGetJoinedGroups(ipcParams, 3, out);
    EXPECT_EQ(res, HC_ERR_IPC_BAD_PARAM);
}


HWTEST_F(DeviceAuthIpcAdaptTest, IpcServiceGaProcessDataTest001, TestSize.Level1)
{
    OHOS::MessageParcel reply;
    uintptr_t out = reinterpret_cast<uintptr_t>(&reply);
    IpcDataInfo ipcParams [] = {GenerateIpcDataInforReqId(), GenerateIpcDataInforCommonData(),
        GenerateIpcDataInforDevAuthCB(),
        GenerateIpcDataInforCBObject()};
    int32_t res = IpcServiceGaProcessData(ipcParams, 4, out);
    EXPECT_EQ(res, HC_ERR_IPC_BAD_PARAM);
    ipcParams[1].valSz -= 1;
    res = IpcServiceGaProcessData(ipcParams, 4, out);
    EXPECT_EQ(res, HC_ERR_IPC_BAD_PARAM);
}

HWTEST_F(DeviceAuthIpcAdaptTest, IpcServiceGaCancelRequest001, TestSize.Level1)
{
    OHOS::MessageParcel reply;
    uintptr_t out = reinterpret_cast<uintptr_t>(&reply);
    IpcDataInfo ipcParams [] = {GenerateIpcDataInforReqId(), GenerateIpcDataInforAppId()};
    ipcParams[0].valSz = 0;
    int32_t res = IpcServiceGaCancelRequest(ipcParams, 2, out);
    EXPECT_EQ(res, HC_ERR_IPC_BAD_PARAM);
    ipcParams[0].valSz = 8;
    res = IpcServiceGaCancelRequest(ipcParams, 2, out);
    EXPECT_EQ(res, HC_SUCCESS);
}

HWTEST_F(DeviceAuthIpcAdaptTest, IpcServiceDaProcessData001, TestSize.Level1)
{
    OHOS::MessageParcel reply;
    uintptr_t out = reinterpret_cast<uintptr_t>(&reply);
    IpcDataInfo ipcParams [] = {GenerateIpcDataInforReqId()};
    int32_t res = IpcServiceDaProcessData(ipcParams, 1, out);
    EXPECT_EQ(res, HC_ERR_IPC_BAD_PARAM);
    ipcParams[0].valSz = 0;
    res = IpcServiceDaProcessData(ipcParams, 1, out);
    EXPECT_EQ(res, HC_ERR_IPC_BAD_PARAM);
}

HWTEST_F(DeviceAuthIpcAdaptTest, IpcServiceDaCancelRequest001, TestSize.Level1)
{
    OHOS::MessageParcel reply;
    uintptr_t out = reinterpret_cast<uintptr_t>(&reply);
    IpcDataInfo ipcParams [] = {GenerateIpcDataInforReqId(), GenerateIpcDataInforAuthParams()};
    ipcParams[0].valSz = 0;
    int32_t res = IpcServiceDaCancelRequest(ipcParams, 2, out);
    EXPECT_EQ(res, HC_ERR_IPC_BAD_PARAM);
    ipcParams[0].valSz = 8;
    ipcParams[1].valSz = 0;
    res = IpcServiceDaCancelRequest(ipcParams, 2, out);
    EXPECT_EQ(res, HC_ERR_IPC_BAD_PARAM);
}

HWTEST_F(DeviceAuthIpcAdaptTest, IpcServiceGmCancelRequest001, TestSize.Level1)
{
    OHOS::MessageParcel reply;
    uintptr_t out = reinterpret_cast<uintptr_t>(&reply);
    IpcDataInfo ipcParams [] = {GenerateIpcDataInforReqId(), GenerateIpcDataInforAppId()};
    ipcParams[0].valSz = 0;
    int32_t res = IpcServiceGmCancelRequest(ipcParams, 2, out);
    EXPECT_EQ(res, HC_ERR_IPC_BAD_PARAM);
    ipcParams[0].valSz = 8;
    ipcParams[1].valSz = 0;
    res = IpcServiceGmCancelRequest(ipcParams, 2, out);
    EXPECT_EQ(res, HC_ERR_IPC_BAD_PARAM);
}
}