/*
 * Copyright (C) 2022 Huawei Device Co., Ltd.
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
#include "common_defs.h"
#include "device_auth.h"
#include "hc_err_trace.h"
#include "hc_log.h"
#include "device_auth_defines.h"
#include "json_utils.h"
#include "securec.h"
#include "base/security/device_auth/services/data_manager/operation_data_manager/src/operation_data_manager.c"

using namespace std;
using namespace testing::ext;

namespace {
#define TEST_STRING "test"
#define TEST_STRING_128 "1234567812345678123456781234567812345678123456781234567812345678" \
    "1234567812345678123456781234567812345678123456781234567812345678"
#define TEST_STRING_256 "1234567812345678123456781234567812345678123456781234567812345678" \
    "1234567812345678123456781234567812345678123456781234567812345678" \
    "1234567812345678123456781234567812345678123456781234567812345678" \
    "1234567812345678123456781234567812345678123456781234567812345678"
#define TEST_STRING_LEN 4
#define TEST_NUM 0
#define DEFAULT_LINE 0
#define TEST_NUM_ZERO 0
#define TEST_NUM_ONE 1
#define TEST_OS_ACCOUNT_ID 100

class DFXOperationCommonTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void DFXOperationCommonTest::SetUpTestCase() {}
void DFXOperationCommonTest::TearDownTestCase() {}

void DFXOperationCommonTest::SetUp()
{
    InitOperationDataManager();
}

void DFXOperationCommonTest::TearDown()
{
    DestroyOperationDataManager();
}

HWTEST_F(DFXOperationCommonTest, DFXOperationCommonTest001, TestSize.Level0)
{
    LOGE(TEST_STRING);
    SET_TRACE_ID(TEST_NUM);
    SET_LOG_MODE_AND_ERR_TRACE(NORMAL_MODE, false);
    int32_t len = GET_ERR_TRACE_LEN();
    ASSERT_EQ(len, 0);
}

HWTEST_F(DFXOperationCommonTest, DFXOperationCommonTest002, TestSize.Level0)
{
    va_list tempAp;
    SET_LOG_MODE_AND_ERR_TRACE(NORMAL_MODE, false);
    RECORD_ERR_TRACE(NULL, DEFAULT_LINE, NULL, tempAp);
    RECORD_ERR_TRACE(TEST_STRING, DEFAULT_LINE, NULL, tempAp);
    RECORD_ERR_TRACE(TEST_STRING, DEFAULT_LINE, TEST_STRING, tempAp);
    const char *errTrace = GET_ERR_TRACE();
    (void)errTrace;
    int32_t len = GET_ERR_TRACE_LEN();
    EXPECT_EQ(len, 0);
}

HWTEST_F(DFXOperationCommonTest, DFXOperationCommonTest003, TestSize.Level0)
{
    SET_LOG_MODE_AND_ERR_TRACE(TRACE_MODE, true);
    LOGE(TEST_STRING);
    SET_LOG_MODE_AND_ERR_TRACE(NORMAL_MODE, true);
    LOGE(TEST_STRING_256);
    LOGE(TEST_STRING_256);
    LOGE(TEST_STRING_256);
    LOGE(TEST_STRING_128);
    SET_LOG_MODE_AND_ERR_TRACE(NORMAL_MODE, false);
    int32_t len = GET_ERR_TRACE_LEN();
    EXPECT_EQ(len, 0);
}

HWTEST_F(DFXOperationCommonTest, DFXOperationCommonTest004, TestSize.Level0)
{
    bool res = IsOsAccountOperationInfoLoaded(INVALID_OS_ACCOUNT);
    EXPECT_EQ(res, false);
    TlvOperation tlvOperation;
    Operation entry;
    tlvOperation.caller.data.parcel.data = NULL;
    tlvOperation.caller.data.parcel.beginPos = TEST_NUM_ZERO;
    tlvOperation.caller.data.parcel.endPos = TEST_NUM_ZERO;
    res = SetOperationElement(&tlvOperation, &entry);
    EXPECT_EQ(res, false);
    tlvOperation.caller.data = CreateString();
    entry.caller = CreateString();
    tlvOperation.function.data.parcel.data = NULL;
    tlvOperation.function.data.parcel.beginPos = TEST_NUM_ZERO;
    tlvOperation.function.data.parcel.endPos = TEST_NUM_ZERO;
    res = SetOperationElement(&tlvOperation, &entry);
    EXPECT_EQ(res, false);
    tlvOperation.function.data = CreateString();
    entry.function = CreateString();
    tlvOperation.operationInfo.data.parcel.data = NULL;
    tlvOperation.operationInfo.data.parcel.beginPos = TEST_NUM_ZERO;
    tlvOperation.operationInfo.data.parcel.endPos = TEST_NUM_ZERO;
    res = SetOperationElement(&tlvOperation, &entry);
    EXPECT_EQ(res, false);
    tlvOperation.operationInfo.data = CreateString();
    entry.operationInfo = CreateString();
    res = SetOperationElement(&tlvOperation, &entry);
    EXPECT_EQ(res, true);
    DeleteString(&tlvOperation.caller.data);
    DeleteString(&entry.caller);
    DeleteString(&tlvOperation.function.data);
    DeleteString(&entry.function);
    DeleteString(&tlvOperation.operationInfo.data);
    DeleteString(&entry.operationInfo);
}

HWTEST_F(DFXOperationCommonTest, DFXOperationCommonTest005, TestSize.Level0)
{
    OperationVec vec = CreateOperationVec();
    HcOperationDataBaseV1 dbv1;
    Operation *operation1 = CreateOperationRecord();
    Operation operation2;
    operation2.caller.parcel.data = NULL;
    operation2.caller.parcel.beginPos = TEST_NUM_ZERO;
    operation2.caller.parcel.endPos = TEST_NUM_ZERO;

    TLV_INIT(HcOperationDataBaseV1, &dbv1)
    bool res = SaveOperations(&vec, &dbv1);
    EXPECT_EQ(res, true);

    vec.pushBackT(&vec, operation1);
    res = SaveOperations(&vec, &dbv1);
    EXPECT_EQ(res, true);

    vec.pushBackT(&vec, &operation2);
    res = SaveOperations(&vec, &dbv1);
    EXPECT_EQ(res, false);

    DestroyOperationRecord(operation1);
    TLV_DEINIT(dbv1)
    DestroyOperationVec(&vec);
}

HWTEST_F(DFXOperationCommonTest, DFXOperationCommonTest006, TestSize.Level0)
{
    OsAccountOperationInfo testInfo;
    testInfo.osAccountId = DEFAULT_OS_ACCOUNT;
    testInfo.operations = CreateOperationVec();

    bool res = SaveOperationInfoToParcel(&testInfo, NULL);
    EXPECT_EQ(res, false);

    HcParcel parcel = CreateParcel(0, 0);
    res = SaveOperationInfoToParcel(&testInfo, &parcel);
    EXPECT_EQ(res, true);
    DeleteParcel(&parcel);

    ClearOperationVec(&testInfo.operations);
}

HWTEST_F(DFXOperationCommonTest, DFXOperationCommonTest007, TestSize.Level0)
{
    char path[TEST_NUM_ONE] = { 0 };
    bool res = GetOsAccountOperationInfoPathCe(DEFAULT_OS_ACCOUNT, path, TEST_NUM_ONE);
    EXPECT_EQ(res, false);
    SaveParcelToFile(path, NULL);
    EXPECT_EQ(res, false);

    char filePath[MAX_DB_PATH_LEN] = { 0 };
    res = GetOsAccountOperationInfoPathCe(DEFAULT_OS_ACCOUNT, filePath, MAX_DB_PATH_LEN);
    EXPECT_EQ(res, true);
    res = SaveParcelToFile(path, NULL);
    EXPECT_EQ(res, false);
    HcParcel parcel = CreateParcel(0, 0);
    res = SaveParcelToFile(path, &parcel);
    EXPECT_EQ(res, false);
    DeleteParcel(&parcel);
}

HWTEST_F(DFXOperationCommonTest, DFXOperationCommonTest008, TestSize.Level0)
{
    OsAccountOperationInfo testInfo;
    testInfo.osAccountId = DEFAULT_OS_ACCOUNT;
    testInfo.operations = CreateOperationVec();

    int32_t res = SaveOperationInfo(NULL);
    EXPECT_EQ(res, HC_ERR_INVALID_PARAMS);

    res = SaveOperationInfo(&testInfo);
    EXPECT_EQ(res, HC_SUCCESS);

    res = SaveOperationInfo(&testInfo);
    EXPECT_EQ(res, HC_SUCCESS);

    bool ret = SaveTainedOperation(INVALID_OS_ACCOUNT);
    EXPECT_EQ(ret, true);

    ClearOperationVec(&testInfo.operations);
}

HWTEST_F(DFXOperationCommonTest, DFXOperationCommonTest009, TestSize.Level0)
{
    char filePath[MAX_DB_PATH_LEN] = { 0 };
    bool res = GetOsAccountOperationInfoPathCe(DEFAULT_OS_ACCOUNT, filePath, MAX_DB_PATH_LEN);
    EXPECT_EQ(res, true);
    res = ReadParcelFromFile(NULL, NULL);
    EXPECT_EQ(res, false);

    res = ReadParcelFromFile(filePath, NULL);
    EXPECT_EQ(res, false);

    HcParcel parcel = CreateParcel(0, 0);
    res = ReadParcelFromFile(filePath, &parcel);
    EXPECT_EQ(res, true);
    DeleteParcel(&parcel);
}

HWTEST_F(DFXOperationCommonTest, DFXOperationCommonTest010, TestSize.Level0)
{
    TlvOperation tlvOperation;
    Operation entry;
    entry.caller.parcel.data = NULL;
    entry.caller.parcel.beginPos = TEST_NUM_ZERO;
    entry.caller.parcel.endPos = TEST_NUM_ZERO;
    bool res = GenerateOperationFromTlv(&tlvOperation, &entry);
    EXPECT_EQ(res, false);
    tlvOperation.caller.data = CreateString();
    entry.caller = CreateString();
    entry.function.parcel.data = NULL;
    entry.function.parcel.beginPos = TEST_NUM_ZERO;
    entry.function.parcel.endPos = TEST_NUM_ZERO;
    res = GenerateOperationFromTlv(&tlvOperation, &entry);
    EXPECT_EQ(res, false);
    tlvOperation.function.data = CreateString();
    entry.function = CreateString();
    entry.operationInfo.parcel.data = NULL;
    entry.operationInfo.parcel.beginPos = TEST_NUM_ZERO;
    entry.operationInfo.parcel.endPos = TEST_NUM_ZERO;
    res = GenerateOperationFromTlv(&tlvOperation, &entry);
    EXPECT_EQ(res, false);
    tlvOperation.operationInfo.data = CreateString();
    entry.operationInfo = CreateString();
    res = GenerateOperationFromTlv(&tlvOperation, &entry);
    EXPECT_EQ(res, true);
    DeleteString(&tlvOperation.caller.data);
    DeleteString(&entry.caller);
    DeleteString(&tlvOperation.function.data);
    DeleteString(&entry.function);
    DeleteString(&tlvOperation.operationInfo.data);
    DeleteString(&entry.operationInfo);
}

HWTEST_F(DFXOperationCommonTest, DFXOperationCommonTest011, TestSize.Level0)
{
    LoadOsAccountDb(DEFAULT_OS_ACCOUNT);
    OsAccountOperationInfo info;
    info.osAccountId = DEFAULT_OS_ACCOUNT;
    info.isTained = false;
    info.operations = CreateOperationVec();
    HcOperationDataBaseV1 dbv1;
    TLV_INIT(HcOperationDataBaseV1, &dbv1)

    bool res = LoadOperations(&dbv1, &info.operations);
    EXPECT_EQ(res, true);

    res = ReadInfoFromParcel(NULL, NULL);
    EXPECT_EQ(res, false);

    TLV_DEINIT(dbv1)
    DestroyOperationVec(&info.operations);
}

HWTEST_F(DFXOperationCommonTest, DFXOperationCommonTest012, TestSize.Level0)
{
    DestroyOperationDataManager();
    InitOperationDataManager();
    OsAccountOperationInfo *info = GetOperationInfoByOsAccountId(DEFAULT_OS_ACCOUNT);
    EXPECT_NE(info, NULL);

    Operation entry2;
    Operation entry1;
    entry1.caller.parcel.data = NULL;
    entry1.caller.parcel.beginPos = TEST_NUM_ZERO;
    entry1.caller.parcel.endPos = TEST_NUM_ZERO;
    bool res = GenerateOperationFromOperation(&entry2, &entry1);
    EXPECT_EQ(res, false);
    entry2.caller = CreateString();
    entry1.caller = CreateString();
    entry1.function.parcel.data = NULL;
    entry1.function.parcel.beginPos = TEST_NUM_ZERO;
    entry1.function.parcel.endPos = TEST_NUM_ZERO;
    res = GenerateOperationFromOperation(&entry2, &entry1);
    EXPECT_EQ(res, false);
    entry2.function = CreateString();
    entry1.function = CreateString();
    entry1.operationInfo.parcel.data = NULL;
    entry1.operationInfo.parcel.beginPos = TEST_NUM_ZERO;
    entry1.operationInfo.parcel.endPos = TEST_NUM_ZERO;
    res = GenerateOperationFromOperation(&entry2, &entry1);
    EXPECT_EQ(res, false);
    entry2.operationInfo = CreateString();
    entry1.operationInfo = CreateString();
    res = GenerateOperationFromOperation(&entry2, &entry1);
    EXPECT_EQ(res, true);
    DeleteString(&entry2.caller);
    DeleteString(&entry1.caller);
    DeleteString(&entry2.function);
    DeleteString(&entry1.function);
    DeleteString(&entry2.operationInfo);
    DeleteString(&entry1.operationInfo);
}

HWTEST_F(DFXOperationCommonTest, DFXOperationCommonTest013, TestSize.Level0)
{
    ClearOperationVec(NULL);
    Operation entry1;
    entry1.caller.parcel.data = NULL;
    entry1.caller.parcel.beginPos = TEST_NUM_ZERO;
    entry1.caller.parcel.endPos = TEST_NUM_ZERO;
    Operation *operation1 = CreateOperationRecord();
    Operation *operation2 = DeepCopyOperationRecord(NULL);
    EXPECT_EQ(operation2, NULL);
    operation2 = DeepCopyOperationRecord(&entry1);
    EXPECT_EQ(operation2, NULL);
    operation2 = DeepCopyOperationRecord(operation1);
    EXPECT_NE(operation2, NULL);
    DestroyOperationRecord(operation2);

    operation1->operationType = OPERATION_ANY;
    int32_t res = RecordOperationData(TEST_OS_ACCOUNT_ID, NULL);
    EXPECT_EQ(res, HC_ERR_NULL_PTR);

    res = RecordOperationData(TEST_OS_ACCOUNT_ID, operation1);
    EXPECT_EQ(res, HC_SUCCESS);
    res = RecordOperationData(TEST_OS_ACCOUNT_ID, operation1);
    EXPECT_EQ(res, HC_SUCCESS);
    OsAccountOperationInfo *info = GetOperationInfoByOsAccountId(TEST_OS_ACCOUNT_ID);
    RemoveRedundantRecord(info, TEST_NUM_ONE);

    DestroyOperationRecord(operation1);
}

HWTEST_F(DFXOperationCommonTest, DFXOperationCommonTest014, TestSize.Level0)
{
    char record[DEFAULT_RECENT_OPERATION_CNT * DEFAULT_RECORD_OPERATION_SIZE] = { 0 };
    int32_t res = GetOperationDataRecently(TEST_OS_ACCOUNT_ID, OPERATION_ANY, NULL, TEST_NUM_ZERO, TEST_NUM_ONE);
    EXPECT_EQ(res, -1);
    res = GetOperationDataRecently(TEST_OS_ACCOUNT_ID, OPERATION_ANY, record,
        DEFAULT_RECENT_OPERATION_CNT * DEFAULT_RECORD_OPERATION_SIZE, TEST_NUM_ONE);
    EXPECT_NE(res, -1);
}
}