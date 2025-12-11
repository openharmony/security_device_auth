/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "dfx_fuzzer.h"

#include <cinttypes>
#include <unistd.h>
#include "common_defs.h"
#include "device_auth.h"
#include "hc_err_trace.h"
#include "hc_log.h"
#include "device_auth_defines.h"
#include "json_utils.h"
#include "securec.h"
#include "base/security/device_auth/services/data_manager/operation_data_manager/src/operation_data_manager.c"

namespace OHOS {
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

static int32_t DfxTestCase001(void)
{
    LOGE(TEST_STRING);
    SET_TRACE_ID(TEST_NUM);
    SET_LOG_MODE_AND_ERR_TRACE(NORMAL_MODE, false);
    int32_t len = GET_ERR_TRACE_LEN();
    return len;
}

static int32_t DfxTestCase002(void)
{
    va_list tempAp;
    SET_LOG_MODE_AND_ERR_TRACE(NORMAL_MODE, false);
    RECORD_ERR_TRACE(NULL, DEFAULT_LINE, NULL, tempAp);
    RECORD_ERR_TRACE(TEST_STRING, DEFAULT_LINE, NULL, tempAp);
    RECORD_ERR_TRACE(TEST_STRING, DEFAULT_LINE, TEST_STRING, tempAp);
    const char *errTrace = GET_ERR_TRACE();
    (void)errTrace;
    int32_t len = GET_ERR_TRACE_LEN();
    return len;
}

static int32_t DfxTestCase003(void)
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
    return len;
}

static int32_t DfxTestCase004(void)
{
    bool res = IsOsAccountOperationInfoLoaded(INVALID_OS_ACCOUNT);
    TlvOperation tlvOperation;
    Operation entry;
    tlvOperation.caller.data.parcel.data = NULL;
    tlvOperation.caller.data.parcel.beginPos = TEST_NUM_ZERO;
    tlvOperation.caller.data.parcel.endPos = TEST_NUM_ZERO;
    res = SetOperationElement(&tlvOperation, &entry);
    tlvOperation.caller.data = CreateString();
    entry.caller = CreateString();
    tlvOperation.function.data.parcel.data = NULL;
    tlvOperation.function.data.parcel.beginPos = TEST_NUM_ZERO;
    tlvOperation.function.data.parcel.endPos = TEST_NUM_ZERO;
    res = SetOperationElement(&tlvOperation, &entry);
    tlvOperation.function.data = CreateString();
    entry.function = CreateString();
    tlvOperation.operationInfo.data.parcel.data = NULL;
    tlvOperation.operationInfo.data.parcel.beginPos = TEST_NUM_ZERO;
    tlvOperation.operationInfo.data.parcel.endPos = TEST_NUM_ZERO;
    res = SetOperationElement(&tlvOperation, &entry);
    tlvOperation.operationInfo.data = CreateString();
    entry.operationInfo = CreateString();
    res = SetOperationElement(&tlvOperation, &entry);
    DeleteString(&tlvOperation.caller.data);
    DeleteString(&entry.caller);
    DeleteString(&tlvOperation.function.data);
    DeleteString(&entry.function);
    DeleteString(&tlvOperation.operationInfo.data);
    DeleteString(&entry.operationInfo);
    return res;
}

static int32_t DfxTestCase005(void)
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

    vec.pushBackT(&vec, operation1);
    res = SaveOperations(&vec, &dbv1);

    vec.pushBackT(&vec, &operation2);
    res = SaveOperations(&vec, &dbv1);

    DestroyOperationRecord(operation1);
    TLV_DEINIT(dbv1)
    DestroyOperationVec(&vec);
    return res;
}

static int32_t DfxTestCase006(void)
{
    OsAccountOperationInfo testInfo;
    testInfo.osAccountId = DEFAULT_OS_ACCOUNT;
    testInfo.operations = CreateOperationVec();

    bool res = SaveOperationInfoToParcel(&testInfo, NULL);

    HcParcel parcel = CreateParcel(0, 0);
    res = SaveOperationInfoToParcel(&testInfo, &parcel);
    DeleteParcel(&parcel);

    ClearOperationVec(&testInfo.operations);
    return res;
}

static int32_t DfxTestCase007(void)
{
    char path[TEST_NUM_ONE] = { 0 };
    bool res = GetOsAccountOperationInfoPathCe(DEFAULT_OS_ACCOUNT, path, TEST_NUM_ONE);
    SaveParcelToFile(path, NULL);

    char filePath[MAX_DB_PATH_LEN] = { 0 };
    res = GetOsAccountOperationInfoPathCe(DEFAULT_OS_ACCOUNT, filePath, MAX_DB_PATH_LEN);
    res = SaveParcelToFile(path, NULL);
    HcParcel parcel = CreateParcel(0, 0);
    res = SaveParcelToFile(path, &parcel);
    DeleteParcel(&parcel);
    return res;
}

static int32_t DfxTestCase008(void)
{
    OsAccountOperationInfo testInfo;
    testInfo.osAccountId = DEFAULT_OS_ACCOUNT;
    testInfo.operations = CreateOperationVec();

    int32_t res = SaveOperationInfo(NULL);

    res = SaveOperationInfo(&testInfo);

    res = SaveOperationInfo(&testInfo);

    (void)SaveTainedOperation(INVALID_OS_ACCOUNT);

    ClearOperationVec(&testInfo.operations);
    return res;
}

static int32_t DfxTestCase009(void)
{
    char filePath[MAX_DB_PATH_LEN] = { 0 };
    bool res = GetOsAccountOperationInfoPathCe(DEFAULT_OS_ACCOUNT, filePath, MAX_DB_PATH_LEN);
    res = ReadParcelFromFile(NULL, NULL);

    res = ReadParcelFromFile(filePath, NULL);
    return res;
}

static int32_t DfxTestCase010(void)
{
    TlvOperation tlvOperation;
    Operation entry;
    entry.caller.parcel.data = NULL;
    entry.caller.parcel.beginPos = TEST_NUM_ZERO;
    entry.caller.parcel.endPos = TEST_NUM_ZERO;
    bool res = GenerateOperationFromTlv(&tlvOperation, &entry);
    tlvOperation.caller.data = CreateString();
    entry.caller = CreateString();
    entry.function.parcel.data = NULL;
    entry.function.parcel.beginPos = TEST_NUM_ZERO;
    entry.function.parcel.endPos = TEST_NUM_ZERO;
    res = GenerateOperationFromTlv(&tlvOperation, &entry);
    tlvOperation.function.data = CreateString();
    entry.function = CreateString();
    entry.operationInfo.parcel.data = NULL;
    entry.operationInfo.parcel.beginPos = TEST_NUM_ZERO;
    entry.operationInfo.parcel.endPos = TEST_NUM_ZERO;
    res = GenerateOperationFromTlv(&tlvOperation, &entry);
    tlvOperation.operationInfo.data = CreateString();
    entry.operationInfo = CreateString();
    res = GenerateOperationFromTlv(&tlvOperation, &entry);
    DeleteString(&tlvOperation.caller.data);
    DeleteString(&entry.caller);
    DeleteString(&tlvOperation.function.data);
    DeleteString(&entry.function);
    DeleteString(&tlvOperation.operationInfo.data);
    DeleteString(&entry.operationInfo);
    return res;
}

static int32_t DfxTestCase011(void)
{
    LoadOsAccountDb(DEFAULT_OS_ACCOUNT);
    OsAccountOperationInfo info;
    info.osAccountId = DEFAULT_OS_ACCOUNT;
    info.isTained = false;
    info.operations = CreateOperationVec();
    HcOperationDataBaseV1 dbv1;
    TLV_INIT(HcOperationDataBaseV1, &dbv1)

    bool res = LoadOperations(&dbv1, &info.operations);

    res = ReadInfoFromParcel(NULL, NULL);

    TLV_DEINIT(dbv1)
    DestroyOperationVec(&info.operations);
    return res;
}

static int32_t DfxTestCase012(void)
{
    DestroyOperationDataManager();
    InitOperationDataManager();
    OsAccountOperationInfo *info = GetOperationInfoByOsAccountId(DEFAULT_OS_ACCOUNT);
    (void)info;
    Operation entry2;
    Operation entry1;
    entry1.caller.parcel.data = NULL;
    entry1.caller.parcel.beginPos = TEST_NUM_ZERO;
    entry1.caller.parcel.endPos = TEST_NUM_ZERO;
    bool res = GenerateOperationFromOperation(&entry2, &entry1);
    entry2.caller = CreateString();
    entry1.caller = CreateString();
    entry1.function.parcel.data = NULL;
    entry1.function.parcel.beginPos = TEST_NUM_ZERO;
    entry1.function.parcel.endPos = TEST_NUM_ZERO;
    res = GenerateOperationFromOperation(&entry2, &entry1);
    entry2.function = CreateString();
    entry1.function = CreateString();
    entry1.operationInfo.parcel.data = NULL;
    entry1.operationInfo.parcel.beginPos = TEST_NUM_ZERO;
    entry1.operationInfo.parcel.endPos = TEST_NUM_ZERO;
    res = GenerateOperationFromOperation(&entry2, &entry1);
    entry2.operationInfo = CreateString();
    entry1.operationInfo = CreateString();
    res = GenerateOperationFromOperation(&entry2, &entry1);
    DeleteString(&entry2.caller);
    DeleteString(&entry1.caller);
    DeleteString(&entry2.function);
    DeleteString(&entry1.function);
    DeleteString(&entry2.operationInfo);
    DeleteString(&entry1.operationInfo);
    return res;
}

static int32_t DfxTestCase013(void)
{
    ClearOperationVec(NULL);
    Operation entry1;
    entry1.caller.parcel.data = NULL;
    entry1.caller.parcel.beginPos = TEST_NUM_ZERO;
    entry1.caller.parcel.endPos = TEST_NUM_ZERO;
    Operation *operation1 = CreateOperationRecord();
    Operation *operation2 = DeepCopyOperationRecord(NULL);
    operation2 = DeepCopyOperationRecord(&entry1);
    operation2 = DeepCopyOperationRecord(operation1);
    DestroyOperationRecord(operation2);

    operation1->operationType = OPERATION_ANY;
    int32_t res = RecordOperationData(TEST_OS_ACCOUNT_ID, NULL);

    res = RecordOperationData(TEST_OS_ACCOUNT_ID, operation1);
    res = RecordOperationData(TEST_OS_ACCOUNT_ID, operation1);
    OsAccountOperationInfo *info = GetOperationInfoByOsAccountId(TEST_OS_ACCOUNT_ID);
    RemoveRedundantRecord(info, TEST_NUM_ONE);

    DestroyOperationRecord(operation1);
    return res;
}

static int32_t DfxTestCase014(void)
{
    char record[DEFAULT_RECENT_OPERATION_CNT * DEFAULT_RECORD_OPERATION_SIZE] = { 0 };
    int32_t res = GetOperationDataRecently(TEST_OS_ACCOUNT_ID, OPERATION_ANY, NULL, TEST_NUM_ZERO, TEST_NUM_ONE);
    res = GetOperationDataRecently(TEST_OS_ACCOUNT_ID, OPERATION_ANY, record,
        DEFAULT_RECENT_OPERATION_CNT * DEFAULT_RECORD_OPERATION_SIZE, TEST_NUM_ONE);
    return res;
}

static int32_t DfxTestCase015(void)
{
    bool ret = SaveTainedOperation(TEST_OS_ACCOUNT_ID);
#ifdef DEV_AUTH_HIVIEW_ENABLE
    LoadAllAccountsData();
#endif
    LoadDataIfNotLoaded(TEST_OS_ACCOUNT_ID);
    ret = IsOsAccountOperationInfoLoaded(INVALID_OS_ACCOUNT);
    Operation *operation1 = CreateOperationRecord();
    int32_t res = RecordOperationData(TEST_OS_ACCOUNT_ID, operation1);
    char record[TEST_NUM_ONE * DEFAULT_RECORD_OPERATION_SIZE] = { 0 };
    res = GetOperationDataRecently(TEST_OS_ACCOUNT_ID, OPERATION_ANY, record,
        TEST_NUM_ONE * DEFAULT_RECORD_OPERATION_SIZE, TEST_NUM_ONE);
#ifdef DEV_AUTH_HIVIEW_ENABLE
    DevAuthDataBaseDump(0);
#endif
    DestroyOperationRecord(operation1);
    return res;
}

static void DfxFuzzPart(void)
{
    InitOperationDataManager();
    (void)DfxTestCase001();
    (void)DfxTestCase002();
    (void)DfxTestCase003();
    (void)DfxTestCase004();
    (void)DfxTestCase005();
    (void)DfxTestCase006();
    (void)DfxTestCase007();
    (void)DfxTestCase008();
    (void)DfxTestCase009();
    (void)DfxTestCase010();
    (void)DfxTestCase011();
    (void)DfxTestCase012();
    (void)DfxTestCase013();
    (void)DfxTestCase014();
    (void)DfxTestCase015();
    DestroyOperationDataManager();
}

bool FuzzDoCallback(const uint8_t* data, size_t size)
{
    (void)data;
    (void)size;
    (void)DfxFuzzPart();
    return true;
}
}
/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    OHOS::FuzzDoCallback(data, size);
    return 0;
}

