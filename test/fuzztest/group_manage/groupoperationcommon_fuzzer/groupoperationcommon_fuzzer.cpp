/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#include "groupoperationcommon_fuzzer.h"

#include "alg_defs.h"
#include "common_defs.h"
#include "device_auth.h"
#include "group_operation_common.h"
#include "hc_dev_info.h"
#include "json_utils.h"
#include "securec.h"
#include "data_manager.h"

namespace OHOS {
static const char *NORMAL_STR = "abc";
static const Uint8Buff NORMAL_BUFF = { 0, 0 };
static QueryGroupParams g_queryGroupParams = {
    .groupId = NORMAL_STR,
    .groupName = NORMAL_STR,
    .ownerName = NORMAL_STR,
    .groupType = PEER_TO_PEER_GROUP,
    .userId = NULL,
    .groupVisibility = ALL_GROUP_VISIBILITY
    };

static int32_t GenerateGroupParams(const CJson *jsonParams, const char *groupId, TrustedGroupEntry *groupParams)
{
    (void)jsonParams;
    (void)groupId;
    (void)groupParams;
    return HC_SUCCESS;
}

static int32_t GenerateDevParams(const CJson *jsonParams, const char *groupId, TrustedDeviceEntry *devParams)
{
    (void)jsonParams;
    (void)groupId;
    (void)devParams;
    return HC_SUCCESS;
}

static void GroupOperationTest01(void)
{
    (void)GetGroupEntryById(DEFAULT_OS_ACCOUNT, nullptr);
}

static void GroupOperationTest02(void)
{
    (void)IsTrustedDeviceInGroup(DEFAULT_OS_ACCOUNT, nullptr, NORMAL_STR, true);
}

static void GroupOperationTest03(void)
{
    (void)IsTrustedDeviceInGroup(DEFAULT_OS_ACCOUNT, NORMAL_STR, nullptr, true);
}

static void GroupOperationTest04(void)
{
    (void)IsTrustedDeviceInGroup(DEFAULT_OS_ACCOUNT, NORMAL_STR, NORMAL_STR, true);
}

static void GroupOperationTest05(void)
{
    (void)IsGroupOwner(DEFAULT_OS_ACCOUNT, nullptr, NORMAL_STR);
}

static void GroupOperationTest06(void)
{
    (void)IsGroupOwner(DEFAULT_OS_ACCOUNT, NORMAL_STR, nullptr);
}

static void GroupOperationTest07(void)
{
    (void)IsGroupOwner(DEFAULT_OS_ACCOUNT, NORMAL_STR, NORMAL_STR);
}

static void GroupOperationTest08(void)
{
    (void)IsGroupExistByGroupId(DEFAULT_OS_ACCOUNT, nullptr);
}

static void GroupOperationTest09(void)
{
    (void)CheckGroupAccessible(DEFAULT_OS_ACCOUNT, nullptr, NORMAL_STR);
}

static void GroupOperationTest10(void)
{
    (void)CheckGroupAccessible(DEFAULT_OS_ACCOUNT, NORMAL_STR, nullptr);
}

static void GroupOperationTest11(void)
{
    (void)CheckGroupAccessible(DEFAULT_OS_ACCOUNT, NORMAL_STR, NORMAL_STR);
}

static void GroupOperationTest12(void)
{
    (void)CheckGroupEditAllowed(DEFAULT_OS_ACCOUNT, nullptr, NORMAL_STR);
}

static void GroupOperationTest13(void)
{
    (void)CheckGroupEditAllowed(DEFAULT_OS_ACCOUNT, NORMAL_STR, nullptr);
}

static void GroupOperationTest14(void)
{
    (void)CheckGroupEditAllowed(DEFAULT_OS_ACCOUNT, NORMAL_STR, NORMAL_STR);
}

static void GroupOperationTest15(void)
{
    (void)GetGroupInfo(DEFAULT_OS_ACCOUNT, &g_queryGroupParams, nullptr);
}

static void GroupOperationTest16(void)
{
    (void)GetTrustedDevInfoById(DEFAULT_OS_ACCOUNT, nullptr, true, NORMAL_STR, nullptr);
}

static void GroupOperationTest17(void)
{
    (void)GetTrustedDevInfoById(DEFAULT_OS_ACCOUNT, NORMAL_STR, true, nullptr, nullptr);
}

static void GroupOperationTest18(void)
{
    (void)GetTrustedDevInfoById(DEFAULT_OS_ACCOUNT, NORMAL_STR, true, NORMAL_STR, nullptr);
}

static void GroupOperationTest19(void)
{
    uint8_t *hashMessage = NULL;
    uint32_t messageSize = 0;
    (void)GetHashMessage(nullptr, &NORMAL_BUFF, &hashMessage, &messageSize);
}

static void GroupOperationTest20(void)
{
    uint8_t *hashMessage = NULL;
    uint32_t messageSize = 0;
    (void)GetHashMessage(&NORMAL_BUFF, nullptr, &hashMessage, &messageSize);
}

static void GroupOperationTest21(void)
{
    uint32_t messageSize = 0;
    (void)GetHashMessage(&NORMAL_BUFF, &NORMAL_BUFF, nullptr, &messageSize);
}

static void GroupOperationTest22(void)
{
    uint8_t *hashMessage = NULL;
    (void)GetHashMessage(&NORMAL_BUFF, &NORMAL_BUFF, &hashMessage, nullptr);
}

static void GroupOperationTest23(void)
{
    (void)GetCurDeviceNumByGroupId(DEFAULT_OS_ACCOUNT, nullptr);
}

static void GroupOperationTest24(void)
{
    (void)AssertPeerDeviceNotSelf(nullptr);
}

static void GroupOperationTest25(void)
{
    char localUdid[INPUT_UDID_LEN] = { 0 };
    (void)HcGetUdid((uint8_t *)localUdid, INPUT_UDID_LEN);
    (void)AssertPeerDeviceNotSelf(localUdid);
}

static void GroupOperationTest26(void)
{
    (void)CheckGroupExist(DEFAULT_OS_ACCOUNT, nullptr);
}

static void GroupOperationTest27(void)
{
    CJson *jsonParams = CreateJson();
    (void)AddGroupToDatabaseByJson(DEFAULT_OS_ACCOUNT, nullptr, jsonParams, NORMAL_STR);
    FreeJson(jsonParams);
}

static void GroupOperationTest28(void)
{
    (void)AddGroupToDatabaseByJson(DEFAULT_OS_ACCOUNT, GenerateGroupParams, nullptr, NORMAL_STR);
}

static void GroupOperationTest29(void)
{
    CJson *jsonParams = CreateJson();
    (void)AddGroupToDatabaseByJson(DEFAULT_OS_ACCOUNT, GenerateGroupParams, jsonParams, nullptr);
    FreeJson(jsonParams);
}

static void GroupOperationTest30(void)
{
    CJson *jsonParams = CreateJson();
    (void)AddDeviceToDatabaseByJson(DEFAULT_OS_ACCOUNT, nullptr, jsonParams, NORMAL_STR);
    FreeJson(jsonParams);
}

static void GroupOperationTest31(void)
{
    (void)AddDeviceToDatabaseByJson(DEFAULT_OS_ACCOUNT, GenerateDevParams, nullptr, NORMAL_STR);
}

static void GroupOperationTest32(void)
{
    CJson *jsonParams = CreateJson();
    (void)AddDeviceToDatabaseByJson(DEFAULT_OS_ACCOUNT, GenerateDevParams, jsonParams, nullptr);
    FreeJson(jsonParams);
}

static void GroupOperationTest33(void)
{
    (void)DelGroupFromDb(DEFAULT_OS_ACCOUNT, nullptr);
}

static void GroupOperationTest34(void)
{
    const char *groupId = "ABCD";
    (void)DelGroupFromDb(DEFAULT_OS_ACCOUNT, groupId);
}

static void GroupOperationTest35(void)
{
    char *returnJsonStr = nullptr;
    (void)ConvertGroupIdToJsonStr(nullptr, &returnJsonStr);
}

static void GroupOperationTest36(void)
{
    (void)ConvertGroupIdToJsonStr(NORMAL_STR, nullptr);
}

static void GroupOperationTest37(void)
{
    char *returnJsonStr = nullptr;
    (void)GenerateBindSuccessData(nullptr, NORMAL_STR, NORMAL_STR, &returnJsonStr);
}

static void GroupOperationTest38(void)
{
    char *returnJsonStr = nullptr;
    (void)GenerateBindSuccessData(NORMAL_STR, nullptr, NORMAL_STR, &returnJsonStr);
}

static void GroupOperationTest39(void)
{
    (void)GenerateBindSuccessData(NORMAL_STR, NORMAL_STR, NORMAL_STR, nullptr);
}

static void GroupOperationTest40(void)
{
    char *returnJsonStr = nullptr;
    (void)GenerateUnbindSuccessData(nullptr, NORMAL_STR, &returnJsonStr);
}

static void GroupOperationTest41(void)
{
    char *returnJsonStr = nullptr;
    (void)GenerateUnbindSuccessData(NORMAL_STR, nullptr, &returnJsonStr);
}

static void GroupOperationTest42(void)
{
    (void)GenerateUnbindSuccessData(NORMAL_STR, NORMAL_STR, nullptr);
}


static void GroupOperationTest43(void)
{
    (void)ProcessKeyPair(CREATE_KEY_PAIR, nullptr, NORMAL_STR);
}

static void GroupOperationTest44(void)
{
    CJson *jsonParams = CreateJson();
    (void)ProcessKeyPair(CREATE_KEY_PAIR, jsonParams, nullptr);
    FreeJson(jsonParams);
}

static void GroupOperationTest45(void)
{
    uint32_t groupType;
    (void)GetGroupTypeFromDb(DEFAULT_OS_ACCOUNT, nullptr, &groupType);
}

static void GroupOperationTest46(void)
{
    (void)GetGroupTypeFromDb(DEFAULT_OS_ACCOUNT, NORMAL_STR, nullptr);
}

static void GroupOperationTest47(void)
{
    uint32_t groupType;
    (void)GetGroupTypeFromDb(DEFAULT_OS_ACCOUNT, NORMAL_STR, &groupType);
}

static void GroupOperationTest48(void)
{
    char *userId = nullptr;
    (void)GetUserIdFromJson(nullptr, &userId);
}

static void GroupOperationTest49(void)
{
    CJson *jsonParams = CreateJson();
    (void)GetUserIdFromJson(jsonParams, nullptr);
    FreeJson(jsonParams);
}

static void GroupOperationTest50(void)
{
    char *userId = nullptr;
    CJson *jsonParams = CreateJson();
    (void)GetUserIdFromJson(jsonParams, &userId);
    FreeJson(jsonParams);
}

static void GroupOperationTest51(void)
{
    char *sharedUserId = nullptr;
    (void)GetSharedUserIdFromJson(nullptr, &sharedUserId);
}

static void GroupOperationTest52(void)
{
    CJson *jsonParams = CreateJson();
    (void)GetSharedUserIdFromJson(jsonParams, nullptr);
    FreeJson(jsonParams);
}

static void GroupOperationTest53(void)
{
    char *sharedUserId = nullptr;
    CJson *jsonParams = CreateJson();
    (void)GetSharedUserIdFromJson(jsonParams, &sharedUserId);
    FreeJson(jsonParams);
}

static void GroupOperationTest54(void)
{
    const char *groupId = nullptr;
    (void)GetGroupIdFromJson(nullptr, &groupId);
}

static void GroupOperationTest55(void)
{
    CJson *jsonParams = CreateJson();
    (void)GetGroupIdFromJson(jsonParams, nullptr);
    FreeJson(jsonParams);
}

static void GroupOperationTest56(void)
{
    const char *groupId = nullptr;
    CJson *jsonParams = CreateJson();
    (void)GetGroupIdFromJson(jsonParams, &groupId);
    FreeJson(jsonParams);
}

static void GroupOperationTest57(void)
{
    const char *appId = nullptr;
    (void)GetAppIdFromJson(nullptr, &appId);
}

static void GroupOperationTest58(void)
{
    CJson *jsonParams = CreateJson();
    (void)GetAppIdFromJson(jsonParams, nullptr);
    FreeJson(jsonParams);
}

static void GroupOperationTest59(void)
{
    const char *appId = nullptr;
    CJson *jsonParams = CreateJson();
    (void)GetAppIdFromJson(jsonParams, &appId);
    FreeJson(jsonParams);
}

static void GroupOperationTest60(void)
{
    (void)AssertGroupTypeMatch(PEER_TO_PEER_GROUP, IDENTICAL_ACCOUNT_GROUP);
}

static void GroupOperationTest61(void)
{
    char *hash = nullptr;
    (void)GetHashResult(nullptr, SHA256_LEN, hash, SHA256_LEN);
}

static void GroupOperationTest62(void)
{
    const uint8_t *info;
    (void)GetHashResult(info, SHA256_LEN, nullptr, SHA256_LEN);
}

static void FuzzInnerPart1(void)
{
    (void)GroupOperationTest01();
    (void)GroupOperationTest02();
    (void)GroupOperationTest03();
    (void)GroupOperationTest04();
    (void)GroupOperationTest05();
    (void)GroupOperationTest06();
    (void)GroupOperationTest07();
    (void)GroupOperationTest08();
    (void)GroupOperationTest09();
    (void)GroupOperationTest10();
    (void)GroupOperationTest11();
    (void)GroupOperationTest12();
    (void)GroupOperationTest13();
    (void)GroupOperationTest14();
    (void)GroupOperationTest15();
    (void)GroupOperationTest16();
    (void)GroupOperationTest17();
    (void)GroupOperationTest18();
    (void)GroupOperationTest19();
    (void)GroupOperationTest20();
    (void)GroupOperationTest21();
    (void)GroupOperationTest22();
    (void)GroupOperationTest23();
    (void)GroupOperationTest24();
    (void)GroupOperationTest25();
    (void)GroupOperationTest26();
    (void)GroupOperationTest27();
    (void)GroupOperationTest28();
    (void)GroupOperationTest29();
    (void)GroupOperationTest30();
    (void)GroupOperationTest31();
}

static void FuzzInnerPart2(void)
{
    (void)GroupOperationTest32();
    (void)GroupOperationTest33();
    (void)GroupOperationTest34();
    (void)GroupOperationTest35();
    (void)GroupOperationTest36();
    (void)GroupOperationTest37();
    (void)GroupOperationTest38();
    (void)GroupOperationTest39();
    (void)GroupOperationTest40();
    (void)GroupOperationTest41();
    (void)GroupOperationTest42();
    (void)GroupOperationTest43();
    (void)GroupOperationTest44();
    (void)GroupOperationTest45();
    (void)GroupOperationTest46();
    (void)GroupOperationTest47();
    (void)GroupOperationTest48();
    (void)GroupOperationTest49();
    (void)GroupOperationTest50();
    (void)GroupOperationTest51();
    (void)GroupOperationTest52();
    (void)GroupOperationTest53();
    (void)GroupOperationTest54();
    (void)GroupOperationTest55();
    (void)GroupOperationTest56();
    (void)GroupOperationTest57();
    (void)GroupOperationTest58();
    (void)GroupOperationTest59();
    (void)GroupOperationTest60();
    (void)GroupOperationTest61();
    (void)GroupOperationTest62();
}

bool FuzzDoCallback(const uint8_t* data, size_t size)
{
    InitDeviceAuthService();
    (void)data;
    (void)size;
    (void)FuzzInnerPart1();
    (void)FuzzInnerPart2();
    DestroyDeviceAuthService();
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

