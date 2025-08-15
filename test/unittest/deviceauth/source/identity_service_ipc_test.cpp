/*
 * Copyright (C) 2025 Huawei Device Co., Ltd.
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
#include <cstring>
#include <unistd.h>
#include <gtest/gtest.h>
#include "device_auth.h"
#include "device_auth_defines.h"
#include "json_utils.h"
#include "string_util.h"
#include "hc_types.h"
#include "securec.h"
#include "nativetoken_kit.h"
#include "token_setproc.h"
#include "accesstoken_kit.h"

using namespace std;
using namespace testing::ext;

namespace {
#define PROC_NAME_DEVICE_MANAGER "device_manager"
#define PROC_NAME_SOFT_BUS "softbus_server"
#define PROC_NAME_DEVICE_SECURITY_LEVEL "dslm_service"
#define TEST_DEVICE_ID "TestDeviceId"
#define TEST_RESULT_SUCCESS 0
#define TEST_OS_ACCOUNT_ID 100
#define TEST_APP_ID "TestAppId"
#define TEST_APP_ID2 "TestAppId2"
#define TEST_USER_ID "4269DC28B639681698809A67EDAD08E39F207900038F91FEF95DD042FE2874E4"
#define TEST_USER_ID2 "DCBA4321"
#define TEST_CRED_ID "52E2706717D5C39D736E134CC1E3BE1BAA2AA52DB7C76A37C749558BD2E6492C"
#define QUERY_RESULT_NUM 0
static const char *ADD_PARAMS =
    "{\"credType\":2,\"keyFormat\":3,\"algorithmType\":3,\"subject\":1,\"issuer\":1,"
    "\"proofType\":1,\"method\":1,\"authorizedScope\":1,\"userId\":\"TestUserId\","
    "\"deviceId\":\"TestDeviceId\",\"credOwner\":\"TestAppId\","
    "\"authorizedAppList\":[\"TestName1\",\"TestName2\",\"TestName3\"],"
    "\"peerUserSpaceId\":100,\"extendInfo\":\"\"}";
static const char *ADD_PARAMS1 =
    "{\"credType\":0,\"keyFormat\":4,\"algorithmType\":3,\"subject\":1,\"issuer\":1,"
    "\"proofType\":1,\"method\":1,\"authorizedScope\":1,\"userId\":\"TestUserId\","
    "\"deviceId\":\"TestDeviceId\",\"credOwner\":\"TestAppId\","
    "\"authorizedAppList\":[\"TestName1\",\"TestName2\",\"TestName3\"],"
    "\"peerUserSpaceId\":100,\"extendInfo\":\"\"}";
static const char *ADD_PARAMS14 =
    "{\"credType\":2,\"keyFormat\":3,\"algorithmType\":3,\"subject\":1,\"issuer\":1,"
    "\"proofType\":1,\"method\":1,\"authorizedScope\":1,\"userId\":\"TestUserId\","
    "\"deviceId\":\"TestDeviceId\",\"credOwner\":\"TestAppId1\","
    "\"authorizedAppList\":[\"TestName1\",\"TestName2\",\"TestName3\"],"
    "\"peerUserSpaceId\":\"100\",\"extendInfo\":\"\"}";
static const char *ADD_PARAMS17 =
    "{\"credType\":2,\"keyFormat\":3,\"algorithmType\":3,\"subject\":1,"
    "\"proofType\":1,\"method\":1,\"authorizedScope\":1,"
    "\"deviceId\":\"TestDeviceId\",\"credOwner\":\"TestAppId\"}";
static const char *ADD_PARAMS18 =
    "{\"credType\":3,\"keyFormat\":4,\"algorithmType\":3,\"subject\":1,\"issuer\":1,"
    "\"proofType\":1,\"method\":1,\"authorizedScope\":1,\"userId\":\"TestUserId0\","
    "\"deviceId\":\"TestDeviceId0\",\"credOwner\":\"TestAppId\"}";
static const char *REQUEST_PARAMS =
    "{\"authorizedScope\":1, \"authorizedAppList\":[\"TestName1\",\"TestName2\",\"TestName3\","
    "\"TestName4\"],\"extendInfo\":\"\"}";
static const char *AGREE_PARAMS =
    "{\"credType\":2, \"deviceId\":\"TestDeviceId\",\"credOwner\":\"TestAppId\",\"subject\":1,"
    "\"keyFormat\":2,\"proofType\":1,\"authorizedScope\":1,\"algorithmType\":3,\"peerUserSpaceId\":\"100\","
    "\"keyValue\":\"3059301306072a8648ce3d020106082a8648ce3d030107034200043bb1f8107c6306bddcdb70cd9fee0e581"
    "5bbd305184871cd2880657eb2cc88aeece1a7f076d9fff7e1114e3bc9dfa45b061b2755b46fc282ef59763b4c0288bd\"}";
static const char *BATCH_UPDATE_PARAMS =
    "{\"baseInfo\":{\"credType\":3,\"keyFormat\":2,\"algorithmType\":3,\"subject\":2,\"authorizedScope\":2,"
    "\"issuer\":1,\"proofType\":2,\"credOwner\":\"TestAppId\"},"
    "\"updateLists\":[{\"userId\":\"TestUserId\",\"deviceId\":\"TestDeviceId\"}]}";
static const char *BATCH_UPDATE_PARAMS1 =
    "{\"baseInfo\":{\"credType\":1,\"keyFormat\":2,\"algorithmType\":3,\"subject\":2,\"authorizedScope\":2,"
    "\"issuer\":1,\"proofType\":2,\"credOwner\":\"TestAppId\"},"
    "\"updateLists\":[{\"userId\":\"TestUserId\",\"deviceId\":\"TestDeviceId\"}]}";

static const char *QUERY_PARAMS = "{\"deviceId\":\"TestDeviceId\"}";
static const char *DEL_PARAMS = "{\"credOwner\":\"TestAppId\"}";
static const char *DEL_PARAMS1 = "{\"credOwner\":\"TestAppId\",\"userIdHash\":\"12D2\",\"deviceIdHash\":\"12D2\"}";
static void NativeTokenSet(const char *procName)
{
    const char *acls[] = {
        "ohos.permission.ACCESS_DEVAUTH_CRED_PRIVILEGE",
    };
    const char *perms[] = {
        "ohos.permission.ACCESS_DEVAUTH_CRED_PRIVILEGE",
    };
    uint64_t tokenId;
    NativeTokenInfoParams infoInstance = {
        .dcapsNum = 0,
        .permsNum = 1,
        .aclsNum = 1,
        .dcaps = nullptr,
        .perms = perms,
        .acls = acls,
        .processName = procName,
        .aplStr = "system_core",
    };
    tokenId = GetAccessTokenId(&infoInstance);
    SetSelfTokenID(tokenId);
    OHOS::Security::AccessToken::AccessTokenKit::ReloadNativeTokenInfo();
}

class GetCredMgrInstanceTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void GetCredMgrInstanceTest::SetUpTestCase() {}
void GetCredMgrInstanceTest::TearDownTestCase() {}

void GetCredMgrInstanceTest::SetUp()
{
    int ret = InitDeviceAuthService();
    EXPECT_EQ(ret, HC_SUCCESS);
}

void GetCredMgrInstanceTest::TearDown()
{
    DestroyDeviceAuthService();
}

HWTEST_F(GetCredMgrInstanceTest, GetCredMgrInstanceTest001, TestSize.Level0)
{
    const CredManager *cm = GetCredMgrInstance();
    EXPECT_NE(cm, nullptr);
}

class GetCredAuthInstanceTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void GetCredAuthInstanceTest::SetUpTestCase() {}
void GetCredAuthInstanceTest::TearDownTestCase() {}

void GetCredAuthInstanceTest::SetUp()
{
    int ret = InitDeviceAuthService();
    EXPECT_EQ(ret, HC_SUCCESS);
}

void GetCredAuthInstanceTest::TearDown()
{
    DestroyDeviceAuthService();
}

HWTEST_F(GetCredAuthInstanceTest, GetCredAuthInstanceTest001, TestSize.Level0)
{
    const CredAuthManager *ca = GetCredAuthInstance();
    EXPECT_NE(ca, nullptr);
}

class CredMgrAddCredentialTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void CredMgrAddCredentialTest::SetUpTestCase() {}
void CredMgrAddCredentialTest::TearDownTestCase() {}

void CredMgrAddCredentialTest::SetUp()
{
    NativeTokenSet(PROC_NAME_DEVICE_MANAGER);
    int ret = InitDeviceAuthService();
    ASSERT_EQ(ret, HC_SUCCESS);
    const CredManager *cm = GetCredMgrInstance();
    EXPECT_NE(cm, nullptr);
}

void CredMgrAddCredentialTest::TearDown()
{
    DestroyDeviceAuthService();
}

HWTEST_F(CredMgrAddCredentialTest, CredMgrAddCredentialTest001, TestSize.Level0)
{
    const CredManager *cm = GetCredMgrInstance();
    ASSERT_NE(cm, nullptr);
    char *returnData = nullptr;
    int32_t ret = cm->addCredential(TEST_OS_ACCOUNT_ID, nullptr, &returnData);
    EXPECT_NE(ret, IS_SUCCESS);
    cm->destroyInfo(&returnData);
}


HWTEST_F(CredMgrAddCredentialTest, CredMgrAddCredentialTest002, TestSize.Level0)
{
    const CredManager *cm = GetCredMgrInstance();
    ASSERT_NE(cm, nullptr);
    char *returnData = nullptr;
    int32_t ret = cm->addCredential(TEST_OS_ACCOUNT_ID, ADD_PARAMS, nullptr);
    EXPECT_NE(ret, IS_SUCCESS);
    cm->destroyInfo(&returnData);
}

HWTEST_F(CredMgrAddCredentialTest, CredMgrAddCredentialTest003, TestSize.Level0)
{
    const CredManager *cm = GetCredMgrInstance();
    ASSERT_NE(cm, nullptr);
    char *returnData = nullptr;
    int32_t ret = cm->addCredential(TEST_OS_ACCOUNT_ID, ADD_PARAMS1, &returnData);
    EXPECT_NE(ret, IS_SUCCESS);
    cm->destroyInfo(&returnData);
}

HWTEST_F(CredMgrAddCredentialTest, CredMgrAddCredentialTest004, TestSize.Level0)
{
    const CredManager *cm = GetCredMgrInstance();
    ASSERT_NE(cm, nullptr);
    char *returnData = nullptr;
    int32_t ret = cm->addCredential(TEST_OS_ACCOUNT_ID, ADD_PARAMS, &returnData);
    EXPECT_EQ(ret, IS_SUCCESS);
    cm->destroyInfo(&returnData);
}

class CredMgrExportCredentialTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void CredMgrExportCredentialTest::SetUpTestCase() {}
void CredMgrExportCredentialTest::TearDownTestCase() {}

void CredMgrExportCredentialTest::SetUp()
{
    NativeTokenSet(PROC_NAME_DEVICE_MANAGER);
    int ret = InitDeviceAuthService();
    ASSERT_EQ(ret, HC_SUCCESS);
}

void CredMgrExportCredentialTest::TearDown()
{
    DestroyDeviceAuthService();
}

HWTEST_F(CredMgrExportCredentialTest, CredMgrExportCredentialTest001, TestSize.Level0)
{
    const CredManager *cm = GetCredMgrInstance();
    ASSERT_NE(cm, nullptr);
    char *returnData = nullptr;
    int32_t ret = cm->exportCredential(TEST_OS_ACCOUNT_ID, nullptr, &returnData);
    EXPECT_NE(ret, IS_SUCCESS);
    cm->destroyInfo(&returnData);
}

HWTEST_F(CredMgrExportCredentialTest, CredMgrExportCredentialTest002, TestSize.Level0)
{
    const CredManager *cm = GetCredMgrInstance();
    ASSERT_NE(cm, nullptr);
    char *credId = nullptr;
    int32_t ret = cm->addCredential(TEST_OS_ACCOUNT_ID, ADD_PARAMS, &credId);
    EXPECT_EQ(ret, IS_SUCCESS);
    ret = cm->exportCredential(TEST_OS_ACCOUNT_ID, credId, nullptr);
    HcFree(credId);
    EXPECT_NE(ret, IS_SUCCESS);
}

HWTEST_F(CredMgrExportCredentialTest, CredMgrExportCredentialTest003, TestSize.Level0)
{
    const CredManager *cm = GetCredMgrInstance();
    ASSERT_NE(cm, nullptr);
    char *credId = nullptr;
    int32_t ret = cm->addCredential(TEST_OS_ACCOUNT_ID, ADD_PARAMS, &credId);
    EXPECT_EQ(ret, IS_SUCCESS);
    char *returnData = nullptr;
    ret = cm->exportCredential(TEST_OS_ACCOUNT_ID, credId, &returnData);
    HcFree(credId);
    cm->destroyInfo(&returnData);
    EXPECT_EQ(ret, IS_SUCCESS);
}

HWTEST_F(CredMgrExportCredentialTest, CredMgrExportCredentialTest004, TestSize.Level0)
{
    const CredManager *cm = GetCredMgrInstance();
    ASSERT_NE(cm, nullptr);
    char *returnData = nullptr;
    int32_t ret = cm->exportCredential(TEST_OS_ACCOUNT_ID, static_cast<const char *>(TEST_CRED_ID), &returnData);
    EXPECT_NE(ret, IS_SUCCESS);
}

class CredMgrQueryCredentialByParamsTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void CredMgrQueryCredentialByParamsTest::SetUpTestCase() {}
void CredMgrQueryCredentialByParamsTest::TearDownTestCase() {}

void CredMgrQueryCredentialByParamsTest::SetUp()
{
    NativeTokenSet(PROC_NAME_DEVICE_MANAGER);
    int ret = InitDeviceAuthService();
    EXPECT_EQ(ret, IS_SUCCESS);
}

void CredMgrQueryCredentialByParamsTest::TearDown()
{
    DestroyDeviceAuthService();
}

HWTEST_F(CredMgrQueryCredentialByParamsTest, CredMgrQueryCredentialByParamsTest001, TestSize.Level0)
{
    const CredManager *cm = GetCredMgrInstance();
    ASSERT_NE(cm, nullptr);
    char *returnData = nullptr;
    int32_t ret = cm->addCredential(TEST_OS_ACCOUNT_ID, ADD_PARAMS, &returnData);
    HcFree(returnData);
    returnData = nullptr;
    EXPECT_EQ(ret, IS_SUCCESS);
    ret = cm->addCredential(TEST_OS_ACCOUNT_ID, ADD_PARAMS14, &returnData);
    HcFree(returnData);
    EXPECT_EQ(ret, IS_SUCCESS);
    char *credIdList = nullptr;
    ret = cm->queryCredentialByParams(TEST_OS_ACCOUNT_ID, QUERY_PARAMS, &credIdList);
    EXPECT_EQ(ret, IS_SUCCESS);
    CJson *jsonArr = CreateJsonFromString(credIdList);
    int32_t size = GetItemNum(jsonArr);
    HcFree(credIdList);
    FreeJson(jsonArr);
    EXPECT_NE(size, QUERY_RESULT_NUM);
}

HWTEST_F(CredMgrQueryCredentialByParamsTest, CredMgrQueryCredentialByParamsTest002, TestSize.Level0)
{
    const CredManager *cm = GetCredMgrInstance();
    ASSERT_NE(cm, nullptr);
    char *credIdList = nullptr;
    int32_t ret = cm->queryCredentialByParams(TEST_OS_ACCOUNT_ID, nullptr, &credIdList);
    EXPECT_NE(ret, IS_SUCCESS);
}

HWTEST_F(CredMgrQueryCredentialByParamsTest, CredMgrQueryCredentialByParamsTest003, TestSize.Level0)
{
    const CredManager *cm = GetCredMgrInstance();
    ASSERT_NE(cm, nullptr);
    int32_t ret = cm->queryCredentialByParams(TEST_OS_ACCOUNT_ID, QUERY_PARAMS, nullptr);
    EXPECT_NE(ret, IS_SUCCESS);
}

class CredMgrQueryCredInfoByCredIdTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void CredMgrQueryCredInfoByCredIdTest::SetUpTestCase() {}
void CredMgrQueryCredInfoByCredIdTest::TearDownTestCase() {}

void CredMgrQueryCredInfoByCredIdTest::SetUp()
{
    NativeTokenSet(PROC_NAME_DEVICE_MANAGER);
    int ret = InitDeviceAuthService();
    EXPECT_EQ(ret, IS_SUCCESS);
}

void CredMgrQueryCredInfoByCredIdTest::TearDown()
{
    DestroyDeviceAuthService();
}

HWTEST_F(CredMgrQueryCredInfoByCredIdTest, CredMgrQueryCredInfoByCredIdTest001, TestSize.Level0)
{
    const CredManager *cm = GetCredMgrInstance();
    ASSERT_NE(cm, nullptr);
    char *credId = nullptr;
    int32_t ret = cm->addCredential(TEST_OS_ACCOUNT_ID, ADD_PARAMS, &credId);
    EXPECT_EQ(ret, IS_SUCCESS);
    char *returnCredInfo = nullptr;
    ret = cm->queryCredInfoByCredId(TEST_OS_ACCOUNT_ID, credId, &returnCredInfo);
    HcFree(credId);
    EXPECT_EQ(ret, IS_SUCCESS);
    CJson *credInfoJson = CreateJsonFromString(returnCredInfo);
    HcFree(returnCredInfo);
    const char *deviceId = GetStringFromJson(credInfoJson, FIELD_DEVICE_ID);
    if (deviceId != nullptr) {
        EXPECT_EQ(IsStrEqual(deviceId, TEST_DEVICE_ID), true);
    }
    FreeJson(credInfoJson);
}

HWTEST_F(CredMgrQueryCredInfoByCredIdTest, CredMgrQueryCredInfoByCredIdTest002, TestSize.Level0)
{
    const CredManager *cm = GetCredMgrInstance();
    ASSERT_NE(cm, nullptr);
    char *returnCredInfo = nullptr;
    int32_t ret = cm->queryCredInfoByCredId(TEST_OS_ACCOUNT_ID, nullptr, &returnCredInfo);
    EXPECT_NE(ret, IS_SUCCESS);
}

HWTEST_F(CredMgrQueryCredInfoByCredIdTest, CredMgrQueryCredInfoByCredIdTest003, TestSize.Level0)
{
    const CredManager *cm = GetCredMgrInstance();
    ASSERT_NE(cm, nullptr);
    int32_t ret = cm->queryCredInfoByCredId(TEST_OS_ACCOUNT_ID, static_cast<const char *>(TEST_CRED_ID), nullptr);
    EXPECT_NE(ret, IS_SUCCESS);
}

HWTEST_F(CredMgrQueryCredInfoByCredIdTest, CredMgrQueryCredInfoByCredIdTest004, TestSize.Level0)
{
    const CredManager *cm = GetCredMgrInstance();
    ASSERT_NE(cm, nullptr);
    char *returnCredInfo = nullptr;
    int32_t ret = cm->queryCredInfoByCredId(TEST_OS_ACCOUNT_ID, static_cast<const char *>(TEST_CRED_ID),
        &returnCredInfo);
    EXPECT_NE(ret, IS_SUCCESS);
    HcFree(returnCredInfo);
}

class CredMgrDeleteCredentialTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void CredMgrDeleteCredentialTest::SetUpTestCase() {}
void CredMgrDeleteCredentialTest::TearDownTestCase() {}

void CredMgrDeleteCredentialTest::SetUp()
{
    NativeTokenSet(PROC_NAME_DEVICE_MANAGER);
    int ret = InitDeviceAuthService();
    EXPECT_EQ(ret, IS_SUCCESS);
}

void CredMgrDeleteCredentialTest::TearDown()
{
    DestroyDeviceAuthService();
}

HWTEST_F(CredMgrDeleteCredentialTest, CredMgrDeleteCredentialTest001, TestSize.Level0)
{
    const CredManager *cm = GetCredMgrInstance();
    ASSERT_NE(cm, nullptr);
    char *credId = nullptr;
    int32_t ret = cm->addCredential(TEST_OS_ACCOUNT_ID, ADD_PARAMS, &credId);
    EXPECT_EQ(ret, IS_SUCCESS);
    ret = cm->deleteCredential(TEST_OS_ACCOUNT_ID, credId);
    HcFree(credId);
    EXPECT_EQ(ret, IS_SUCCESS);
}

HWTEST_F(CredMgrDeleteCredentialTest, CredMgrDeleteCredentialTest002, TestSize.Level0)
{
    const CredManager *cm = GetCredMgrInstance();
    ASSERT_NE(cm, nullptr);
    int32_t ret = cm->deleteCredential(TEST_OS_ACCOUNT_ID, nullptr);
    EXPECT_NE(ret, IS_SUCCESS);
}

HWTEST_F(CredMgrDeleteCredentialTest, CredMgrDeleteCredentialTest003, TestSize.Level0)
{
    const CredManager *cm = GetCredMgrInstance();
    ASSERT_NE(cm, nullptr);
    int32_t ret = cm->deleteCredential(TEST_OS_ACCOUNT_ID,  static_cast<const char *>(TEST_CRED_ID));
    EXPECT_NE(ret, IS_SUCCESS);
}

class CredMgrUpdateCredInfoTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void CredMgrUpdateCredInfoTest::SetUpTestCase() {}
void CredMgrUpdateCredInfoTest::TearDownTestCase() {}

void CredMgrUpdateCredInfoTest::SetUp()
{
    NativeTokenSet(PROC_NAME_DEVICE_MANAGER);
    int ret = InitDeviceAuthService();
    EXPECT_EQ(ret, IS_SUCCESS);
}

void CredMgrUpdateCredInfoTest::TearDown()
{
    DestroyDeviceAuthService();
}

HWTEST_F(CredMgrUpdateCredInfoTest, CredMgrUpdateCredInfoTest001, TestSize.Level0)
{
    const CredManager *cm = GetCredMgrInstance();
    ASSERT_NE(cm, nullptr);
    char *credId = nullptr;
    int32_t ret = cm->addCredential(TEST_OS_ACCOUNT_ID, ADD_PARAMS, &credId);
    EXPECT_EQ(ret, IS_SUCCESS);
    ret = cm->updateCredInfo(TEST_OS_ACCOUNT_ID, credId, REQUEST_PARAMS);
    HcFree(credId);
    EXPECT_EQ(ret, IS_SUCCESS);
}

HWTEST_F(CredMgrUpdateCredInfoTest, CredMgrUpdateCredInfoTest002, TestSize.Level0)
{
    const CredManager *cm = GetCredMgrInstance();
    ASSERT_NE(cm, nullptr);
    char *credId = nullptr;
    int32_t ret = cm->addCredential(TEST_OS_ACCOUNT_ID, ADD_PARAMS, &credId);
    EXPECT_EQ(ret, IS_SUCCESS);
    ret = cm->updateCredInfo(TEST_OS_ACCOUNT_ID, credId, "");
    HcFree(credId);
    EXPECT_NE(ret, IS_SUCCESS);
}

HWTEST_F(CredMgrUpdateCredInfoTest, CredMgrUpdateCredInfoTest003, TestSize.Level0)
{
    const CredManager *cm = GetCredMgrInstance();
    ASSERT_NE(cm, nullptr);
    char *credId = nullptr;
    int32_t ret = cm->addCredential(TEST_OS_ACCOUNT_ID, ADD_PARAMS, &credId);
    EXPECT_EQ(ret, IS_SUCCESS);
    ret = cm->updateCredInfo(TEST_OS_ACCOUNT_ID, credId, nullptr);
    HcFree(credId);
    EXPECT_NE(ret, IS_SUCCESS);
}

HWTEST_F(CredMgrUpdateCredInfoTest, CredMgrUpdateCredInfoTest004, TestSize.Level0)
{
    const CredManager *cm = GetCredMgrInstance();
    ASSERT_NE(cm, nullptr);
    char *credId = nullptr;
    int32_t ret = cm->addCredential(TEST_OS_ACCOUNT_ID, ADD_PARAMS, &credId);
    EXPECT_EQ(ret, IS_SUCCESS);
    ret = cm->updateCredInfo(TEST_OS_ACCOUNT_ID, nullptr, REQUEST_PARAMS);
    HcFree(credId);
    EXPECT_NE(ret, IS_SUCCESS);
}


class CredMgrRegCredListenerTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void CredMgrRegCredListenerTest::SetUpTestCase() {}
void CredMgrRegCredListenerTest::TearDownTestCase() {}

void CredMgrRegCredListenerTest::SetUp()
{
    NativeTokenSet(PROC_NAME_DEVICE_MANAGER);
    int ret = InitDeviceAuthService();
    EXPECT_EQ(ret, IS_SUCCESS);
}

void CredMgrRegCredListenerTest::TearDown()
{
    DestroyDeviceAuthService();
}

HWTEST_F(CredMgrRegCredListenerTest, CredMgrRegCredListenerTest001, TestSize.Level0)
{
    const CredManager *cm = GetCredMgrInstance();
    ASSERT_NE(cm, nullptr);
    CredChangeListener listener;
    int32_t ret = cm->registerChangeListener(TEST_APP_ID, &listener);
    EXPECT_EQ(ret, IS_SUCCESS);
}

HWTEST_F(CredMgrRegCredListenerTest, CredMgrRegCredListenerTest002, TestSize.Level0)
{
    const CredManager *cm = GetCredMgrInstance();
    ASSERT_NE(cm, nullptr);
    CredChangeListener listener;
    int32_t ret = cm->registerChangeListener(TEST_APP_ID, &listener);
    EXPECT_EQ(ret, IS_SUCCESS);
    ret = cm->registerChangeListener(TEST_APP_ID, &listener);
    EXPECT_EQ(ret, IS_SUCCESS);
}

HWTEST_F(CredMgrRegCredListenerTest, CredMgrRegCredListenerTest003, TestSize.Level0)
{
    const CredManager *cm = GetCredMgrInstance();
    ASSERT_NE(cm, nullptr);
    CredChangeListener listener;
    int32_t ret = cm->registerChangeListener(nullptr, &listener);
    EXPECT_NE(ret, IS_SUCCESS);
}

HWTEST_F(CredMgrRegCredListenerTest, CredMgrRegCredListenerTest004, TestSize.Level0)
{
    const CredManager *cm = GetCredMgrInstance();
    ASSERT_NE(cm, nullptr);
    int32_t ret = cm->registerChangeListener(TEST_APP_ID, nullptr);
    EXPECT_NE(ret, IS_SUCCESS);
}

class CredMgrUnRegCredListenerTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void CredMgrUnRegCredListenerTest::SetUpTestCase() {}
void CredMgrUnRegCredListenerTest::TearDownTestCase() {}

void CredMgrUnRegCredListenerTest::SetUp()
{
    NativeTokenSet(PROC_NAME_DEVICE_MANAGER);
    int ret = InitDeviceAuthService();
    EXPECT_EQ(ret, IS_SUCCESS);
}

void CredMgrUnRegCredListenerTest::TearDown()
{
    DestroyDeviceAuthService();
}

HWTEST_F(CredMgrUnRegCredListenerTest, CredMgrUnRegCredListenerTest001, TestSize.Level0)
{
    const CredManager *cm = GetCredMgrInstance();
    ASSERT_NE(cm, nullptr);
    CredChangeListener listener;
    int32_t ret = cm->registerChangeListener(TEST_APP_ID, &listener);
    EXPECT_EQ(ret, IS_SUCCESS);
    ret = cm->unregisterChangeListener(TEST_APP_ID);
    EXPECT_EQ(ret, IS_SUCCESS);
}

HWTEST_F(CredMgrUnRegCredListenerTest, CredMgrUnRegCredListenerTest002, TestSize.Level0)
{
    const CredManager *cm = GetCredMgrInstance();
    ASSERT_NE(cm, nullptr);
    int32_t ret = cm->unregisterChangeListener(TEST_APP_ID);
    EXPECT_EQ(ret, IS_SUCCESS);
}

HWTEST_F(CredMgrUnRegCredListenerTest, CredMgrUnRegCredListenerTest003, TestSize.Level0)
{
    const CredManager *cm = GetCredMgrInstance();
    ASSERT_NE(cm, nullptr);
    int32_t ret = cm->unregisterChangeListener(nullptr);
    EXPECT_NE(ret, IS_SUCCESS);
}

class CredMgrAgreeCredentialTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void CredMgrAgreeCredentialTest::SetUpTestCase() {}
void CredMgrAgreeCredentialTest::TearDownTestCase() {}

void CredMgrAgreeCredentialTest::SetUp()
{
    NativeTokenSet(PROC_NAME_DEVICE_MANAGER);
    int ret = InitDeviceAuthService();
    EXPECT_EQ(ret, IS_SUCCESS);
}

void CredMgrAgreeCredentialTest::TearDown()
{
    DestroyDeviceAuthService();
}

HWTEST_F(CredMgrAgreeCredentialTest, CredMgrAgreeCredentialTest001, TestSize.Level0)
{
    const CredManager *cm = GetCredMgrInstance();
    ASSERT_NE(cm, nullptr);
    char *selfCredId = nullptr;
    int32_t ret = cm->addCredential(TEST_OS_ACCOUNT_ID, ADD_PARAMS17, &selfCredId);
    EXPECT_EQ(ret, IS_SUCCESS);
    char *returnData = nullptr;
    ret = cm->agreeCredential(TEST_OS_ACCOUNT_ID, selfCredId, AGREE_PARAMS, &returnData);
    HcFree(selfCredId);
    HcFree(returnData);
    EXPECT_EQ(ret, IS_SUCCESS);
}

HWTEST_F(CredMgrAgreeCredentialTest, CredMgrAgreeCredentialTest002, TestSize.Level0)
{
    const CredManager *cm = GetCredMgrInstance();
    ASSERT_NE(cm, nullptr);
    char *returnData = nullptr;
    int32_t ret = cm->agreeCredential(TEST_OS_ACCOUNT_ID, nullptr, AGREE_PARAMS, &returnData);
    EXPECT_NE(ret, IS_SUCCESS);
}

HWTEST_F(CredMgrAgreeCredentialTest, CredMgrAgreeCredentialTest003, TestSize.Level0)
{
    const CredManager *cm = GetCredMgrInstance();
    ASSERT_NE(cm, nullptr);
    char *returnData = nullptr;
    int32_t ret = cm->agreeCredential(TEST_OS_ACCOUNT_ID, TEST_CRED_ID, nullptr, &returnData);
    EXPECT_NE(ret, IS_SUCCESS);
}

HWTEST_F(CredMgrAgreeCredentialTest, CredMgrAgreeCredentialTest004, TestSize.Level0)
{
    const CredManager *cm = GetCredMgrInstance();
    ASSERT_NE(cm, nullptr);
    int32_t ret = cm->agreeCredential(TEST_OS_ACCOUNT_ID, TEST_CRED_ID, AGREE_PARAMS, nullptr);
    EXPECT_NE(ret, IS_SUCCESS);
}


class CredMgrBatchUpdateCredsTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void CredMgrBatchUpdateCredsTest::SetUpTestCase() {}
void CredMgrBatchUpdateCredsTest::TearDownTestCase() {}

void CredMgrBatchUpdateCredsTest::SetUp()
{
    NativeTokenSet(PROC_NAME_DEVICE_MANAGER);
    int ret = InitDeviceAuthService();
    EXPECT_EQ(ret, IS_SUCCESS);
}

void CredMgrBatchUpdateCredsTest::TearDown()
{
    DestroyDeviceAuthService();
}

HWTEST_F(CredMgrBatchUpdateCredsTest, CredMgrBatchUpdateCredsTest001, TestSize.Level0)
{
    const CredManager *cm = GetCredMgrInstance();
    ASSERT_NE(cm, nullptr);
    char *returnData = nullptr;
    int32_t ret = cm->batchUpdateCredentials(TEST_OS_ACCOUNT_ID, BATCH_UPDATE_PARAMS, &returnData);
    HcFree(returnData);
    EXPECT_EQ(ret, IS_SUCCESS);
}

HWTEST_F(CredMgrBatchUpdateCredsTest, CredMgrBatchUpdateCredsTest002, TestSize.Level0)
{
    const CredManager *cm = GetCredMgrInstance();
    ASSERT_NE(cm, nullptr);
    char *returnData = nullptr;
    int32_t ret = cm->batchUpdateCredentials(TEST_OS_ACCOUNT_ID, nullptr, &returnData);
    EXPECT_NE(ret, IS_SUCCESS);
}

HWTEST_F(CredMgrBatchUpdateCredsTest, CredMgrBatchUpdateCredsTest003, TestSize.Level0)
{
    const CredManager *cm = GetCredMgrInstance();
    ASSERT_NE(cm, nullptr);
    char *returnData = nullptr;
    int32_t ret = cm->batchUpdateCredentials(TEST_OS_ACCOUNT_ID, BATCH_UPDATE_PARAMS1, &returnData);
    EXPECT_NE(ret, IS_SUCCESS);
}

HWTEST_F(CredMgrBatchUpdateCredsTest, CredMgrBatchUpdateCredsTest004, TestSize.Level0)
{
    const CredManager *cm = GetCredMgrInstance();
    ASSERT_NE(cm, nullptr);
    int32_t ret = cm->batchUpdateCredentials(TEST_OS_ACCOUNT_ID, BATCH_UPDATE_PARAMS, nullptr);
    EXPECT_NE(ret, IS_SUCCESS);
}

HWTEST_F(CredMgrBatchUpdateCredsTest, CredMgrBatchUpdateCredsTest005, TestSize.Level0)
{
    const CredManager *cm = GetCredMgrInstance();
    ASSERT_NE(cm, nullptr);
    char *credId = nullptr;
    int32_t ret = cm->addCredential(TEST_OS_ACCOUNT_ID, ADD_PARAMS18, &credId);
    HcFree(credId);
    EXPECT_EQ(ret, IS_SUCCESS);
    char *returnData = nullptr;
    ret = cm->batchUpdateCredentials(TEST_OS_ACCOUNT_ID, BATCH_UPDATE_PARAMS, &returnData);
    HcFree(returnData);
    EXPECT_EQ(ret, IS_SUCCESS);
}

class CredMgrDelCredByParamsTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void CredMgrDelCredByParamsTest::SetUpTestCase() {}
void CredMgrDelCredByParamsTest::TearDownTestCase() {}

void CredMgrDelCredByParamsTest::SetUp()
{
    NativeTokenSet(PROC_NAME_DEVICE_MANAGER);
    int ret = InitDeviceAuthService();
    EXPECT_EQ(ret, IS_SUCCESS);
}

void CredMgrDelCredByParamsTest::TearDown()
{
    DestroyDeviceAuthService();
}

HWTEST_F(CredMgrDelCredByParamsTest, CredMgrDelCredByParamsTest001, TestSize.Level0)
{
    const CredManager *cm = GetCredMgrInstance();
    ASSERT_NE(cm, nullptr);
    char *credId = nullptr;
    int32_t ret = cm->addCredential(TEST_OS_ACCOUNT_ID, ADD_PARAMS, &credId);
    HcFree(credId);
    EXPECT_EQ(ret, IS_SUCCESS);
    char *returnData = nullptr;
    ret = cm->deleteCredByParams(TEST_OS_ACCOUNT_ID, DEL_PARAMS, &returnData);
    HcFree(returnData);
    EXPECT_EQ(ret, IS_SUCCESS);
}

HWTEST_F(CredMgrDelCredByParamsTest, CredMgrDelCredByParamsTest002, TestSize.Level0)
{
    const CredManager *cm = GetCredMgrInstance();
    ASSERT_NE(cm, nullptr);
    char *returnData = nullptr;
    int32_t ret = cm->deleteCredByParams(TEST_OS_ACCOUNT_ID, nullptr, &returnData);
    EXPECT_NE(ret, IS_SUCCESS);
}

HWTEST_F(CredMgrDelCredByParamsTest, CredMgrDelCredByParamsTest003, TestSize.Level0)
{
    const CredManager *cm = GetCredMgrInstance();
    ASSERT_NE(cm, nullptr);
    int32_t ret = cm->deleteCredByParams(TEST_OS_ACCOUNT_ID, DEL_PARAMS, nullptr);
    EXPECT_NE(ret, IS_SUCCESS);
}

HWTEST_F(CredMgrDelCredByParamsTest, CredMgrDelCredByParamsTest004, TestSize.Level0)
{
    const CredManager *cm = GetCredMgrInstance();
    ASSERT_NE(cm, nullptr);
    char *credId = nullptr;
    int32_t ret = cm->addCredential(TEST_OS_ACCOUNT_ID, ADD_PARAMS, &credId);
    HcFree(credId);
    EXPECT_EQ(ret, IS_SUCCESS);
    char *returnData = nullptr;
    ret = cm->deleteCredByParams(TEST_OS_ACCOUNT_ID, DEL_PARAMS1, &returnData);
    HcFree(returnData);
    EXPECT_EQ(ret, IS_SUCCESS);
}
}
