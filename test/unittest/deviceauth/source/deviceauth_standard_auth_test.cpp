/*
 * Copyright (C) 2021-2022 Huawei Device Co., Ltd.
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

#include "deviceauth_standard_test.h"
#include <cinttypes>
#include <unistd.h>
#include <gtest/gtest.h>
#include "account_module_defines.h"
#include "alg_loader.h"
#include "common_defs.h"
#include "device_auth.h"
#include "device_auth_defines.h"
#include "device_auth_ext.h"
#include "hc_dev_info_mock.h"
#include "json_utils_mock.h"
#include "json_utils.h"
#include "protocol_task_main_mock.h"
#include "securec.h"

using namespace std;
using namespace testing::ext;

namespace {
#define TEST_REQ_ID 123
#define TEST_REQ_ID2 321
#define TEST_REQ_ID3 132
#define TEST_REQ_ID4 213
#define TEST_APP_ID "TestAppId"
#define TEST_APP_ID2 "TestAppId2"
#define TEST_GROUP_NAME "TestGroup"
#define TEST_AUTH_ID "TestAuthId"
#define TEST_AUTH_ID2 "TestAuthId2"
#define TEST_AUTH_ID3 "TestAuthId3"
#define TEST_UDID "TestUdid"
#define TEST_UDID2 "TestUdid2"
#define TEST_UDID_CLIENT "5420459D93FE773F9945FD64277FBA2CAB8FB996DDC1D0B97676FBB1242B3930"
#define TEST_UDID_SERVER "52E2706717D5C39D736E134CC1E3BE1BAA2AA52DB7C76A37C749558BD2E6492C"
#define TEST_USER_ID_AUTH "4269DC28B639681698809A67EDAD08E39F207900038F91FEF95DD042FE2874E4"
#define TEST_USER_ID "1234ABCD"
#define TEST_USER_ID2 "DCBA4321"
#define TEST_GROUP_ID "E2EE6F830B176B2C96A9F99BFAE2A61F5D1490B9F4A090E9D8C2874C230C7C21"
#define TEST_GROUP_ID2 "F2AA208B1E010542B20A34B03B4B6289EA7C7F6DFE97DA2E370348B826682D3D"
#define TEST_GROUP_ID3 "1234ABCD"
#define TEST_GROUP_ID4 "6B7B805962B8EB8275D73128BFDAA7ECD755A2EC304E36543941874A277FA75F"
#define TEST_AUTH_CODE "37364761534f454d33567a73424e794f33573330507069434b31676f7254706b"
#define TEST_AUTH_CODE2 "2f7562744654535564586e665467546b322b4b506b65626373466f48766a4335"
#define TEST_AUTH_CODE3 "1234567812345678123456781234567812345678123456781234567812345678"
#define TEST_AUTH_TOKEN3 "10F9F0576E61730193D2052B7F771887124A68F1607EFCF7796C1491F834CD92"
#define TEST_QUERY_PARAMS "bac"
#define TEST_PIN_CODE "123456"
#define TEST_GROUP_DATA_PATH "/data/service/el1/public/deviceauthMock"
#define TEST_HKS_MAIN_DATA_PATH "/data/service/el1/public/huks_service/tmp/+0+0+0+0"
#define TEST_DEV_AUTH_TEMP_KEY_PAIR_LEN 32
#define TEST_DEV_AUTH_SLEEP_TIME 50000
#define TEST_DEV_AUTH_SLEEP_TIME2 60000
static const int32_t TEST_AUTH_OS_ACCOUNT_ID = 100;
static const int TEST_DEV_AUTH_BUFFER_SIZE = 128;
static const char *INVALID_JSON_STR = "invalid json format";
static const char *CREATE_PARAMS = "{\"groupName\":\"TestGroup\",\"deviceId\":\"TestAuthId\",\"groupType\":256,\"group"
    "Visibility\":-1,\"userType\":0,\"expireTime\":-1}";
static const char *CREATE_PARAMS3 = "{\"groupType\":1282,\"userId\":\"1234ABCD\",\"peerUserId\":\"DCBA4321\"}";
static const char *DISBAND_PARAMS =
    "{\"groupId\":\"E2EE6F830B176B2C96A9F99BFAE2A61F5D1490B9F4A090E9D8C2874C230C7C21\"}";
static const char *DISBAND_PARAMS2 = "{\"groupId\":\"1234ABCD\"}";
static const char *DISBAND_PARAMS3 =
    "{\"groupId\":\"6B7B805962B8EB8275D73128BFDAA7ECD755A2EC304E36543941874A277FA75F\"}";
static const char *ADD_PARAMS =
    "{\"groupId\":\"E2EE6F830B176B2C96A9F99BFAE2A61F5D1490B9F4A090E9D8C2874C230C7C21\","
    "\"groupType\":256,\"pinCode\":\"123456\"}";
static const char *ADD_PARAMS2 =
    "{\"groupType\":1,\"groupId\":\"1234ABCD\","
    "\"deviceList\":[{\"deviceId\":\"TestAuthId2\",\"udid\":\"TestUdid\",\"userId\":\"1234ABCD\","
    "\"credential\":{\"credentialType\":1,"
    "\"authCode\":\"37364761534f454d33567a73424e794f33573330507069434b31676f7254706b\"}},"
    "{\"deviceId\":\"TestAuthId3\",\"udid\":\"TestUdid2\",\"userId\":\"1234ABCD\","
    "\"credential\":{\"credentialType\":1,"
    "\"authCode\":\"2f7562744654535564586e665467546b322b4b506b65626373466f48766a4335\"}}]}";
static const char *ADD_PARAMS3 =
    "{\"groupType\":1282,\"groupId\":\"6B7B805962B8EB8275D73128BFDAA7ECD755A2EC304E36543941874A277FA75F\","
    "\"deviceList\":[{\"deviceId\":\"TestAuthId2\",\"udid\":\"TestUdid\",\"userId\":\"DCBA4321\","
    "\"credential\":{\"credentialType\":1,"
    "\"authCode\":\"37364761534f454d33567a73424e794f33573330507069434b31676f7254706b\"}},"
    "{\"deviceId\":\"TestAuthId3\",\"udid\":\"TestUdid2\",\"userId\":\"DCBA4321\","
    "\"credential\":{\"credentialType\":1,"
    "\"authCode\":\"2f7562744654535564586e665467546b322b4b506b65626373466f48766a4335\"}}]}";
static const char *ADD_PARAMS4 =
    "{\"groupType\":1,\"groupId\":\"4269DC28B639681698809A67EDAD08E39F207900038F91FEF95DD042FE2874E4\","
    "\"deviceList\":[{\"deviceId\":\"52E2706717D5C39D736E134CC1E3BE1BAA2AA52DB7C76A37C749558BD2E6492C\","
    "\"udid\":\"52E2706717D5C39D736E134CC1E3BE1BAA2AA52DB7C76A37C749558BD2E6492C\","
    "\"userId\":\"4269DC28B639681698809A67EDAD08E39F207900038F91FEF95DD042FE2874E4\","
    "\"credential\":{\"credentialType\":1,"
    "\"authCode\":\"10F9F0576E61730193D2052B7F771887124A68F1607EFCF7796C1491F834CD92\"}},"
    "{\"deviceId\":\"TestAuthId3\",\"udid\":\"TestUdid2\","
    "\"userId\":\"4269DC28B639681698809A67EDAD08E39F207900038F91FEF95DD042FE2874E4\","
    "\"credential\":{\"credentialType\":1,"
    "\"authCode\":\"2f7562744654535564586e665467546b322b4b506b65626373466f48766a4335\"}}]}";
static const char *ADD_PARAMS5 =
    "{\"groupType\":1,\"groupId\":\"4269DC28B639681698809A67EDAD08E39F207900038F91FEF95DD042FE2874E4\","
    "\"deviceList\":[{\"deviceId\":\"5420459D93FE773F9945FD64277FBA2CAB8FB996DDC1D0B97676FBB1242B3930\","
    "\"udid\":\"5420459D93FE773F9945FD64277FBA2CAB8FB996DDC1D0B97676FBB1242B3930\","
    "\"userId\":\"4269DC28B639681698809A67EDAD08E39F207900038F91FEF95DD042FE2874E4\","
    "\"credential\":{\"credentialType\":1,"
    "\"authCode\":\"10F9F0576E61730193D2052B7F771887124A68F1607EFCF7796C1491F834CD92\"}},"
    "{\"deviceId\":\"TestAuthId3\",\"udid\":\"TestUdid2\","
    "\"userId\":\"4269DC28B639681698809A67EDAD08E39F207900038F91FEF95DD042FE2874E4\","
    "\"credential\":{\"credentialType\":1,"
    "\"authCode\":\"2f7562744654535564586e665467546b322b4b506b65626373466f48766a4335\"}}]}";
static const char *DELETE_PARAMS2 =
    "{\"groupType\":1,\"groupId\":\"1234ABCD\","
    "\"deviceList\":[{\"deviceId\":\"TestAuthId2\"},{\"deviceId\":\"TestAuthId3\"}]}";
static const char *DELETE_PARAMS3 =
    "{\"groupType\":1282,\"groupId\":\"6B7B805962B8EB8275D73128BFDAA7ECD755A2EC304E36543941874A277FA75F\","
    "\"deviceList\":[{\"deviceId\":\"TestAuthId2\"},{\"deviceId\":\"TestAuthId3\"}]}";
static const char *GET_REG_INFO_PARAMS =
    "{\"version\":\"1.0.0\",\"deviceId\":\"TestAuthId\",\"userId\":\"1234ABCD\"}";
static const char *AUTH_PARAMS = "{\"peerConnDeviceId\":\"52E2706717D5C39D736E134CC1E3BE1BAA2AA52DB7C76A37C"
    "749558BD2E6492C\",\"servicePkgName\":\"TestAppId\",\"isClient\":true}";

enum AsyncStatus {
    ASYNC_STATUS_WAITING = 0,
    ASYNC_STATUS_TRANSMIT = 1,
    ASYNC_STATUS_FINISH = 2,
    ASYNC_STATUS_ERROR = 3
};

static AsyncStatus volatile g_asyncStatus;
static uint32_t g_transmitDataMaxLen = 2048;
static uint8_t g_transmitData[2048] = { 0 };
static uint32_t g_transmitDataLen = 0;

static bool OnTransmit(int64_t requestId, const uint8_t *data, uint32_t dataLen)
{
    (void)requestId;
    if (memcpy_s(g_transmitData, g_transmitDataMaxLen, data, dataLen) != EOK) {
        return false;
    }
    g_transmitDataLen = dataLen;
    g_asyncStatus = ASYNC_STATUS_TRANSMIT;
    return true;
}

static void OnSessionKeyReturned(int64_t requestId, const uint8_t *sessionKey, uint32_t sessionKeyLen)
{
    (void)requestId;
    (void)sessionKey;
    (void)sessionKeyLen;
    return;
}

static void OnFinish(int64_t requestId, int operationCode, const char *authReturn)
{
    (void)requestId;
    (void)operationCode;
    (void)authReturn;
    g_asyncStatus = ASYNC_STATUS_FINISH;
}

static void OnError(int64_t requestId, int operationCode, int errorCode, const char *errorReturn)
{
    (void)requestId;
    (void)operationCode;
    (void)errorCode;
    (void)errorReturn;
    g_asyncStatus = ASYNC_STATUS_ERROR;
}

static char *OnBindRequest(int64_t requestId, int operationCode, const char* reqParam)
{
    (void)requestId;
    (void)operationCode;
    (void)reqParam;
    CJson *json = CreateJson();
    AddIntToJson(json, FIELD_CONFIRMATION, REQUEST_ACCEPTED);
    AddIntToJson(json, FIELD_OS_ACCOUNT_ID, TEST_AUTH_OS_ACCOUNT_ID);
    AddStringToJson(json, FIELD_PIN_CODE, TEST_PIN_CODE);
    AddStringToJson(json, FIELD_DEVICE_ID, TEST_AUTH_ID2);
    char *returnDataStr = PackJsonToString(json);
    FreeJson(json);
    return returnDataStr;
}

static char *OnAuthRequest(int64_t requestId, int operationCode, const char* reqParam)
{
    (void)requestId;
    (void)operationCode;
    (void)reqParam;
    CJson *json = CreateJson();
    AddIntToJson(json, FIELD_CONFIRMATION, REQUEST_ACCEPTED);
    AddIntToJson(json, FIELD_OS_ACCOUNT_ID, TEST_AUTH_OS_ACCOUNT_ID);
    AddStringToJson(json, FIELD_PEER_CONN_DEVICE_ID, TEST_UDID_CLIENT);
    AddStringToJson(json, FIELD_SERVICE_PKG_NAME, TEST_APP_ID);
    char *returnDataStr = PackJsonToString(json);
    FreeJson(json);
    return returnDataStr;
}

static DeviceAuthCallback g_gmCallback = {
    .onTransmit = OnTransmit,
    .onSessionKeyReturned = OnSessionKeyReturned,
    .onFinish = OnFinish,
    .onError = OnError,
    .onRequest = OnBindRequest
};

static DeviceAuthCallback g_gaCallback = {
    .onTransmit = OnTransmit,
    .onSessionKeyReturned = OnSessionKeyReturned,
    .onFinish = OnFinish,
    .onError = OnError,
    .onRequest = OnAuthRequest
};

static void RemoveDir(const char *path)
{
    char strBuf[TEST_DEV_AUTH_BUFFER_SIZE] = {0};
    if (path == nullptr) {
        return;
    }
    if (sprintf_s(strBuf, sizeof(strBuf) - 1, "rm -rf %s", path) < 0) {
        return;
    }
    system(strBuf);
}

static void DeleteDatabase()
{
    RemoveDir(TEST_GROUP_DATA_PATH);
    RemoveDir(TEST_HKS_MAIN_DATA_PATH);
}

static bool GenerateTempKeyPair(Uint8Buff *keyAlias)
{
    int ret = GetLoaderInstance()->checkKeyExist(keyAlias, false, DEFAULT_OS_ACCOUNT);
    if (ret != HC_SUCCESS) {
        printf("Key pair not exist, start to generate\n");
        int32_t authId = 0;
        Uint8Buff authIdBuff = { reinterpret_cast<uint8_t *>(&authId), sizeof(int32_t)};
        ExtraInfo extInfo = {authIdBuff, -1, -1};
        KeyParams keyParams = { { keyAlias->val, keyAlias->length, true }, false, DEFAULT_OS_ACCOUNT };
        ret = GetLoaderInstance()->generateKeyPairWithStorage(&keyParams, TEST_DEV_AUTH_TEMP_KEY_PAIR_LEN, P256,
            KEY_PURPOSE_SIGN_VERIFY, &extInfo);
    } else {
        printf("Server key pair already exists\n");
    }

    if (ret != HC_SUCCESS) {
        printf("Generate key pair failed\n");
        return false;
    } else {
        printf("Generate key pair for server success\n");
    }
    return true;
}

static CJson *GetAsyCredentialJson(string registerInfo)
{
    uint8_t keyAliasValue[] = "TestServerKeyPair";
    int32_t keyAliasLen = 18;
    Uint8Buff keyAlias = {
        .val = keyAliasValue,
        .length = keyAliasLen
    };
    if (!GenerateTempKeyPair(&keyAlias)) {
        return nullptr;
    }
    uint8_t *serverPkVal = reinterpret_cast<uint8_t *>(HcMalloc(SERVER_PK_SIZE, 0));
    Uint8Buff serverPk = {
        .val = serverPkVal,
        .length = SERVER_PK_SIZE
    };

    KeyParams keyAliasParams = { { keyAlias.val, keyAlias.length, true }, false, DEFAULT_OS_ACCOUNT };
    int32_t ret = GetLoaderInstance()->exportPublicKey(&keyAliasParams, &serverPk);
    if (ret != HC_SUCCESS) {
        printf("export PublicKey failed\n");
        HcFree(serverPkVal);
        return nullptr;
    }

    Uint8Buff messageBuff = {
        .val = reinterpret_cast<uint8_t *>(const_cast<char *>(registerInfo.c_str())),
        .length = registerInfo.length() + 1
    };
    uint8_t *signatureValue = reinterpret_cast<uint8_t *>(HcMalloc(SIGNATURE_SIZE, 0));
    Uint8Buff signature = {
        .val = signatureValue,
        .length = SIGNATURE_SIZE
    };
    ret = GetLoaderInstance()->sign(&keyAliasParams, &messageBuff, P256, &signature);
    if (ret != HC_SUCCESS) {
        printf("Sign pkInfo failed.\n");
        HcFree(serverPkVal);
        HcFree(signatureValue);
        return nullptr;
    }

    CJson *pkInfoJson = CreateJsonFromString(registerInfo.c_str());
    CJson *credentialJson = CreateJson();
    (void)AddIntToJson(credentialJson, FIELD_CREDENTIAL_TYPE, ASYMMETRIC_CRED);
    (void)AddByteToJson(credentialJson, FIELD_SERVER_PK, serverPkVal, serverPk.length);
    (void)AddByteToJson(credentialJson, FIELD_PK_INFO_SIGNATURE, signatureValue, signature.length);
    (void)AddObjToJson(credentialJson, FIELD_PK_INFO, pkInfoJson);
    FreeJson(pkInfoJson);
    return credentialJson;
}

static void CreateDemoGroup(int32_t osAccountId, int64_t reqId, const char *appId, const char *createParams)
{
    g_asyncStatus = ASYNC_STATUS_WAITING;
    const DeviceGroupManager *gm = GetGmInstance();
    int32_t ret = gm->createGroup(osAccountId, reqId, appId, createParams);
    if (ret != HC_SUCCESS) {
        g_asyncStatus = ASYNC_STATUS_ERROR;
        return;
    }
    while (g_asyncStatus == ASYNC_STATUS_WAITING) {
        usleep(TEST_DEV_AUTH_SLEEP_TIME);
    }
    usleep(TEST_DEV_AUTH_SLEEP_TIME);
}

static void CreateDemoIdenticalAccountGroup()
{
    g_asyncStatus = ASYNC_STATUS_WAITING;
    const DeviceGroupManager *gm = GetGmInstance();
    ASSERT_NE(gm, nullptr);
    char *returnData = nullptr;
    int32_t ret = gm->getRegisterInfo(GET_REG_INFO_PARAMS, &returnData);
    ASSERT_EQ(ret, HC_SUCCESS);
    ASSERT_NE(returnData, nullptr);
    string registerInfo(returnData);

    CJson *credJson = GetAsyCredentialJson(registerInfo);
    ASSERT_NE(credJson, nullptr);
    CJson *json = CreateJson();
    AddIntToJson(json, FIELD_GROUP_TYPE, IDENTICAL_ACCOUNT_GROUP);
    AddStringToJson(json, FIELD_USER_ID, TEST_USER_ID);
    AddObjToJson(json, FIELD_CREDENTIAL, credJson);
    char *jsonStr = PackJsonToString(json);
    FreeJson(credJson);
    FreeJson(json);
    gm->destroyInfo(&returnData);
    ASSERT_NE(jsonStr, nullptr);
    ret = gm->createGroup(DEFAULT_OS_ACCOUNT, TEST_REQ_ID, TEST_APP_ID, jsonStr);
    FreeJsonString(jsonStr);
    ASSERT_EQ(ret, HC_SUCCESS);
    while (g_asyncStatus == ASYNC_STATUS_WAITING) {
        usleep(TEST_DEV_AUTH_SLEEP_TIME);
    }
}

static void CreateDemoSymClientIdenticalAccountGroup(void)
{
    g_asyncStatus = ASYNC_STATUS_WAITING;
    const DeviceGroupManager *gm = GetGmInstance();
    ASSERT_NE(gm, nullptr);

    CJson *credJson = CreateJson();
    (void)AddIntToJson(credJson, FIELD_CREDENTIAL_TYPE, SYMMETRIC_CRED);
    (void)AddStringToJson(credJson, FIELD_AUTH_CODE, TEST_AUTH_CODE3);
    CJson *json = CreateJson();
    AddIntToJson(json, FIELD_GROUP_TYPE, IDENTICAL_ACCOUNT_GROUP);
    AddStringToJson(json, FIELD_USER_ID, TEST_USER_ID_AUTH);
    AddObjToJson(json, FIELD_CREDENTIAL, credJson);
    char *jsonStr = PackJsonToString(json);
    FreeJson(credJson);
    FreeJson(json);
    if (jsonStr == nullptr) {
        return;
    }
    int32_t ret = gm->createGroup(DEFAULT_OS_ACCOUNT, TEST_REQ_ID, TEST_APP_ID, jsonStr);
    FreeJsonString(jsonStr);
    ASSERT_EQ(ret, HC_SUCCESS);
    while (g_asyncStatus == ASYNC_STATUS_WAITING) {
        usleep(TEST_DEV_AUTH_SLEEP_TIME);
    }
    ASSERT_EQ(g_asyncStatus, ASYNC_STATUS_FINISH);
}

static void CreateDemoSymServerIdenticalAccountGroup(void)
{
    g_asyncStatus = ASYNC_STATUS_WAITING;
    const DeviceGroupManager *gm = GetGmInstance();
    ASSERT_NE(gm, nullptr);

    CJson *credJson = CreateJson();
    (void)AddIntToJson(credJson, FIELD_CREDENTIAL_TYPE, SYMMETRIC_CRED);
    (void)AddStringToJson(credJson, FIELD_AUTH_CODE, TEST_AUTH_CODE3);
    CJson *json = CreateJson();
    AddIntToJson(json, FIELD_GROUP_TYPE, IDENTICAL_ACCOUNT_GROUP);
    AddStringToJson(json, FIELD_USER_ID, TEST_USER_ID_AUTH);
    AddObjToJson(json, FIELD_CREDENTIAL, credJson);
    char *jsonStr = PackJsonToString(json);
    FreeJson(credJson);
    FreeJson(json);
    if (jsonStr == nullptr) {
        return;
    }

    int32_t ret = gm->createGroup(TEST_AUTH_OS_ACCOUNT_ID, TEST_REQ_ID, TEST_APP_ID, jsonStr);
    FreeJsonString(jsonStr);
    ASSERT_EQ(ret, HC_SUCCESS);
    while (g_asyncStatus == ASYNC_STATUS_WAITING) {
        usleep(TEST_DEV_AUTH_SLEEP_TIME);
    }
    ASSERT_EQ(g_asyncStatus, ASYNC_STATUS_FINISH);
}

static void CreateDemoAcrossAccountGroup(int32_t osAccountId, int64_t reqId, const char *appId,
    const char *createParams)
{
    g_asyncStatus = ASYNC_STATUS_WAITING;
    const DeviceGroupManager *gm = GetGmInstance();
    ASSERT_NE(gm, nullptr);
    int32_t ret = gm->createGroup(osAccountId, reqId, appId, createParams);
    ASSERT_EQ(ret, HC_SUCCESS);
    while (g_asyncStatus == ASYNC_STATUS_WAITING) {
        usleep(TEST_DEV_AUTH_SLEEP_TIME);
    }
}

static void DeleteDemoGroup(int32_t osAccountId, int64_t reqId, const char *appId,
    const char *disbandParams)
{
    g_asyncStatus = ASYNC_STATUS_WAITING;
    const DeviceGroupManager *gm = GetGmInstance();
    ASSERT_NE(gm, nullptr);
    int32_t ret = gm->deleteGroup(osAccountId, reqId, appId, disbandParams);
    ASSERT_EQ(ret, HC_SUCCESS);
    while (g_asyncStatus == ASYNC_STATUS_WAITING) {
        usleep(TEST_DEV_AUTH_SLEEP_TIME);
    }
}

static void DeleteDemoIdenticalAccountGroup(void)
{
    g_asyncStatus = ASYNC_STATUS_WAITING;
    const DeviceGroupManager *gm = GetGmInstance();
    ASSERT_NE(gm, nullptr);
    int32_t ret = gm->deleteGroup(DEFAULT_OS_ACCOUNT, TEST_REQ_ID, TEST_APP_ID, DISBAND_PARAMS2);
    ASSERT_EQ(ret, HC_SUCCESS);
    while (g_asyncStatus == ASYNC_STATUS_WAITING) {
        usleep(TEST_DEV_AUTH_SLEEP_TIME);
    }
    ASSERT_EQ(g_asyncStatus, ASYNC_STATUS_FINISH);
}

static void DeleteDemoAcrossAccountGroup(void)
{
    g_asyncStatus = ASYNC_STATUS_WAITING;
    const DeviceGroupManager *gm = GetGmInstance();
    ASSERT_NE(gm, nullptr);
    int32_t ret = gm->deleteGroup(DEFAULT_OS_ACCOUNT, TEST_REQ_ID, TEST_APP_ID, DISBAND_PARAMS3);
    ASSERT_EQ(ret, HC_SUCCESS);
    while (g_asyncStatus == ASYNC_STATUS_WAITING) {
        usleep(TEST_DEV_AUTH_SLEEP_TIME);
    }
    ASSERT_EQ(g_asyncStatus, ASYNC_STATUS_FINISH);
}

static void AddDemoMember(void)
{
    g_asyncStatus = ASYNC_STATUS_WAITING;
    bool isClient = true;
    SetDeviceStatus(isClient);
    const DeviceGroupManager *gm = GetGmInstance();
    int32_t ret = gm->addMemberToGroup(DEFAULT_OS_ACCOUNT, TEST_REQ_ID, TEST_APP_ID, ADD_PARAMS);
    if (ret != HC_SUCCESS) {
        g_asyncStatus = ASYNC_STATUS_ERROR;
        return;
    }
    while (g_asyncStatus == ASYNC_STATUS_WAITING) {
        usleep(TEST_DEV_AUTH_SLEEP_TIME);
    }
    while (g_asyncStatus == ASYNC_STATUS_TRANSMIT) {
        isClient = !isClient;
        SetDeviceStatus(isClient);
        g_asyncStatus = ASYNC_STATUS_WAITING;
        uint8_t tmpTransmitData[2048] = { 0 };
        uint32_t tmpTransmitDataLen = 0;
        if (memcpy_s(tmpTransmitData, sizeof(tmpTransmitData), g_transmitData, g_transmitDataLen) != EOK) {
            g_asyncStatus = ASYNC_STATUS_ERROR;
            return;
        }
        tmpTransmitDataLen = g_transmitDataLen;
        (void)memset_s(g_transmitData, g_transmitDataMaxLen, 0, g_transmitDataMaxLen);
        g_transmitDataLen = 0;
        if (isClient) {
            ret = gm->processData(TEST_REQ_ID, tmpTransmitData, tmpTransmitDataLen);
        } else {
            ret = gm->processData(TEST_REQ_ID2, tmpTransmitData, tmpTransmitDataLen);
        }
        if (ret != HC_SUCCESS) {
            g_asyncStatus = ASYNC_STATUS_ERROR;
            return;
        }
        while (g_asyncStatus == ASYNC_STATUS_WAITING) {
            usleep(TEST_DEV_AUTH_SLEEP_TIME);
        }
        if (g_asyncStatus == ASYNC_STATUS_ERROR) {
            break;
        }
        if (g_transmitDataLen > 0) {
            g_asyncStatus = ASYNC_STATUS_TRANSMIT;
        }
    }
    usleep(TEST_DEV_AUTH_SLEEP_TIME2);
    SetDeviceStatus(true);
}

static void AuthDemoMember(void)
{
    g_asyncStatus = ASYNC_STATUS_WAITING;
    bool isClient = true;
    SetDeviceStatus(isClient);
    const GroupAuthManager *ga = GetGaInstance();
    ASSERT_NE(ga, nullptr);
    int32_t ret = ga->authDevice(DEFAULT_OS_ACCOUNT, TEST_REQ_ID3, AUTH_PARAMS, &g_gaCallback);
    if (ret != HC_SUCCESS) {
        g_asyncStatus = ASYNC_STATUS_ERROR;
        return;
    }
    while (g_asyncStatus == ASYNC_STATUS_WAITING) {
        usleep(TEST_DEV_AUTH_SLEEP_TIME);
    }
    while (g_asyncStatus == ASYNC_STATUS_TRANSMIT) {
        isClient = !isClient;
        SetDeviceStatus(isClient);
        g_asyncStatus = ASYNC_STATUS_WAITING;
        if (isClient) {
            ret = ga->processData(TEST_REQ_ID3, g_transmitData, g_transmitDataLen, &g_gaCallback);
        } else {
            ret = ga->processData(TEST_REQ_ID4, g_transmitData, g_transmitDataLen, &g_gaCallback);
        }
        (void)memset_s(g_transmitData, g_transmitDataMaxLen, 0, g_transmitDataMaxLen);
        g_transmitDataLen = 0;
        if (ret != HC_SUCCESS) {
            g_asyncStatus = ASYNC_STATUS_ERROR;
            return;
        }
        while (g_asyncStatus == ASYNC_STATUS_WAITING) {
            usleep(TEST_DEV_AUTH_SLEEP_TIME);
        }
        if (g_asyncStatus == ASYNC_STATUS_ERROR) {
            break;
        }
        if (g_transmitDataLen > 0) {
            g_asyncStatus = ASYNC_STATUS_TRANSMIT;
        }
    }
    SetDeviceStatus(true);
}

class GmProcessDataTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void GmProcessDataTest::SetUpTestCase() {}
void GmProcessDataTest::TearDownTestCase() {}

void GmProcessDataTest::SetUp()
{
    int ret = InitDeviceAuthService();
    EXPECT_EQ(ret, HC_SUCCESS);
}

void GmProcessDataTest::TearDown()
{
    DestroyDeviceAuthService();
}

HWTEST_F(GmProcessDataTest, GmProcessDataTest002, TestSize.Level0)
{
    const DeviceGroupManager *gm = GetGmInstance();
    EXPECT_NE(gm, nullptr);
    int32_t ret = gm->processData(TEST_REQ_ID, nullptr, 0);
    EXPECT_NE(ret, HC_SUCCESS);
}

class GmAddMultiMembersToGroupTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void GmAddMultiMembersToGroupTest::SetUpTestCase() {}
void GmAddMultiMembersToGroupTest::TearDownTestCase() {}

void GmAddMultiMembersToGroupTest::SetUp()
{
    DeleteDatabase();
    int ret = InitDeviceAuthService();
    EXPECT_EQ(ret, HC_SUCCESS);
}

void GmAddMultiMembersToGroupTest::TearDown()
{
    DestroyDeviceAuthService();
}

HWTEST_F(GmAddMultiMembersToGroupTest, GmAddMultiMembersToGroupTest001, TestSize.Level0)
{
    const DeviceGroupManager *gm = GetGmInstance();
    ASSERT_NE(gm, nullptr);
    int32_t ret = gm->addMultiMembersToGroup(DEFAULT_OS_ACCOUNT, nullptr, TEST_QUERY_PARAMS);
    ASSERT_EQ(ret, HC_ERR_INVALID_PARAMS);
}

HWTEST_F(GmAddMultiMembersToGroupTest, GmAddMultiMembersToGroupTest002, TestSize.Level0)
{
    const DeviceGroupManager *gm = GetGmInstance();
    ASSERT_NE(gm, nullptr);
    int32_t ret = gm->addMultiMembersToGroup(DEFAULT_OS_ACCOUNT, TEST_APP_ID, nullptr);
    ASSERT_EQ(ret, HC_ERR_INVALID_PARAMS);
}

HWTEST_F(GmAddMultiMembersToGroupTest, GmAddMultiMembersToGroupTest003, TestSize.Level0)
{
    const DeviceGroupManager *gm = GetGmInstance();
    ASSERT_NE(gm, nullptr);
    int32_t ret = gm->addMultiMembersToGroup(DEFAULT_OS_ACCOUNT, TEST_APP_ID, INVALID_JSON_STR);
    ASSERT_NE(ret, HC_SUCCESS);
}

HWTEST_F(GmAddMultiMembersToGroupTest, GmAddMultiMembersToGroupTest004, TestSize.Level0)
{
    const DeviceGroupManager *gm = GetGmInstance();
    ASSERT_NE(gm, nullptr);
    const char *addParams =
    "\"groupId\":\"1234ABCD\","
    "\"deviceList\":[{\"deviceId\":\"TestAuthId2\",\"udid\":\"TestUdid\",\"userId\":\"1234ABCD\","
    "\"credential\":{\"credentialType\":1,"
    "\"authCode\":\"37364761534f454d33567a73424e794f33573330507069434b31676f7254706b\"}},"
    "{\"deviceId\":\"TestAuthId3\",\"udid\":\"TestUdid2\",\"userId\":\"1234ABCD\","
    "\"credential\":{\"credentialType\":1,"
    "\"authCode\":\"2f7562744654535564586e665467546b322b4b506b65626373466f48766a4335\"}}]}";
    int32_t ret = gm->addMultiMembersToGroup(DEFAULT_OS_ACCOUNT, TEST_APP_ID, addParams);
    ASSERT_NE(ret, HC_SUCCESS);
}

HWTEST_F(GmAddMultiMembersToGroupTest, GmAddMultiMembersToGroupTest005, TestSize.Level0)
{
    const DeviceGroupManager *gm = GetGmInstance();
    ASSERT_NE(gm, nullptr);
    const char *addParams =
    "{\"groupType\":1132123,\"groupId\":\"1234ABCD\","
    "\"deviceList\":[{\"deviceId\":\"TestAuthId2\",\"udid\":\"TestUdid\",\"userId\":\"1234ABCD\","
    "\"credential\":{\"credentialType\":1,"
    "\"authCode\":\"37364761534f454d33567a73424e794f33573330507069434b31676f7254706b\"}},"
    "{\"deviceId\":\"TestAuthId3\",\"udid\":\"TestUdid2\",\"userId\":\"1234ABCD\","
    "\"credential\":{\"credentialType\":1,"
    "\"authCode\":\"2f7562744654535564586e665467546b322b4b506b65626373466f48766a4335\"}}]}";
    int32_t ret = gm->addMultiMembersToGroup(DEFAULT_OS_ACCOUNT, TEST_APP_ID, addParams);
    ASSERT_NE(ret, HC_SUCCESS);
}

HWTEST_F(GmAddMultiMembersToGroupTest, GmAddMultiMembersToGroupTest006, TestSize.Level0)
{
    const DeviceGroupManager *gm = GetGmInstance();
    ASSERT_NE(gm, nullptr);
    const char *addParams =
    "{\"groupType\":256,\"groupId\":\"1234ABCD\","
    "\"deviceList\":[{\"deviceId\":\"TestAuthId2\",\"udid\":\"TestUdid\",\"userId\":\"1234ABCD\","
    "\"credential\":{\"credentialType\":1,"
    "\"authCode\":\"37364761534f454d33567a73424e794f33573330507069434b31676f7254706b\"}},"
    "{\"deviceId\":\"TestAuthId3\",\"udid\":\"TestUdid2\",\"userId\":\"1234ABCD\","
    "\"credential\":{\"credentialType\":1,"
    "\"authCode\":\"2f7562744654535564586e665467546b322b4b506b65626373466f48766a4335\"}}]}";
    int32_t ret = gm->addMultiMembersToGroup(DEFAULT_OS_ACCOUNT, TEST_APP_ID, addParams);
    ASSERT_NE(ret, HC_SUCCESS);
}

HWTEST_F(GmAddMultiMembersToGroupTest, GmAddMultiMembersToGroupTest007, TestSize.Level0)
{
    const DeviceGroupManager *gm = GetGmInstance();
    ASSERT_NE(gm, nullptr);
    int32_t ret = gm->regCallback(TEST_APP_ID, &g_gmCallback);
    ASSERT_EQ(ret, HC_SUCCESS);
    CreateDemoIdenticalAccountGroup();
    ASSERT_EQ(g_asyncStatus, ASYNC_STATUS_FINISH);
    ret = gm->addMultiMembersToGroup(DEFAULT_OS_ACCOUNT, TEST_APP_ID, ADD_PARAMS2);
    ASSERT_EQ(ret, HC_SUCCESS);
}

HWTEST_F(GmAddMultiMembersToGroupTest, GmAddMultiMembersToGroupTest008, TestSize.Level0)
{
    const DeviceGroupManager *gm = GetGmInstance();
    ASSERT_NE(gm, nullptr);
    int32_t ret = gm->regCallback(TEST_APP_ID, &g_gmCallback);
    ASSERT_EQ(ret, HC_SUCCESS);
    CreateDemoIdenticalAccountGroup();
    ASSERT_EQ(g_asyncStatus, ASYNC_STATUS_FINISH);
    CreateDemoAcrossAccountGroup(DEFAULT_OS_ACCOUNT, TEST_REQ_ID, TEST_APP_ID, CREATE_PARAMS3);
    ASSERT_EQ(g_asyncStatus, ASYNC_STATUS_FINISH);
    ret = gm->addMultiMembersToGroup(DEFAULT_OS_ACCOUNT, TEST_APP_ID, ADD_PARAMS3);
    ASSERT_EQ(ret, HC_SUCCESS);
}

class GmDelMultiMembersFromGroupTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void GmDelMultiMembersFromGroupTest::SetUpTestCase() {}
void GmDelMultiMembersFromGroupTest::TearDownTestCase() {}

void GmDelMultiMembersFromGroupTest::SetUp()
{
    DeleteDatabase();
    int ret = InitDeviceAuthService();
    EXPECT_EQ(ret, HC_SUCCESS);
}

void GmDelMultiMembersFromGroupTest::TearDown()
{
    DestroyDeviceAuthService();
}

HWTEST_F(GmDelMultiMembersFromGroupTest, GmDelMultiMembersFromGroupTest001, TestSize.Level0)
{
    const DeviceGroupManager *gm = GetGmInstance();
    ASSERT_NE(gm, nullptr);
    int32_t ret = gm->delMultiMembersFromGroup(DEFAULT_OS_ACCOUNT, nullptr, TEST_QUERY_PARAMS);
    ASSERT_EQ(ret, HC_ERR_INVALID_PARAMS);
}

HWTEST_F(GmDelMultiMembersFromGroupTest, GmDelMultiMembersFromGroupTest002, TestSize.Level0)
{
    const DeviceGroupManager *gm = GetGmInstance();
    ASSERT_NE(gm, nullptr);
    int32_t ret = gm->delMultiMembersFromGroup(DEFAULT_OS_ACCOUNT, TEST_APP_ID, nullptr);
    ASSERT_EQ(ret, HC_ERR_INVALID_PARAMS);
}

HWTEST_F(GmDelMultiMembersFromGroupTest, GmDelMultiMembersFromGroupTest003, TestSize.Level0)
{
    const DeviceGroupManager *gm = GetGmInstance();
    ASSERT_NE(gm, nullptr);
    int32_t ret = gm->delMultiMembersFromGroup(DEFAULT_OS_ACCOUNT, TEST_APP_ID, INVALID_JSON_STR);
    ASSERT_NE(ret, HC_SUCCESS);
}

HWTEST_F(GmDelMultiMembersFromGroupTest, GmDelMultiMembersFromGroupTest004, TestSize.Level0)
{
    const DeviceGroupManager *gm = GetGmInstance();
    ASSERT_NE(gm, nullptr);
    const char *deleteParams =
    "{\"groupId\":\"1234ABCD\","
    "\"deviceList\":[{\"deviceId\":\"TestAuthId2\"},{\"deviceId\":\"TestAuthId3\"}]}";
    int32_t ret = gm->delMultiMembersFromGroup(DEFAULT_OS_ACCOUNT, TEST_APP_ID, deleteParams);
    ASSERT_NE(ret, HC_SUCCESS);
}

HWTEST_F(GmDelMultiMembersFromGroupTest, GmDelMultiMembersFromGroupTest005, TestSize.Level0)
{
    const DeviceGroupManager *gm = GetGmInstance();
    ASSERT_NE(gm, nullptr);
    const char *deleteParams =
    "{\"groupType\":1123123,\"groupId\":\"1234ABCD\","
    "\"deviceList\":[{\"deviceId\":\"TestAuthId2\"},{\"deviceId\":\"TestAuthId3\"}]}";
    int32_t ret = gm->delMultiMembersFromGroup(DEFAULT_OS_ACCOUNT, TEST_APP_ID, deleteParams);
    ASSERT_NE(ret, HC_SUCCESS);
}

HWTEST_F(GmDelMultiMembersFromGroupTest, GmDelMultiMembersFromGroupTest006, TestSize.Level0)
{
    const DeviceGroupManager *gm = GetGmInstance();
    ASSERT_NE(gm, nullptr);
    const char *deleteParams =
    "{\"groupType\":256,\"groupId\":\"1234ABCD\","
    "\"deviceList\":[{\"deviceId\":\"TestAuthId2\"},{\"deviceId\":\"TestAuthId3\"}]}";
    int32_t ret = gm->delMultiMembersFromGroup(DEFAULT_OS_ACCOUNT, TEST_APP_ID, deleteParams);
    ASSERT_NE(ret, HC_SUCCESS);
}

HWTEST_F(GmDelMultiMembersFromGroupTest, GmDelMultiMembersFromGroupTest007, TestSize.Level0)
{
    const DeviceGroupManager *gm = GetGmInstance();
    ASSERT_NE(gm, nullptr);
    int32_t ret = gm->regCallback(TEST_APP_ID, &g_gmCallback);
    ASSERT_EQ(ret, HC_SUCCESS);
    CreateDemoIdenticalAccountGroup();
    ASSERT_EQ(g_asyncStatus, ASYNC_STATUS_FINISH);
    ret = gm->addMultiMembersToGroup(DEFAULT_OS_ACCOUNT, TEST_APP_ID, ADD_PARAMS2);
    ASSERT_EQ(ret, HC_SUCCESS);
    ret = gm->delMultiMembersFromGroup(DEFAULT_OS_ACCOUNT, TEST_APP_ID, DELETE_PARAMS2);
    ASSERT_EQ(ret, HC_SUCCESS);
}

HWTEST_F(GmDelMultiMembersFromGroupTest, GmDelMultiMembersFromGroupTest008, TestSize.Level0)
{
    const DeviceGroupManager *gm = GetGmInstance();
    ASSERT_NE(gm, nullptr);
    int32_t ret = gm->regCallback(TEST_APP_ID, &g_gmCallback);
    ASSERT_EQ(ret, HC_SUCCESS);
    CreateDemoIdenticalAccountGroup();
    ASSERT_EQ(g_asyncStatus, ASYNC_STATUS_FINISH);
    CreateDemoAcrossAccountGroup(DEFAULT_OS_ACCOUNT, TEST_REQ_ID, TEST_APP_ID, CREATE_PARAMS3);
    ASSERT_EQ(g_asyncStatus, ASYNC_STATUS_FINISH);
    ret = gm->addMultiMembersToGroup(DEFAULT_OS_ACCOUNT, TEST_APP_ID, ADD_PARAMS3);
    ASSERT_EQ(ret, HC_SUCCESS);
    ret = gm->delMultiMembersFromGroup(DEFAULT_OS_ACCOUNT, TEST_APP_ID, DELETE_PARAMS3);
    ASSERT_EQ(ret, HC_SUCCESS);
}

class GmGetRegisterInfoTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void GmGetRegisterInfoTest::SetUpTestCase() {}
void GmGetRegisterInfoTest::TearDownTestCase() {}

void GmGetRegisterInfoTest::SetUp()
{
    int ret = InitDeviceAuthService();
    EXPECT_EQ(ret, HC_SUCCESS);
}

void GmGetRegisterInfoTest::TearDown()
{
    DestroyDeviceAuthService();
}

HWTEST_F(GmGetRegisterInfoTest, GmGetRegisterInfoTest001, TestSize.Level0)
{
    const DeviceGroupManager *gm = GetGmInstance();
    ASSERT_NE(gm, nullptr);
    char *returnData = nullptr;
    int32_t ret = gm->getRegisterInfo(nullptr, &returnData);
    ASSERT_EQ(ret, HC_ERR_INVALID_PARAMS);
}

HWTEST_F(GmGetRegisterInfoTest, GmGetRegisterInfoTest002, TestSize.Level0)
{
    const DeviceGroupManager *gm = GetGmInstance();
    ASSERT_NE(gm, nullptr);
    int32_t ret = gm->getRegisterInfo(TEST_QUERY_PARAMS, nullptr);
    ASSERT_EQ(ret, HC_ERR_INVALID_PARAMS);
}

HWTEST_F(GmGetRegisterInfoTest, GmGetRegisterInfoTest003, TestSize.Level0)
{
    const DeviceGroupManager *gm = GetGmInstance();
    ASSERT_NE(gm, nullptr);
    char *returnData = nullptr;
    int32_t ret = gm->getRegisterInfo(GET_REG_INFO_PARAMS, &returnData);
    ASSERT_EQ(ret, HC_SUCCESS);
    ASSERT_NE(returnData, nullptr);
    gm->destroyInfo(&returnData);
}

class GmDeleteGroupTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void GmDeleteGroupTest::SetUpTestCase() {}
void GmDeleteGroupTest::TearDownTestCase() {}

void GmDeleteGroupTest::SetUp()
{
    DeleteDatabase();
}

void GmDeleteGroupTest::TearDown() {}

HWTEST_F(GmDeleteGroupTest, GmDeleteGroupTest001, TestSize.Level0)
{
    int32_t ret = InitDeviceAuthService();
    ASSERT_EQ(ret, HC_SUCCESS);
    const DeviceGroupManager *gm = GetGmInstance();
    ASSERT_NE(gm, nullptr);
    ret = gm->deleteGroup(DEFAULT_OS_ACCOUNT, TEST_REQ_ID, TEST_APP_ID, nullptr);
    ASSERT_NE(ret, HC_SUCCESS);
    DestroyDeviceAuthService();
}

HWTEST_F(GmDeleteGroupTest, GmDeleteGroupTest002, TestSize.Level0)
{
    int32_t ret = InitDeviceAuthService();
    ASSERT_EQ(ret, HC_SUCCESS);
    const DeviceGroupManager *gm = GetGmInstance();
    ASSERT_NE(gm, nullptr);
    ret = gm->regCallback(TEST_APP_ID, &g_gmCallback);
    ASSERT_EQ(ret, HC_SUCCESS);
    DeleteDemoGroup(DEFAULT_OS_ACCOUNT, TEST_REQ_ID, TEST_APP_ID, DISBAND_PARAMS);
    ASSERT_EQ(g_asyncStatus, ASYNC_STATUS_ERROR);
    DestroyDeviceAuthService();
}

HWTEST_F(GmDeleteGroupTest, GmDeleteGroupTest003, TestSize.Level0)
{
    int32_t ret = InitDeviceAuthService();
    ASSERT_EQ(ret, HC_SUCCESS);
    const DeviceGroupManager *gm = GetGmInstance();
    ASSERT_NE(gm, nullptr);
    ret = gm->regCallback(TEST_APP_ID, &g_gmCallback);
    ASSERT_EQ(ret, HC_SUCCESS);
    ret = gm->deleteGroup(DEFAULT_OS_ACCOUNT, TEST_REQ_ID, TEST_APP_ID, INVALID_JSON_STR);
    ASSERT_NE(ret, HC_SUCCESS);
    DestroyDeviceAuthService();
}

HWTEST_F(GmDeleteGroupTest, GmDeleteGroupTest004, TestSize.Level0)
{
    int32_t ret = InitDeviceAuthService();
    ASSERT_EQ(ret, HC_SUCCESS);
    const DeviceGroupManager *gm = GetGmInstance();
    ASSERT_NE(gm, nullptr);
    ret = gm->deleteGroup(DEFAULT_OS_ACCOUNT, TEST_REQ_ID, TEST_APP_ID, DISBAND_PARAMS);
    ASSERT_NE(ret, HC_SUCCESS);
    DestroyDeviceAuthService();
}

HWTEST_F(GmDeleteGroupTest, GmDeleteGroupTest005, TestSize.Level0)
{
    int32_t ret = InitDeviceAuthService();
    ASSERT_EQ(ret, HC_SUCCESS);
    const DeviceGroupManager *gm = GetGmInstance();
    ASSERT_NE(gm, nullptr);
    ret = gm->regCallback(TEST_APP_ID, &g_gmCallback);
    ASSERT_EQ(ret, HC_SUCCESS);
    CreateDemoGroup(DEFAULT_OS_ACCOUNT, TEST_REQ_ID, TEST_APP_ID, CREATE_PARAMS);
    ASSERT_EQ(g_asyncStatus, ASYNC_STATUS_FINISH);
    DeleteDemoGroup(DEFAULT_OS_ACCOUNT, TEST_REQ_ID, TEST_APP_ID, DISBAND_PARAMS);
    ASSERT_EQ(g_asyncStatus, ASYNC_STATUS_FINISH);
    DestroyDeviceAuthService();
}

HWTEST_F(GmDeleteGroupTest, GmDeleteGroupTest006, TestSize.Level0)
{
    SetIsoSupported(true);
    SetPakeV1Supported(false);
    int32_t ret = InitDeviceAuthService();
    ASSERT_EQ(ret, HC_SUCCESS);
    const DeviceGroupManager *gm = GetGmInstance();
    ASSERT_NE(gm, nullptr);
    ret = gm->regCallback(TEST_APP_ID, &g_gmCallback);
    ASSERT_EQ(ret, HC_SUCCESS);
    CreateDemoGroup(DEFAULT_OS_ACCOUNT, TEST_REQ_ID, TEST_APP_ID, CREATE_PARAMS);
    ASSERT_EQ(g_asyncStatus, ASYNC_STATUS_FINISH);
    AddDemoMember();
    ASSERT_EQ(g_asyncStatus, ASYNC_STATUS_FINISH);
    DeleteDemoGroup(DEFAULT_OS_ACCOUNT, TEST_REQ_ID, TEST_APP_ID, DISBAND_PARAMS);
    ASSERT_EQ(g_asyncStatus, ASYNC_STATUS_FINISH);
    DestroyDeviceAuthService();
}

HWTEST_F(GmDeleteGroupTest, GmDeleteGroupTest007, TestSize.Level0)
{
    int32_t ret = InitDeviceAuthService();
    ASSERT_EQ(ret, HC_SUCCESS);
    const DeviceGroupManager *gm = GetGmInstance();
    ASSERT_NE(gm, nullptr);
    ret = gm->regCallback(TEST_APP_ID, &g_gmCallback);
    ASSERT_EQ(ret, HC_SUCCESS);
    CreateDemoIdenticalAccountGroup();
    ASSERT_EQ(g_asyncStatus, ASYNC_STATUS_FINISH);
    CreateDemoAcrossAccountGroup(DEFAULT_OS_ACCOUNT, TEST_REQ_ID, TEST_APP_ID, CREATE_PARAMS3);
    ASSERT_EQ(g_asyncStatus, ASYNC_STATUS_FINISH);
    DeleteDemoAcrossAccountGroup();
    DeleteDemoIdenticalAccountGroup();
    DestroyDeviceAuthService();
}

HWTEST_F(GmDeleteGroupTest, GmDeleteGroupTest008, TestSize.Level0)
{
    int32_t ret = InitDeviceAuthService();
    ASSERT_EQ(ret, HC_SUCCESS);
    const DeviceGroupManager *gm = GetGmInstance();
    ASSERT_NE(gm, nullptr);
    ret = gm->regCallback(TEST_APP_ID, &g_gmCallback);
    ASSERT_EQ(ret, HC_SUCCESS);
    CreateDemoIdenticalAccountGroup();
    ASSERT_EQ(g_asyncStatus, ASYNC_STATUS_FINISH);
    ret = gm->addMultiMembersToGroup(DEFAULT_OS_ACCOUNT, TEST_APP_ID, ADD_PARAMS2);
    ASSERT_EQ(ret, HC_SUCCESS);
    CreateDemoAcrossAccountGroup(DEFAULT_OS_ACCOUNT, TEST_REQ_ID, TEST_APP_ID, CREATE_PARAMS3);
    ASSERT_EQ(g_asyncStatus, ASYNC_STATUS_FINISH);
    DeleteDemoAcrossAccountGroup();
    DeleteDemoIdenticalAccountGroup();
    DestroyDeviceAuthService();
}

HWTEST_F(GmDeleteGroupTest, GmDeleteGroupTest009, TestSize.Level0)
{
    int32_t ret = InitDeviceAuthService();
    ASSERT_EQ(ret, HC_SUCCESS);
    const DeviceGroupManager *gm = GetGmInstance();
    ASSERT_NE(gm, nullptr);
    ret = gm->regCallback(TEST_APP_ID, &g_gmCallback);
    ASSERT_EQ(ret, HC_SUCCESS);
    CreateDemoIdenticalAccountGroup();
    ASSERT_EQ(g_asyncStatus, ASYNC_STATUS_FINISH);
    CreateDemoAcrossAccountGroup(DEFAULT_OS_ACCOUNT, TEST_REQ_ID, TEST_APP_ID, CREATE_PARAMS3);
    ASSERT_EQ(g_asyncStatus, ASYNC_STATUS_FINISH);
    ret = gm->addMultiMembersToGroup(DEFAULT_OS_ACCOUNT, TEST_APP_ID, ADD_PARAMS3);
    ASSERT_EQ(ret, HC_SUCCESS);
    DeleteDemoAcrossAccountGroup();
    DeleteDemoIdenticalAccountGroup();
    DestroyDeviceAuthService();
}

class GmCancelRequestTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void GmCancelRequestTest::SetUpTestCase() {}

void GmCancelRequestTest::TearDownTestCase() {}

void GmCancelRequestTest::SetUp()
{
    DeleteDatabase();
}

void GmCancelRequestTest::TearDown() {}

HWTEST_F(GmCancelRequestTest, GmCancelRequestTest001, TestSize.Level0)
{
    int32_t ret = InitDeviceAuthService();
    ASSERT_EQ(ret, HC_SUCCESS);
    const DeviceGroupManager *gm = GetGmInstance();
    ASSERT_NE(gm, nullptr);
    gm->cancelRequest(TEST_REQ_ID, nullptr);
    DestroyDeviceAuthService();
}

HWTEST_F(GmCancelRequestTest, GmCancelRequestTest002, TestSize.Level0)
{
    SetIsoSupported(true);
    SetPakeV1Supported(false);
    int32_t ret = InitDeviceAuthService();
    ASSERT_EQ(ret, HC_SUCCESS);
    const DeviceGroupManager *gm = GetGmInstance();
    ASSERT_NE(gm, nullptr);
    ret = gm->regCallback(TEST_APP_ID, &g_gmCallback);
    ASSERT_EQ(ret, HC_SUCCESS);
    CreateDemoGroup(DEFAULT_OS_ACCOUNT, TEST_REQ_ID, TEST_APP_ID, CREATE_PARAMS);
    ASSERT_EQ(g_asyncStatus, ASYNC_STATUS_FINISH);
    ret = gm->addMemberToGroup(DEFAULT_OS_ACCOUNT, TEST_REQ_ID, TEST_APP_ID, ADD_PARAMS);
    ASSERT_EQ(ret, HC_SUCCESS);
    gm->cancelRequest(TEST_REQ_ID, TEST_APP_ID);
    usleep(TEST_DEV_AUTH_SLEEP_TIME);
    DestroyDeviceAuthService();
}

HWTEST_F(GmCancelRequestTest, GmCancelRequestTest003, TestSize.Level0)
{
    SetIsoSupported(true);
    SetPakeV1Supported(false);
    int32_t ret = InitDeviceAuthService();
    ASSERT_EQ(ret, HC_SUCCESS);
    const DeviceGroupManager *gm = GetGmInstance();
    ASSERT_NE(gm, nullptr);
    ret = gm->regCallback(TEST_APP_ID, &g_gmCallback);
    ASSERT_EQ(ret, HC_SUCCESS);
    CreateDemoGroup(DEFAULT_OS_ACCOUNT, TEST_REQ_ID, TEST_APP_ID, CREATE_PARAMS);
    ASSERT_EQ(g_asyncStatus, ASYNC_STATUS_FINISH);
    ret = gm->addMemberToGroup(DEFAULT_OS_ACCOUNT, TEST_REQ_ID, TEST_APP_ID, ADD_PARAMS);
    ASSERT_EQ(ret, HC_SUCCESS);
    gm->cancelRequest(TEST_REQ_ID2, TEST_APP_ID);
    usleep(TEST_DEV_AUTH_SLEEP_TIME);
    DestroyDeviceAuthService();
}

HWTEST_F(GmCancelRequestTest, GmCancelRequestTest004, TestSize.Level0)
{
    SetIsoSupported(true);
    SetPakeV1Supported(false);
    int32_t ret = InitDeviceAuthService();
    ASSERT_EQ(ret, HC_SUCCESS);
    const DeviceGroupManager *gm = GetGmInstance();
    ASSERT_NE(gm, nullptr);
    ret = gm->regCallback(TEST_APP_ID, &g_gmCallback);
    ASSERT_EQ(ret, HC_SUCCESS);
    CreateDemoGroup(DEFAULT_OS_ACCOUNT, TEST_REQ_ID, TEST_APP_ID, CREATE_PARAMS);
    ASSERT_EQ(g_asyncStatus, ASYNC_STATUS_FINISH);
    ret = gm->addMemberToGroup(DEFAULT_OS_ACCOUNT, TEST_REQ_ID, TEST_APP_ID, ADD_PARAMS);
    ASSERT_EQ(ret, HC_SUCCESS);
    gm->cancelRequest(TEST_REQ_ID, TEST_APP_ID2);
    usleep(TEST_DEV_AUTH_SLEEP_TIME);
    DestroyDeviceAuthService();
}

HWTEST_F(GmCancelRequestTest, GmCancelRequestTest005, TestSize.Level0)
{
    SetIsoSupported(true);
    SetPakeV1Supported(false);
    int32_t ret = InitDeviceAuthService();
    ASSERT_EQ(ret, HC_SUCCESS);
    const DeviceGroupManager *gm = GetGmInstance();
    ASSERT_NE(gm, nullptr);
    ret = gm->regCallback(TEST_APP_ID, &g_gmCallback);
    ASSERT_EQ(ret, HC_SUCCESS);
    CreateDemoGroup(DEFAULT_OS_ACCOUNT, TEST_REQ_ID, TEST_APP_ID, CREATE_PARAMS);
    ASSERT_EQ(g_asyncStatus, ASYNC_STATUS_FINISH);
    ret = gm->addMemberToGroup(DEFAULT_OS_ACCOUNT, TEST_REQ_ID, TEST_APP_ID, ADD_PARAMS);
    ASSERT_EQ(ret, HC_SUCCESS);
    const GroupAuthManager *ga = GetGaInstance();
    ASSERT_NE(ga, nullptr);
    ga->cancelRequest(TEST_REQ_ID, TEST_APP_ID);
    usleep(TEST_DEV_AUTH_SLEEP_TIME);
    DestroyDeviceAuthService();
}

class GmDestroyInfoTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void GmDestroyInfoTest::SetUpTestCase()
{
    int32_t ret = InitDeviceAuthService();
    ASSERT_EQ(ret, HC_SUCCESS);
}

void GmDestroyInfoTest::TearDownTestCase()
{
    DestroyDeviceAuthService();
}

void GmDestroyInfoTest::SetUp() {}

void GmDestroyInfoTest::TearDown() {}

HWTEST_F(GmDestroyInfoTest, GmDestroyInfoTest001, TestSize.Level0)
{
    const DeviceGroupManager *gm = GetGmInstance();
    ASSERT_NE(gm, nullptr);
    gm->destroyInfo(nullptr);
}

HWTEST_F(GmDestroyInfoTest, GmDestroyInfoTest002, TestSize.Level0)
{
    const DeviceGroupManager *gm = GetGmInstance();
    ASSERT_NE(gm, nullptr);
    char *str = nullptr;
    gm->destroyInfo(&str);
}

class GaAuthDeviceTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void GaAuthDeviceTest::SetUpTestCase() {}
void GaAuthDeviceTest::TearDownTestCase() {}

void GaAuthDeviceTest::SetUp()
{
    DeleteDatabase();
}

void GaAuthDeviceTest::TearDown() {}

HWTEST_F(GaAuthDeviceTest, GaAuthDeviceTest001, TestSize.Level0)
{
    int32_t ret = InitDeviceAuthService();
    ASSERT_EQ(ret, HC_SUCCESS);
    const GroupAuthManager *ga = GetGaInstance();
    ASSERT_NE(ga, nullptr);
    ret = ga->authDevice(DEFAULT_OS_ACCOUNT, TEST_REQ_ID, nullptr, &g_gmCallback);
    ASSERT_EQ(ret, HC_ERR_INVALID_PARAMS);
    DestroyDeviceAuthService();
}

HWTEST_F(GaAuthDeviceTest, GaAuthDeviceTest002, TestSize.Level0)
{
    int32_t ret = InitDeviceAuthService();
    ASSERT_EQ(ret, HC_SUCCESS);
    const GroupAuthManager *ga = GetGaInstance();
    ASSERT_NE(ga, nullptr);
    ret = ga->authDevice(DEFAULT_OS_ACCOUNT, TEST_REQ_ID, AUTH_PARAMS, nullptr);
    ASSERT_NE(ret, HC_SUCCESS);
    DestroyDeviceAuthService();
}

HWTEST_F(GaAuthDeviceTest, GaAuthDeviceTest003, TestSize.Level0)
{
    SetIsoSupported(true);
    SetPakeV1Supported(false);
    int32_t ret = InitDeviceAuthService();
    ASSERT_EQ(ret, HC_SUCCESS);
    const DeviceGroupManager *gm = GetGmInstance();
    ASSERT_NE(gm, nullptr);
    ret = gm->regCallback(TEST_APP_ID, &g_gmCallback);
    ASSERT_EQ(ret, HC_SUCCESS);
    CreateDemoGroup(DEFAULT_OS_ACCOUNT, TEST_REQ_ID, TEST_APP_ID, CREATE_PARAMS);
    ASSERT_EQ(g_asyncStatus, ASYNC_STATUS_FINISH);
    AddDemoMember();
    ASSERT_EQ(g_asyncStatus, ASYNC_STATUS_FINISH);
    AuthDemoMember();
    ASSERT_EQ(g_asyncStatus, ASYNC_STATUS_FINISH);
    DestroyDeviceAuthService();
}

HWTEST_F(GaAuthDeviceTest, GaAuthDeviceTest004, TestSize.Level0)
{
    SetIsoSupported(false);
    SetPakeV1Supported(true);
    int32_t ret = InitDeviceAuthService();
    ASSERT_EQ(ret, HC_SUCCESS);
    const DeviceGroupManager *gm = GetGmInstance();
    ASSERT_NE(gm, nullptr);
    ret = gm->regCallback(TEST_APP_ID, &g_gmCallback);
    ASSERT_EQ(ret, HC_SUCCESS);
    CreateDemoGroup(DEFAULT_OS_ACCOUNT, TEST_REQ_ID, TEST_APP_ID, CREATE_PARAMS);
    ASSERT_EQ(g_asyncStatus, ASYNC_STATUS_FINISH);
    AddDemoMember();
    ASSERT_EQ(g_asyncStatus, ASYNC_STATUS_FINISH);
    AuthDemoMember();
    ASSERT_EQ(g_asyncStatus, ASYNC_STATUS_FINISH);
    DestroyDeviceAuthService();
}

HWTEST_F(GaAuthDeviceTest, GaAuthDeviceTest005, TestSize.Level0)
{
    SetIsoSupported(true);
    SetPakeV1Supported(false);
    int32_t ret = InitDeviceAuthService();
    ASSERT_EQ(ret, HC_SUCCESS);
    const DeviceGroupManager *gm = GetGmInstance();
    ASSERT_NE(gm, nullptr);
    ret = gm->regCallback(TEST_APP_ID, &g_gmCallback);
    ASSERT_EQ(ret, HC_SUCCESS);
    CreateDemoSymClientIdenticalAccountGroup();
    ASSERT_EQ(ret, HC_SUCCESS);
    SetDeviceStatus(false);
    CreateDemoSymServerIdenticalAccountGroup();
    SetDeviceStatus(true);
    AuthDemoMember();
    ASSERT_EQ(g_asyncStatus, ASYNC_STATUS_FINISH);
    DestroyDeviceAuthService();
}

HWTEST_F(GaAuthDeviceTest, GaAuthDeviceTest006, TestSize.Level0)
{
    SetIsoSupported(true);
    SetPakeV1Supported(false);
    int32_t ret = InitDeviceAuthService();
    ASSERT_EQ(ret, HC_SUCCESS);
    const DeviceGroupManager *gm = GetGmInstance();
    ASSERT_NE(gm, nullptr);
    ret = gm->regCallback(TEST_APP_ID, &g_gmCallback);
    ASSERT_EQ(ret, HC_SUCCESS);
    CreateDemoSymClientIdenticalAccountGroup();
    SetDeviceStatus(false);
    CreateDemoSymServerIdenticalAccountGroup();
    SetDeviceStatus(true);
    ret = gm->addMultiMembersToGroup(DEFAULT_OS_ACCOUNT, TEST_APP_ID, ADD_PARAMS4);
    ASSERT_EQ(ret, HC_SUCCESS);
    SetDeviceStatus(false);
    ret = gm->addMultiMembersToGroup(TEST_AUTH_OS_ACCOUNT_ID, TEST_APP_ID, ADD_PARAMS5);
    ASSERT_EQ(ret, HC_SUCCESS);
    SetDeviceStatus(true);
    AuthDemoMember();
    ASSERT_EQ(g_asyncStatus, ASYNC_STATUS_FINISH);
    DestroyDeviceAuthService();
}

class GaProcessDataTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void GaProcessDataTest::SetUpTestCase() {}
void GaProcessDataTest::TearDownTestCase() {}

void GaProcessDataTest::SetUp()
{
    int ret = InitDeviceAuthService();
    EXPECT_EQ(ret, HC_SUCCESS);
}

void GaProcessDataTest::TearDown()
{
    DestroyDeviceAuthService();
}

HWTEST_F(GaProcessDataTest, GaProcessDataTest002, TestSize.Level0)
{
    const GroupAuthManager *ga = GetGaInstance();
    EXPECT_NE(ga, nullptr);
    int32_t ret = ga->processData(TEST_REQ_ID, nullptr, 0, nullptr);
    EXPECT_NE(ret, HC_SUCCESS);
}

class GaCancelRequestTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void GaCancelRequestTest::SetUpTestCase() {}

void GaCancelRequestTest::TearDownTestCase() {}

void GaCancelRequestTest::SetUp()
{
    DeleteDatabase();
}

void GaCancelRequestTest::TearDown() {}

HWTEST_F(GaCancelRequestTest, GaCancelRequestTest001, TestSize.Level0)
{
    SetIsoSupported(true);
    SetPakeV1Supported(false);
    int32_t ret = InitDeviceAuthService();
    ASSERT_EQ(ret, HC_SUCCESS);
    const DeviceGroupManager *gm = GetGmInstance();
    ASSERT_NE(gm, nullptr);
    ret = gm->regCallback(TEST_APP_ID, &g_gmCallback);
    ASSERT_EQ(ret, HC_SUCCESS);
    CreateDemoGroup(DEFAULT_OS_ACCOUNT, TEST_REQ_ID, TEST_APP_ID, CREATE_PARAMS);
    ASSERT_EQ(g_asyncStatus, ASYNC_STATUS_FINISH);
    AddDemoMember();
    ASSERT_EQ(g_asyncStatus, ASYNC_STATUS_FINISH);
    const GroupAuthManager *ga = GetGaInstance();
    ASSERT_NE(ga, nullptr);
    ret = ga->authDevice(DEFAULT_OS_ACCOUNT, TEST_REQ_ID, AUTH_PARAMS, &g_gaCallback);
    ASSERT_EQ(ret, HC_SUCCESS);
    ga->cancelRequest(TEST_REQ_ID, TEST_APP_ID);
    usleep(TEST_DEV_AUTH_SLEEP_TIME);
    DestroyDeviceAuthService();
}

HWTEST_F(GaCancelRequestTest, GaCancelRequestTest002, TestSize.Level0)
{
    SetIsoSupported(true);
    SetPakeV1Supported(false);
    int32_t ret = InitDeviceAuthService();
    ASSERT_EQ(ret, HC_SUCCESS);
    const DeviceGroupManager *gm = GetGmInstance();
    ASSERT_NE(gm, nullptr);
    ret = gm->regCallback(TEST_APP_ID, &g_gmCallback);
    ASSERT_EQ(ret, HC_SUCCESS);
    CreateDemoGroup(DEFAULT_OS_ACCOUNT, TEST_REQ_ID, TEST_APP_ID, CREATE_PARAMS);
    ASSERT_EQ(g_asyncStatus, ASYNC_STATUS_FINISH);
    AddDemoMember();
    ASSERT_EQ(g_asyncStatus, ASYNC_STATUS_FINISH);
    const GroupAuthManager *ga = GetGaInstance();
    ASSERT_NE(ga, nullptr);
    ret = ga->authDevice(DEFAULT_OS_ACCOUNT, TEST_REQ_ID, AUTH_PARAMS, &g_gaCallback);
    ASSERT_EQ(ret, HC_SUCCESS);
    ga->cancelRequest(TEST_REQ_ID2, TEST_APP_ID);
    usleep(TEST_DEV_AUTH_SLEEP_TIME);
    DestroyDeviceAuthService();
}

HWTEST_F(GaCancelRequestTest, GaCancelRequestTest003, TestSize.Level0)
{
    SetIsoSupported(true);
    SetPakeV1Supported(false);
    int32_t ret = InitDeviceAuthService();
    ASSERT_EQ(ret, HC_SUCCESS);
    const DeviceGroupManager *gm = GetGmInstance();
    ASSERT_NE(gm, nullptr);
    ret = gm->regCallback(TEST_APP_ID, &g_gmCallback);
    ASSERT_EQ(ret, HC_SUCCESS);
    CreateDemoGroup(DEFAULT_OS_ACCOUNT, TEST_REQ_ID, TEST_APP_ID, CREATE_PARAMS);
    ASSERT_EQ(g_asyncStatus, ASYNC_STATUS_FINISH);
    AddDemoMember();
    ASSERT_EQ(g_asyncStatus, ASYNC_STATUS_FINISH);
    const GroupAuthManager *ga = GetGaInstance();
    ASSERT_NE(ga, nullptr);
    ret = ga->authDevice(DEFAULT_OS_ACCOUNT, TEST_REQ_ID, AUTH_PARAMS, &g_gaCallback);
    ASSERT_EQ(ret, HC_SUCCESS);
    ga->cancelRequest(TEST_REQ_ID, TEST_APP_ID2);
    usleep(TEST_DEV_AUTH_SLEEP_TIME);
    DestroyDeviceAuthService();
}

HWTEST_F(GaCancelRequestTest, GaCancelRequestTest004, TestSize.Level0)
{
    SetIsoSupported(true);
    SetPakeV1Supported(false);
    int32_t ret = InitDeviceAuthService();
    ASSERT_EQ(ret, HC_SUCCESS);
    const DeviceGroupManager *gm = GetGmInstance();
    ASSERT_NE(gm, nullptr);
    ret = gm->regCallback(TEST_APP_ID, &g_gmCallback);
    ASSERT_EQ(ret, HC_SUCCESS);
    CreateDemoGroup(DEFAULT_OS_ACCOUNT, TEST_REQ_ID, TEST_APP_ID, CREATE_PARAMS);
    ASSERT_EQ(g_asyncStatus, ASYNC_STATUS_FINISH);
    AddDemoMember();
    ASSERT_EQ(g_asyncStatus, ASYNC_STATUS_FINISH);
    const GroupAuthManager *ga = GetGaInstance();
    ASSERT_NE(ga, nullptr);
    ret = ga->authDevice(DEFAULT_OS_ACCOUNT, TEST_REQ_ID, AUTH_PARAMS, &g_gaCallback);
    ASSERT_EQ(ret, HC_SUCCESS);
    gm->cancelRequest(TEST_REQ_ID, TEST_APP_ID);
    usleep(TEST_DEV_AUTH_SLEEP_TIME);
    DestroyDeviceAuthService();
}

class DevAuthTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void DevAuthTest::SetUpTestCase() {}
void DevAuthTest::TearDownTestCase()
{
    DeleteDatabase();
}

void DevAuthTest::SetUp()
{
    DeleteDatabase();
}

void DevAuthTest::TearDown() {}

HWTEST_F(DevAuthTest, DevAuthTest001, TestSize.Level0)
{
    StartRecordJsonCallNum();
    int32_t ret = InitDeviceAuthService();
    ASSERT_EQ(ret, HC_SUCCESS);
    const DeviceGroupManager *gm = GetGmInstance();
    ASSERT_NE(gm, nullptr);
    ret = gm->regCallback(TEST_APP_ID, &g_gmCallback);
    ASSERT_EQ(ret, HC_SUCCESS);
    CreateDemoGroup(DEFAULT_OS_ACCOUNT, TEST_REQ_ID, TEST_APP_ID, CREATE_PARAMS);
    ASSERT_EQ(g_asyncStatus, ASYNC_STATUS_FINISH);
    DestroyDeviceAuthService();
    uint32_t mallocCount = GetJsonCallNum();
    printf("mock count: %u\n", mallocCount);
    for (int i = 0; i < mallocCount; i++) {
        ResetRecordJsonCallNum();
        SetJsonCallMockIndex(i);
        ret = InitDeviceAuthService();
        if (ret != HC_SUCCESS) {
            continue;
        }
        const DeviceGroupManager *gm = GetGmInstance();
        ret = gm->regCallback(TEST_APP_ID, &g_gmCallback);
        if (ret != HC_SUCCESS) {
            DestroyDeviceAuthService();
            continue;
        }
        CreateDemoGroup(DEFAULT_OS_ACCOUNT, TEST_REQ_ID, TEST_APP_ID, CREATE_PARAMS);
        if (g_asyncStatus != ASYNC_STATUS_FINISH) {
            DestroyDeviceAuthService();
            DeleteDatabase();
            continue;
        }
        DestroyDeviceAuthService();
    }
}

HWTEST_F(DevAuthTest, DevAuthTest101, TestSize.Level0)
{
    SetIsoSupported(true);
    SetPakeV1Supported(false);
    int32_t ret = InitDeviceAuthService();
    ASSERT_EQ(ret, HC_SUCCESS);
    const DeviceGroupManager *gm = GetGmInstance();
    ASSERT_NE(gm, nullptr);
    ret = gm->regCallback(TEST_APP_ID, &g_gmCallback);
    ASSERT_EQ(ret, HC_SUCCESS);
    CreateDemoGroup(DEFAULT_OS_ACCOUNT, TEST_REQ_ID, TEST_APP_ID, CREATE_PARAMS);
    ASSERT_EQ(g_asyncStatus, ASYNC_STATUS_FINISH);
    StartRecordJsonCallNum();
    AddDemoMember();
    ASSERT_EQ(g_asyncStatus, ASYNC_STATUS_FINISH);
    DestroyDeviceAuthService();
    DeleteDatabase();
    uint32_t mallocCount = GetJsonCallNum();
    printf("mock count: %u\n", mallocCount);
    for (int i = 0; i < mallocCount; i++) {
        ret = InitDeviceAuthService();
        ASSERT_EQ(ret, HC_SUCCESS);
        const DeviceGroupManager *gm = GetGmInstance();
        ret = gm->regCallback(TEST_APP_ID, &g_gmCallback);
        ASSERT_EQ(ret, HC_SUCCESS);
        CreateDemoGroup(DEFAULT_OS_ACCOUNT, TEST_REQ_ID, TEST_APP_ID, CREATE_PARAMS);
        if (g_asyncStatus != ASYNC_STATUS_FINISH) {
            DestroyDeviceAuthService();
            DeleteDatabase();
            continue;
        }
        ResetRecordJsonCallNum();
        SetJsonCallMockIndex(i);
        AddDemoMember();
        if (g_asyncStatus != ASYNC_STATUS_FINISH) {
            DestroyDeviceAuthService();
            DeleteDatabase();
            continue;
        }
        DestroyDeviceAuthService();
    }
}

HWTEST_F(DevAuthTest, DevAuthTest002, TestSize.Level0)
{
    int32_t ret = InitDeviceAuthService();
    ASSERT_EQ(ret, HC_SUCCESS);
    const DeviceGroupManager *gm = GetGmInstance();
    ASSERT_NE(gm, nullptr);
    ret = gm->regCallback(TEST_APP_ID, &g_gmCallback);
    ASSERT_EQ(ret, HC_SUCCESS);
    CreateDemoGroup(DEFAULT_OS_ACCOUNT, TEST_REQ_ID, TEST_APP_ID, CREATE_PARAMS);
    ASSERT_EQ(g_asyncStatus, ASYNC_STATUS_FINISH);

    StartRecordJsonCallNum();
    ret = gm->checkAccessToGroup(DEFAULT_OS_ACCOUNT, TEST_APP_ID, TEST_GROUP_ID);
    ASSERT_EQ(ret, HC_SUCCESS);
    uint32_t mallocCount = GetJsonCallNum();
    for (int i = 0; i < mallocCount; i++) {
        ResetRecordJsonCallNum();
        SetJsonCallMockIndex(i);
        ret = gm->checkAccessToGroup(DEFAULT_OS_ACCOUNT, TEST_APP_ID, TEST_GROUP_ID);
        if (ret != HC_SUCCESS) {
            continue;
        }
    }
    DestroyDeviceAuthService();
}

HWTEST_F(DevAuthTest, DevAuthTest003, TestSize.Level0)
{
    int32_t ret = InitDeviceAuthService();
    ASSERT_EQ(ret, HC_SUCCESS);
    const DeviceGroupManager *gm = GetGmInstance();
    ASSERT_NE(gm, nullptr);
    ret = gm->regCallback(TEST_APP_ID, &g_gmCallback);
    ASSERT_EQ(ret, HC_SUCCESS);
    CreateDemoGroup(DEFAULT_OS_ACCOUNT, TEST_REQ_ID, TEST_APP_ID, CREATE_PARAMS);
    ASSERT_EQ(g_asyncStatus, ASYNC_STATUS_FINISH);

    StartRecordJsonCallNum();
    char *returnData = nullptr;
    uint32_t returnNum = 0;
    const char *queryParams = "{\"udid\":\"5420459D93FE773F9945FD64277FBA2CAB8FB996DDC1D0B97676FBB1242"
        "B3930\",\"isSelfPk\":true}";
    ret = gm->getPkInfoList(DEFAULT_OS_ACCOUNT, TEST_APP_ID, queryParams, &returnData, &returnNum);
    ASSERT_EQ(ret, HC_SUCCESS);
    gm->destroyInfo(&returnData);
    uint32_t mallocCount = GetJsonCallNum();
    for (int i = 0; i < mallocCount; i++) {
        ResetRecordJsonCallNum();
        SetJsonCallMockIndex(i);
        ret = gm->getPkInfoList(DEFAULT_OS_ACCOUNT, TEST_APP_ID, queryParams, &returnData, &returnNum);
        if (ret != HC_SUCCESS) {
            continue;
        }
        gm->destroyInfo(&returnData);
    }
    DestroyDeviceAuthService();
}

HWTEST_F(DevAuthTest, DevAuthTest004, TestSize.Level0)
{
    int32_t ret = InitDeviceAuthService();
    ASSERT_EQ(ret, HC_SUCCESS);
    const DeviceGroupManager *gm = GetGmInstance();
    ASSERT_NE(gm, nullptr);
    ret = gm->regCallback(TEST_APP_ID, &g_gmCallback);
    ASSERT_EQ(ret, HC_SUCCESS);
    CreateDemoGroup(DEFAULT_OS_ACCOUNT, TEST_REQ_ID, TEST_APP_ID, CREATE_PARAMS);
    ASSERT_EQ(g_asyncStatus, ASYNC_STATUS_FINISH);

    StartRecordJsonCallNum();
    char *returnData = nullptr;
    ret = gm->getGroupInfoById(DEFAULT_OS_ACCOUNT, TEST_APP_ID, TEST_GROUP_ID, &returnData);
    ASSERT_EQ(ret, HC_SUCCESS);
    gm->destroyInfo(&returnData);
    uint32_t mallocCount = GetJsonCallNum();
    for (int i = 0; i < mallocCount; i++) {
        ResetRecordJsonCallNum();
        SetJsonCallMockIndex(i);
        ret = gm->getGroupInfoById(DEFAULT_OS_ACCOUNT, TEST_APP_ID, TEST_GROUP_ID, &returnData);
        if (ret != HC_SUCCESS) {
            continue;
        }
        gm->destroyInfo(&returnData);
    }
    DestroyDeviceAuthService();
}

HWTEST_F(DevAuthTest, DevAuthTest005, TestSize.Level0)
{
    int32_t ret = InitDeviceAuthService();
    ASSERT_EQ(ret, HC_SUCCESS);
    const DeviceGroupManager *gm = GetGmInstance();
    ASSERT_NE(gm, nullptr);
    ret = gm->regCallback(TEST_APP_ID, &g_gmCallback);
    ASSERT_EQ(ret, HC_SUCCESS);
    CreateDemoGroup(DEFAULT_OS_ACCOUNT, TEST_REQ_ID, TEST_APP_ID, CREATE_PARAMS);
    ASSERT_EQ(g_asyncStatus, ASYNC_STATUS_FINISH);

    StartRecordJsonCallNum();
    char *returnData = nullptr;
    uint32_t returnNum = 0;
    const char *queryParams = "{\"groupOwner\":\"TestAppId\"}";
    ret = gm->getGroupInfo(DEFAULT_OS_ACCOUNT, TEST_APP_ID, queryParams, &returnData, &returnNum);
    ASSERT_EQ(ret, HC_SUCCESS);
    gm->destroyInfo(&returnData);
    uint32_t mallocCount = GetJsonCallNum();
    for (int i = 0; i < mallocCount; i++) {
        ResetRecordJsonCallNum();
        SetJsonCallMockIndex(i);
        ret = gm->getGroupInfo(DEFAULT_OS_ACCOUNT, TEST_APP_ID, queryParams, &returnData, &returnNum);
        if (ret != HC_SUCCESS) {
            continue;
        }
        gm->destroyInfo(&returnData);
    }
    DestroyDeviceAuthService();
}

HWTEST_F(DevAuthTest, DevAuthTest006, TestSize.Level0)
{
    int32_t ret = InitDeviceAuthService();
    ASSERT_EQ(ret, HC_SUCCESS);
    const DeviceGroupManager *gm = GetGmInstance();
    ASSERT_NE(gm, nullptr);
    ret = gm->regCallback(TEST_APP_ID, &g_gmCallback);
    ASSERT_EQ(ret, HC_SUCCESS);
    CreateDemoGroup(DEFAULT_OS_ACCOUNT, TEST_REQ_ID, TEST_APP_ID, CREATE_PARAMS);
    ASSERT_EQ(g_asyncStatus, ASYNC_STATUS_FINISH);

    StartRecordJsonCallNum();
    char *returnData = nullptr;
    uint32_t returnNum = 0;
    ret = gm->getJoinedGroups(DEFAULT_OS_ACCOUNT, TEST_APP_ID, PEER_TO_PEER_GROUP, &returnData, &returnNum);
    ASSERT_EQ(ret, HC_SUCCESS);
    gm->destroyInfo(&returnData);
    uint32_t mallocCount = GetJsonCallNum();
    for (int i = 0; i < mallocCount; i++) {
        ResetRecordJsonCallNum();
        SetJsonCallMockIndex(i);
        ret = gm->getJoinedGroups(DEFAULT_OS_ACCOUNT, TEST_APP_ID, PEER_TO_PEER_GROUP, &returnData, &returnNum);
        if (ret != HC_SUCCESS) {
            continue;
        }
        gm->destroyInfo(&returnData);
    }
    DestroyDeviceAuthService();
}

HWTEST_F(DevAuthTest, DevAuthTest007, TestSize.Level0)
{
    int32_t ret = InitDeviceAuthService();
    ASSERT_EQ(ret, HC_SUCCESS);
    const DeviceGroupManager *gm = GetGmInstance();
    ASSERT_NE(gm, nullptr);
    ret = gm->regCallback(TEST_APP_ID, &g_gmCallback);
    ASSERT_EQ(ret, HC_SUCCESS);
    CreateDemoGroup(DEFAULT_OS_ACCOUNT, TEST_REQ_ID, TEST_APP_ID, CREATE_PARAMS);
    ASSERT_EQ(g_asyncStatus, ASYNC_STATUS_FINISH);

    StartRecordJsonCallNum();
    char *returnData = nullptr;
    uint32_t returnNum = 0;
    ret = gm->getRelatedGroups(DEFAULT_OS_ACCOUNT, TEST_APP_ID, TEST_AUTH_ID, &returnData, &returnNum);
    ASSERT_EQ(ret, HC_SUCCESS);
    gm->destroyInfo(&returnData);
    uint32_t mallocCount = GetJsonCallNum();
    for (int i = 0; i < mallocCount; i++) {
        ResetRecordJsonCallNum();
        SetJsonCallMockIndex(i);
        ret = gm->getRelatedGroups(DEFAULT_OS_ACCOUNT, TEST_APP_ID, TEST_AUTH_ID, &returnData, &returnNum);
        if (ret != HC_SUCCESS) {
            continue;
        }
        gm->destroyInfo(&returnData);
    }
    DestroyDeviceAuthService();
}

HWTEST_F(DevAuthTest, DevAuthTest008, TestSize.Level0)
{
    int32_t ret = InitDeviceAuthService();
    ASSERT_EQ(ret, HC_SUCCESS);
    const DeviceGroupManager *gm = GetGmInstance();
    ASSERT_NE(gm, nullptr);
    ret = gm->regCallback(TEST_APP_ID, &g_gmCallback);
    ASSERT_EQ(ret, HC_SUCCESS);
    CreateDemoGroup(DEFAULT_OS_ACCOUNT, TEST_REQ_ID, TEST_APP_ID, CREATE_PARAMS);
    ASSERT_EQ(g_asyncStatus, ASYNC_STATUS_FINISH);

    StartRecordJsonCallNum();
    char *returnData = nullptr;
    ret = gm->getDeviceInfoById(DEFAULT_OS_ACCOUNT, TEST_APP_ID, TEST_AUTH_ID, TEST_GROUP_ID, &returnData);
    ASSERT_EQ(ret, HC_SUCCESS);
    gm->destroyInfo(&returnData);
    uint32_t mallocCount = GetJsonCallNum();
    for (int i = 0; i < mallocCount; i++) {
        ResetRecordJsonCallNum();
        SetJsonCallMockIndex(i);
        ret = gm->getDeviceInfoById(DEFAULT_OS_ACCOUNT, TEST_APP_ID, TEST_AUTH_ID, TEST_GROUP_ID, &returnData);
        if (ret != HC_SUCCESS) {
            continue;
        }
        gm->destroyInfo(&returnData);
    }
    DestroyDeviceAuthService();
}

HWTEST_F(DevAuthTest, DevAuthTest009, TestSize.Level0)
{
    int32_t ret = InitDeviceAuthService();
    ASSERT_EQ(ret, HC_SUCCESS);
    const DeviceGroupManager *gm = GetGmInstance();
    ASSERT_NE(gm, nullptr);
    ret = gm->regCallback(TEST_APP_ID, &g_gmCallback);
    ASSERT_EQ(ret, HC_SUCCESS);
    CreateDemoGroup(DEFAULT_OS_ACCOUNT, TEST_REQ_ID, TEST_APP_ID, CREATE_PARAMS);
    ASSERT_EQ(g_asyncStatus, ASYNC_STATUS_FINISH);

    StartRecordJsonCallNum();
    char *returnData = nullptr;
    uint32_t returnNum = 0;
    ret = gm->getTrustedDevices(DEFAULT_OS_ACCOUNT, TEST_APP_ID, TEST_GROUP_ID, &returnData, &returnNum);
    ASSERT_EQ(ret, HC_SUCCESS);
    gm->destroyInfo(&returnData);
    uint32_t mallocCount = GetJsonCallNum();
    for (int i = 0; i < mallocCount; i++) {
        ResetRecordJsonCallNum();
        SetJsonCallMockIndex(i);
        ret = gm->getTrustedDevices(DEFAULT_OS_ACCOUNT, TEST_APP_ID, TEST_GROUP_ID, &returnData, &returnNum);
        if (ret != HC_SUCCESS) {
            continue;
        }
        gm->destroyInfo(&returnData);
    }
    DestroyDeviceAuthService();
}

HWTEST_F(DevAuthTest, DevAuthTest010, TestSize.Level0)
{
    SetIsoSupported(true);
    SetPakeV1Supported(false);
    int32_t ret = InitDeviceAuthService();
    ASSERT_EQ(ret, HC_SUCCESS);
    const DeviceGroupManager *gm = GetGmInstance();
    ASSERT_NE(gm, nullptr);
    ret = gm->regCallback(TEST_APP_ID, &g_gmCallback);
    ASSERT_EQ(ret, HC_SUCCESS);
    CreateDemoGroup(DEFAULT_OS_ACCOUNT, TEST_REQ_ID, TEST_APP_ID, CREATE_PARAMS);
    ASSERT_EQ(g_asyncStatus, ASYNC_STATUS_FINISH);

    StartRecordJsonCallNum();
    bool isExist = gm->isDeviceInGroup(DEFAULT_OS_ACCOUNT, TEST_APP_ID, TEST_GROUP_ID, TEST_AUTH_ID);
    ASSERT_EQ(isExist, true);
    uint32_t mallocCount = GetJsonCallNum();
    for (int i = 0; i < mallocCount; i++) {
        ResetRecordJsonCallNum();
        SetJsonCallMockIndex(i);
        isExist = gm->isDeviceInGroup(DEFAULT_OS_ACCOUNT, TEST_APP_ID, TEST_GROUP_ID, TEST_AUTH_ID);
        if (!isExist) {
            continue;
        }
    }
    DestroyDeviceAuthService();
}

class ExtPartTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
    ExtPart *extPart;
};

void ExtPartTest::SetUpTestCase() {}
void ExtPartTest::TearDownTestCase() {}

void ExtPartTest::SetUp()
{
    int ret = InitDeviceAuthService();
    EXPECT_EQ(ret, HC_SUCCESS);
    extPart = reinterpret_cast<ExtPart *>(HcMalloc(sizeof(ExtPart), 0));
    ASSERT_NE(extPart, nullptr);
}

void ExtPartTest::TearDown()
{
    DestroyDeviceAuthService();
    HcFree(extPart);
}

HWTEST_F(ExtPartTest, ExtPartTestTest001, TestSize.Level0)
{
    int ret = InitExtPart(nullptr, extPart);
    EXPECT_EQ(ret, HC_SUCCESS);
}

HWTEST_F(ExtPartTest, ExtPartTestTest002, TestSize.Level0)
{
    ExtPluginList list = GetExtPlugins(extPart);
    ASSERT_NE(list, nullptr);
}

HWTEST_F(ExtPartTest, ExtPartTestTest003, TestSize.Level0)
{
    DestroyExtPart(extPart);
    ASSERT_TRUE(extPart->instance == nullptr);
}
}
