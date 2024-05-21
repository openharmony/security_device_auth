/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include "devauthfunc_fuzzer.h"

#include <cstddef>
#include <cstdint>
#include <string>

#include <cinttypes>
#include <unistd.h>
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

namespace OHOS {
#define TEST_APP_ID "TestAppId"
#define TEST_APP_ID2 "TestAppId2"
#define TEST_REQ_ID 123
#define TEST_REQ_ID2 321
#define TEST_REQ_ID3 132
#define TEST_REQ_ID4 213
#define TEST_GROUP_NAME "TestGroup"
#define TEST_AUTH_ID "TestAuthId"
#define TEST_AUTH_ID2 "TestAuthId2"
#define TEST_AUTH_ID3 "TestAuthId3"
#define TEST_UDID "TestUdid"
#define TEST_UDID2 "TestUdid2"
#define TEST_QUERY_PARAMS "bac"
#define TEST_PIN_CODE "123456"
#define TEST_UDID_CLIENT "5420459D93FE773F9945FD64277FBA2CAB8FB996DDC1D0B97676FBB1242B3930"
#define TEST_UDID_SERVER "52E2706717D5C39D736E134CC1E3BE1BAA2AA52DB7C76A37C749558BD2E6492C"
#define TEST_GROUP_ID "E2EE6F830B176B2C96A9F99BFAE2A61F5D1490B9F4A090E9D8C2874C230C7C21"
#define TEST_GROUP_ID2 "F2AA208B1E010542B20A34B03B4B6289EA7C7F6DFE97DA2E370348B826682D3D"
#define TEST_GROUP_ID3 "4269DC28B639681698809A67EDAD08E39F207900038F91FEF95DD042FE2874E4"
#define TEST_GROUP_ID4 "6B7B805962B8EB8275D73128BFDAA7ECD755A2EC304E36543941874A277FA75F"
#define TEST_USER_ID_AUTH "4269DC28B639681698809A67EDAD08E39F207900038F91FEF95DD042FE2874E4"
#define TEST_USER_ID "4269DC28B639681698809A67EDAD08E39F207900038F91FEF95DD042FE2874E4"
#define TEST_AUTH_CODE "37364761534f454d33567a73424e794f33573330507069434b31676f7254706b"
#define TEST_AUTH_CODE2 "2f7562744654535564586e665467546b322b4b506b65626373466f48766a4335"
#define TEST_AUTH_CODE3 "1234567812345678123456781234567812345678123456781234567812345678"
#define TEST_AUTH_TOKEN3 "10F9F0576E61730193D2052B7F771887124A68F1607EFCF7796C1491F834CD92"
#define TEST_DEV_AUTH_SLEEP_TIME 50000
#define TEST_DEV_AUTH_SLEEP_TIME2 600000
#define TEST_TRANSMIT_DATA_LEN 2048
#define TEST_HKS_DATA_PATH "/data/service/el1/public/huks_service/tmp/+0+0+0+0"
#define TEST_DEV_AUTH_TEMP_KEY_PAIR_LEN 32
static const int32_t TEST_AUTH_OS_ACCOUNT_ID = 100;
static const int TEST_DEV_AUTH_BUFFER_SIZE = 128;
static const char *CREATE_PARAMS = "{\"groupName\":\"TestGroup\",\"deviceId\":\"TestAuthId\",\"groupType\":256,\"group"
    "Visibility\":-1,\"userType\":0,\"expireTime\":-1}";
static const char *CREATE_PARAMS2 = "{\"groupType\":1282,\"userId\":\"4269DC28B639681698809A67EDAD08E39F20790"
    "0038F91FEF95DD042FE2874E4\",\"peerUserId\":\"6B7B805962B8EB8275D73128BFDAA7ECD755A2EC304E36543941874A277FA75F\"}";
static const char *DISBAND_PARAMS =
    "{\"groupId\":\"E2EE6F830B176B2C96A9F99BFAE2A61F5D1490B9F4A090E9D8C2874C230C7C21\"}";
static const char *DISBAND_PARAMS2 =
    "{\"groupId\":\"4269DC28B639681698809A67EDAD08E39F207900038F91FEF95DD042FE2874E4\"}";
static const char *DISBAND_PARAMS3 =
    "{\"groupId\":\"FF52352E8082CE2B34DEF7A55F40BA694F64D5200ADA86686B862772F3517A84\"}";
static const char *ADD_PARAMS =
    "{\"groupId\":\"E2EE6F830B176B2C96A9F99BFAE2A61F5D1490B9F4A090E9D8C2874C230C7C21\","
    "\"groupType\":256,\"pinCode\":\"123456\"}";
static const char *AUTH_PARAMS = "{\"peerConnDeviceId\":\"52E2706717D5C39D736E134CC1E3BE1BAA2AA52DB7C76A37C"
    "749558BD2E6492C\",\"servicePkgName\":\"TestAppId\",\"isClient\":true}";
static const char *ADD_MULTI_PARAMS =
    "{\"groupType\":1,\"groupId\":\"4269DC28B639681698809A67EDAD08E39F207900038F91FEF95DD042FE2874E4\","
    "\"deviceList\":[{\"deviceId\":\"TestAuthId2\",\"udid\":\"TestUdid2\","
    "\"userId\":\"4269DC28B639681698809A67EDAD08E39F207900038F91FEF95DD042FE2874E4\","
    "\"credential\":{\"credentialType\":1,"
    "\"authCode\":\"37364761534f454d33567a73424e794f33573330507069434b31676f7254706b\"}},"
    "{\"deviceId\":\"TestAuthId3\",\"udid\":\"TestUdid3\","
    "\"userId\":\"4269DC28B639681698809A67EDAD08E39F207900038F91FEF95DD042FE2874E4\","
    "\"credential\":{\"credentialType\":1,"
    "\"authCode\":\"2f7562744654535564586e665467546b322b4b506b65626373466f48766a4335\"}}]}";
static const char *DEL_MULTI_PARAMS =
    "{\"groupType\":1,\"groupId\":\"4269DC28B639681698809A67EDAD08E39F207900038F91FEF95DD042FE2874E4\","
    "\"deviceList\":[{\"deviceId\":\"TestAuthId2\"},{\"deviceId\":\"TestAuthId3\"}]}";
static const char *DELETE_PARAMS =
    "{\"groupId\":\"E2EE6F830B176B2C96A9F99BFAE2A61F5D1490B9F4A090E9D8C2874C230C7C21\",\"deleteId\":\"TestAuthId2\"}";
static const char *GET_REGISTER_INFO_PARAMS =
    "{\"version\":\"1.0.0\",\"deviceId\":\"TestAuthId\","
    "\"userId\":\"4269DC28B639681698809A67EDAD08E39F207900038F91FEF95DD042FE2874E4\"}";
static const char *QUERY_PARAMS = "{\"groupOwner\":\"TestAppId\"}";

enum AsyncStatus {
    ASYNC_STATUS_WAITING = 0,
    ASYNC_STATUS_TRANSMIT = 1,
    ASYNC_STATUS_FINISH = 2,
    ASYNC_STATUS_ERROR = 3
};

static AsyncStatus volatile g_asyncStatus;
static uint8_t g_transmitData[2048] = { 0 };
static uint32_t g_transmitDataLen = 0;

static bool OnTransmit(int64_t requestId, const uint8_t *data, uint32_t dataLen)
{
    if (memcpy_s(g_transmitData, TEST_TRANSMIT_DATA_LEN, data, dataLen) != EOK) {
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
    g_asyncStatus = ASYNC_STATUS_FINISH;
}

static void OnError(int64_t requestId, int operationCode, int errorCode, const char *errorReturn)
{
    g_asyncStatus = ASYNC_STATUS_ERROR;
}

static char *OnBindRequest(int64_t requestId, int operationCode, const char* reqParam)
{
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

static void OnGroupCreated(const char *groupInfo) {}

static void OnGroupDeleted(const char *groupInfo) {}

static void OnDeviceBound(const char *peerUdid, const char* groupInfo) {}

static void OnDeviceUnBound(const char *peerUdid, const char* groupInfo) {}

static void OnDeviceNotTrusted(const char *peerUdid) {}

static void OnLastGroupDeleted(const char *peerUdid, int groupType) {}

static void OnTrustedDeviceNumChanged(int curTrustedDeviceNum) {}

static DataChangeListener g_listener = {
    .onGroupCreated = OnGroupCreated,
    .onGroupDeleted = OnGroupDeleted,
    .onDeviceBound = OnDeviceBound,
    .onDeviceUnBound = OnDeviceUnBound,
    .onDeviceNotTrusted = OnDeviceNotTrusted,
    .onLastGroupDeleted = OnLastGroupDeleted,
    .onTrustedDeviceNumChanged = OnTrustedDeviceNumChanged
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
    return;
}

static void DeleteDatabase()
{
    const char *groupPath = "/data/service/el1/public/deviceauthMock";
    RemoveDir(groupPath);
    RemoveDir(TEST_HKS_DATA_PATH);
    return;
}

static int32_t GenerateTempKeyPair(const Uint8Buff *keyAlias)
{
    int32_t ret = GetLoaderInstance()->checkKeyExist(keyAlias);
    if (ret != HC_SUCCESS) {
        int32_t authId = 0;
        Uint8Buff authIdBuff = { reinterpret_cast<uint8_t *>(&authId), sizeof(int32_t)};
        ExtraInfo extInfo = {authIdBuff, -1, -1};
        ret = GetLoaderInstance()->generateKeyPairWithStorage(keyAlias, TEST_DEV_AUTH_TEMP_KEY_PAIR_LEN, P256,
            KEY_PURPOSE_SIGN_VERIFY, &extInfo);
    }
    return ret;
}

static CJson *GetAsyCredentialJson(const std::string registerInfo)
{
    uint8_t keyAliasValue[] = "TestServerKeyPair";
    int32_t keyAliasLen = 18;
    Uint8Buff keyAlias = {
        .val = keyAliasValue,
        .length = keyAliasLen
    };
    if (GenerateTempKeyPair(&keyAlias) != HC_SUCCESS) {
        return nullptr;
    }
    uint8_t *serverPkVal = reinterpret_cast<uint8_t *>(HcMalloc(SERVER_PK_SIZE, 0));
    Uint8Buff serverPk = {
        .val = serverPkVal,
        .length = SERVER_PK_SIZE
    };

    int32_t ret = GetLoaderInstance()->exportPublicKey(&keyAlias, &serverPk);
    if (ret != HC_SUCCESS) {
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
    ret = GetLoaderInstance()->sign(&keyAlias, &messageBuff, P256, &signature, true);
    if (ret != HC_SUCCESS) {
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

static int32_t CreateDemoGroup(int32_t osAccountId, int64_t reqId, const char *appId, const char *createParams)
{
    g_asyncStatus = ASYNC_STATUS_WAITING;
    const DeviceGroupManager *gm = GetGmInstance();
    if (gm == nullptr) {
        return HC_ERR_NULL_PTR;
    }
    int32_t ret = gm->createGroup(osAccountId, reqId, appId, createParams);
    if (ret != HC_SUCCESS) {
        g_asyncStatus = ASYNC_STATUS_ERROR;
        return ret;
    }
    while (g_asyncStatus == ASYNC_STATUS_WAITING) {
        usleep(TEST_DEV_AUTH_SLEEP_TIME);
    }
    usleep(TEST_DEV_AUTH_SLEEP_TIME);
    return g_asyncStatus == ASYNC_STATUS_ERROR ? HC_ERROR : HC_SUCCESS;
}

static int32_t CreateDemoIdenticalAccountGroup(int32_t osAccountId, int64_t reqId,
    const char *appId, const char *userId)
{
    g_asyncStatus = ASYNC_STATUS_WAITING;
    const DeviceGroupManager *gm = GetGmInstance();
    if (gm == nullptr) {
        return HC_ERR_NULL_PTR;
    }
    char *returnData = nullptr;
    int32_t ret = gm->getRegisterInfo(GET_REGISTER_INFO_PARAMS, &returnData);
    if (ret != HC_SUCCESS) {
        return ret;
    }
    std::string registerInfo(returnData);
    CJson *credJson = GetAsyCredentialJson(registerInfo);
    if (ret != HC_SUCCESS) {
        gm->destroyInfo(&returnData);
        return ret;
    }
    CJson *json = CreateJson();
    AddIntToJson(json, FIELD_GROUP_TYPE, IDENTICAL_ACCOUNT_GROUP);
    AddStringToJson(json, FIELD_USER_ID, userId);
    AddObjToJson(json, FIELD_CREDENTIAL, credJson);
    char *jsonStr = PackJsonToString(json);
    FreeJson(credJson);
    FreeJson(json);
    gm->destroyInfo(&returnData);
    ret = gm->createGroup(osAccountId, reqId, appId, jsonStr);
    FreeJsonString(jsonStr);
    if (ret != HC_SUCCESS) {
        return ret;
    }
    while (g_asyncStatus == ASYNC_STATUS_WAITING) {
        usleep(TEST_DEV_AUTH_SLEEP_TIME);
    }
    return g_asyncStatus == ASYNC_STATUS_ERROR ? HC_ERROR : HC_SUCCESS;
}

static int32_t DeleteDemoGroup(int32_t osAccountId, int64_t reqId, const char *appId,
    const char *disbandParams)
{
    g_asyncStatus = ASYNC_STATUS_WAITING;
    const DeviceGroupManager *gm = GetGmInstance();
    if (gm == nullptr) {
        return HC_ERR_NULL_PTR;
    }
    int32_t ret = gm->deleteGroup(osAccountId, reqId, appId, disbandParams);
    if (ret != HC_SUCCESS) {
        return ret;
    }
    while (g_asyncStatus == ASYNC_STATUS_WAITING) {
        usleep(TEST_DEV_AUTH_SLEEP_TIME);
    }
    return g_asyncStatus == ASYNC_STATUS_ERROR ? HC_ERROR : HC_SUCCESS;
}

static int32_t AddDemoMember(void)
{
    g_asyncStatus = ASYNC_STATUS_WAITING;
    bool isClient = true;
    SetDeviceStatus(isClient);
    const DeviceGroupManager *gm = GetGmInstance();
    if (gm == nullptr) {
        return HC_ERR_NULL_PTR;
    }
    int32_t ret = gm->addMemberToGroup(DEFAULT_OS_ACCOUNT, TEST_REQ_ID, TEST_APP_ID, ADD_PARAMS);
    if (ret != HC_SUCCESS) {
        g_asyncStatus = ASYNC_STATUS_ERROR;
        return ret;
    }
    while (g_asyncStatus == ASYNC_STATUS_WAITING) {
        usleep(TEST_DEV_AUTH_SLEEP_TIME);
    }
    while (g_asyncStatus == ASYNC_STATUS_TRANSMIT) {
        isClient = !isClient;
        SetDeviceStatus(isClient);
        g_asyncStatus = ASYNC_STATUS_WAITING;
        if (isClient) {
            ret = gm->processData(TEST_REQ_ID, g_transmitData, g_transmitDataLen);
        } else {
            ret = gm->processData(TEST_REQ_ID2, g_transmitData, g_transmitDataLen);
        }
        (void)memset_s(g_transmitData, TEST_TRANSMIT_DATA_LEN, 0, TEST_TRANSMIT_DATA_LEN);
        g_transmitDataLen = 0;
        if (ret != HC_SUCCESS) {
            g_asyncStatus = ASYNC_STATUS_ERROR;
            return ret;
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
    return g_asyncStatus == ASYNC_STATUS_ERROR ? HC_ERROR : HC_SUCCESS;
}

static int32_t AuthDemoMember(void)
{
    g_asyncStatus = ASYNC_STATUS_WAITING;
    bool isClient = true;
    SetDeviceStatus(isClient);
    const GroupAuthManager *ga = GetGaInstance();
    if (ga == nullptr) {
        return HC_ERR_NULL_PTR;
    }
    int32_t ret = ga->authDevice(DEFAULT_OS_ACCOUNT, TEST_REQ_ID3, AUTH_PARAMS, &g_gaCallback);
    if (ret != HC_SUCCESS) {
        g_asyncStatus = ASYNC_STATUS_ERROR;
        return ret;
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
        (void)memset_s(g_transmitData, TEST_TRANSMIT_DATA_LEN, 0, TEST_TRANSMIT_DATA_LEN);
        g_transmitDataLen = 0;
        if (ret != HC_SUCCESS) {
            g_asyncStatus = ASYNC_STATUS_ERROR;
            return ret;
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
    return g_asyncStatus == ASYNC_STATUS_ERROR ? HC_ERROR : HC_SUCCESS;
}

static int32_t DelDemoMember(int32_t osAccountId, int64_t reqId, const char *appId,
    const char *deleteParams)
{
    g_asyncStatus = ASYNC_STATUS_WAITING;
    const DeviceGroupManager *gm = GetGmInstance();
    if (gm == nullptr) {
        return HC_ERR_NULL_PTR;
    }
    int32_t ret = gm->deleteMemberFromGroup(osAccountId, reqId, appId, deleteParams);
    if (ret != HC_SUCCESS) {
        return ret;
    }
    while (g_asyncStatus == ASYNC_STATUS_WAITING) {
        usleep(TEST_DEV_AUTH_SLEEP_TIME);
    }
    return g_asyncStatus == ASYNC_STATUS_ERROR ? HC_ERROR : HC_SUCCESS;
}

static int32_t DevAuthTestCase004(void)
{
    DeleteDatabase();
    int32_t ret = InitDeviceAuthService();
    if (ret != HC_SUCCESS) {
        return ret;
    }
    do {
        const DeviceGroupManager *gm = GetGmInstance();
        ret = gm->regCallback(TEST_APP_ID, &g_gmCallback);
        if (ret != HC_SUCCESS) {
            break;
        }
        ret = gm->unRegCallback(TEST_APP_ID);
    } while (0);
    DestroyDeviceAuthService();
    return ret;
}

static int32_t DevAuthTestCase005(void)
{
    DeleteDatabase();
    int32_t ret = InitDeviceAuthService();
    if (ret != HC_SUCCESS) {
        return ret;
    }
    do {
        const DeviceGroupManager *gm = GetGmInstance();
        ret = gm->regCallback(TEST_APP_ID, &g_gmCallback);
        if (ret != HC_SUCCESS) {
            break;
        }
        ret = CreateDemoGroup(DEFAULT_OS_ACCOUNT, TEST_REQ_ID, TEST_APP_ID, CREATE_PARAMS);
    } while (0);
    DestroyDeviceAuthService();
    return ret;
}

static int32_t DevAuthTestCase006(void)
{
    DeleteDatabase();
    int32_t ret = InitDeviceAuthService();
    if (ret != HC_SUCCESS) {
        return ret;
    }
    do {
        const DeviceGroupManager *gm = GetGmInstance();
        ret = gm->regCallback(TEST_APP_ID, &g_gmCallback);
        if (ret != HC_SUCCESS) {
            break;
        }
        ret = CreateDemoGroup(DEFAULT_OS_ACCOUNT, TEST_REQ_ID, TEST_APP_ID, CREATE_PARAMS);
        if (ret != HC_SUCCESS) {
            break;
        }
        ret = AddDemoMember();
    } while (0);
    DestroyDeviceAuthService();
    return ret;
}

static int32_t DevAuthTestCase007(void)
{
    DeleteDatabase();
    int32_t ret = InitDeviceAuthService();
    if (ret != HC_SUCCESS) {
        return ret;
    }
    do {
        const DeviceGroupManager *gm = GetGmInstance();
        ret = gm->regCallback(TEST_APP_ID, &g_gmCallback);
        if (ret != HC_SUCCESS) {
            break;
        }
        ret = CreateDemoGroup(DEFAULT_OS_ACCOUNT, TEST_REQ_ID, TEST_APP_ID, CREATE_PARAMS);
        if (ret != HC_SUCCESS) {
            break;
        }
        ret = AddDemoMember();
        if (ret != HC_SUCCESS) {
            break;
        }
        ret = AuthDemoMember();
    } while (0);
    DestroyDeviceAuthService();
    return ret;
}

static int32_t DevAuthTestCase008(void)
{
    DeleteDatabase();
    int32_t ret = InitDeviceAuthService();
    if (ret != HC_SUCCESS) {
        return ret;
    }
    do {
        const DeviceGroupManager *gm = GetGmInstance();
        ret = gm->regCallback(TEST_APP_ID, &g_gmCallback);
        if (ret != HC_SUCCESS) {
            break;
        }
        ret = CreateDemoGroup(DEFAULT_OS_ACCOUNT, TEST_REQ_ID, TEST_APP_ID, CREATE_PARAMS);
        if (ret != HC_SUCCESS) {
            break;
        }
        ret = AddDemoMember();
        if (ret != HC_SUCCESS) {
            break;
        }
        ret = DelDemoMember(DEFAULT_OS_ACCOUNT, TEST_REQ_ID, TEST_APP_ID, DELETE_PARAMS);
    } while (0);
    DestroyDeviceAuthService();
    return ret;
}

static int32_t DevAuthTestCase009(void)
{
    DeleteDatabase();
    int32_t ret = InitDeviceAuthService();
    if (ret != HC_SUCCESS) {
        return ret;
    }
    do {
        const DeviceGroupManager *gm = GetGmInstance();
        ret = gm->regCallback(TEST_APP_ID, &g_gmCallback);
        if (ret != HC_SUCCESS) {
            break;
        }
        ret = CreateDemoGroup(DEFAULT_OS_ACCOUNT, TEST_REQ_ID, TEST_APP_ID, CREATE_PARAMS);
        if (ret != HC_SUCCESS) {
            break;
        }
        ret = DeleteDemoGroup(DEFAULT_OS_ACCOUNT, TEST_REQ_ID, TEST_APP_ID, DISBAND_PARAMS);
    } while (0);
    DestroyDeviceAuthService();
    return ret;
}

static int32_t DevAuthTestCase010(void)
{
    DeleteDatabase();
    int32_t ret = InitDeviceAuthService();
    if (ret != HC_SUCCESS) {
        return ret;
    }
    do {
        char *returnData = nullptr;
        ret = GetGmInstance()->getRegisterInfo(GET_REGISTER_INFO_PARAMS, &returnData);
        if (ret != HC_SUCCESS) {
            break;
        }
        if (returnData == nullptr) {
            ret = HC_ERROR;
        }
    } while (0);
    DestroyDeviceAuthService();
    return ret;
}

static int32_t DevAuthTestCase011(void)
{
    DeleteDatabase();
    int32_t ret = InitDeviceAuthService();
    if (ret != HC_SUCCESS) {
        return ret;
    }
    do {
        const DeviceGroupManager *gm = GetGmInstance();
        ret = gm->regCallback(TEST_APP_ID, &g_gmCallback);
        if (ret != HC_SUCCESS) {
            break;
        }
        ret = CreateDemoIdenticalAccountGroup(DEFAULT_OS_ACCOUNT, TEST_REQ_ID, TEST_APP_ID, TEST_USER_ID);
    } while (0);
    DestroyDeviceAuthService();
    return ret;
}

static int32_t DevAuthTestCase012(void)
{
    DeleteDatabase();
    int32_t ret = InitDeviceAuthService();
    if (ret != HC_SUCCESS) {
        return ret;
    }
    do {
        const DeviceGroupManager *gm = GetGmInstance();
        ret = gm->regCallback(TEST_APP_ID, &g_gmCallback);
        if (ret != HC_SUCCESS) {
            break;
        }
        ret = CreateDemoIdenticalAccountGroup(DEFAULT_OS_ACCOUNT, TEST_REQ_ID, TEST_APP_ID, TEST_USER_ID);
        if (ret != HC_SUCCESS) {
            break;
        }
        ret = gm->addMultiMembersToGroup(DEFAULT_OS_ACCOUNT, TEST_APP_ID, ADD_MULTI_PARAMS);
    } while (0);
    DestroyDeviceAuthService();
    return ret;
}

static int32_t DevAuthTestCase013(void)
{
    DeleteDatabase();
    SetDeviceStatus(true);
    int32_t ret = InitDeviceAuthService();
    if (ret != HC_SUCCESS) {
        return ret;
    }
    DestroyDeviceAuthService();
    SetDeviceStatus(false);
    ret = InitDeviceAuthService();
    if (ret != HC_SUCCESS) {
        return ret;
    }
    DestroyDeviceAuthService();
    SetDeviceStatus(true);
    ret = InitDeviceAuthService();
    if (ret != HC_SUCCESS) {
        return ret;
    }
    do {
        const DeviceGroupManager *gm = GetGmInstance();
        ret = gm->regCallback(TEST_APP_ID, &g_gmCallback);
        if (ret != HC_SUCCESS) {
            break;
        }
        SetDeviceStatus(true);
        ret = CreateDemoIdenticalAccountGroup(DEFAULT_OS_ACCOUNT, TEST_REQ_ID, TEST_APP_ID, TEST_USER_ID);
        if (ret != HC_SUCCESS) {
            break;
        }
        SetDeviceStatus(false);
        ret = CreateDemoIdenticalAccountGroup(TEST_AUTH_OS_ACCOUNT_ID, TEST_REQ_ID, TEST_APP_ID, TEST_USER_ID);
        if (ret != HC_SUCCESS) {
            break;
        }
        ret = AuthDemoMember();
    } while (0);
    DestroyDeviceAuthService();
    return ret;
}

static int32_t DevAuthTestCase014(void)
{
    DeleteDatabase();
    int32_t ret = InitDeviceAuthService();
    if (ret != HC_SUCCESS) {
        return ret;
    }
    do {
        const DeviceGroupManager *gm = GetGmInstance();
        ret = gm->regCallback(TEST_APP_ID, &g_gmCallback);
        if (ret != HC_SUCCESS) {
            break;
        }
        ret = CreateDemoIdenticalAccountGroup(DEFAULT_OS_ACCOUNT, TEST_REQ_ID, TEST_APP_ID, TEST_USER_ID);
        if (ret != HC_SUCCESS) {
            break;
        }
        ret = gm->addMultiMembersToGroup(DEFAULT_OS_ACCOUNT, TEST_APP_ID, ADD_MULTI_PARAMS);
        if (ret != HC_SUCCESS) {
            break;
        }
        ret = gm->delMultiMembersFromGroup(DEFAULT_OS_ACCOUNT, TEST_APP_ID, DEL_MULTI_PARAMS);
    } while (0);
    DestroyDeviceAuthService();
    return ret;
}

static int32_t DevAuthTestCase015(void)
{
    DeleteDatabase();
    int32_t ret = InitDeviceAuthService();
    if (ret != HC_SUCCESS) {
        return ret;
    }
    do {
        const DeviceGroupManager *gm = GetGmInstance();
        ret = gm->regCallback(TEST_APP_ID, &g_gmCallback);
        if (ret != HC_SUCCESS) {
            break;
        }
        ret = CreateDemoIdenticalAccountGroup(DEFAULT_OS_ACCOUNT, TEST_REQ_ID, TEST_APP_ID, TEST_USER_ID);
        if (ret != HC_SUCCESS) {
            break;
        }
        ret = gm->addMultiMembersToGroup(DEFAULT_OS_ACCOUNT, TEST_APP_ID, ADD_MULTI_PARAMS);
        if (ret != HC_SUCCESS) {
            break;
        }
        ret = DeleteDemoGroup(DEFAULT_OS_ACCOUNT, TEST_REQ_ID, TEST_APP_ID, DISBAND_PARAMS2);
    } while (0);
    DestroyDeviceAuthService();
    return ret;
}

static int32_t DevAuthTestCase016(void)
{
    DeleteDatabase();
    int32_t ret = InitDeviceAuthService();
    if (ret != HC_SUCCESS) {
        return ret;
    }
    do {
        const DeviceGroupManager *gm = GetGmInstance();
        ret = gm->regCallback(TEST_APP_ID, &g_gmCallback);
        if (ret != HC_SUCCESS) {
            break;
        }
        ret = CreateDemoIdenticalAccountGroup(DEFAULT_OS_ACCOUNT, TEST_REQ_ID, TEST_APP_ID, TEST_USER_ID);
        if (ret != HC_SUCCESS) {
            break;
        }
        ret = CreateDemoGroup(DEFAULT_OS_ACCOUNT, TEST_REQ_ID, TEST_APP_ID, CREATE_PARAMS2);
    } while (0);
    DestroyDeviceAuthService();
    return ret;
}

static int32_t DevAuthTestCase018(void)
{
    DeleteDatabase();
    int32_t ret = InitDeviceAuthService();
    if (ret != HC_SUCCESS) {
        return ret;
    }
    do {
        const DeviceGroupManager *gm = GetGmInstance();
        ret = gm->regCallback(TEST_APP_ID, &g_gmCallback);
        if (ret != HC_SUCCESS) {
            break;
        }
        ret = CreateDemoIdenticalAccountGroup(DEFAULT_OS_ACCOUNT, TEST_REQ_ID, TEST_APP_ID, TEST_USER_ID);
        if (ret != HC_SUCCESS) {
            break;
        }
        ret = CreateDemoGroup(DEFAULT_OS_ACCOUNT, TEST_REQ_ID, TEST_APP_ID, CREATE_PARAMS2);
        if (ret != HC_SUCCESS) {
            break;
        }
        ret = DeleteDemoGroup(DEFAULT_OS_ACCOUNT, TEST_REQ_ID, TEST_APP_ID, DISBAND_PARAMS3);
    } while (0);
    DestroyDeviceAuthService();
    return ret;
}

static int32_t DevAuthTestCase019(void)
{
    DeleteDatabase();
    int32_t ret = InitDeviceAuthService();
    if (ret != HC_SUCCESS) {
        return ret;
    }
    do {
        const DeviceGroupManager *gm = GetGmInstance();
        ret = gm->regDataChangeListener(TEST_APP_ID, &g_listener);
    } while (0);
    DestroyDeviceAuthService();
    return ret;
}

static int32_t DevAuthTestCase020(void)
{
    DeleteDatabase();
    int32_t ret = InitDeviceAuthService();
    if (ret != HC_SUCCESS) {
        return ret;
    }
    do {
        const DeviceGroupManager *gm = GetGmInstance();
        ret = gm->regCallback(TEST_APP_ID, &g_gmCallback);
        if (ret != HC_SUCCESS) {
            break;
        }
        ret = gm->regDataChangeListener(TEST_APP_ID, &g_listener);
        if (ret != HC_SUCCESS) {
            break;
        }
        ret = CreateDemoIdenticalAccountGroup(DEFAULT_OS_ACCOUNT, TEST_REQ_ID, TEST_APP_ID, TEST_USER_ID);
        if (ret != HC_SUCCESS) {
            break;
        }
        ret = gm->addMultiMembersToGroup(DEFAULT_OS_ACCOUNT, TEST_APP_ID, ADD_MULTI_PARAMS);
        if (ret != HC_SUCCESS) {
            break;
        }
        ret = gm->delMultiMembersFromGroup(DEFAULT_OS_ACCOUNT, TEST_APP_ID, DEL_MULTI_PARAMS);
        if (ret != HC_SUCCESS) {
            break;
        }
        ret = DeleteDemoGroup(DEFAULT_OS_ACCOUNT, TEST_REQ_ID, TEST_APP_ID, DISBAND_PARAMS2);
    } while (0);
    DestroyDeviceAuthService();
    return ret;
}

static int32_t DevAuthTestCase021(void)
{
    DeleteDatabase();
    int32_t ret = InitDeviceAuthService();
    if (ret != HC_SUCCESS) {
        return ret;
    }
    do {
        const DeviceGroupManager *gm = GetGmInstance();
        ret = gm->regDataChangeListener(TEST_APP_ID, &g_listener);
        if (ret != HC_SUCCESS) {
            break;
        }
        ret = gm->unRegDataChangeListener(TEST_APP_ID);
    } while (0);
    DestroyDeviceAuthService();
    return ret;
}

static int32_t DevAuthTestCase022(void)
{
    DeleteDatabase();
    int32_t ret = InitDeviceAuthService();
    if (ret != HC_SUCCESS) {
        return ret;
    }
    do {
        const DeviceGroupManager *gm = GetGmInstance();
        ret = gm->regCallback(TEST_APP_ID, &g_gmCallback);
        if (ret != HC_SUCCESS) {
            break;
        }
        ret = CreateDemoGroup(DEFAULT_OS_ACCOUNT, TEST_REQ_ID, TEST_APP_ID, CREATE_PARAMS);
        if (ret != HC_SUCCESS) {
            break;
        }
        ret = gm->checkAccessToGroup(DEFAULT_OS_ACCOUNT, TEST_APP_ID, TEST_GROUP_ID);
    } while (0);
    DestroyDeviceAuthService();
    return ret;
}

static int32_t DevAuthTestCase023(void)
{
    DeleteDatabase();
    int32_t ret = InitDeviceAuthService();
    if (ret != HC_SUCCESS) {
        return ret;
    }
    do {
        const DeviceGroupManager *gm = GetGmInstance();
        ret = gm->regCallback(TEST_APP_ID, &g_gmCallback);
        if (ret != HC_SUCCESS) {
            break;
        }
        ret = CreateDemoGroup(DEFAULT_OS_ACCOUNT, TEST_REQ_ID, TEST_APP_ID, CREATE_PARAMS);
        if (ret != HC_SUCCESS) {
            break;
        }
        char* returnRes = nullptr;
        ret = gm->getGroupInfoById(DEFAULT_OS_ACCOUNT, TEST_APP_ID, TEST_GROUP_ID, &returnRes);
        if (ret != HC_SUCCESS || returnRes == nullptr) {
            ret = HC_ERROR;
        }
    } while (0);
    DestroyDeviceAuthService();
    return ret;
}

static int32_t DevAuthTestCase024(void)
{
    DeleteDatabase();
    int32_t ret = InitDeviceAuthService();
    if (ret != HC_SUCCESS) {
        return ret;
    }
    do {
        const DeviceGroupManager *gm = GetGmInstance();
        ret = gm->regCallback(TEST_APP_ID, &g_gmCallback);
        if (ret != HC_SUCCESS) {
            break;
        }
        ret = CreateDemoGroup(DEFAULT_OS_ACCOUNT, TEST_REQ_ID, TEST_APP_ID, CREATE_PARAMS);
        if (ret != HC_SUCCESS) {
            break;
        }
        uint32_t returnNum = 0;
        char* returnRes = nullptr;
        ret = gm->getGroupInfo(DEFAULT_OS_ACCOUNT, TEST_APP_ID, QUERY_PARAMS, &returnRes, &returnNum);
        if (ret != HC_SUCCESS || returnNum == 0 || returnRes == nullptr) {
            ret = HC_ERROR;
        }
    } while (0);
    DestroyDeviceAuthService();
    return ret;
}

static int32_t DevAuthTestCase025(void)
{
    DeleteDatabase();
    int32_t ret = InitDeviceAuthService();
    if (ret != HC_SUCCESS) {
        return ret;
    }
    do {
        const DeviceGroupManager *gm = GetGmInstance();
        ret = gm->regCallback(TEST_APP_ID, &g_gmCallback);
        if (ret != HC_SUCCESS) {
            break;
        }
        ret = CreateDemoGroup(DEFAULT_OS_ACCOUNT, TEST_REQ_ID, TEST_APP_ID, CREATE_PARAMS);
        if (ret != HC_SUCCESS) {
            break;
        }
        uint32_t returnNum = 0;
        char* returnRes = nullptr;
        ret = gm->getJoinedGroups(DEFAULT_OS_ACCOUNT, TEST_APP_ID, PEER_TO_PEER_GROUP, &returnRes, &returnNum);
        if (ret != HC_SUCCESS || returnNum == 0 || returnRes == nullptr) {
            ret = HC_ERROR;
        }
    } while (0);
    DestroyDeviceAuthService();
    return ret;
}

static int32_t DevAuthTestCase026(void)
{
    DeleteDatabase();
    int32_t ret = InitDeviceAuthService();
    if (ret != HC_SUCCESS) {
        return ret;
    }
    do {
        const DeviceGroupManager *gm = GetGmInstance();
        ret = gm->regCallback(TEST_APP_ID, &g_gmCallback);
        if (ret != HC_SUCCESS) {
            break;
        }
        ret = CreateDemoGroup(DEFAULT_OS_ACCOUNT, TEST_REQ_ID, TEST_APP_ID, CREATE_PARAMS);
        if (ret != HC_SUCCESS) {
            break;
        }
        uint32_t returnNum = 0;
        char* returnRes = nullptr;
        ret = gm->getRelatedGroups(DEFAULT_OS_ACCOUNT, TEST_APP_ID, TEST_AUTH_ID, &returnRes, &returnNum);
        if (ret != HC_SUCCESS || returnNum == 0 || returnRes == nullptr) {
            ret = HC_ERROR;
        }
    } while (0);
    DestroyDeviceAuthService();
    return ret;
}

static int32_t DevAuthTestCase027(void)
{
    DeleteDatabase();
    int32_t ret = InitDeviceAuthService();
    if (ret != HC_SUCCESS) {
        return ret;
    }
    do {
        const DeviceGroupManager *gm = GetGmInstance();
        ret = gm->regCallback(TEST_APP_ID, &g_gmCallback);
        if (ret != HC_SUCCESS) {
            break;
        }
        ret = CreateDemoGroup(DEFAULT_OS_ACCOUNT, TEST_REQ_ID, TEST_APP_ID, CREATE_PARAMS);
        if (ret != HC_SUCCESS) {
            break;
        }
        char* returnRes = nullptr;
        ret = gm->getDeviceInfoById(DEFAULT_OS_ACCOUNT, TEST_APP_ID, TEST_AUTH_ID, TEST_GROUP_ID, &returnRes);
        if (ret != HC_SUCCESS || returnRes == nullptr) {
            ret = HC_ERROR;
        }
    } while (0);
    DestroyDeviceAuthService();
    return ret;
}

static int32_t DevAuthTestCase028(void)
{
    DeleteDatabase();
    int32_t ret = InitDeviceAuthService();
    if (ret != HC_SUCCESS) {
        return ret;
    }
    do {
        const DeviceGroupManager *gm = GetGmInstance();
        ret = gm->regCallback(TEST_APP_ID, &g_gmCallback);
        if (ret != HC_SUCCESS) {
            break;
        }
        ret = CreateDemoGroup(DEFAULT_OS_ACCOUNT, TEST_REQ_ID, TEST_APP_ID, CREATE_PARAMS);
        if (ret != HC_SUCCESS) {
            break;
        }
        uint32_t returnNum = 0;
        char* returnRes = nullptr;
        ret = gm->getTrustedDevices(DEFAULT_OS_ACCOUNT, TEST_APP_ID, TEST_GROUP_ID, &returnRes, &returnNum);
        if (ret != HC_SUCCESS || returnNum == 0 || returnRes == nullptr) {
            ret = HC_ERROR;
        }
    } while (0);
    DestroyDeviceAuthService();
    return ret;
}

static int32_t DevAuthTestCase029(void)
{
    DeleteDatabase();
    int32_t ret = InitDeviceAuthService();
    if (ret != HC_SUCCESS) {
        return ret;
    }
    do {
        const DeviceGroupManager *gm = GetGmInstance();
        ret = gm->regCallback(TEST_APP_ID, &g_gmCallback);
        if (ret != HC_SUCCESS) {
            break;
        }
        ret = CreateDemoGroup(DEFAULT_OS_ACCOUNT, TEST_REQ_ID, TEST_APP_ID, CREATE_PARAMS);
        if (ret != HC_SUCCESS) {
            break;
        }
        if (!gm->isDeviceInGroup(DEFAULT_OS_ACCOUNT, TEST_APP_ID, TEST_GROUP_ID, TEST_AUTH_ID)) {
            ret = HC_ERROR;
        }
    } while (0);
    DestroyDeviceAuthService();
    return ret;
}

static int32_t DevAuthTestCase051(void)
{
    SetPakeV1Supported(false);
    SetSessionV2Supported(false);
    int32_t ret = DevAuthTestCase007();
    SetPakeV1Supported(true);
    SetSessionV2Supported(true);
    return ret;
}

static int32_t DevAuthTestCase052(void)
{
    SetIsoSupported(false);
    SetPakeV1Supported(false);
    SetSessionV2Supported(false);
    int32_t ret = DevAuthTestCase007();
    SetIsoSupported(true);
    SetPakeV1Supported(true);
    SetSessionV2Supported(true);
    return ret;
}

static int32_t DevAuthTestCase053(void)
{
    SetIsoSupported(false);
    SetPakeV1Supported(false);
    int32_t ret = DevAuthTestCase007();
    SetIsoSupported(true);
    SetPakeV1Supported(true);
    return ret;
}

bool FuzzDoDevAuthFuncFuzz(const uint8_t* data, size_t size)
{
    (void)data;
    (void)size;
    (void)DevAuthTestCase004();
    (void)DevAuthTestCase005();
    (void)DevAuthTestCase006();
    (void)DevAuthTestCase007();
    (void)DevAuthTestCase008();
    (void)DevAuthTestCase009();
    (void)DevAuthTestCase010();
    (void)DevAuthTestCase011();
    (void)DevAuthTestCase012();
    (void)DevAuthTestCase013();
    (void)DevAuthTestCase014();
    (void)DevAuthTestCase015();
    (void)DevAuthTestCase016();
    (void)DevAuthTestCase018();
    (void)DevAuthTestCase019();
    (void)DevAuthTestCase020();
    (void)DevAuthTestCase021();
    (void)DevAuthTestCase022();
    (void)DevAuthTestCase023();
    (void)DevAuthTestCase024();
    (void)DevAuthTestCase025();
    (void)DevAuthTestCase026();
    (void)DevAuthTestCase027();
    (void)DevAuthTestCase028();
    (void)DevAuthTestCase029();
    (void)DevAuthTestCase051();
    (void)DevAuthTestCase052();
    (void)DevAuthTestCase053();
    return true;
}
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    OHOS::FuzzDoDevAuthFuncFuzz(data, size);
    return 0;
}

