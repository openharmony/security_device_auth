/*
 * Copyright (C) 2024 Huawei Device Co., Ltd.
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
#include "device_auth_defines.h"
#include "device_auth.h"
#include "string_util.h"
#include "cert_operation.h"
#include "identity_manager.h"
#include "identity_common.h"

using namespace std;
using namespace testing::ext;

namespace {
static const std::string TEST_GROUP_ID = "TestGroupId";
static const std::string TEST_DEVICE_ID = "TestDeviceId";
static const std::string TEST_REQUEST_JSON_STR = "TestRequestJsonStr";
static const std::string TEST_PIN_CODE = "11111";
static const int TEST_SIGNATURE_LEN = 32;
static const int TEST_OS_ACCOUNT_ID = 100;

extern "C" int32_t GenerateCertInfo(const Uint8Buff *pkInfoStr, const Uint8Buff *pkInfoSignature, CertInfo *certInfo);

class IdentityManagerTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void IdentityManagerTest::SetUpTestCase() {}
void IdentityManagerTest::TearDownTestCase() {}

void IdentityManagerTest::SetUp()
{
    int32_t ret = InitDeviceAuthService();
    ASSERT_EQ(ret, HC_SUCCESS);
}

void IdentityManagerTest::TearDown()
{
    DestroyDeviceAuthService();
}

HWTEST_F(IdentityManagerTest, IdentityManagerTest001, TestSize.Level0)
{
    int32_t ret = AddCertInfoToJson(nullptr, nullptr);
    EXPECT_NE(ret, HC_SUCCESS);
    CertInfo info = { { nullptr, 0 }, { nullptr, 0 }, P256 };
    ret = AddCertInfoToJson(&info, nullptr);
    EXPECT_NE(ret, HC_SUCCESS);
    CJson *pkInfoJson = CreateJson();
    ASSERT_NE(pkInfoJson, nullptr);
    char *pkInfoStr = PackJsonToString(pkInfoJson);
    FreeJson(pkInfoJson);
    ASSERT_NE(pkInfoStr, nullptr);
    info.pkInfoStr.val = (uint8_t *)pkInfoStr;
    info.pkInfoStr.length = strlen(pkInfoStr) + 1;
    info.signAlg = P256;
    CJson *out = CreateJson();
    ASSERT_NE(out, nullptr);
    ret = AddCertInfoToJson(&info, out);
    EXPECT_NE(ret, HC_SUCCESS);
    uint8_t testSignature[TEST_SIGNATURE_LEN] = { 0 };
    info.pkInfoSignature.val = testSignature;
    info.pkInfoSignature.length = TEST_SIGNATURE_LEN;
    ret = AddCertInfoToJson(&info, out);
    EXPECT_EQ(ret, HC_SUCCESS);
    FreeJsonString(pkInfoStr);
    FreeJson(out);
}

HWTEST_F(IdentityManagerTest, IdentityManagerTest002, TestSize.Level0)
{
    Uint8Buff pkInfoBuf = { nullptr, 0 };
    CertInfo certInfo = { { nullptr, 0 }, { nullptr, 0 }, P256 };
    int32_t ret = GenerateCertInfo(&pkInfoBuf, nullptr, &certInfo);
    EXPECT_NE(ret, HC_SUCCESS);
    CJson *pkInfoJson = CreateJson();
    ASSERT_NE(pkInfoJson, nullptr);
    char *pkInfoStr = PackJsonToString(pkInfoJson);
    FreeJson(pkInfoJson);
    pkInfoBuf.val = (uint8_t *)pkInfoStr;
    pkInfoBuf.length = HcStrlen(pkInfoStr) + 1;
    Uint8Buff pkInfoSigBuf = { nullptr, 0 };
    ret = GenerateCertInfo(&pkInfoBuf, &pkInfoSigBuf, &certInfo);
    EXPECT_NE(ret, HC_SUCCESS);
    FreeJsonString(pkInfoStr);
    HcFree(certInfo.pkInfoStr.val);
}

HWTEST_F(IdentityManagerTest, IdentityManagerTest003, TestSize.Level0)
{
    IdentityInfo *info = CreateIdentityInfo();
    ASSERT_NE(info, nullptr);
    int32_t ret = GetAccountRelatedCredInfo(TEST_OS_ACCOUNT_ID, TEST_GROUP_ID.c_str(),
        TEST_DEVICE_ID.c_str(), true, info);
    EXPECT_NE(ret, HC_SUCCESS);
    ret = GetAccountRelatedCredInfo(TEST_OS_ACCOUNT_ID, nullptr, TEST_DEVICE_ID.c_str(), true, info);
    EXPECT_NE(ret, HC_SUCCESS);
    ret = GetAccountRelatedCredInfo(TEST_OS_ACCOUNT_ID, TEST_GROUP_ID.c_str(), nullptr, true, info);
    DestroyIdentityInfo(info);
    EXPECT_NE(ret, HC_SUCCESS);
    ret = GetAccountRelatedCredInfo(TEST_OS_ACCOUNT_ID, TEST_GROUP_ID.c_str(), TEST_DEVICE_ID.c_str(), true, nullptr);
    EXPECT_NE(ret, HC_SUCCESS);
    ret = GetAccountAsymSharedSecret(TEST_OS_ACCOUNT_ID, nullptr, nullptr);
    EXPECT_NE(ret, HC_SUCCESS);
    CertInfo peerCertInfo = { { nullptr, 0 }, { nullptr, 0 }, P256 };
    ret = GetAccountAsymSharedSecret(TEST_OS_ACCOUNT_ID, &peerCertInfo, nullptr);
    EXPECT_NE(ret, HC_SUCCESS);
    ret = GetAccountSymSharedSecret(nullptr, nullptr, nullptr);
    EXPECT_NE(ret, HC_SUCCESS);
    CJson *in = CreateJson();
    ASSERT_NE(in, nullptr);
    ret = GetAccountSymSharedSecret(in, nullptr, nullptr);
    EXPECT_NE(ret, HC_SUCCESS);
    CJson *urlJson = CreateJson();
    ASSERT_NE(urlJson, nullptr);
    ret = GetAccountSymSharedSecret(in, urlJson, nullptr);
    EXPECT_NE(ret, HC_SUCCESS);
    FreeJson(in);
    FreeJson(urlJson);
    ret = GetAccountAsymCredInfo(TEST_OS_ACCOUNT_ID, nullptr, nullptr);
    EXPECT_NE(ret, HC_SUCCESS);
    CertInfo certInfo = { { nullptr, 0 }, { nullptr, 0 }, P256 };
    ret = GetAccountAsymCredInfo(TEST_OS_ACCOUNT_ID, &certInfo, nullptr);
    EXPECT_NE(ret, HC_SUCCESS);
    ret = GetAccountSymCredInfoByPeerUrl(nullptr, nullptr, nullptr);
    EXPECT_NE(ret, HC_SUCCESS);
    in = CreateJson();
    ASSERT_NE(in, nullptr);
    ret = GetAccountSymCredInfoByPeerUrl(in, nullptr, nullptr);
    EXPECT_NE(ret, HC_SUCCESS);
    urlJson = CreateJson();
    ASSERT_NE(urlJson, nullptr);
    ret = GetAccountSymCredInfoByPeerUrl(in, urlJson, nullptr);
    EXPECT_NE(ret, HC_SUCCESS);
    FreeJson(in);
    FreeJson(urlJson);
}

HWTEST_F(IdentityManagerTest, IdentityManagerTest004, TestSize.Level0)
{
    const CredentialOperator *credOperator = GetCredentialOperator();
    EXPECT_NE(credOperator, nullptr);
    int32_t ret = credOperator->queryCredential(TEST_REQUEST_JSON_STR.c_str(), nullptr);
    EXPECT_NE(ret, HC_SUCCESS);
}

HWTEST_F(IdentityManagerTest, IdentityManagerTest005, TestSize.Level0)
{
    Uint8Buff srcPsk = { nullptr, 0 };
    Uint8Buff sharedSecret = { nullptr, 0 };
    int32_t ret = ConvertPsk(&srcPsk, &sharedSecret);
    EXPECT_NE(ret, HC_SUCCESS);
}

HWTEST_F(IdentityManagerTest, IdentityManagerTest006, TestSize.Level0)
{
    const AuthIdentity *identity = GetGroupAuthIdentity();
    EXPECT_NE(identity, nullptr);
    int32_t ret = identity->getCredInfoByPeerUrl(nullptr, nullptr, nullptr);
    EXPECT_NE(ret, HC_SUCCESS);
    CJson *in = CreateJson();
    ASSERT_NE(in, nullptr);
    ret = identity->getCredInfoByPeerUrl(in, nullptr, nullptr);
    EXPECT_NE(ret, HC_SUCCESS);
    Uint8Buff presharedUrl = { nullptr, 0 };
    ret = identity->getCredInfoByPeerUrl(in, &presharedUrl, nullptr);
    EXPECT_NE(ret, HC_SUCCESS);
    ret = identity->getSharedSecretByUrl(nullptr, nullptr, ALG_EC_SPEKE, nullptr);
    EXPECT_NE(ret, HC_SUCCESS);
    ret = identity->getSharedSecretByUrl(in, nullptr, ALG_EC_SPEKE, nullptr);
    EXPECT_NE(ret, HC_SUCCESS);
    ret = identity->getSharedSecretByUrl(in, &presharedUrl, ALG_EC_SPEKE, nullptr);
    EXPECT_NE(ret, HC_SUCCESS);
    ret = identity->getCredInfoByPeerCert(nullptr, nullptr, nullptr);
    EXPECT_NE(ret, HC_SUCCESS);
    ret = identity->getCredInfoByPeerCert(in, nullptr, nullptr);
    EXPECT_NE(ret, HC_SUCCESS);
    CertInfo certInfo = { { nullptr, 0 }, { nullptr, 0 }, P256 };
    ret = identity->getCredInfoByPeerCert(in, &certInfo, nullptr);
    EXPECT_NE(ret, HC_SUCCESS);
    ret = identity->getSharedSecretByPeerCert(nullptr, nullptr, ALG_EC_SPEKE, nullptr);
    EXPECT_NE(ret, HC_SUCCESS);
    ret = identity->getSharedSecretByPeerCert(in, nullptr, ALG_EC_SPEKE, nullptr);
    EXPECT_NE(ret, HC_SUCCESS);
    CertInfo peerCertInfo = { { nullptr, 0 }, { nullptr, 0 }, P256 };
    ret = identity->getSharedSecretByPeerCert(in, &peerCertInfo, ALG_EC_SPEKE, nullptr);
    EXPECT_NE(ret, HC_SUCCESS);
    FreeJson(in);
}

HWTEST_F(IdentityManagerTest, IdentityManagerTest007, TestSize.Level0)
{
    const AuthIdentity *identity = GetP2pAuthIdentity();
    EXPECT_NE(identity, nullptr);
    CJson *in = CreateJson();
    ASSERT_NE(in, nullptr);
    int32_t ret = identity->getCredInfosByPeerIdentity(in, nullptr);
    EXPECT_NE(ret, HC_SUCCESS);
    (void)AddIntToJson(in, FIELD_OS_ACCOUNT_ID, TEST_OS_ACCOUNT_ID);
    (void)AddStringToJson(in, FIELD_PEER_CONN_DEVICE_ID, TEST_DEVICE_ID.c_str());
    ret = identity->getCredInfosByPeerIdentity(in, nullptr);
    EXPECT_NE(ret, HC_SUCCESS);
    (void)AddIntToJson(in, FIELD_ACQURIED_TYPE, ACQUIRE_TYPE_INVALID);
    ret = identity->getCredInfosByPeerIdentity(in, nullptr);
    EXPECT_NE(ret, HC_SUCCESS);
    FreeJson(in);
    ret = identity->getCredInfoByPeerUrl(nullptr, nullptr, nullptr);
    EXPECT_NE(ret, HC_SUCCESS);
    in = CreateJson();
    ASSERT_NE(in, nullptr);
    ret = identity->getCredInfoByPeerUrl(in, nullptr, nullptr);
    EXPECT_NE(ret, HC_SUCCESS);
    Uint8Buff presharedUrl = { nullptr, 0 };
    ret = identity->getCredInfoByPeerUrl(in, &presharedUrl, nullptr);
    EXPECT_NE(ret, HC_SUCCESS);
    IdentityInfo *info = nullptr;
    ret = identity->getCredInfoByPeerUrl(in, &presharedUrl, &info);
    EXPECT_NE(ret, HC_SUCCESS);
    (void)AddIntToJson(in, FIELD_OS_ACCOUNT_ID, TEST_OS_ACCOUNT_ID);
    Uint8Buff sharedSecret = { nullptr, 0 };
    ret = identity->getSharedSecretByUrl(in, &presharedUrl, ALG_EC_SPEKE, &sharedSecret);
    EXPECT_NE(ret, HC_SUCCESS);
    ret = identity->getSharedSecretByUrl(nullptr, nullptr, ALG_EC_SPEKE, nullptr);
    EXPECT_NE(ret, HC_SUCCESS);
    ret = identity->getSharedSecretByUrl(in, nullptr, ALG_EC_SPEKE, nullptr);
    EXPECT_NE(ret, HC_SUCCESS);
    ret = identity->getSharedSecretByUrl(in, &presharedUrl, ALG_EC_SPEKE, nullptr);
    EXPECT_NE(ret, HC_SUCCESS);
    FreeJson(in);
}

HWTEST_F(IdentityManagerTest, IdentityManagerTest008, TestSize.Level0)
{
    const AuthIdentity *identity = GetPinAuthIdentity();
    EXPECT_NE(identity, nullptr);
    int32_t ret = identity->getCredInfoByPeerUrl(nullptr, nullptr, nullptr);
    EXPECT_NE(ret, HC_SUCCESS);
    CJson *in = CreateJson();
    ASSERT_NE(in, nullptr);
    ret = identity->getCredInfoByPeerUrl(in, nullptr, nullptr);
    EXPECT_NE(ret, HC_SUCCESS);
    Uint8Buff presharedUrl = { nullptr, 0 };
    ret = identity->getCredInfoByPeerUrl(in, &presharedUrl, nullptr);
    EXPECT_NE(ret, HC_SUCCESS);
    IdentityInfo *info = nullptr;
    CJson *urlJson = CreateJson();
    ASSERT_NE(urlJson, nullptr);
    char *urlStr = PackJsonToString(urlJson);
    FreeJson(urlJson);
    ASSERT_NE(urlStr, nullptr);
    presharedUrl.val = (uint8_t *)urlStr;
    presharedUrl.length = HcStrlen(urlStr) + 1;
    ret = identity->getCredInfoByPeerUrl(in, &presharedUrl, &info);
    EXPECT_NE(ret, HC_SUCCESS);
    ret = identity->getSharedSecretByUrl(nullptr, nullptr, ALG_EC_SPEKE, nullptr);
    EXPECT_NE(ret, HC_SUCCESS);
    ret = identity->getSharedSecretByUrl(in, nullptr, ALG_EC_SPEKE, nullptr);
    EXPECT_NE(ret, HC_SUCCESS);
    ret = identity->getSharedSecretByUrl(in, &presharedUrl, ALG_EC_SPEKE, nullptr);
    EXPECT_NE(ret, HC_SUCCESS);
    (void)AddStringToJson(in, FIELD_PIN_CODE, TEST_PIN_CODE.c_str());
    ret = identity->getSharedSecretByUrl(in, &presharedUrl, ALG_ISO, nullptr);
    EXPECT_NE(ret, HC_SUCCESS);
    ret = identity->getSharedSecretByUrl(in, &presharedUrl, ALG_EC_SPEKE, nullptr);
    EXPECT_NE(ret, HC_SUCCESS);
    FreeJson(in);
    FreeJsonString(urlStr);
}
}