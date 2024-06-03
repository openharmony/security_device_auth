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

#include "standardexchangetask_fuzzer.h"
#include "alg_loader.h"
#include "device_auth_defines.h"
#include "securec.h"
#include "identity_defines.h"
#include "common_standard_bind_exchange.h"

namespace OHOS {
static const std::string TEST_APP_ID = "TestAppId";
static const std::string TEST_GROUP_ID = "TestGroupId";
static const std::string TEST_AUTH_ID = "TestAuthId";
static const std::string TEST_SALT = "2f7562744654535564586e665467546b";

static const int AUTH_ID_LENGTH = 10;
static const int PUB_KEY_LENGTH = 128;
static const int NONCE_LENGTH = 64;
static const int INVALID_CIPHER_LENGTH = 16;
static const int VALID_CIPHER_LENGTH = 32;

static int32_t StandardExchangeTaskTest001()
{
    PakeParams pakeParams;
    pakeParams.packageName = const_cast<char *>(TEST_APP_ID.c_str());
    pakeParams.serviceType = const_cast<char *>(TEST_GROUP_ID.c_str());
    int32_t ret = ClientConfirmStandardBindExchange(&pakeParams, nullptr);
    if (ret != HC_SUCCESS) {
        return HC_FALSE;
    }
    return HC_SUCCESS;
}

static int32_t StandardExchangeTaskTest002()
{
    int32_t ret = InitStandardBindExchangeParams(nullptr);
    if (ret != HC_ERR_INVALID_PARAMS) {
        return HC_FALSE;
    }

    DestroyStandardBindExchangeParams(nullptr);

    StandardBindExchangeParams params;
    DestroyStandardBindExchangeParams(&params);
    return HC_SUCCESS;
}

static int32_t StandardExchangeTaskTest003()
{
    PakeParams pakeParams;
    pakeParams.userType = KEY_ALIAS_PSK;
    pakeParams.packageName = const_cast<char *>(TEST_APP_ID.c_str());
    pakeParams.serviceType = const_cast<char *>(TEST_GROUP_ID.c_str());
    uint8_t authId[AUTH_ID_LENGTH] = { 0 };
    (void)memcpy_s(authId, AUTH_ID_LENGTH, TEST_AUTH_ID.c_str(), AUTH_ID_LENGTH);
    pakeParams.baseParams.idSelf.val = authId;
    pakeParams.baseParams.idSelf.length = AUTH_ID_LENGTH;
    pakeParams.baseParams.loader = GetLoaderInstance();

    // pubKeySelf is null, exportPubKey failed
    int32_t ret = ClientRequestStandardBindExchange(&pakeParams, nullptr);
    if (ret == HC_SUCCESS) {
        return HC_FALSE;
    }

    uint8_t publicKey[PUB_KEY_LENGTH] = { 0 };
    StandardBindExchangeParams exchangeParams;
    exchangeParams.pubKeySelf.val = publicKey;
    exchangeParams.pubKeySelf.length = PUB_KEY_LENGTH;

    ret = ClientRequestStandardBindExchange(&pakeParams, &exchangeParams);
    if (ret == HC_SUCCESS) {
        return HC_FALSE;
    }

    uint32_t challengeLen = HcStrlen(TEST_SALT.c_str());
    uint8_t *challengeVal = static_cast<uint8_t *>(HcMalloc(challengeLen, 0));
    (void)memcpy_s(challengeVal, challengeLen, TEST_SALT.c_str(), challengeLen);

    pakeParams.baseParams.challengeSelf.val = challengeVal;
    pakeParams.baseParams.challengeSelf.length = challengeLen;

    ret = ClientRequestStandardBindExchange(&pakeParams, &exchangeParams);
    if (ret == HC_SUCCESS) {
        return HC_FALSE;
    }
    
    pakeParams.baseParams.challengePeer.val = challengeVal;
    pakeParams.baseParams.challengePeer.length = challengeLen;

    ret = ClientRequestStandardBindExchange(&pakeParams, &exchangeParams);
    if (ret == HC_SUCCESS) {
        return HC_FALSE;
    }

    uint8_t nonceVal[NONCE_LENGTH] = { 0 };
    exchangeParams.nonce.val = nonceVal;
    exchangeParams.nonce.length = NONCE_LENGTH;

    // aesGcmEncrypt failed, no sessionkey
    ret = ClientRequestStandardBindExchange(&pakeParams, &exchangeParams);
    if (ret == HC_SUCCESS) {
        return HC_FALSE;
    }
    HcFree(challengeVal);
    return HC_TRUE;
}


static int32_t StandardExchangeTaskTest004()
{
    PakeParams pakeParams;
    pakeParams.userType = KEY_ALIAS_PSK;
    pakeParams.packageName = const_cast<char *>(TEST_APP_ID.c_str());
    pakeParams.serviceType = const_cast<char *>(TEST_GROUP_ID.c_str());
    uint8_t authId[AUTH_ID_LENGTH] = { 0 };
    (void)memcpy_s(authId, AUTH_ID_LENGTH, TEST_AUTH_ID.c_str(), AUTH_ID_LENGTH);
    pakeParams.baseParams.idSelf.val = authId;
    pakeParams.baseParams.idSelf.length = AUTH_ID_LENGTH;
    pakeParams.baseParams.loader = GetLoaderInstance();

    StandardBindExchangeParams exchangeParams;
    exchangeParams.exInfoCipher.length = INVALID_CIPHER_LENGTH;

    int32_t ret = ServerResponseStandardBindExchange(&pakeParams, &exchangeParams);
    if (ret != HC_ERR_ALLOC_MEMORY) {
        return HC_FALSE;
    }

    exchangeParams.exInfoCipher.length = VALID_CIPHER_LENGTH;
    ret = ServerResponseStandardBindExchange(&pakeParams, &exchangeParams);
    if (ret == HC_SUCCESS) {
        return HC_FALSE;
    }
    return HC_TRUE;
}

bool FuzzDoRegCallback(const uint8_t* data, size_t size)
{
    (void)data;
    (void)size;
    (void)StandardExchangeTaskTest001();
    (void)StandardExchangeTaskTest002();
    (void)StandardExchangeTaskTest003();
    (void)StandardExchangeTaskTest004();
    return true;
}
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    OHOS::FuzzDoRegCallback(data, size);
    return 0;
}

