/*
 * Copyright (C) 2023 Huawei Device Co., Ltd.
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

#include "hc_dev_info_mock.h"
#include "hal_error.h"
#include "hc_log.h"
#include "securec.h"

#define MOCK_STORAGE_FILE "/data/service/el1/public/deviceauthMock/hcgroup.dat"
#define MOCK_STORAGE_DIR "/data/service/el1/public/deviceauthMock"
#define MOCK_STORAGE_DIR_CE "/data/service/el1/public/deviceauthMock/ce"
#define MOCK_ACCOUNT_STORAGE_DIR "/data/service/el1/public/deviceauthMock/account"

#ifdef __cplusplus
extern "C" {
#endif

static bool g_isClient = true;
static char *g_clientDevUdid = "5420459D93FE773F9945FD64277FBA2CAB8FB996DDC1D0B97676FBB1242B3930";
static char *g_serverDevUdid = "52E2706717D5C39D736E134CC1E3BE1BAA2AA52DB7C76A37C749558BD2E6492C";

static bool g_isAccountStorageTest = false;

void SetDeviceStatus(bool isClient)
{
    g_isClient = isClient;
}

void SetAccountStorageTest(bool isAccountStorageTest)
{
    g_isAccountStorageTest = isAccountStorageTest;
}

int32_t HcGetUdid(uint8_t *udid, int32_t udidLen)
{
    if (udid == NULL || udidLen < INPUT_UDID_LEN || udidLen > MAX_INPUT_UDID_LEN) {
        return HAL_ERR_INVALID_PARAM;
    }
    char *devUdid;
    if (g_isClient) {
        devUdid = g_clientDevUdid;
        LOGI("Use mock client device udid.");
    } else {
        devUdid = g_serverDevUdid;
        LOGI("Use mock server device udid.");
    }
    if (memcpy_s(udid, udidLen, devUdid, INPUT_UDID_LEN) != EOK) {
        LOGE("Failed to copy udid!");
        return HAL_FAILED;
    }
    return HAL_SUCCESS;
}

const char *GetStoragePath(void)
{
    return MOCK_STORAGE_FILE;
}

const char *GetStorageDirPathCe(void)
{
    return MOCK_STORAGE_DIR_CE;
}

const char *GetStorageDirPath(void)
{
    return MOCK_STORAGE_DIR;
}

const char *GetAccountStoragePath(void)
{
    if (g_isAccountStorageTest) {
        return NULL;
    }
    return MOCK_ACCOUNT_STORAGE_DIR;
}

const char *GetPseudonymStoragePath(void)
{
#ifndef LITE_DEVICE
    const char *storageFile = "/data/service/el1/public/deviceauth/pseudonym";
#else
    const char *storageFile = "/storage/deviceauth/pseudonym";
#endif
    return storageFile;
}

#ifdef __cplusplus
}
#endif
