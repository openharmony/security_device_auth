/*
 * Copyright (C) 2021-2023 Huawei Device Co., Ltd.
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

#include "hc_dev_info.h"
#include "hal_error.h"
#include "hc_log.h"
#include "parameter.h"
#include "securec.h"

#ifdef __cplusplus
extern "C" {
#endif

int32_t HcGetUdid(uint8_t *udid, int32_t udidLen)
{
    if (udid == NULL || udidLen < INPUT_UDID_LEN || udidLen > MAX_INPUT_UDID_LEN) {
        return HAL_ERR_INVALID_PARAM;
    }
    int32_t res = GetDevUdid((char *)udid, udidLen);
    if (res != 0) {
        LOGE("[UDID]: GetDevUdid fail. [Res]: %" LOG_PUB "d", res);
        return HAL_FAILED;
    }
    return HAL_SUCCESS;
}

const char *GetStoragePath(void)
{
#ifndef LITE_DEVICE
    const char *storageFile = "/data/service/el1/public/deviceauth/hcgroup.dat";
#else
    const char *storageFile = "/storage/deviceauth/hcgroup.dat";
#endif
    return storageFile;
}

const char *GetStorageDirPathCe(void)
{
    return "/data/service/el2";
}

const char *GetStorageDirPath(void)
{
#ifndef LITE_DEVICE
    const char *storageFile = "/data/service/el1/public/deviceauth";
#else
    const char *storageFile = "/storage/deviceauth";
#endif
    return storageFile;
}

const char *GetAccountStoragePath(void)
{
#ifndef LITE_DEVICE
    const char *storageFile = "/data/service/el1/public/deviceauth/account";
#else
    const char *storageFile = "/storage/deviceauth/account";
#endif
    return storageFile;
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
