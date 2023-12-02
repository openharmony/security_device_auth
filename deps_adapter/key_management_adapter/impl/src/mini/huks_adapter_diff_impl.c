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

#include "huks_adapter_diff_impl.h"
#include "hal_error.h"
#include "hc_dev_info.h"
#include "hc_file.h"
#include "hc_log.h"
#include "hks_api.h"
#include "hks_type.h"
#include "mbedtls_ec_adapter.h"

int32_t InitHks(void)
{
    LOGI("[HUKS]: HksInitialize enter.");
    int32_t res = HksInitialize();
    LOGI("[HUKS]: HksInitialize quit. [Res]: %d", res);
    if (res == HKS_SUCCESS) {
        return HAL_SUCCESS;
    }

    if ((res != HKS_ERROR_INVALID_KEY_FILE) && (res != HKS_ERROR_CRYPTO_ENGINE_ERROR) &&
        (res != HKS_ERROR_UPDATE_ROOT_KEY_MATERIAL_FAIL)) {
        LOGE("[HUKS]: HksInitialize fail. [Res]: %d", res);
        return HAL_ERR_INIT_FAILED;
    }

    LOGI("Start to delete local database file!");
    HcFileRemove(GetStoragePath());
    LOGI("Delete local database file successfully!");
    LOGI("[HUKS]: HksRefreshKeyInfo enter.");
    res = HksRefreshKeyInfo();
    LOGI("[HUKS]: HksRefreshKeyInfo quit. [Res]: %d", res);
    if (res != HKS_SUCCESS) {
        LOGE("[HUKS]: HksRefreshKeyInfo failed, res: %d", res);
        return HAL_ERR_INIT_FAILED;
    }
    LOGI("[HUKS]: HksInitialize enter.");
    res = HksInitialize();
    LOGI("[HUKS]: HksInitialize quit. [Res]: %d", res);
    if (res != HKS_SUCCESS) {
        LOGE("[HUKS]: HksInitialize fail. [Res]: %d", res);
        return HAL_ERR_INIT_FAILED;
    }

    return HAL_SUCCESS;
}

int32_t HashToPointX25519(const Uint8Buff *hash, Uint8Buff *outEcPoint)
{
    int32_t res = MbedtlsHashToPoint25519(hash, outEcPoint);
    if (res != 0) {
        LOGE("hashToPoint for x25519 failed, res: %d", res);
        return HAL_FAILED;
    }

    return HAL_SUCCESS;
}