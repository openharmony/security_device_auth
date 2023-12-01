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
#include "hc_log.h"
#include "hks_api.h"
#include "hks_type.h"
#include "mbedtls_ec_adapter.h"

int32_t InitHks(void)
{
    LOGI("[HUKS]: HksInitialize enter.");
    int32_t res = HksInitialize();
    LOGI("[HUKS]: HksInitialize quit. [Res]: %d", res);
    if (res != HKS_SUCCESS) {
        LOGE("[HUKS]: HksInitialize fail. [Res]: %d", res);
    }
    return res;
}

int32_t HashToPointX25519(const Uint8Buff *hash, Uint8Buff *outEcPoint)
{
    int32_t res = MbedtlsHashToPoint25519(hash, outEcPoint);
    if (res != 0) {
        LOGE("Hks hashToPoint failed, res: %d", res);
        return HAL_FAILED;
    }

    return HAL_SUCCESS;
}