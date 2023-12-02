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
#include "crypto_hash_to_point.h"
#include "hal_error.h"
#include "hc_log.h"
#include "hks_api.h"
#include "hks_type.h"

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
    struct HksBlob hashBlob = { hash->length, hash->val };
    struct HksBlob pointBlob = { outEcPoint->length, outEcPoint->val };

    int32_t res = OpensslHashToPoint(&hashBlob, &pointBlob);
    if (res != HAL_SUCCESS || pointBlob.size != SHA256_LEN) {
        LOGE("HashToPoint for x25519 failed, res: %d", res);
        return HAL_FAILED;
    }

    return HAL_SUCCESS;
}