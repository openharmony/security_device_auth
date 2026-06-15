/*
 * Copyright (C) 2026 Huawei Device Co., Ltd.
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

#include <stdint.h>
#include "hc_string_mock.h"

int __real_ParcelWriteInt8(void *parcel, char value);

int __wrap_ParcelWriteInt8(void *parcel, char value)
{
    if (GetParcelWriteInt8Mock()) {
        return 0;
    }
    return __real_ParcelWriteInt8(parcel, value);
}

uint32_t __real_GetParcelDataSize(void *parcel);

uint32_t __wrap_GetParcelDataSize(void *parcel)
{
    if (IsGetParcelDataSizeMockEnabled()) {
        return GetGetParcelDataSizeMock();
    }
    return __real_GetParcelDataSize(parcel);
}
