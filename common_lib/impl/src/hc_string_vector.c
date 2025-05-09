/*
 * Copyright (C) 2022 Huawei Device Co., Ltd.
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

#include "hc_string_vector.h"

IMPLEMENT_HC_VECTOR(StringVector, HcString, 1)

StringVector CreateStrVector(void)
{
    return CreateStringVector();
}

void DestroyStrVector(StringVector *vec)
{
    if (vec == NULL) {
        return;
    }
    uint32_t index;
    HcString *strItemPtr = NULL;
    FOR_EACH_HC_VECTOR(*vec, index, strItemPtr) {
        DeleteString(strItemPtr);
    }
    DESTROY_HC_VECTOR(StringVector, vec);
}