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

#include "identity_common.h"
#include "securec.h"

IdentityInfo *CreateIdentityInfo(void)
{
    return NULL;
}

void DestroyIdentityInfo(IdentityInfo *info)
{
    (void)info;
}

IdentityInfoVec CreateIdentityInfoVec(void)
{
    IdentityInfoVec v;
    (void)memset_s(&v, sizeof(IdentityInfoVec), 0, sizeof(IdentityInfoVec));
    return v;
}

void ClearIdentityInfoVec(IdentityInfoVec *vec)
{
    (void)vec;
}

ProtocolEntityVec CreateProtocolEntityVec(void)
{
    ProtocolEntityVec v;
    (void)memset_s(&v, sizeof(ProtocolEntityVec), 0, sizeof(ProtocolEntityVec));
    return v;
}

void ClearProtocolEntityVec(ProtocolEntityVec *vec)
{
    (void)vec;
}