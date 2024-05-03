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

#include "dev_session_v2.h"

#include "device_auth_defines.h"
#include "hc_log.h"
#include "hc_vector.h"

IMPLEMENT_HC_VECTOR(EventList, SessionEvent, 3)
IMPLEMENT_HC_VECTOR(AuthSubSessionList, AuthSubSession *, 1)

int32_t SessionSwitchState(SessionImpl *impl, SessionEvent *event, CJson *sessionMsg)
{
    (void)impl;
    (void)event;
    (void)sessionMsg;
    LOGE("not support.");
    return HC_ERR_NOT_SUPPORT;
}

#ifndef  DEV_AUTH_FUNC_TEST
bool IsSupportSessionV2(void)
{
    return false;
}
#endif
