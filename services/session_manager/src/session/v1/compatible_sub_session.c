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

#include "compatible_sub_session.h"

#include "compatible_bind_sub_session.h"
#include "compatible_auth_sub_session.h"
#include "hc_log.h"

int32_t CreateCompatibleSubSession(SubSessionTypeValue sessionType, CJson *jsonParams,
    const DeviceAuthCallback *callback, CompatibleBaseSubSession **session)

{
    if (jsonParams == NULL || callback == NULL || session == NULL) {
        LOGE("Invalid input params!");
        return HC_ERR_INVALID_PARAMS;
    }
    switch (sessionType) {
        case TYPE_CLIENT_BIND_SUB_SESSION:
            return CreateClientBindSubSession(jsonParams, callback, session);
        case TYPE_SERVER_BIND_SUB_SESSION:
            return CreateServerBindSubSession(jsonParams, callback, session);
        case TYPE_CLIENT_AUTH_SUB_SESSION:
            return CreateClientAuthSubSession(jsonParams, callback, session);
        case TYPE_SERVER_AUTH_SUB_SESSION:
            return CreateServerAuthSubSession(jsonParams, callback, session);
        default:
            LOGE("Invalid session type!");
            return HC_ERR_INVALID_PARAMS;
    }
}

int32_t ProcessCompatibleSubSession(CompatibleBaseSubSession *session, CJson *in, CJson **out, int32_t *status)
{
    if (session == NULL || in == NULL || out == NULL || status == NULL) {
        LOGE("Invalid input params!");
        return HC_ERR_INVALID_PARAMS;
    }
    switch (session->type) {
        case TYPE_CLIENT_BIND_SUB_SESSION:
            return ProcessClientBindSubSession(session, in, out, status);
        case TYPE_SERVER_BIND_SUB_SESSION:
            return ProcessServerBindSubSession(session, in, status);
        case TYPE_CLIENT_AUTH_SUB_SESSION:
            return ProcessClientAuthSubSession(session, in, out, status);
        case TYPE_SERVER_AUTH_SUB_SESSION:
            return ProcessServerAuthSubSession(session, in, status);
        default:
            LOGE("Invalid session type!");
            return HC_ERR_INVALID_PARAMS;
    }
}

void DestroyCompatibleSubSession(CompatibleBaseSubSession *session)
{
    if (session == NULL) {
        LOGE("Input session is null!");
        return;
    }
    switch (session->type) {
        case TYPE_CLIENT_BIND_SUB_SESSION:
        case TYPE_SERVER_BIND_SUB_SESSION:
            DestroyCompatibleBindSubSession(session);
            return;
        case TYPE_CLIENT_AUTH_SUB_SESSION:
        case TYPE_SERVER_AUTH_SUB_SESSION:
            DestroyCompatibleAuthSubSession(session);
            return;
        default:
            LOGE("Invalid session type!");
    }
}