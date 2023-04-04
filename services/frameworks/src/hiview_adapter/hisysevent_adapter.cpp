/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "hisysevent_adapter.h"

#include "hisysevent.h"

#define STR_CALL_EVENT "CALL_EVENT"
#define STR_OS_ACCOUNT_ID "OS_ACCOUNT_ID"
#define STR_FUNC_NAME "FUNC_NAME"
#define STR_APP_ID "APP_ID"
#define STR_REQ_ID "REQ_ID"
#define STR_UNKNOWN "unknown"

void DevAuthReportCallEvent(const char *funcName, int32_t osAccountId, int64_t reqId, const char *appId)
{
    HiSysEventWrite(
        OHOS::HiviewDFX::HiSysEvent::Domain::DEVICE_AUTH,
        STR_CALL_EVENT,
        OHOS::HiviewDFX::HiSysEvent::EventType::STATISTIC,
        STR_OS_ACCOUNT_ID, osAccountId,
        STR_FUNC_NAME, ((funcName != NULL) ? funcName : STR_UNKNOWN),
        STR_REQ_ID, reqId,
        STR_APP_ID, ((appId != NULL) ? appId : STR_UNKNOWN));
}
