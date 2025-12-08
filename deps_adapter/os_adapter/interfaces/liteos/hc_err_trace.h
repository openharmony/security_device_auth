/*
* Copyright (C) 2025 Huawei Device Co., Ltd.
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

#ifndef HC_ERR_TRACE_H
#define HC_ERR_TRACE_H

#ifdef __cplusplus
extern "C" {
#endif

#define FIELD_ERR_TRACE "errTrace"

#define UNKNOWN_ERROR_TRACE "unknown"

#define SET_LOG_MODE_AND_ERR_TRACE(mode, isErrTraceOn)
#define SET_TRACE_ID(traceId)

#define RECORD_ERR_TRACE(funName, lineNum, fmt, ...)

#define GET_ERR_TRACE_LEN() 0
#define GET_ERR_TRACE() "unknown"

typedef enum {
    NORMAL_MODE = 0,
    TRACE_MODE = 1,
} LogMode;

#ifdef __cplusplus
}
#endif
#endif