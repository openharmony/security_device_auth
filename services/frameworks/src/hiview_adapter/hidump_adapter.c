/*
 * Copyright (C) 2022-2025 Huawei Device Co., Ltd.
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

#include "hidump_adapter.h"
#include "hc_log.h"
#include "string.h"
#include "string_util.h"

static DumpCallBack g_dumpCallBack = NULL;
static CredDumpCallBack g_credDumpCallBack = NULL;
static OperationDumpCallBack g_operationDumpCallBack = NULL;
static PerformanceDumpCallBack g_performDumpCallback = NULL;

static void DumpByArgs(int fd, StringVector *strArgVec)
{
    HcString strArg = strArgVec->get(strArgVec, 0);
    if (IsStrEqual(StringGet(&strArg), PERFORM_DUMP_ARG)) {
        if (g_performDumpCallback != NULL) {
            g_performDumpCallback(fd, strArgVec);
        }
    } else if (IsStrEqual(StringGet(&strArg), OPERATION_DUMP_ARG) && g_operationDumpCallBack != NULL) {
        g_operationDumpCallBack(fd);
    } else {
        LOGE("Invalid dumper command!");
    }
}

void DevAuthDump(int fd, StringVector *strArgVec)
{
    if (strArgVec == NULL) {
        LOGE("Dumper arguments vector is null!");
        return;
    }
    if (strArgVec->size(strArgVec) == 0) {
        if (g_dumpCallBack != NULL) {
            g_dumpCallBack(fd);
        }
        if (g_credDumpCallBack != NULL) {
            g_credDumpCallBack(fd);
        }
    } else {
        DumpByArgs(fd, strArgVec);
    }
}

void RegisterDumpFunc(DumpCallBack func)
{
    g_dumpCallBack = func;
}

void RegisterCredDumpFunc(CredDumpCallBack func)
{
    g_credDumpCallBack = func;
}

void RegisterOperationDumpFunc(OperationDumpCallBack func)
{
    g_operationDumpCallBack = func;
}

void RegisterPerformDumpFunc(PerformanceDumpCallBack func)
{
    g_performDumpCallback = func;
}