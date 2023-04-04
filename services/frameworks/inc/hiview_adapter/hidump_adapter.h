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

#ifndef HIDUMP_ADAPTER_H
#define HIDUMP_ADAPTER_H

#ifndef DEV_AUTH_HIVIEW_ENABLE

#define DEV_AUTH_DUMP(fd)
#define DEV_AUTH_REG_DUMP_FUNC(func)

#else

#include <stdio.h>

#define DEV_AUTH_DUMP(fd) DevAuthDump(fd)
#define DEV_AUTH_REG_DUMP_FUNC(func) RegisterDumpFunc(func)

typedef void (*DumpCallBack)(int);

#ifdef __cplusplus
extern "C" {
#endif

void DevAuthDump(int fd);

void RegisterDumpFunc(DumpCallBack func);

#ifdef __cplusplus
}
#endif

#endif

#endif