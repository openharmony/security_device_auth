/*
 * Copyright (C) 2025 Huawei Device Co., Ltd.
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

#ifndef HC_MUTEX_TEST_H
#define HC_MUTEX_TEST_H

#include <stdbool.h>
#include <stdint.h>
#include "pthread.h"
#include "hc_mutex.h"

#ifdef __cplusplus
extern "C" {
#endif

extern bool g_pthreadMutexInitShouldFail;
extern bool g_pthreadMutexLockShouldFail;
extern bool g_pthreadMutexUnlockShouldFail;
extern bool g_pthreadMutexDestroyShouldFail;

void SetPthreadMockFlags(bool initFail, bool lockFail, bool unlockFail, bool destroyFail);

int32_t InitHcMutexTest(HcMutex* mutex, bool isReentrant);
void DestroyHcMutexTest(HcMutex* mutex);
int LockHcMutexTest(HcMutex* mutex);
void UnlockHcMutexTest(HcMutex* mutex);

#ifdef __cplusplus
}
#endif

#endif
