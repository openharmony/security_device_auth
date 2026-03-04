/*
 * Copyright (C) 2025 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
.
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

#include <pthread.h>
#include <dlfcn.h>
#include "hc_mutex_mock.h"

static bool g_pthreadMutexInitShouldFail = false;
static bool g_pthreadMutexLockShouldFail = false;
static bool g_pthreadMutexUnlockShouldFail = false;
static bool g_pthreadMutexDestroyShouldFail = false;

static int (*real_pthread_mutex_init)(pthread_mutex_t *, const pthread_mutexattr_t *) = NULL;
static int (*real_pthread_mutex_lock)(pthread_mutex_t *) = NULL;
static int (*real_pthread_mutex_unlock)(pthread_mutex_t *) = NULL;
static int (*real_pthread_mutex_destroy)(pthread_mutex_t *) = NULL;

static void InitRealPthreadFuncs(void)
{
    if (real_pthread_mutex_init == NULL) {
        void *handle = dlopen("libpthread.so.0", RTLD_LAZY);
        if (handle != NULL) {
            real_pthread_mutex_init = (int (*)(pthread_mutex_t *, const pthread_mutexattr_t *))dlsym(handle, "pthread_mutex_init");
            real_pthread_mutex_lock = (int (*)(pthread_mutex_t *))dlsym(handle, "pthread_mutex_lock");
            real_pthread_mutex_unlock = (int (*)(pthread_mutex_t *))dlsym(handle, "pthread_mutex_unlock");
            real_pthread_mutex_destroy = (int (*)(pthread_mutex_t *))dlsym(handle, "pthread_mutex_destroy");
        }
    }
}

void SetPthreadMockFlags(bool initFail, bool lockFail, bool unlockFail, bool destroyFail)
{
    g_pthreadMutexInitShouldFail = initFail;
    g_pthreadMutexLockShouldFail = lockFail;
    g_pthreadMutexUnlockShouldFail = unlockFail;
    g_pthreadMutexDestroyShouldFail = destroyFail;
}

int __wrap_pthread_mutex_init(pthread_mutex_t *mutex, const pthread_mutexattr_t *attr)
{
    InitRealPthreadFuncs();
    if (g_pthreadMutexInitShouldFail) {
        return 1;
    }
    return real_pthread_mutex_init(mutex, attr);
}

int __wrap_pthread_mutex_lock(pthread_mutex_t *mutex)
{
    InitRealPthreadFuncs();
    if (g_pthreadMutexLockShouldFail) {
        return 1;
    }
    return real_pthread_mutex_lock(mutex);
}

int __wrap_pthread_mutex_unlock(pthread_mutex_t *mutex)
{
    InitRealPthreadFuncs();
    if (g_pthreadMutexUnlockShouldFail) {
        return 1;
    }
    return real_pthread_mutex_unlock(mutex);
}

int __wrap_pthread_mutex_destroy(pthread_mutex_t *mutex)
{
    InitRealPthreadFuncs();
    if (g_pthreadMutexDestroyShouldFail) {
        return 1;
    }
    return real_pthread_mutex_destroy(mutex);
}
