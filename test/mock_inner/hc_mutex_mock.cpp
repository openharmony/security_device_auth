#include "hc_mutex_mock.h"
#include <cstdlib>
#include <cstring>
#include <pthread.h>
#include "hc_log.h"

static MockHcMutex *g_mockHcMutex = nullptr;

void SetMockHcMutex(MockHcMutex *mock)
{
    g_mockHcMutex = mock;
}

static int HcMutexLock(HcMutex *mutex)
{
    if (mutex == nullptr) {
        return -1;
    }
    return pthread_mutex_lock(&mutex->mutex);
}

static void HcMutexUnlock(HcMutex *mutex)
{
    if (mutex == nullptr) {
        return;
    }
    pthread_mutex_unlock(&mutex->mutex);
}

static int32_t RealInitHcMutex(HcMutex *mutex, bool isReentrant)
{
    if (mutex == nullptr) {
        return -1;
    }
    int res = pthread_mutex_init(&mutex->mutex, nullptr);
    if (res != 0) {
        return res;
    }
    mutex->lock = HcMutexLock;
    mutex->unlock = HcMutexUnlock;
    mutex->owner = 0;
    mutex->count = 0;
    mutex->isReentrant = isReentrant;
    mutex->isInitialized = true;
    return 0;
}

static void RealDestroyHcMutex(HcMutex *mutex)
{
    if (mutex == nullptr) {
        return;
    }
    mutex->lock = nullptr;
    mutex->unlock = nullptr;
    mutex->owner = 0;
    mutex->count = 0;
    mutex->isReentrant = false;
    pthread_mutex_destroy(&mutex->mutex);
    mutex->isInitialized = false;
}

static int RealLockHcMutex(HcMutex *mutex)
{
    if (mutex == nullptr || mutex->lock == nullptr) {
        return -1;
    }
    return mutex->lock(mutex);
}

static void RealUnlockHcMutex(HcMutex *mutex)
{
    if (mutex == nullptr || mutex->unlock == nullptr) {
        return;
    }
    mutex->unlock(mutex);
}

extern "C" int32_t InitHcMutex(HcMutex *mutex, bool isReentrant)
{
    if (g_mockHcMutex) {
        return g_mockHcMutex->InitHcMutex(mutex, isReentrant);
    }
    return RealInitHcMutex(mutex, isReentrant);
}

extern "C" void DestroyHcMutex(HcMutex *mutex)
{
    if (g_mockHcMutex) {
        g_mockHcMutex->DestroyHcMutex(mutex);
        return;
    }
    RealDestroyHcMutex(mutex);
}

extern "C" int LockHcMutex(HcMutex *mutex)
{
    if (g_mockHcMutex) {
        return g_mockHcMutex->LockHcMutex(mutex);
    }
    return RealLockHcMutex(mutex);
}

extern "C" void UnlockHcMutex(HcMutex *mutex)
{
    if (g_mockHcMutex) {
        g_mockHcMutex->UnlockHcMutex(mutex);
        return;
    }
    RealUnlockHcMutex(mutex);
}
