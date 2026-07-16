#ifndef HC_MUTEX_MOCK_H
#define HC_MUTEX_MOCK_H

#include <gtest/gtest.h>
#include <gmock/gmock.h>
#include "hc_mutex.h"

class MockHcMutex {
public:
    MOCK_METHOD(int32_t, InitHcMutex, (HcMutex* mutex, bool isReentrant));
    MOCK_METHOD(void, DestroyHcMutex, (HcMutex* mutex));
    MOCK_METHOD(int, LockHcMutex, (HcMutex* mutex));
    MOCK_METHOD(void, UnlockHcMutex, (HcMutex* mutex));
};

void SetMockHcMutex(MockHcMutex *mock);

#endif
