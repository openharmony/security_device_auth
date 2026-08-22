#ifndef OS_ACCOUNT_ADAPTER_MOCK_H
#define OS_ACCOUNT_ADAPTER_MOCK_H

#include <gtest/gtest.h>
#include <gmock/gmock.h>
#include "os_account_adapter.h"

class MockOsAccountAdapter {
public:
    MOCK_METHOD(void, NotifyOsAccountUnlocked, (int32_t osAccountId));
    MOCK_METHOD(void, NotifyOsAccountRemoved, (int32_t osAccountId));
    MOCK_METHOD(void, AddOsAccountEventCallback, (EventCallbackId callbackId, OsAccountCallbackFunc unlockFunc,
        OsAccountCallbackFunc removeFunc));
    MOCK_METHOD(void, RemoveOsAccountEventCallback, (EventCallbackId callbackId));
    MOCK_METHOD(bool, IsOsAccountUnlocked, (int32_t osAccountId));
    MOCK_METHOD(int32_t, DevAuthGetRealOsAccountLocalId, (int32_t inputId));
    MOCK_METHOD(bool, CheckIsForegroundOsAccountId, (int32_t osAccountId));
    MOCK_METHOD(void, InitOsAccountAdapter, ());
    MOCK_METHOD(void, DestroyOsAccountAdapter, ());
    MOCK_METHOD(int32_t, GetAllOsAccountIds, (int32_t **osAccountIds, uint32_t *size));
    MOCK_METHOD(bool, IsOsAccountSupported, ());
    MOCK_METHOD(int32_t, GetCurrentActiveOsAccountId, ());
};

void SetMockOsAccountAdapter(MockOsAccountAdapter *mock);

#endif
