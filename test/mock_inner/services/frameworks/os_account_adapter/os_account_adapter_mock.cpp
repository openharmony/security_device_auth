#include "os_account_adapter_mock.h"
#include "hc_log.h"

static MockOsAccountAdapter *g_mockOsAccountAdapter = nullptr;

void SetMockOsAccountAdapter(MockOsAccountAdapter *mock)
{
    g_mockOsAccountAdapter = mock;
}

extern "C" void NotifyOsAccountUnlocked(int32_t osAccountId)
{
    if (g_mockOsAccountAdapter) {
        g_mockOsAccountAdapter->NotifyOsAccountUnlocked(osAccountId);
        return;
    }
    LOGE("NotifyOsAccountUnlocked called without mock!");
}

extern "C" void NotifyOsAccountRemoved(int32_t osAccountId)
{
    if (g_mockOsAccountAdapter) {
        g_mockOsAccountAdapter->NotifyOsAccountRemoved(osAccountId);
        return;
    }
    LOGE("NotifyOsAccountRemoved called without mock!");
}

extern "C" int32_t DevAuthGetRealOsAccountLocalId(int32_t inputId)
{
    if (g_mockOsAccountAdapter) {
        return g_mockOsAccountAdapter->DevAuthGetRealOsAccountLocalId(inputId);
    }
    LOGE("DevAuthGetRealOsAccountLocalId called without mock!");
    return -1;
}

extern "C" bool CheckIsForegroundOsAccountId(int32_t osAccountId)
{
    if (g_mockOsAccountAdapter) {
        return g_mockOsAccountAdapter->CheckIsForegroundOsAccountId(osAccountId);
    }
    LOGE("CheckIsForegroundOsAccountId called without mock!");
    return false;
}

extern "C" bool IsOsAccountUnlocked(int32_t osAccountId)
{
    if (g_mockOsAccountAdapter) {
        return g_mockOsAccountAdapter->IsOsAccountUnlocked(osAccountId);
    }
    LOGE("IsOsAccountUnlocked called without mock!");
    return false;
}

extern "C" void AddOsAccountEventCallback(EventCallbackId callbackId, OsAccountCallbackFunc unlockFunc,
    OsAccountCallbackFunc removeFunc)
{
    if (g_mockOsAccountAdapter) {
        g_mockOsAccountAdapter->AddOsAccountEventCallback(callbackId, unlockFunc, removeFunc);
        return;
    }
    LOGE("AddOsAccountEventCallback called without mock!");
}

extern "C" void RemoveOsAccountEventCallback(EventCallbackId callbackId)
{
    if (g_mockOsAccountAdapter) {
        g_mockOsAccountAdapter->RemoveOsAccountEventCallback(callbackId);
        return;
    }
    LOGE("RemoveOsAccountEventCallback called without mock!");
}

extern "C" void InitOsAccountAdapter(void)
{
    if (g_mockOsAccountAdapter) {
        g_mockOsAccountAdapter->InitOsAccountAdapter();
        return;
    }
    LOGE("InitOsAccountAdapter called without mock!");
}

extern "C" void DestroyOsAccountAdapter(void)
{
    if (g_mockOsAccountAdapter) {
        g_mockOsAccountAdapter->DestroyOsAccountAdapter();
        return;
    }
    LOGE("DestroyOsAccountAdapter called without mock!");
}

extern "C" int32_t GetAllOsAccountIds(int32_t **osAccountIds, uint32_t *size)
{
    if (g_mockOsAccountAdapter) {
        return g_mockOsAccountAdapter->GetAllOsAccountIds(osAccountIds, size);
    }
    LOGE("GetAllOsAccountIds called without mock!");
    return -1;
}

extern "C" bool IsOsAccountSupported(void)
{
    if (g_mockOsAccountAdapter) {
        return g_mockOsAccountAdapter->IsOsAccountSupported();
    }
    LOGE("IsOsAccountSupported called without mock!");
    return false;
}

extern "C" int32_t GetCurrentActiveOsAccountId(void)
{
    if (g_mockOsAccountAdapter) {
        return g_mockOsAccountAdapter->GetCurrentActiveOsAccountId();
    }
    LOGE("GetCurrentActiveOsAccountId called without mock!");
    return -1;
}
