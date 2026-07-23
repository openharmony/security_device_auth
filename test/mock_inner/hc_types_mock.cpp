#include "hc_types_mock.h"
#include <cstdlib>
#include <cstring>
#include "securec.h"
#include "hc_types.h"
#include "hc_log.h"

#define MAX_MALLOC_SIZE (1024 * 1024 * 100)

static MockHcTypes *g_mockHcTypes = nullptr;

void SetMockHcTypes(MockHcTypes *mock)
{
    g_mockHcTypes = mock;
}

static void *RealHcMalloc(uint32_t size, char val)
{
    if (size == 0 || size > MAX_MALLOC_SIZE) {
        return nullptr;
    }
    void *addr = malloc(size);
    if (addr == nullptr) {
        return nullptr;
    }
    if (val != 0) {
        (void)memset_s(addr, size, val, size);
    }
    return addr;
}

static void RealHcFree(void *addr)
{
    if (addr != nullptr) {
        free(addr);
    }
}

extern "C" void *HcMalloc(uint32_t size, char val)
{
    if (g_mockHcTypes) {
        return g_mockHcTypes->Malloc(size, val);
    }
    return RealHcMalloc(size, val);
}

extern "C" void HcFree(void *addr)
{
    if (g_mockHcTypes) {
        g_mockHcTypes->Free(addr);
        return;
    }
    RealHcFree(addr);
}

extern "C" uint32_t HcStrlen(const char *str)
{
    if (str == nullptr) {
        return 0;
    }
    return static_cast<uint32_t>(strlen(str));
}
