#ifndef HC_TYPES_MOCK_H
#define HC_TYPES_MOCK_H

#include <gtest/gtest.h>
#include <gmock/gmock.h>
#include <stdint.h>

class MockHcTypes {
public:
    MOCK_METHOD(void*, Malloc, (uint32_t size, char val));
    MOCK_METHOD(void, Free, (void* addr));
};

void SetMockHcTypes(MockHcTypes *mock);

#endif
