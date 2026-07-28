#ifndef STRING_UTIL_MOCK_H
#define STRING_UTIL_MOCK_H

#include <gtest/gtest.h>
#include <gmock/gmock.h>
#include <cstdint>

class MockStringUtil {
public:
    MOCK_METHOD(int32_t, DeepCopyString, (const char *str, char **newStr));
};

void SetMockStringUtil(MockStringUtil *mock);

#endif
