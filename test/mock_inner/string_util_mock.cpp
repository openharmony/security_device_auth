#include "string_util_mock.h"
#include <cstdlib>
#include <cstring>
#include <cstdint>
#include "securec.h"
#include "string_util.h"
#include "clib_error.h"
#include "hc_types.h"

static constexpr uint8_t HEX_THRESHOLD_DEC = 9;
static constexpr uint8_t HEX_ASCII_OFFSET_LETTER = 0x37;
static constexpr uint8_t HEX_ASCII_OFFSET_DIGIT = 0x30;
static constexpr int DECIMAL_BASE = 10;

static MockStringUtil *g_mockStringUtil = nullptr;

void SetMockStringUtil(MockStringUtil *mock)
{
    g_mockStringUtil = mock;
}

static int32_t RealDeepCopyString(const char *str, char **newStr)
{
    if (str == nullptr || newStr == nullptr) {
        return CLIB_ERR_NULL_PTR;
    }
    uint32_t len = HcStrlen(str);
    if (len == 0) {
        return CLIB_ERR_INVALID_LEN;
    }
    char *val = static_cast<char *>(HcMalloc(len + 1, 0));
    if (val == nullptr) {
        return CLIB_ERR_BAD_ALLOC;
    }
    if (memcpy_s(val, len + 1, str, len) != EOK) {
        HcFree(val);
        return CLIB_ERR_MEMORY_COPY;
    }
    *newStr = val;
    return CLIB_SUCCESS;
}

extern "C" int32_t DeepCopyString(const char *str, char **newStr)
{
    if (g_mockStringUtil) {
        return g_mockStringUtil->DeepCopyString(str, newStr);
    }
    return RealDeepCopyString(str, newStr);
}

extern "C" int32_t ByteToHexString(const uint8_t *byte, uint32_t byteLen, char *hexStr, uint32_t hexLen)
{
    if (byte == nullptr || hexStr == nullptr) {
        return CLIB_ERR_NULL_PTR;
    }
    if (hexLen < byteLen * BYTE_TO_HEX_OPER_LENGTH + 1) {
        return CLIB_ERR_INVALID_LEN;
    }
    for (uint32_t i = 0; i < byteLen; i++) {
        uint8_t high = (byte[i] >> 4) & 0xF;
        uint8_t low = byte[i] & 0xF;
        hexStr[i * BYTE_TO_HEX_OPER_LENGTH] = (high > HEX_THRESHOLD_DEC) ?
            (high + HEX_ASCII_OFFSET_LETTER) : (high + HEX_ASCII_OFFSET_DIGIT);
        hexStr[i * BYTE_TO_HEX_OPER_LENGTH + 1] = (low > HEX_THRESHOLD_DEC) ?
            (low + HEX_ASCII_OFFSET_LETTER) : (low + HEX_ASCII_OFFSET_DIGIT);
    }
    hexStr[byteLen * BYTE_TO_HEX_OPER_LENGTH] = '\0';
    return CLIB_SUCCESS;
}

extern "C" int32_t HexStringToByte(const char *hexStr, uint8_t *byte, uint32_t byteLen)
{
    return CLIB_SUCCESS;
}

extern "C" int64_t StringToInt64(const char *cp)
{
    if (cp == nullptr) {
        return 0;
    }
    return strtoll(cp, nullptr, DECIMAL_BASE);
}

extern "C" int32_t ToUpperCase(const char *oriStr, char **desStr)
{
    return CLIB_SUCCESS;
}

extern "C" void PrintBuffer(const uint8_t *msgBuff, uint32_t msgLen, const char *msgTag)
{
}

extern "C" int32_t GetAnonymousString(const char *originStr, char *anonymousStr, uint32_t anonymousLen, bool maskMiddle)
{
    return CLIB_SUCCESS;
}

extern "C" bool IsStrEqual(const char *str1, const char *str2)
{
    if (str1 == nullptr && str2 == nullptr) {
        return true;
    }
    if (str1 == nullptr || str2 == nullptr) {
        return false;
    }
    return strcmp(str1, str2) == 0;
}

extern "C" int32_t GenerateStringFromData(const uint8_t *data, uint32_t dataLen, char **outStr)
{
    return CLIB_SUCCESS;
}
