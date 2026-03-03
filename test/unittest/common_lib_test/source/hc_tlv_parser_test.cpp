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

#include <gtest/gtest.h>
#include "hc_tlv_parser.h"
#include "hc_parcel.h"
#include "hc_types.h"

using namespace testing::ext;

namespace {
static const uint32_t TEST_BUFFER_SIZE = 32;


class HcTlvParserTest : public testing::Test {
};

HWTEST_F(HcTlvParserTest, ParseTlvHeadTest001, TestSize.Level0)
{
    HcParcel parcel = CreateParcel(TEST_BUFFER_SIZE, TEST_BUFFER_SIZE);

    TlvBase tlvBase = { 0 };
    HcBool ret = ParseTlvHead(&tlvBase, &parcel);
    EXPECT_EQ(ret, HC_FALSE);

    DeleteParcel(&parcel);
}

HWTEST_F(HcTlvParserTest, ParseTlvHeadTest002, TestSize.Level0)
{
    HcBool ret = ParseTlvHead(nullptr, nullptr);
    EXPECT_EQ(ret, HC_FALSE);
}

HWTEST_F(HcTlvParserTest, ParseTlvNodeTest001, TestSize.Level0)
{
    HcParcel parcel = CreateParcel(TEST_BUFFER_SIZE, TEST_BUFFER_SIZE);

    TlvBase tlvBase = { 0 };
    int32_t ret = ParseTlvNode(&tlvBase, &parcel, HC_TRUE);
    EXPECT_EQ(ret, TLV_FAIL);

    DeleteParcel(&parcel);
}

HWTEST_F(HcTlvParserTest, ParseTlvNodeTest002, TestSize.Level0)
{
    int32_t ret = ParseTlvNode(nullptr, nullptr, HC_TRUE);
    EXPECT_EQ(ret, TLV_FAIL);
}

HWTEST_F(HcTlvParserTest, GetlenTlvNodeTest001, TestSize.Level0)
{
    TlvBase tlvBase = { 0 };
    int32_t ret = GetlenTlvNode(&tlvBase);
    EXPECT_EQ(ret, TLV_FAIL);
}

HWTEST_F(HcTlvParserTest, GetlenTlvNodeTest002, TestSize.Level0)
{
    int32_t ret = GetlenTlvNode(nullptr);
    EXPECT_EQ(ret, TLV_FAIL);
}

HWTEST_F(HcTlvParserTest, DeinitTltvNodeTest001, TestSize.Level0)
{
    TlvBase *tlvBase = nullptr;
    DeinitTlvNode(tlvBase);
    EXPECT_EQ(tlvBase, nullptr);
}

HWTEST_F(HcTlvParserTest, GetTagTest001, TestSize.Level0)
{
    unsigned short tag = GetTag(0x1234, 0xFFFF);
    EXPECT_EQ(tag, 0x1234);
}

HWTEST_F(HcTlvParserTest, GetTagTest002, TestSize.Level0)
{
    unsigned short tag = GetTag(0xFFFF, 0x1234);
    EXPECT_EQ(tag, 0x1234);
}

HWTEST_F(HcTlvParserTest, InitTlvBufferTest001, TestSize.Level0)
{
    TlvBuffer tlvBuffer;
    InitTlvBuffer(&tlvBuffer, 0x1234);
    EXPECT_EQ(tlvBuffer.base.checkTag, 0x1234);
    EXPECT_NE(tlvBuffer.base.parse, nullptr);
    EXPECT_NE(tlvBuffer.base.encode, nullptr);
    EXPECT_NE(tlvBuffer.base.getlen, nullptr);
    EXPECT_NE(tlvBuffer.base.deinit, nullptr);
    tlvBuffer.base.deinit((TlvBase *)&tlvBuffer);
}

HWTEST_F(HcTlvParserTest, InitTlvStringTest001, TestSize.Level0)
{
    TlvString tlvString;
    InitTlvString(&tlvString, 0x1234);
    EXPECT_EQ(tlvString.base.checkTag, 0x1234);
    EXPECT_NE(tlvString.base.parse, nullptr);
    EXPECT_NE(tlvString.base.encode, nullptr);
    EXPECT_NE(tlvString.base.getlen, nullptr);
    EXPECT_NE(tlvString.base.deinit, nullptr);
    tlvString.base.deinit((TlvBase *)&tlvString);
}

HWTEST_F(HcTlvParserTest, InitTlvUint32Test001, TestSize.Level0)
{
    TlvUint32 tlvUint32;
    InitTlvUint32(&tlvUint32, 0x1234);
    EXPECT_EQ(tlvUint32.base.checkTag, 0x1234);
    EXPECT_NE(tlvUint32.base.parse, nullptr);
    EXPECT_NE(tlvUint32.base.encode, nullptr);
    EXPECT_NE(tlvUint32.base.getlen, nullptr);
    EXPECT_NE(tlvUint32.base.deinit, nullptr);
    tlvUint32.base.deinit((TlvBase *)&tlvUint32);
}

HWTEST_F(HcTlvParserTest, InitTlvInt32Test001, TestSize.Level0)
{
    TlvInt32 tlvInt32;
    InitTlvInt32(&tlvInt32, 0x1234);
    EXPECT_EQ(tlvInt32.base.checkTag, 0x1234);
    EXPECT_NE(tlvInt32.base.parse, nullptr);
    EXPECT_NE(tlvInt32.base.encode, nullptr);
    EXPECT_NE(tlvInt32.base.getlen, nullptr);
    EXPECT_NE(tlvInt32.base.deinit, nullptr);
    tlvInt32.base.deinit((TlvBase *)&tlvInt32);
}

HWTEST_F(HcTlvParserTest, InitTlvUint16Test001, TestSize.Level0)
{
    TlvUint16 tlvUint16;
    InitTlvUint16(&tlvUint16, 0x1234);
    EXPECT_EQ(tlvUint16.base.checkTag, 0x1234);
    EXPECT_NE(tlvUint16.base.parse, nullptr);
    EXPECT_NE(tlvUint16.base.encode, nullptr);
    EXPECT_NE(tlvUint16.base.getlen, nullptr);
    EXPECT_NE(tlvUint16.base.deinit, nullptr);
    tlvUint16.base.deinit((TlvBase *)&tlvUint16);
}

HWTEST_F(HcTlvParserTest, InitTlvInt16Test001, TestSize.Level0)
{
    TlvInt16 tlvInt16;
    InitTlvInt16(&tlvInt16, 0x1234);
    EXPECT_EQ(tlvInt16.base.checkTag, 0x1234);
    EXPECT_NE(tlvInt16.base.parse, nullptr);
    EXPECT_NE(tlvInt16.base.encode, nullptr);
    EXPECT_NE(tlvInt16.base.getlen, nullptr);
    EXPECT_NE(tlvInt16.base.deinit, nullptr);
    tlvInt16.base.deinit((TlvBase *)&tlvInt16);
}

HWTEST_F(HcTlvParserTest, InitTlvUint8Test001, TestSize.Level0)
{
    TlvUint8 tlvUint8;
    InitTlvUint8(&tlvUint8, 0x1234);
    EXPECT_EQ(tlvUint8.base.checkTag, 0x1234);
    EXPECT_NE(tlvUint8.base.parse, nullptr);
    EXPECT_NE(tlvUint8.base.encode, nullptr);
    EXPECT_NE(tlvUint8.base.getlen, nullptr);
    EXPECT_NE(tlvUint8.base.deinit, nullptr);
    tlvUint8.base.deinit((TlvBase *)&tlvUint8);
}

HWTEST_F(HcTlvParserTest, InitTlvInt8Test001, TestSize.Level0)
{
    TlvInt8 tlvInt8;
    InitTlvInt8(&tlvInt8, 0x1234);
    EXPECT_EQ(tlvInt8.base.checkTag, 0x1234);
    EXPECT_NE(tlvInt8.base.parse, nullptr);
    EXPECT_NE(tlvInt8.base.encode, nullptr);
    EXPECT_NE(tlvInt8.base.getlen, nullptr);
    EXPECT_NE(tlvInt8.base.deinit, nullptr);
    tlvInt8.base.deinit((TlvBase *)&tlvInt8);
}

HWTEST_F(HcTlvParserTest, InitTlvUint64Test001, TestSize.Level0)
{
    TlvUint64 tlvUint64;
    InitTlvUint64(&tlvUint64, 0x1234);
    EXPECT_EQ(tlvUint64.base.checkTag, 0x1234);
    EXPECT_NE(tlvUint64.base.parse, nullptr);
    EXPECT_NE(tlvUint64.base.encode, nullptr);
    EXPECT_NE(tlvUint64.base.getlen, nullptr);
    EXPECT_NE(tlvUint64.base.deinit, nullptr);
    tlvUint64.base.deinit((TlvBase *)&tlvUint64);
}

HWTEST_F(HcTlvParserTest, InitTlvInt64Test001, TestSize.Level0)
{
    TlvInt64 tlvInt64;
    InitTlvInt64(&tlvInt64, 0x1234);
    EXPECT_EQ(tlvInt64.base.checkTag, 0x1234);
    EXPECT_NE(tlvInt64.base.parse, nullptr);
    EXPECT_NE(tlvInt64.base.encode, nullptr);
    EXPECT_NE(tlvInt64.base.getlen, nullptr);
    EXPECT_NE(tlvInt64.base.deinit, nullptr);
    tlvInt64.base.deinit((TlvBase *)&tlvInt64);
}

HWTEST_F(HcTlvParserTest, EncodeTlvMessageTest001, TestSize.Level0)
{
    TlvUint32 tlvUint32;
    InitTlvUint32(&tlvUint32, 0x1234);
    tlvUint32.data = 0x5678;
    HcParcel parcel = CreateParcel(TEST_BUFFER_SIZE, TEST_BUFFER_SIZE);
    HcBool ret = EncodeTlvMessage((TlvBase *)&tlvUint32, &parcel);
    EXPECT_EQ(ret, HC_TRUE);
    DeleteParcel(&parcel);
    tlvUint32.base.deinit((TlvBase *)&tlvUint32);
}

HWTEST_F(HcTlvParserTest, EncodeTlvMessageTest002, TestSize.Level0)
{
    HcParcel parcel = CreateParcel(TEST_BUFFER_SIZE, TEST_BUFFER_SIZE);
    HcBool ret = EncodeTlvMessage(nullptr, &parcel);
    EXPECT_EQ(ret, HC_FALSE);
    ret = EncodeTlvMessage(nullptr, nullptr);
    EXPECT_EQ(ret, HC_FALSE);
    DeleteParcel(&parcel);
}

HWTEST_F(HcTlvParserTest, DecodeTlvMessageTest001, TestSize.Level0)
{
    TlvUint32 tlvUint32;
    InitTlvUint32(&tlvUint32, 0x1234);
    tlvUint32.data = 0x5678;
    HcParcel srcParcel = CreateParcel(TEST_BUFFER_SIZE, TEST_BUFFER_SIZE);
    EncodeTlvMessage((TlvBase *)&tlvUint32, &srcParcel);
    TlvUint32 tlvUint32Dst;
    InitTlvUint32(&tlvUint32Dst, 0x1234);
    HcBool ret = DecodeTlvMessage((TlvBase *)&tlvUint32Dst, &srcParcel, HC_FALSE);
    EXPECT_EQ(ret, HC_TRUE);
    EXPECT_EQ(tlvUint32Dst.data, tlvUint32.data);
    DeleteParcel(&srcParcel);
    tlvUint32.base.deinit((TlvBase *)&tlvUint32);
    tlvUint32Dst.base.deinit((TlvBase *)&tlvUint32Dst);
}

HWTEST_F(HcTlvParserTest, DecodeTlvMessageTest002, TestSize.Level0)
{
    HcParcel parcel = CreateParcel(TEST_BUFFER_SIZE, TEST_BUFFER_SIZE);
    HcBool ret = DecodeTlvMessage(nullptr, &parcel, HC_FALSE);
    EXPECT_EQ(ret, HC_FALSE);
    ret = DecodeTlvMessage(nullptr, nullptr, HC_FALSE);
    EXPECT_EQ(ret, HC_FALSE);
    DeleteParcel(&parcel);
}
}
