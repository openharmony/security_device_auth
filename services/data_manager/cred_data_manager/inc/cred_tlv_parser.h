/*
 * Copyright (C) 2025 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
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

#ifndef CRED_TLV_PARSER_H
#define CRED_TLV_PARSER_H

#include <hc_parcel.h>
#include <hc_vector.h>
#include <hc_string.h>

#ifdef __cplusplus
extern "C" {
#endif

#define USE_DEFAULT_TAG 0xFFFF
#define CRED_TLV_FAIL (-1)
#define NO_REVERT 0
#define NEED_REVERT 1
#define MAX_TOTOL_LEN (100 * 1024 * 1024)

typedef struct CredTlvBaseT {
    unsigned short tag;
    unsigned int length;
    unsigned short checkTag;
    unsigned short hasValue;
    int64_t (*parse)(struct CredTlvBaseT *, HcParcel *, HcBool);
    int64_t (*getlen)(struct CredTlvBaseT *);
    int64_t (*encode)(struct CredTlvBaseT *, HcParcel *);
    void (*deinit)(struct CredTlvBaseT *);
} CredTlvBase;

#define DECLARE_CRED_TLV_STRUCT(x) \
    CredTlvBase base; \
    unsigned int offsetCount; \
    unsigned int offset[x];

unsigned short GetCredTag(unsigned short checkTag, unsigned short defaultTag);

#define BEGIN_CRED_TLV_STRUCT_DEFINE(TlvS, CheckTag) \
void Init##TlvS(TlvS *tlv, unsigned short checkTag) \
{ \
    typedef TlvS TlvStructType; \
    unsigned int index = 0; \
    (void)memset_s(&tlv->base, sizeof(tlv->base), 0, sizeof(tlv->base)); \
    tlv->base.checkTag = GetCredTag(checkTag, CheckTag);

#define CRED_TLV_MEMBER_OPTION(TlvMember, TlvMemberName, CheckTag) \
    Init##TlvMember(&tlv->TlvMemberName, CheckTag); \
    tlv->TlvMemberName.base.option = 1; \
    tlv->offset[index++] = offsetof(TlvStructType, TlvMemberName);

#define CRED_TLV_MEMBER(TlvMember, TlvMemberName, CheckTag) \
    Init##TlvMember(&tlv->TlvMemberName, CheckTag); \
    tlv->offset[index++] = offsetof(TlvStructType, TlvMemberName);

#define END_CRED_TLV_STRUCT_DEFINE(void) \
    tlv->offsetCount = index; \
    tlv->base.parse = ParseCredTlvStruct; \
    tlv->base.getlen = GetLenCredTlvStruct; \
    tlv->base.encode = EncodeCredTlvStruct; \
    tlv->base.deinit = DeinitCredTlvStruct; \
}

#define DECLARE_CRED_TLV_FIX_LENGTH_TYPE(TlvName, TypeName) \
typedef struct \
{ \
    CredTlvBase base; \
    TypeName data; \
} TlvName;

DECLARE_CRED_TLV_FIX_LENGTH_TYPE(CredTlvInt32, int)
DECLARE_CRED_TLV_FIX_LENGTH_TYPE(CredTlvInt16, short)
DECLARE_CRED_TLV_FIX_LENGTH_TYPE(CredTlvInt8, char)
DECLARE_CRED_TLV_FIX_LENGTH_TYPE(CredTlvUint32, uint32_t)
DECLARE_CRED_TLV_FIX_LENGTH_TYPE(CredTlvUint16, uint16_t)
DECLARE_CRED_TLV_FIX_LENGTH_TYPE(CredTlvUint8, uint8_t)
DECLARE_CRED_TLV_FIX_LENGTH_TYPE(CredTlvUint64, uint64_t)
DECLARE_CRED_TLV_FIX_LENGTH_TYPE(CredTlvInt64, uint64_t)

#define DEFINE_CRED_TLV_FIX_LENGTH_TYPE(TlvName, Revert) \
int64_t ParseCredTlv##TlvName(CredTlvBase *tlv, HcParcel *parcel, HcBool strict) \
{ \
    (void)strict; \
    TlvName *realTlv = (TlvName *)(tlv); \
    HcBool readRet = HC_FALSE; \
    if (tlv->length != sizeof(realTlv->data)) \
    { \
        return CRED_TLV_FAIL; \
    } \
\
    if (Revert) \
    { \
        readRet = ParcelReadRevert(parcel, &realTlv->data, sizeof(realTlv->data)); \
    } else { \
        readRet = ParcelRead(parcel, &realTlv->data, sizeof(realTlv->data)); \
    } \
    if (readRet) \
    { \
        return tlv->length; \
    } else { \
        return CRED_TLV_FAIL; \
    } \
} \
\
int64_t GetLenCredTlv##TlvName(CredTlvBase *tlv) \
{ \
    TlvName *realTlv = (TlvName *)(tlv); \
    return (int64_t)sizeof(realTlv->data); \
} \
\
int64_t EncodeCredTlv##TlvName(CredTlvBase *tlv, HcParcel *parcel) \
{ \
    HcBool writeRet = HC_FALSE; \
    TlvName *realTlv = (TlvName *)(tlv); \
    if (Revert) \
    { \
        writeRet = ParcelWriteRevert(parcel, &realTlv->data, sizeof(realTlv->data)); \
    } else { \
        writeRet = ParcelWrite(parcel, &realTlv->data, sizeof(realTlv->data)); \
    } \
    if (writeRet) \
    { \
        return sizeof(realTlv->data); \
    } else { \
        return CRED_TLV_FAIL; \
    } \
} \
\
DECLARE_CRED_TLV_PARSE_FUNC(TlvName, ParseCredTlv##TlvName, GetLenCredTlv##TlvName, EncodeCredTlv##TlvName);

void DeinitCredTlvFixMember(CredTlvBase *tlv);

#define DECLARE_CRED_TLV_PARSE_FUNC(TlvName, TlvParseFunc, TlvGetLenFunc, TlvEncodeFunc) \
void Init##TlvName(TlvName *tlv, unsigned short checkTag) \
{ \
    (void)memset_s(&tlv->base, sizeof(tlv->base), 0, sizeof(tlv->base)); \
    tlv->base.parse = TlvParseFunc; \
    tlv->base.getlen = TlvGetLenFunc; \
    tlv->base.encode = TlvEncodeFunc; \
    tlv->base.deinit = DeinitCredTlvFixMember; \
    tlv->base.checkTag = checkTag; \
}

#define CRED_TLV_INIT(TlvName, TlvData) Init##TlvName(TlvData, USE_DEFAULT_TAG);

#define CRED_TLV_DEINIT(TlvData) TlvData.base.deinit((CredTlvBase *)(&TlvData));
typedef struct {
    CredTlvBase base;
    unsigned int offsetCount;
    unsigned int offset[0];
} CredTlvOffsetExample;

HcBool ParseCredTlvHead(CredTlvBase *tlv, HcParcel *parcel);
int64_t ParseCredTlvNode(CredTlvBase *tlv, HcParcel *parcel, HcBool strict);
int64_t GetlenCredTlvNode(CredTlvBase *tlv);
void DeinitCredTlvNode(CredTlvBase *tlv);

int64_t ParseCredTlvStruct(CredTlvBase *tlv, HcParcel *parcel, HcBool strict);
int64_t EncodeCredTlvStruct(CredTlvBase *tlv, HcParcel *parcel);
int64_t GetLenCredTlvStruct(CredTlvBase *tlv);
void DeinitCredTlvStruct(CredTlvBase *tlv);
int64_t EncodeCredTlvNode(CredTlvBase *tlv, HcParcel *parcel, HcBool isRoot);
HcBool DecodeCredTlvMessage(CredTlvBase *msg, HcParcel *parcel, HcBool strict);
HcBool EncodeCredTlvMessage(CredTlvBase *msg, HcParcel *parcel);

typedef struct {
    CredTlvBase base;
    HcParcel data;
} CredTlvBuffer;

void InitCredTlvBuffer(CredTlvBuffer *tlv, unsigned short checkTag);
int64_t ParseCredTlvBuffer(CredTlvBase *tlv, HcParcel *parcel, HcBool strict);
int64_t GetlenCredTlvBuffer(CredTlvBase *tlv);
int64_t EncodeCredTlvBuffer(CredTlvBase *tlv, HcParcel *parcel);
void DeinitCredTlvBuffer(CredTlvBase *tlv);

typedef struct {
    CredTlvBase base;
    HcString data;
} CredTlvString;

void InitCredTlvString(CredTlvString *tlv, unsigned short checkTag);
int64_t ParseCredTlvString(CredTlvBase *tlv, HcParcel *parcel, HcBool strict);
int64_t GetlenCredTlvString(CredTlvBase *tlv);
int64_t EncodeCredTlvString(CredTlvBase *tlv, HcParcel *parcel);
void DeinitCredTlvString(CredTlvBase *tlv);

#define DECLEAR_CRED_INIT_FUNC(TlvStruct) \
void Init##TlvStruct(TlvStruct *tlv, unsigned short checkTag);

DECLEAR_CRED_INIT_FUNC(CredTlvUint64)
DECLEAR_CRED_INIT_FUNC(CredTlvUint32)
DECLEAR_CRED_INIT_FUNC(CredTlvUint16)
DECLEAR_CRED_INIT_FUNC(CredTlvUint8)
DECLEAR_CRED_INIT_FUNC(CredTlvInt64)
DECLEAR_CRED_INIT_FUNC(CredTlvInt32)
DECLEAR_CRED_INIT_FUNC(CredTlvInt16)
DECLEAR_CRED_INIT_FUNC(CredTlvInt8)

#define DECLARE_CRED_TLV_VECTOR(TlvVecName, TlvVecElement) \
DECLARE_HC_VECTOR(Vec##TlvVecName, TlvVecElement) \
typedef struct { \
    CredTlvBase base; \
    Vec##TlvVecName data; \
} TlvVecName; \
void DeinitTlv##TlvVecName(CredTlvBase *tlv); \
void Init##TlvVecName(TlvVecName *tlv, unsigned short checkTag);

#define IMPLEMENT_CRED_TLV_VECTOR(TlvVecName, TlvElementName, VecAllocCount) \
IMPLEMENT_HC_VECTOR(Vec##TlvVecName, TlvElementName, VecAllocCount) \
int64_t ParseTlv##TlvVecName(CredTlvBase *tlv, HcParcel *parcel, HcBool strict) \
{ \
    TlvVecName *realTlv = (TlvVecName *)(tlv); \
    uint32_t count = 0; \
    if (!ParcelReadUint32(parcel, &count)) { \
        return CRED_TLV_FAIL; \
    } \
    int64_t totalLen = sizeof(count); \
    uint32_t index = 0; \
    for (index = 0; index < count; ++index) { \
        TlvElementName tlvElement; \
        TlvElementName *curElement = realTlv->data.pushBack(&realTlv->data, &tlvElement); \
        if (curElement == NULL) { \
            return CRED_TLV_FAIL; \
        } \
        CRED_TLV_INIT(TlvElementName, curElement); \
\
        int64_t elementLen = ParseCredTlvNode((CredTlvBase *)curElement, parcel, strict); \
        if (elementLen < 0) { \
            return CRED_TLV_FAIL; \
        } \
        totalLen += elementLen; \
        if (totalLen >= MAX_TOTOL_LEN) { \
            return CRED_TLV_FAIL; \
        } \
    } \
\
    return totalLen; \
} \
\
int64_t EncodeTlv##TlvVecName(CredTlvBase *tlv, HcParcel *parcel) \
{ \
    TlvVecName *realTlv = (TlvVecName *)(tlv); \
    uint32_t index = 0; \
    TlvElementName *element = NULL; \
    int64_t totalLen = 4; \
    uint32_t count = realTlv->data.size(&realTlv->data); \
    if (!ParcelWriteUint32(parcel, count)) { \
        return CRED_TLV_FAIL; \
    } \
\
    FOR_EACH_HC_VECTOR(realTlv->data, index, element) { \
        if (element != NULL) { \
            int64_t len = EncodeCredTlvNode((CredTlvBase *)element, parcel, HC_FALSE); \
            totalLen += len; \
            if (totalLen >= MAX_TOTOL_LEN) { \
                return CRED_TLV_FAIL; \
            } \
        } \
    } \
    return totalLen; \
} \
int64_t GetLenTlv##TlvVecName(CredTlvBase *tlv) \
{ \
    TlvVecName *realTlv = (TlvVecName *)(tlv); \
    uint32_t index = 0; \
    TlvElementName *element = NULL; \
    int64_t totalLen = sizeof(int32_t); \
    FOR_EACH_HC_VECTOR(realTlv->data, index, element) { \
        if (element != NULL) { \
            totalLen += GetlenCredTlvNode((CredTlvBase *)element); \
            if (totalLen >= MAX_TOTOL_LEN) { \
                return CRED_TLV_FAIL; \
            } \
        } else { \
            return CRED_TLV_FAIL; \
        } \
    } \
    return totalLen; \
} \
\
void DeinitTlv##TlvVecName(CredTlvBase *tlv) \
{ \
    TlvVecName *realTlv = (TlvVecName *)(tlv); \
    uint32_t index = 0; \
    TlvElementName *element = NULL; \
    FOR_EACH_HC_VECTOR(realTlv->data, index, element) { \
        if (element != NULL) { \
            CRED_TLV_DEINIT((*element)); \
        } \
    } \
    DESTROY_HC_VECTOR(Vec##TlvVecName, &((TlvVecName *)tlv)->data); \
} \
\
void Init##TlvVecName(TlvVecName *tlv, unsigned short checkTag) \
{ \
    (void)memset_s(&tlv->base, sizeof(tlv->base), 0, sizeof(tlv->base)); \
    tlv->base.parse = ParseTlv##TlvVecName; \
    tlv->base.encode = EncodeTlv##TlvVecName; \
    tlv->base.getlen = GetLenTlv##TlvVecName; \
    tlv->base.deinit = DeinitTlv##TlvVecName; \
    tlv->base.checkTag = checkTag; \
    tlv->data = CREATE_HC_VECTOR(Vec##TlvVecName); \
}

#ifdef __cplusplus
}
#endif
#endif
