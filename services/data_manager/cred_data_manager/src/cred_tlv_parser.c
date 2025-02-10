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

#include "cred_tlv_parser.h"
#include <stddef.h>

#define MAX_CRED_TLV_LENGTH (4800 * 1024)

HcBool ParseCredTlvHead(CredTlvBase *tlv, HcParcel *parcel)
{
#ifdef IS_BIG_ENDIAN
    if (!ParcelReadUint16Revert(parcel, &tlv->tag)) {
        return HC_FALSE;
    }
#else
    if (!ParcelReadUint16(parcel, &tlv->tag)) {
        return HC_FALSE;
    }
#endif

    if (tlv->tag != tlv->checkTag) {
        return HC_FALSE;
    }
#ifdef IS_BIG_ENDIAN
    if (!ParcelReadUint32Revert(parcel, &tlv->length)) {
        return HC_FALSE;
    }
#else
    if (!ParcelReadUint32(parcel, &tlv->length)) {
        return HC_FALSE;
    }
#endif
    if (tlv->length > MAX_CRED_TLV_LENGTH) {
        return HC_FALSE;
    }
    return HC_TRUE;
}

int64_t ParseCredTlvNode(CredTlvBase *tlv, HcParcel *parcel, HcBool strict)
{
    if (!ParseCredTlvHead(tlv, parcel)) {
        return CRED_TLV_FAIL;
    } else {
        if (GetParcelDataSize(parcel) < tlv->length) {
            return CRED_TLV_FAIL;
        }

        int64_t ret = tlv->parse(tlv, parcel, strict);
        if (ret < 0 || ret > MAX_CRED_TLV_LENGTH) {
            return CRED_TLV_FAIL;
        } else {
            return ret + sizeof(tlv->tag) + sizeof(tlv->length);
        }
    }
}

int64_t GetlenCredTlvNode(CredTlvBase *tlv)
{
    int64_t bodyLen = tlv->getlen(tlv);
    if (bodyLen < 0 || bodyLen > MAX_CRED_TLV_LENGTH) {
        return CRED_TLV_FAIL;
    } else {
        tlv->length = bodyLen + sizeof(tlv->tag) + sizeof(tlv->length);
        return tlv->length;
    }
}

void DeinitCredTlvNode(CredTlvBase *tlv)
{
    if (tlv != NULL) {
        tlv->deinit(tlv);
    }
}

int64_t EncodeCredTlvNode(CredTlvBase *tlv, HcParcel *parcel, HcBool isRoot)
{
    int64_t bodyLen = tlv->getlen(tlv);
    if (bodyLen < 0 || bodyLen > MAX_CRED_TLV_LENGTH) {
        return CRED_TLV_FAIL;
    } else if (bodyLen == 0) {
        if (isRoot) {
            ResetParcel(parcel, sizeof(uint16_t) + sizeof(uint32_t), 0);
        }
#ifdef IS_BIG_ENDIAN
        ParcelWriteUint16Revert(parcel, tlv->checkTag);
        ParcelWriteUint32Revert(parcel, bodyLen);
#else
        ParcelWriteUint16(parcel, tlv->checkTag);
        ParcelWriteUint32(parcel, bodyLen);
#endif
        return sizeof(tlv->tag) + sizeof(tlv->length);
    } else { // has value
        if (isRoot) {
            ResetParcel(parcel, sizeof(uint16_t) + sizeof(uint32_t) + bodyLen, 0);
        }
        int64_t encodeLen;
        tlv->length = (uint32_t)bodyLen;
#ifdef IS_BIG_ENDIAN
        ParcelWriteUint16Revert(parcel, tlv->checkTag);
        ParcelWriteUint32Revert(parcel, tlv->length);
#else
        ParcelWriteUint16(parcel, tlv->checkTag);
        ParcelWriteUint32(parcel, tlv->length);
#endif
        encodeLen = tlv->encode(tlv, parcel);
        if (encodeLen < 0 || encodeLen > MAX_CRED_TLV_LENGTH) {
            return CRED_TLV_FAIL;
        } else {
            return encodeLen + sizeof(tlv->tag) + sizeof(tlv->length);
        }
    }
}

static CredTlvBase* GetEmptyStructNode(CredTlvBase *tlv, unsigned short tag)
{
    if (tlv == NULL) {
        return NULL;
    }

    unsigned int index;
    unsigned int memberCount = *(unsigned int *)((char *)tlv + offsetof(CredTlvOffsetExample, offsetCount));
    unsigned int *offset = (unsigned int *)((char *)tlv + offsetof(CredTlvOffsetExample, offset));
    for (index = 0; index < memberCount; ++index) {
        CredTlvBase *tlvChild = (CredTlvBase *)(((char *)tlv) + offset[index]);
        if (tlvChild->checkTag == tag && tlvChild->hasValue == 0) {
            return tlvChild;
        }
    }

    return NULL;
}

static int64_t CheckStructNodeAllHasValue(CredTlvBase *tlv)
{
    if (tlv == NULL) {
        return 0;
    } else {
        unsigned int index;
        unsigned int memberCount = *(unsigned int *)((char *)tlv + offsetof(CredTlvOffsetExample, offsetCount));
        unsigned int *offset = (unsigned int *)((char *)tlv + offsetof(CredTlvOffsetExample, offset));
        for (index = 0; index < memberCount; ++index) {
            CredTlvBase *tlvChild = (CredTlvBase *)(((char *)tlv) + offset[index]);
            if (tlvChild->hasValue == 0) {
                return -1;
            }
        }
    }

    return 0;
}

static void SetStructNodeHasValue(CredTlvBase *tlv)
{
    if (tlv != NULL) {
        tlv->hasValue = 1;
    }
}

static int64_t ParseAndSkipTlvUnknownNode(HcParcel *parcel)
{
    // read tag
    uint16_t tag = 0;
    if (!ParcelReadUint16(parcel, &tag)) {
        return CRED_TLV_FAIL;
    }

    // read length
    uint32_t length = 0;
    if (!ParcelReadUint32(parcel, &length)) {
        return CRED_TLV_FAIL;
    }

    // pop data
    if (!ParcelPopFront(parcel, length)) {
        return CRED_TLV_FAIL;
    }

    return sizeof(tag) + sizeof(length) + length;
}

int64_t ParseCredTlvStruct(CredTlvBase *tlv, HcParcel *parcel, HcBool strict)
{
    int64_t childTotalLength = 0;
    do {
        uint16_t tag = 0;
        if (!ParcelReadWithoutPopData(parcel, &tag, sizeof(tag))) {
            return CRED_TLV_FAIL;
        }
        CredTlvBase *tlvChild = GetEmptyStructNode(tlv, tag);
        if (tlvChild == NULL) {
            if (strict) {
                return CRED_TLV_FAIL;
            }

            int64_t unknownChildLength = ParseAndSkipTlvUnknownNode(parcel);
            if (unknownChildLength < 0 || unknownChildLength > MAX_CRED_TLV_LENGTH) {
                return CRED_TLV_FAIL;
            }
            childTotalLength += unknownChildLength;
            if (childTotalLength > MAX_CRED_TLV_LENGTH) {
                return CRED_TLV_FAIL;
            }
        } else {
            int64_t childLength = ParseCredTlvNode(tlvChild, parcel, strict);
            if (childLength < 0 || childLength > MAX_CRED_TLV_LENGTH) {
                return CRED_TLV_FAIL;
            }
            SetStructNodeHasValue(tlvChild);
            childTotalLength += childLength;
            if (childTotalLength > MAX_CRED_TLV_LENGTH) {
                return CRED_TLV_FAIL;
            }
        }
    } while (childTotalLength < tlv->length);

    if (childTotalLength > tlv->length) {
        return CRED_TLV_FAIL;
    }

    if (strict && CheckStructNodeAllHasValue(tlv) != 0) {
        return CRED_TLV_FAIL;
    }

    return childTotalLength;
}

int64_t EncodeCredTlvStruct(CredTlvBase *tlv, HcParcel *parcel)
{
    unsigned int index;
    unsigned int memberCount = *(unsigned int *)((char *)tlv + offsetof(CredTlvOffsetExample, offsetCount));
    unsigned int *offset = (unsigned int *)((char *)tlv + offsetof(CredTlvOffsetExample, offset));

    uint32_t totalLen = 0;
    for (index = 0; index < memberCount; ++index) {
        CredTlvBase *tlvChild = (CredTlvBase *)(((char *)tlv) + offset[index]);
        int64_t childLen = EncodeCredTlvNode(tlvChild, parcel, HC_FALSE);
        if (childLen < 0 || childLen > MAX_CRED_TLV_LENGTH) {
            return CRED_TLV_FAIL;
        } else {
            totalLen += childLen;
        }
        if (totalLen > MAX_CRED_TLV_LENGTH) {
            return CRED_TLV_FAIL;
        }
    }

    return totalLen;
}

int64_t GetLenCredTlvStruct(CredTlvBase *tlv)
{
    unsigned int index;
    unsigned int memberCount = *(unsigned int *)((char *)tlv + offsetof(CredTlvOffsetExample, offsetCount));
    unsigned int *offset = (unsigned int *)((char *)tlv + offsetof(CredTlvOffsetExample, offset));
    int64_t childTotalLength = 0;

    for (index = 0; index < memberCount; ++index) {
        CredTlvBase *tlvChild = (CredTlvBase *)(((char *)tlv) + offset[index]);
        int64_t childLength = GetlenCredTlvNode(tlvChild);
        if (childLength <= 0 || childLength > MAX_CRED_TLV_LENGTH) {
            return CRED_TLV_FAIL;
        } else {
            childTotalLength += childLength;
        }
        if (childTotalLength > MAX_CRED_TLV_LENGTH) {
            return CRED_TLV_FAIL;
        }
    }

    return childTotalLength;
}

void DeinitCredTlvStruct(CredTlvBase *tlv)
{
    unsigned int index;
    unsigned int memberCount = *(unsigned int *)((char *)tlv + offsetof(CredTlvOffsetExample, offsetCount));
    unsigned int *offset = (unsigned int *)((char *)tlv + offsetof(CredTlvOffsetExample, offset));

    for (index = 0; index < memberCount; ++index) {
        CredTlvBase *tlvChild = (CredTlvBase *)(((char *)tlv) + offset[index]);
        DeinitCredTlvNode(tlvChild);
    }
}

HcBool DecodeCredTlvMessage(CredTlvBase *msg, HcParcel *parcel, HcBool strict)
{
    if (msg == NULL || parcel == NULL) {
        return HC_FALSE;
    } else {
        int64_t msgLen = ParseCredTlvNode(msg, parcel, strict);
        if (msgLen > MAX_CRED_TLV_LENGTH) {
            return HC_FALSE;
        }
        if ((int64_t)(msg->length + sizeof(msg->length) + sizeof(msg->tag)) != msgLen) {
            return HC_FALSE;
        }

        if (GetParcelDataSize(parcel) != 0) {
            return HC_FALSE;
        }
    }

    return HC_TRUE;
}


HcBool EncodeCredTlvMessage(CredTlvBase *msg, HcParcel *parcel)
{
    if (msg == NULL || parcel == NULL) {
        return HC_FALSE;
    } else {
        if (EncodeCredTlvNode(msg, parcel, HC_TRUE) < 0) {
            return HC_FALSE;
        }
    }

    return HC_TRUE;
}

int64_t ParseCredTlvBuffer(CredTlvBase *tlv, HcParcel *parcel, HcBool strict)
{
    (void)strict;
    CredTlvBuffer *realTlv = (CredTlvBuffer *)(tlv);
    if (tlv->length == 0 || ParcelReadParcel(parcel, &realTlv->data, tlv->length, HC_FALSE)) {
        return tlv->length;
    } else {
        return CRED_TLV_FAIL;
    }
}

int64_t GetlenCredTlvBuffer(CredTlvBase *tlv)
{
    CredTlvBuffer *realTlv = (CredTlvBuffer *)(tlv);
    return (int64_t)GetParcelDataSize(&realTlv->data);
}

int64_t EncodeCredTlvBuffer(CredTlvBase *tlv, HcParcel *parcel)
{
    CredTlvBuffer *realTlv = (CredTlvBuffer *)(tlv);
    int64_t len = GetlenCredTlvBuffer(tlv);
    if (len <= 0 || len > MAX_CRED_TLV_LENGTH) {
        return CRED_TLV_FAIL;
    }

    if (ParcelReadParcel(&realTlv->data, parcel, len, HC_TRUE)) {
        return len;
    } else {
        return CRED_TLV_FAIL;
    }
}

void DeinitCredTlvBuffer(CredTlvBase *tlv)
{
    DeleteParcel(&((CredTlvBuffer *)tlv)->data);
}

void InitCredTlvBuffer(CredTlvBuffer *tlv, unsigned short checkTag)
{
    (void)memset_s(&tlv->base, sizeof(tlv->base), 0, sizeof(tlv->base));
    tlv->base.parse = ParseCredTlvBuffer;
    tlv->base.getlen = GetlenCredTlvBuffer;
    tlv->base.encode = EncodeCredTlvBuffer;
    tlv->base.deinit = DeinitCredTlvBuffer;
    tlv->base.checkTag = checkTag;
    tlv->data = CreateParcel(PARCEL_DEFAULT_LENGTH, PARCEL_DEFAULT_ALLOC_UNIT);
}

int64_t ParseCredTlvString(CredTlvBase *tlv, HcParcel *parcel, HcBool strict)
{
    (void)strict;
    CredTlvString *realTlv = (CredTlvString *)(tlv);
    ClearParcel(&realTlv->data.parcel);
    if (tlv->length == 0 || ParcelReadParcel(parcel, &realTlv->data.parcel, tlv->length, HC_FALSE)) {
        return tlv->length;
    } else {
        return CRED_TLV_FAIL;
    }
}

int64_t GetlenCredTlvString(CredTlvBase *tlv)
{
    CredTlvString *realTlv = (CredTlvString *)(tlv);
    return (int64_t)GetParcelDataSize(&realTlv->data.parcel);
}

int64_t EncodeCredTlvString(CredTlvBase *tlv, HcParcel *parcel)
{
    CredTlvString *realTlv = (CredTlvString *)(tlv);
    int64_t len = GetlenCredTlvString(tlv);
    if (len <= 0 || len > MAX_CRED_TLV_LENGTH) {
        return CRED_TLV_FAIL;
    }

    if (ParcelReadParcel(&realTlv->data.parcel, parcel, len, HC_TRUE)) {
        return len;
    } else {
        return CRED_TLV_FAIL;
    }
}

void DeinitCredTlvString(CredTlvBase *tlv)
{
    DeleteString(&((CredTlvString*)tlv)->data);
}

void InitCredTlvString(CredTlvString *tlv, unsigned short checkTag)
{
    (void)memset_s(&tlv->base, sizeof(tlv->base), 0, sizeof(tlv->base));
    tlv->base.parse = ParseCredTlvString;
    tlv->base.getlen = GetlenCredTlvString;
    tlv->base.encode = EncodeCredTlvString;
    tlv->base.deinit = DeinitCredTlvString;
    tlv->base.checkTag = checkTag;
    tlv->data = CreateString();
}

unsigned short GetCredTag(unsigned short checkTag, unsigned short defaultTag)
{
    if (checkTag == USE_DEFAULT_TAG) {
        return defaultTag;
    } else {
        return checkTag;
    }
}

void DeinitCredTlvFixMember(CredTlvBase* tlv)
{
    (void)tlv;
    return;
}

#ifdef IS_BIG_ENDIAN
DEFINE_CRED_TLV_FIX_LENGTH_TYPE(CredTlvInt64, NEED_REVERT)
DEFINE_CRED_TLV_FIX_LENGTH_TYPE(CredTlvInt32, NEED_REVERT)
DEFINE_CRED_TLV_FIX_LENGTH_TYPE(CredTlvInt16, NEED_REVERT)
DEFINE_CRED_TLV_FIX_LENGTH_TYPE(CredTlvInt8, NEED_REVERT)
DEFINE_CRED_TLV_FIX_LENGTH_TYPE(CredTlvUint64, NEED_REVERT)
DEFINE_CRED_TLV_FIX_LENGTH_TYPE(CredTlvUint32, NEED_REVERT)
DEFINE_CRED_TLV_FIX_LENGTH_TYPE(CredTlvUint16, NEED_REVERT)
DEFINE_CRED_TLV_FIX_LENGTH_TYPE(CredTlvUint8, NEED_REVERT)
#else
DEFINE_CRED_TLV_FIX_LENGTH_TYPE(CredTlvInt64, NO_REVERT)
DEFINE_CRED_TLV_FIX_LENGTH_TYPE(CredTlvInt32, NO_REVERT)
DEFINE_CRED_TLV_FIX_LENGTH_TYPE(CredTlvInt16, NO_REVERT)
DEFINE_CRED_TLV_FIX_LENGTH_TYPE(CredTlvInt8, NO_REVERT)
DEFINE_CRED_TLV_FIX_LENGTH_TYPE(CredTlvUint64, NO_REVERT)
DEFINE_CRED_TLV_FIX_LENGTH_TYPE(CredTlvUint32, NO_REVERT)
DEFINE_CRED_TLV_FIX_LENGTH_TYPE(CredTlvUint16, NO_REVERT)
DEFINE_CRED_TLV_FIX_LENGTH_TYPE(CredTlvUint8, NO_REVERT)
#endif
