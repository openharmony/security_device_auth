/*
 * Copyright (C) 2023 Huawei Device Co., Ltd.
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

#include "auth_sub_session.h"

#include "device_auth_defines.h"
#include "hc_log.h"
#include "hc_types.h"
#include "iso_protocol.h"
#include "ec_speke_protocol.h"
#include "dl_speke_protocol.h"

#define MAX_MSG_LEN 1024

typedef int32_t (*CreateProtocolFunc)(const void *baseParams, bool isClient, BaseProtocol **);

typedef struct {
    int32_t protocolType;
    CreateProtocolFunc createProtocolFunc;
} ProtocolComponent;

typedef struct {
    AuthSubSession base;
    BaseProtocol *instance;
} AuthSubSessionImpl;

static const ProtocolComponent PROTOCOL_COMPONENT_LIB[] = {
#ifdef ENABLE_EC_SPEKE
    { PROTOCOL_TYPE_EC_SPEKE, CreateEcSpekeProtocol },
#endif
#ifdef ENABLE_P2P_BIND_DL_SPEKE
    { PROTOCOL_TYPE_DL_SPEKE, CreateDlSpekeProtocol },
#endif
#ifdef ENABLE_ISO
    { PROTOCOL_TYPE_ISO, CreateIsoProtocol },
#endif
};

static const ProtocolComponent *GetProtocolComponent(int32_t protocolType)
{
    for (uint32_t i = 0; i < sizeof(PROTOCOL_COMPONENT_LIB) / sizeof(ProtocolComponent); i++) {
        if (PROTOCOL_COMPONENT_LIB[i].protocolType == protocolType) {
            return &PROTOCOL_COMPONENT_LIB[i];
        }
    }
    return NULL;
}

static int32_t StartAuthSubSession(AuthSubSession *self, CJson **returnSendMsg)
{
    if ((self == NULL) || (returnSendMsg == NULL)) {
        LOGE("invalid params.");
        return HC_ERR_INVALID_PARAMS;
    }
    AuthSubSessionImpl *impl = (AuthSubSessionImpl *)self;
    BaseProtocol *protocol = impl->instance;
    int32_t res = protocol->start(protocol, returnSendMsg);
    if (res != HC_SUCCESS) {
        return res;
    }
    impl->base.state = AUTH_STATE_RUNNING;
    return HC_SUCCESS;
}

static int32_t ProcessAuthSubSession(AuthSubSession *self, const CJson *receviedMsg, CJson **returnSendMsg)
{
    if ((self == NULL) || (receviedMsg == NULL) || (returnSendMsg == NULL)) {
        LOGE("invalid params.");
        return HC_ERR_INVALID_PARAMS;
    }
    AuthSubSessionImpl *impl = (AuthSubSessionImpl *)self;
    BaseProtocol *protocol = impl->instance;
    int32_t res = protocol->process(protocol, receviedMsg, returnSendMsg);
    if (res != HC_SUCCESS) {
        return res;
    }
    impl->base.state = (protocol->curState == protocol->finishState) ? AUTH_STATE_FINISH : AUTH_STATE_RUNNING;
    return HC_SUCCESS;
}

static int32_t SetPsk(AuthSubSession *self, const Uint8Buff *psk)
{
    if ((self == NULL) || (psk == NULL)) {
        LOGE("invalid params.");
        return HC_ERR_INVALID_PARAMS;
    }
    AuthSubSessionImpl *impl = (AuthSubSessionImpl *)self;
    return impl->instance->setPsk(impl->instance, psk);
}

static int32_t SetSelfProtectedMsg(AuthSubSession *self, const Uint8Buff *selfMsg)
{
    if ((self == NULL) || (selfMsg == NULL)) {
        LOGE("invalid params.");
        return HC_ERR_INVALID_PARAMS;
    }
    AuthSubSessionImpl *impl = (AuthSubSessionImpl *)self;
    return impl->instance->setSelfProtectedMsg(impl->instance, selfMsg);
}

static int32_t SetPeerProtectedMsg(AuthSubSession *self, const Uint8Buff *peerMsg)
{
    if ((self == NULL) || (peerMsg == NULL)) {
        LOGE("invalid params.");
        return HC_ERR_INVALID_PARAMS;
    }
    AuthSubSessionImpl *impl = (AuthSubSessionImpl *)self;
    return impl->instance->setPeerProtectedMsg(impl->instance, peerMsg);
}

static int32_t GetSessionKey(AuthSubSession *self, Uint8Buff *returnSessionKey)
{
    if ((self == NULL) || (returnSessionKey == NULL)) {
        LOGE("invalid params.");
        return HC_ERR_INVALID_PARAMS;
    }
    AuthSubSessionImpl *impl = (AuthSubSessionImpl *)self;
    return impl->instance->getSessionKey(impl->instance, returnSessionKey);
}

static void DestroyAuthSubSession(AuthSubSession *self)
{
    if (self == NULL) {
        LOGD("self is NULL.");
        return;
    }
    AuthSubSessionImpl *impl = (AuthSubSessionImpl *)self;
    impl->instance->destroy(impl->instance);
    HcFree(impl);
}

int32_t CreateAuthSubSession(int32_t protocolType, void *params, bool isClient, AuthSubSession **returnObj)
{
    if ((params == NULL) || (returnObj == NULL)) {
        LOGE("invalid params.");
        return HC_ERR_INVALID_PARAMS;
    }
    const ProtocolComponent *component = GetProtocolComponent(protocolType);
    if (component == NULL) {
        LOGE("no protocol component found. type = %d.", protocolType);
        return HC_ERR_UNSUPPORTED_VERSION;
    }
    BaseProtocol *protocol;
    int32_t res = component->createProtocolFunc(params, isClient, &protocol);
    if (res != HC_SUCCESS) {
        LOGE("create protocol fail.");
        return res;
    }
    AuthSubSessionImpl *impl = (AuthSubSessionImpl *)HcMalloc(sizeof(AuthSubSessionImpl), 0);
    if (impl == NULL) {
        LOGE("allocate impl memory fail.");
        protocol->destroy(protocol);
        return HC_ERR_ALLOC_MEMORY;
    }
    impl->base.protocolType = protocolType;
    impl->base.state = AUTH_STATE_INIT;
    impl->base.start = StartAuthSubSession;
    impl->base.process = ProcessAuthSubSession;
    impl->base.setPsk = SetPsk;
    impl->base.setSelfProtectedMsg = SetSelfProtectedMsg;
    impl->base.setPeerProtectedMsg = SetPeerProtectedMsg;
    impl->base.getSessionKey = GetSessionKey;
    impl->base.destroy = DestroyAuthSubSession;
    impl->instance = protocol;
    *returnObj = (AuthSubSession *)impl;
    return HC_SUCCESS;
}

bool IsProtocolSupport(int32_t protocolType)
{
    return GetProtocolComponent(protocolType) != NULL;
}
