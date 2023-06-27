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

#ifndef DEV_AUTH_BASE_CMD_H
#define DEV_AUTH_BASE_CMD_H

#include "json_utils.h"
#include "string_util.h"

typedef enum {
    ABORT_IF_ERROR = 1,
    CONTINUE_IF_ERROR = 2
} ErrorHandleStrategy;

typedef enum {
    CMD_STATE_CONTINUE = 1,
    CMD_STATE_FINISH = 2,
} CmdState;

typedef struct BaseCmd BaseCmd;
struct BaseCmd {
    int32_t type;
    bool isCaller;
    int32_t strategy;
    int32_t curState;
    int32_t beginState;
    int32_t finishState;
    int32_t failState;
    int32_t (*start)(BaseCmd *, CJson **);
    int32_t (*process)(BaseCmd *, const CJson *, CJson **, CmdState *);
    void (*destroy)(BaseCmd *);
};

#endif
