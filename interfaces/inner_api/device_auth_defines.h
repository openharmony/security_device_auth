/*
 * Copyright (C) 2021-2023 Huawei Device Co., Ltd.
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

#ifndef DEVICE_AUTH_DEFINES_H
#define DEVICE_AUTH_DEFINES_H

/**
 * @brief describes all error codes
 */
enum {
    /* common error code, 0x00000000 ~ 0x00000FFF */
    HC_SUCCESS = 0x00000000,                                              // 0

    HC_ERROR = 0x00000001,                                                // 1
    HC_ERR_INVALID_PARAMS = 0x00000002,                                   // 2
    HC_ERR_INVALID_LEN = 0x00000003,                                      // 3
    HC_ERR_NULL_PTR = 0x00000004,                                         // 4
    HC_ERR_ALLOC_MEMORY = 0x00000005,                                     // 5
    HC_ERR_MEMORY_COPY = 0x00000006,                                      // 6
    HC_ERR_CONVERT_FAILED = 0x00000007,                                   // 7
    HC_ERR_NOT_SUPPORT = 0x00000008,                                      // 8
    HC_ERR_TIME_OUT = 0x00000009,                                         // 9
    HC_ERR_CASE = 0x0000000A,                                             // 10
    HC_ERR_BAD_TIMING = 0x0000000B,                                       // 11
    HC_ERR_PEER_ERROR = 0x0000000C,                                       // 12
    HC_ERR_FILE = 0x0000000D,                                             // 13
    HC_ERR_MEMORY_COMPARE = 0x0000000E,                                   // 14
    HC_ERR_OUT_OF_LIMIT = 0x0000000F,                                     // 15
    HC_ERR_INIT_FAILED = 0x00000010,                                      // 16

    /* error code for algorithm adapter , 0x00001000 ~ 0x00001FFF */
    HC_ERR_KEY_NOT_EXIST = 0x00001001,                                    // 4097
    HC_ERR_GENERATE_KEY_FAILED = 0x00001002,                              // 4098
    HC_ERR_INVALID_PUBLIC_KEY = 0x00001003,                               // 4099
    HC_ERR_VERIFY_FAILED = 0x00001004,                                    // 4100
    HC_ERR_HASH_FAIL = 0x00001005,                                        // 4101
    HC_ERR_ALG_FAIL = 0x00001006,                                         // 4102
    HC_ERR_HKS_PARAM_SET_FAILED = 0x00001007,                             // 4103

    /* error code for json util , 0x00002000 ~ 0x00002FFF */
    HC_ERR_JSON_FAIL = 0x00002001,                                        // 8193
    HC_ERR_JSON_CREATE = 0x00002002,                                      // 8194
    HC_ERR_JSON_GET = 0x00002003,                                         // 8195
    HC_ERR_JSON_ADD = 0x00002004,                                         // 8196
    HC_ERR_PACKAGE_JSON_TO_STRING_FAIL = 0x00002005,                      // 8197

    /* error code for ipc, 0x00003000 ~ 0x00003FFF */
    HC_ERR_IPC_INTERNAL_FAILED = 0x00003001,                              // 12289
    HC_ERR_IPC_UNKNOW_OPCODE = 0x00003002,                                // 12290
    HC_ERR_IPC_CALL_DATA_LENGTH = 0x00003003,                             // 12291
    HC_ERR_IPC_METHOD_ID_INVALID = 0x00003004,                            // 12292
    HC_ERR_IPC_BAD_MESSAGE_LENGTH = 0x00003005,                           // 12293
    HC_ERR_IPC_BAD_VAL_LENGTH = 0x00003006,                               // 12294
    HC_ERR_IPC_BAD_PARAM_NUM = 0x00003007,                                // 12295
    HC_ERR_IPC_BAD_MSG_TYPE = 0x00003008,                                 // 12296
    HC_ERR_IPC_GET_SERVICE = 0x00003009,                                  // 12297
    HC_ERR_IPC_GET_PROXY = 0x0000300A,                                    // 12298
    HC_ERR_IPC_INIT = 0x0000300B,                                         // 12299
    HC_ERR_IPC_BUILD_PARAM = 0x0000300C,                                  // 12300
    HC_ERR_IPC_PROC_FAILED = 0x0000300D,                                  // 12301
    HC_ERR_IPC_UNKNOW_REPLY = 0x0000300E,                                 // 12302
    HC_ERR_IPC_OUT_DATA_NUM = 0x0000300F,                                 // 12303
    HC_ERR_IPC_OUT_DATA = 0x00003010,                                     // 12304
    HC_ERR_IPC_BAD_PARAM = 0x00003011,                                    // 12305
    HC_ERR_IPC_SERVICE_DIED = 0x00003012,                                 // 12306

    /* error code for module , 0x00004000 ~ 0x00004FFF */
    HC_ERR_MODULE_NOT_FOUNT = 0x00004001,                                 // 16385
    HC_ERR_UNSUPPORTED_METHOD = 0x00004002,                               // 16386
    HC_ERR_UNSUPPORTED_VERSION = 0x00004003,                              // 16387
    HC_ERR_UNSUPPORTED_CURVE = 0x00004004,                                // 16388
    HC_ERR_BAD_MESSAGE = 0x00004005,                                      // 16389
    HC_ERR_PROOF_NOT_MATCH = 0x00004006,                                  // 16390
    HC_ERR_INIT_TASK_FAIL = 0x00004007,                                   // 16391
    HC_ERR_TASK_IS_NULL = 0x00004008,                                     // 16392
    HC_ERR_TASK_ID_IS_NOT_MATCH = 0x00004009,                             // 16393
    HC_ERR_INVALID_ALG = 0x0000400A,                                      // 16394
    HC_ERR_IGNORE_MSG = 0x0000400B,                                       // 16395
    HC_ERR_LOCAL_IDENTITY_NOT_EXIST = 0x0000400C,                         // 16396
    HC_ERR_UNSUPPORTED_OPCODE = 0x0000400D,                               // 16397
    HC_ERR_AUTH_TOKEN = 0x0000400E,                                       // 16398
    HC_ERR_PSK = 0x0000400F,                                              // 16399
    HC_ERR_TOKEN = 0x00004010,                                            // 16400
    HC_ERR_GENERATE_RANDOM = 0x00004011,                                  // 16401
    HC_ERR_STATUS = 0x00004012,                                           // 16402
    HC_ERR_STEP = 0x00004013,                                             // 16403
    HC_ERR_IDENTITY_DUPLICATED = 0x00004014,                              // 16404

    /* error code for group , 0x00005000 ~ 0x00005FFF */
    HC_ERR_ACCESS_DENIED = 0x00005001,                                    // 20481
    HC_ERR_CALLBACK_NOT_FOUND = 0x00005002,                               // 20482
    HC_ERR_SERVICE_NEED_RESTART = 0x00005003,                             // 20483
    HC_ERR_NO_CANDIDATE_GROUP = 0x00005004,                               // 20484
    HC_ERR_TRANSMIT_FAIL = 0x00005005,                                    // 20485
    HC_ERR_REQUEST_EXIST = 0x00005006,                                    // 20486
    HC_ERR_REQUEST_NOT_FOUND = 0x00005007,                                // 20487
    HC_ERR_SESSION_NOT_EXIST = 0x00005008,                                // 20488
    HC_ERR_SESSION_ID_CONFLICT = 0x00005009,                              // 20489
    HC_ERR_REQ_REJECTED = 0x0000500A,                                     // 20490
    HC_ERR_SERVER_CONFIRM_FAIL = 0x0000500B,                              // 20491
    HC_ERR_CREATE_SESSION_FAIL = 0x0000500C,                              // 20492
    HC_ERR_SESSION_IS_FULL = 0x0000500D,                                  // 20493
    HC_ERR_INVALID_UDID = 0x0000500E,                                     // 20494
    HC_ERR_INVALID_TCIS_ID = 0x0000500F,                                  // 20495
    HC_ERR_DEL_GROUP = 0x00005010,                                        // 20496
    HC_ERR_INFORM_ERR = 0x00005011,                                       // 20497
    HC_ERR_ONLY_ACCOUNT_RELATED = 0x00005012,                             // 20498

    /* error code for database , 0x00006000 ~ 0x00006FFF */
    HC_ERR_DB = 0x00006001,                                               // 24577
    HC_ERR_BEYOND_LIMIT = 0x00006002,                                     // 24578
    HC_ERR_SAVE_DB_FAILED = 0x00006003,                                   // 24579
    HC_ERR_ROLE_NOT_EXIST = 0x00006004,                                   // 24580
    HC_ERR_MANAGER_NOT_EXIST = 0x00006005,                                // 24581
    HC_ERR_GROUP_DUPLICATE = 0x00006006,                                  // 24582
    HC_ERR_GROUP_NOT_EXIST = 0x00006007,                                  // 24583
    HC_ERR_DEVICE_NOT_EXIST = 0x00006008,                                 // 24584
    HC_ERR_DEVICE_DUPLICATE = 0x00006009,                                 // 24585
    HC_ERR_LOST_DATA = 0x0000600A,                                        // 24586
    HC_ERR_OS_ACCOUNT_NOT_UNLOCKED = 0x0000600B,                          // 24587

    /* error code for broadcast , 0x00007000 ~ 0x00007FFF */
    HC_ERR_LISTENER_NOT_EXIST = 0x00007001,                               // 28673

    /* error code for channel , 0x00008000 ~ 0x00008FFF */
    HC_ERR_CHANNEL_NOT_EXIST = 0x00008001,                                // 32769
    HC_ERR_SOFT_BUS = 0x00008002,                                         // 32770

    /* error code used on account-related authenticator */
    HC_ERR_GET_PK_INFO = 0x00009001,                                      // 36865
    HC_ERR_ACCOUNT_TASK_IS_FULL = 0x00009002,                             // 36866
    HC_ERR_ACCOUNT_ECDH_FAIL = 0x00009003,                                // 36867
    HC_ERR_ACCOUNT_VERIFY_PK_SIGN = 0x00009004,                           // 36868
    HC_ERR_AUTH_STATUS = 0x00009005,                                      // 36869
    HC_ERR_AUTH_INTERNAL = 0x00009006,                                    // 36870
    HC_ERR_ADD_ACCOUNT_TASK = 0x00009007,                                 // 36871
    HC_ERR_CLIENT_CONFIRM_PROTOCOL = 0x00009008,                          // 36872
    HC_ERR_SERVER_CONFIRM_PROTOCOL = 0x00009009,                          // 36873

    /* error code used on DAS service */
    INVALID_PARAMETERS = 0xF0000001,                                      // -268435455
    EXCEED_AUTHORITY = 0xF0000002,                                        // -268435454
    TIMEOUT = 0xF0000003,                                                 // -268435453
    NOT_REGISTERED = 0xF0000004,                                          // -268435452
    NOT_TRUST_PEER = 0xF0000005,                                          // -268435451
    NOT_TRUST_CONTROLLER = 0xF0000006,                                    // -268435450
    NOT_TRUST_ACCESSORY = 0xF0000007,                                     // -268435449
    OVER_MAX_TRUST_NUM = 0xF0000008,                                      // -268435448
    CONNECTION_INTERRUPTED = 0xF0000009,                                  // -268435447
    UNSUPPORTED_VERSION = 0xF000000A,                                     // -268435446
    BAD_PAYLOAD = 0xF000000B,                                             // -268435445
    ALGORITHM_UNSUPPORTED = 0xF000000C,                                   // -268435444
    PROOF_MISMATCH = 0xF000000D,                                          // -268435443
};

#endif
