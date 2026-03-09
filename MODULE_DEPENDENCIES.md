# device_auth 模块依赖关系图

## 模块架构概览

```
device_auth (根模块)
├── common_lib (公共库)
│   ├── impl/src (实现)
│   └── interfaces (接口)
├── deps_adapter (依赖适配器)
│   ├── key_management_adapter (密钥管理适配器)
│   └── os_adapter (操作系统适配器)
├── services (服务层)
│   ├── frameworks (框架)
│   ├── protocol (协议)
│   ├── session_manager (会话管理)
│   ├── identity_service (身份服务)
│   ├── legacy (遗留组件)
│   ├── ext_plugin_manager (扩展插件管理)
│   ├── data_manager (数据管理)
│   ├── privacy_enhancement (隐私增强)
│   ├── mk_agree (MK 协议)
│   ├── key_agree_sdk (密钥协商 SDK)
│   └── sa (系统服务)
└── interfaces (接口层)
    └── kits/napi (NAPI 接口)
```

## 核心依赖关系

### 1. services (服务层) 依赖

```
services (主服务)
├── 依赖 common_lib (公共库)
├── 依赖 deps_adapter (依赖适配器)
│   ├── key_management_adapter (密钥管理)
│   └── os_adapter (操作系统适配器)
└── 内部模块依赖
    ├── frameworks (框架层)
    ├── protocol (协议层)
    ├── session_manager (会话管理)
    ├── identity_service (身份服务)
    ├── legacy (遗留组件)
    ├── ext_plugin_manager (扩展插件管理)
    ├── data_manager (数据管理)
    ├── privacy_enhancement (隐私增强)
    ├── mk_agree (MK 协议)
    └── sa (系统服务)
```

### 2. deps_adapter (依赖适配器) 依赖

```
deps_adapter
├── key_management_adapter (密钥管理适配器)
│   ├── 依赖 common mbedtls/ec_adapter
│   ├── 依赖 common huks_adapter
│   ├── 依赖 common huks_adapter_utils
│   └── 依赖 common alg_loader
└── os_adapter (操作系统适配器)
    ├── 依赖 common hc_log (日志)
    ├── 依赖 common hc_err_trace (错误跟踪)
    ├── 依赖 linux hc_file (文件操作)
    ├── 依赖 linux hc_thread (线程)
    ├── 依赖 linux hc_condition (条件变量)
    ├── 依赖 linux hc_init_protection (初始化保护)
    └── 依赖 linux hc_dev_info (设备信息)
```

### 3. frameworks (框架层) 依赖

```
frameworks
├── 依赖 common_lib (公共库)
├── 依赖 deps_adapter (依赖适配器)
├── 内部模块
│   ├── src/module (模块管理)
│   ├── src/task_manager (任务管理)
│   ├── src/session (会话)
│   ├── src/os_account_adapter (账号适配器)
│   ├── src/plugin_adapter (插件适配器)
│   ├── src/hiview_adapter (HiView 适配器)
│   ├── src/permission_adapter (权限适配器)
│   └── src/security_label_adapter (安全标签适配器)
└── sdk (SDK)
    └── sa_load_on_demand (按需加载)
```

### 4. protocol (协议层) 依赖

```
protocol
├── 依赖 common_lib (公共库)
├── 依赖 deps_adapter (依赖适配器)
├── 内部协议模块
│   ├── pake_protocol (PAKE 协议)
│   │   ├── pake_v1_protocol (V1 协议)
│   │   ├── pake_v2_protocol (V2 协议)
│   │   ├── pake_protocol_dl_common (DL 通用)
│   │   └── pake_protocol_ec_common (EC 通用)
│   └── iso_protocol (ISO 协议)
│       ├── iso_protocol_common (ISO 通用)
│       └── iso_task (ISO 任务)
└── inc (协议接口)
```

### 5. session_manager (会话管理) 依赖

```
session_manager
├── 依赖 common_lib (公共库)
├依赖 deps_adapter (依赖适配器)
├── 依赖 services/frameworks (框架层)
├── 内部会话模块
│   ├── session (会话基础)
│   ├── mini_session (最小会话)
│   ├── v1 (V1 会话)
│   │   ├── compatible_bind_sub_session (兼容绑定子会话)
│   │   └── compatible_auth_sub_session (兼容认证子会话)
│   └── v2 (V2 会话)
│       ├── auth_sub_session (认证子会话)
│       │   ├── protocol_lib (协议库)
│       │   │   ├── dl_speke_protocol (DL-SPEKE 协议)
│       │   │   ├── ec_speke_protocol (EC-SPEKE 协议)
│       │   │   └── iso_protocol (ISO 协议)
│       │   └── expand_sub_session (扩展子会话)
│       │       └── expand_process_lib (扩展处理库)
│       │           ├── auth_code_import (认证码导入)
│       │           ├── pub_key_exchange (公钥交换)
│       │           └── save_trusted_info (保存可信信息)
│       └── expand_sub_session (扩展子会话)
```

### 6. identity_service (身份服务) 依赖

```
identity_service
├── 依赖 common_lib (公共库)
├── 依赖 deps_adapter (依赖适配器)
├── 内部模块
│   ├── src/identity_service (身份服务)
│   ├── src/identity_operation (身份操作)
│   ├── src/identity_service_impl (身份服务实现)
│   ├── cred_data_manager (凭证数据管理)
│   ├── cred_listener (凭证监听器)
│   └── cred_session_util (凭证会话工具)
```

### 7. legacy (遗留组件) 依赖

```
legacy
├── 依赖 common_lib (公共库)
├── 依赖 deps_adapter (依赖适配器)
├── 内部模块
│   ├── group_auth (组认证)
│   │   ├── group_auth_manager (组认证管理器)
│   │   ├── group_operation (组操作)
│   │   │   ├── group_operation_common (组操作通用)
│   │   │   ├── peer_to_peer_group (点对点组)
│   │   │   ├── identical_account_group (相同账号组)
│   │   │   └── across_account_group (跨账号组)
│   │   ├── group_data_manager (组数据管理器)
│   │   ├── group_manager (组管理器)
│   │   │   ├── broadcast_manager (广播管理器)
│   │   │   ├── callback_manager (回调管理器)
│   │   │   └── channel_manager (通道管理器)
│   │   │       └── soft_bus_channel (SoftBus 通道)
│   │   └── channel_manager (通道管理器)
│   └── authenticators (认证器)
│       ├── account_unrelated (账号无关)
│       │   ├── iso_task (ISO 任务)
│       │   └── pake_task (PAKE 任务)
│       │       ├── pake_v1_task (V1 任务)
│       │       └── pake_v2_task (V2 任务)
│       └── account_related (账号相关)
│           └── creds_manager (凭证管理器)
└── identity_manager (身份管理器)
    ├── src/identity_manager (身份管理器)
    ├── src/credential_operator (凭证操作符)
    ├── src/identity_common (身份通用)
    ├── src/identity_group (身份组)
    └── src/identity_p2p (身份 P2P)
```

### 8. ext_plugin_manager (扩展插件管理) 依赖

```
ext_plugin_manager
├── 依赖 common_lib (公共库)
├── 依赖 deps_adapter (依赖适配器)
├── 内部模块
│   ├── src/ext_plugin_manager (扩展插件管理器)
│   ├── src/account_related (账号相关)
│   └── inc (接口)
```

### 9. data_manager (数据管理) 依赖

```
data_manager
├── 依赖 common_lib (公共库)
├── 依赖 deps_adapter (依赖适配器)
├── 内部模块
│   ├── group_data_manager (组数据管理器)
│   └── operation_data_manager (操作数据管理器)
```

### 10. privacy_enhancement (隐私增强) 依赖

```
privacy_enhancement
├── 依赖 common_lib (公共_lib)
├── 依赖 deps_adapter (依赖适配器)
└── 内部模块
    └── src/pseudonym_manager (伪名管理器)
```

### 11. mk_agree (MK 协议) 依赖

```
mk_agree
├── 依赖 common_lib (公共库)
├── 依赖 deps_adapter (依赖适配器)
└── 内部模块
    ├── src/key_manager (密钥管理器)
    ├── src/mk_agree_task (MK 协议任务)
    └── src/mk_agree_common (MK 协议通用)
```

### 12. key_agree_sdk (密钥协商 SDK) 依赖

```
key_agree_sdk
├── 依赖 common_lib (公共库)
├── 依赖 deps_adapter (依赖适配器)
└── 内部模块
    └── src (SDK 实现)
```

### 13. sa (系统服务) 依赖

```
sa (System Ability)
├── 依赖 common_lib (公共库)
├── 依赖 deps_adapter (依赖适配器)
├── 依赖 services/frameworks (框架层)
└── 内部模块
    ├── src/sa (SA 实现)
    ├── inc (接口)
    ├── cache_common_event_handler (缓存公共事件处理器)
    ├── critical_handler (关键处理器)
    └── unload_handler (卸载处理器)
```

## 外部依赖

### 系统级依赖
- **cJSON**: JSON 解析库
- **c_utils**: 通用工具库
- **hilog**: HiLog 日志库
- **bounds_checking_function**: 边界检查函数
- **dsoftbus**: 分布式软总线
  - **kits/common**: 公共接口
  - **kits/transport**: 传输接口
  - **inner_kits/transport**: 内部传输接口
  - **sdk**: SDK 客户端

### 加密依赖
- **mbedtls**: 加密库 (EC-SPEKE, ISO 协议)
- **huks**: 硬件密钥库 (密钥管理)

### 测试依赖
- **googletest**: Google 测试框架
  - **gtest**: 测试框架
  - **gmock**: Mock 框架

## 构建目标依赖

### 主要构建目标

1. **deviceauth_sdk_build**: SDK 构建
   - 依赖: services:deviceauth_sdk

2. **deviceauth_service_build**: 服务构建
   - 依赖: services:deviceauth_service
   - 依赖: services/sa/sa_profile:deviceauth_sa_profile

3. **deviceauth_build**: 设备认证构建
   - 依赖: services:deviceauth

4. **deviceauth_napi_build**: NAPI 构建
   - 依赖: interfaces/kits/napi:deviceauth_napi

5. **deviceauth_test_build**: 测试构建
   - 依赖: 所有测试模块

## 依赖层次总结

### 第1层：基础库
- **common_lib**: 公共工具库（无内部依赖）

### 第2层：适配器层
- **deps_adapter**: 依赖 common_lib
  - **key_management_adapter**: 密钥管理适配器
  - **os_adapter**: 操作系统适配器

### 第3层：核心服务
- **services/frameworks**: 依赖 common_lib, deps_adapter
- **services/protocol**: 依赖 common_lib, deps_adapter
- **services/session_manager**: 依赖 common_lib, deps_adapter, services/frameworks
- **services/identity_service**: 依赖 common_lib, deps_adapter
- **services/legacy**: 依赖 common_lib, deps_adapter
- **services/ext_plugin_manager**: 依赖 common_lib, deps_adapter
- **services/data_manager**: 依赖 common_lib, deps_adapter
- **services/privacy_enhancement**: 依赖 common_lib, deps_adapter
- **services/mk_agree**: 依赖 common_lib, deps_adapter
- **services/key_agree_sdk**: 依赖 common_lib, deps_adapter
- **services/sa**: 依赖 common_lib, deps_adapter, services/frameworks

### 第4层：接口层
- **interfaces/kits/napi**: 依赖 services/frameworks

### 第5层：测试层
- **test/unittest**: 依赖所有服务和接口层

## 循环依赖检测

### 无循环依赖 ✅
所有模块依赖关系都是单向的，没有循环依赖：
- common_lib → deps_adapter → services → interfaces
- 测试层依赖所有其他层

### 模块间通信

1. **IPC 通信**:
   - frameworks/src/standard/ipc_adapter (IPC 适配器)
   - frameworks/src/standard/ipc_dev_auth_proxy (设备认证代理)
   - frameworks/src/standard/ipc_callback_proxy (回调代理)

2. **SoftBus 通信**:
   - frameworks/src/channel_manager/soft_bus_channel (SoftBus 通道)
   - 依赖 dsoftbus SDK

3. **HiView 通信**:
   - frameworks/src/hiview_adapter (HiView 适配器)
   - frameworks/src/hisysevent_adapter (HiSysEvent 适配器)
   - frameworks/src/performance_dumper (性能转储)

4. **插件系统**:
   - frameworks/src/plugin_adapter (插件适配器)
   - services/ext_plugin_manager (扩展插件管理器)
   - 支持动态加载插件

## 模块职责划分

### common_lib (公共库)
- 职责：提供基础工具和数据结构
- 主要模块：
  - hc_types: 类型定义
  - hc_string: 字符串操作
  - hc_parcel: 数据包
  - hc_string_vector: 字符串向量
  - hc_time: 时间操作
  - hc_tlv_parser: TLV 解析器
  - hc_mutex: 互斥锁
  - uint8buff_utils: 字节缓冲区工具
  - string_util: 字符串工具
  - json_utils: JSON 工具

### deps_adapter (依赖适配器)
- 职责：适配外部依赖（加密库、操作系统）
- 主要模块：
  - key_management_adapter: 密钥管理适配器
  - os_adapter: 操作系统适配器

### services (服务层)
- 职责：实现核心业务逻辑
- 主要模块：
  - frameworks: 框架层（IPC、插件、任务管理等）
  - protocol: 协议层（PAKE、ISO）
  - session_manager: 会话管理
  - identity_service: 身份服务
  - legacy: 遗留组件（组认证、认证器）
  - ext_plugin_manager: 扩展插件管理
  - data_manager: 数据管理
  - privacy_enhancement: 隐私增强
  - mk_agree: MK 协议
  - key_agree_sdk: 密钥协商 SDK
  - sa: 系统服务

### interfaces (接口层)
- 职责：提供对外接口
- 主要模块：
  - inner_api: 内部 API
  - kits/napi: NAPI 接口
