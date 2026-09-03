# Device Auth 组件指引（OpenHarmony @ohos/device_auth, v4.0.2）

> 本仓库面向 Agent 的指导文档统一使用中文；代码标识符、命令、路径、文件名保留原文。核心逻辑为 C 语言、v-table 式伪 OOP；IPC/SA/NAPI 层为 C++（禁异常/RTTI，不用 C++ virtual 做跨模块多态）。支持 mini/small/standard 三个 OS 等级。

## 项目定位

优先按这些目录定位问题：

- `services/`：SA 服务端全部业务（核心 `device_auth.c` + session_manager/protocol/legacy/identity_service/data_manager/mk_agree/privacy_enhancement/ext_plugin_manager/frameworks/sa）。
- `frameworks/`：客户端 SDK（`ipc_sdk.c` + `{lite,standard}/`）、SA 生命周期（`deviceauth_sa.cpp`）、mini 版 in-process 库（`deviceauth_lite/`）、按需加载（`sdk/`）。
- `interfaces/`：对外 API（`inner_api/device_auth.h`、`deviceauth_lite/hichain.h`、错误码 `device_auth_defines.h`、NAPI `kits/napi`）。
- `deps_adapter/`：密码学适配（`key_management_adapter/`，AlgLoader→HUKS）与 OS 适配（`os_adapter/`，HcFile 等）。
- `common_lib/`：hc_types/hc_string/hc_parcel/TLV/json_utils/hc_log 等。
- `default_config/{mini,small,standard}/` + `*.gni`：特性开关与源码裁剪。
- `test/`：unittest（含 tdd_framework）、mock_inner/mock_ext、fuzztest。

### 按任务类型定位代码

| 任务类型 | 首选位置 | 关键锚点 |
| --- | --- | --- |
| 新增/修改对外 API | `interfaces/inner_api/` + `services/device_auth.c` + `frameworks/src/ipc_sdk.c` + `ipc_service_common.c` + stub callMap | `device_auth.c:1084+`、`ipc_sdk.c:789`、`deviceauth_sa.cpp:54-103` |
| 认证会话流程（V2 握手/展开指令） | `services/session_manager/src/session/` | `dev_session_fwk.c:849`、`v2/dev_session_v2.c` |
| ISO/SPAKE 握手算法 | V2：`session/v2/auth_sub_session/protocol_lib/`；共享层：`services/protocol/` | `iso_protocol.c:845`、`pake_v2_protocol_common.c` |
| 组管理/绑定/老认证流程 | `services/legacy/group_manager`、`group_auth`、`authenticators/` | `group_manager.c:24+`、`dev_auth_module_manager.c:184` |
| 凭据/身份/PIN | `services/identity_service/`、`services/legacy/identity_manager/`、`legacy/creds_manager/` | `identity_operation.c:354/1173`、`identity_pin.c` |
| MK 协商/匿名 ID | `services/mk_agree`、`privacy_enhancement` | `mk_agree_task.c:655`、`pseudonym_manager.c:855` |
| 独立协商 SDK | `services/key_agree_sdk/` | `key_agree_sdk.h:96-104` |
| 持久化文件 | `services/data_manager/`（TLV） | `group/credential/operation_data_manager.c` |
| 加解密/密钥操作 | `deps_adapter/key_management_adapter/` | `alg_defs.h:151-179`、`huks_adapter.c:1102` |
| 文件 IO/OS 能力 | `deps_adapter/os_adapter/` | `hc_file.c`、`hc_dev_info.c` |
| 回调链路/SA 拉起 | `frameworks/src/standard/`、`frameworks/sdk/` | `ipc_adapt.cpp:1083/1115`、`sa_load_on_demand.cpp:87` |
| 特性开关/源码裁剪 | `deviceauth_env.gni`、`services/deviceauth.gni`、`default_config/*/` | `deviceauth.gni:360/371-405` |
| NAPI(Js) 接口 | `interfaces/kits/napi/` | 对应 napi 目录 |

## 构建和验证

构建命令从 OpenHarmony 根目录（`/home/openharmony_local`）执行，不在本子目录执行：

```bash
./build.sh --product-name rk3568 --build-target deviceauth_build           # 全量
./build.sh --product-name rk3568 --build-target deviceauth_service_build   # 服务
./build.sh --product-name rk3568 --build-target deviceauth_sdk_build       # SDK
./build.sh --product-name rk3568 --build-target deviceauth_napi_build      # NAPI
./build.sh --product-name rk3568 --build-target deviceauth_test_build      # 全部测试
# 单测：编译单个 gtest 目标后过滤执行
out/rk3568/<...>/iso_protocol_test --gtest_filter=IsoProtocolTest.IsoInit001*
```

测试目标清单——套件：`deviceauth_llt`、`device_auth_func_test`、`deviceauth_unit_test`、`device_auth_identity_service_test`、`device_auth_interface_test`、`device_auth_ipc_test`、`light_auth_test`、`identity_service_ipc_test`、`dfx_operation_common_test`；TDD 分模块：`auth_sub_session_test`、`iso_protocol_test`、`ec_speke_protocol_test`、`dl_speke_protocol_test`、`expand_sub_session_test`、`auth_code_import_test`、`pub_key_exchange_test`、`save_trusted_info_test`、`creds_manager_test`、`perform_dumper_test`、`os_account_adapter_test`、`mini_session_manager_test`；公共库：`hc_types_test`、`json_utils_test`、`hc_string_test`、`hc_log_test`、`fuzztest`。

编译器强制告警即错误（`-O2 -ftrapv -Wall -Werror -Wextra -Wshadow -fstack-protector-all -D_FORTIFY_SOURCE=2 -Wformat=2 -Wfloat-equal -Wdate-time`，见 `deviceauth_env.gni:32-46`；standard 额外 cfi/ubsan）。发现 warning 须修复，禁止抑制。

本仓库提供 skill：`build-test`（后台编译+轮询+审查 out/rk3568 日志）、`run-ut`（后台跑 UT+解析 report/task_log.log，失败/crash 从 result 目录取堆栈）。

### 完成标准

任务被认为完成，当且仅当：

1. **代码改动已完成** - `git commit -s`，多代理协作时添加 `Co-Authored-By: Agent`
2. **本地构建通过** - 受影响的 deviceauth_*_build 目标编译成功
3. **相关测试通过** - 按 `docs/knowledge/verification.md` 的改动→测试映射执行并提供输出摘要
4. **mock 同步** - 新增接口的真实实现必须同步补对应 `src/mock/` 空实现，否则非特性构建立即断链
5. **安全清单逐条核对** - 见"项目约束→安全关键约束"

### 如果无法运行验证

明确说明原因（如跨设备组网/真实 HUKS/软总线依赖），列出推荐验证步骤与预期日志关键字（hisysevent 定义见仓库根 `hisysevent.yaml`）供人工执行，标记需板侧验证的部分，不得声称已验证。

### 完成报告格式

改动摘要（文件列表、改动点）、验证结果（构建/测试输出）、风险评估（API/报文兼容性、密钥安全、性能）、未完成事项。

## 知识索引

稳定背景知识在 `docs/knowledge/`。改动前按场景读取对应文件：

| 场景 | 修改位置 | 先读文档 |
| --- | --- | --- |
| 对外 API、v-table 入口、初始化/销毁顺序 | `services/device_auth.c`、`interfaces/` | `docs/knowledge/api-entry-routing.md` |
| 会话状态机、V1/V2 分轨、子会话、expand 指令 | `services/session_manager/` | `docs/knowledge/auth-session-pipeline.md` |
| ISO/EC-SPAKE/DL-SPAKE/PAKE 握手算法、报文字段 | `services/protocol/`、`session/v2/.../protocol_lib/` | `docs/knowledge/protocol-handshake.md` |
| 凭据库、身份解析、PIN、组认证任务机、外部插件 | `legacy/`、`identity_service/` | `docs/knowledge/identity-credentials.md` |
| 任何加密/解密/签名/密钥操作、HUKS 适配 | `deps_adapter/key_management_adapter/` | `docs/knowledge/crypto-alg-loader-huks.md` |
| 文件读写、TLV 格式、分区/权限/安全标签、多用户路径 | `data_manager/`、`os_adapter/` | `docs/knowledge/data-storage-files.md` |
| 客户端调用、IPC、回调回传、SA 生命周期/卸载保护 | `frameworks/`、`services/sa/`、`services/frameworks/` | `docs/knowledge/ipc-client-sdk-sa.md` |
| MK 协商、pseudonym、独立协商 SDK | `mk_agree/`、`key_agree_sdk/`、`privacy_enhancement/` | `docs/knowledge/key-agreement-mk-sdk.md` |
| OS 等级/特性开关、mock 机制、BUILD.gn 接入 | `*.gni`、`default_config/`、`test/` | `docs/knowledge/build-config-mock.md` |
| 构建、跑测试、选择验证目标、完成判定 | 任何构建/测试相关改动 | `docs/knowledge/verification.md` |

### 开始编辑前

1. 确认任务类别，按上表确定需要阅读的文档
2. 同名文件先确认调用方集合（本项目有多套 iso/pake/creds_manager 同名实现，见 protocol-handshake.md、identity-credentials.md）
3. 根据"项目约束"确认不违反任何约束
4. 声明："我将修改 X，已阅读 Y 文档，遵循 Z 约束"

## 编码约定

- **4 空格**缩进禁 Tab；单行 **120 字符**上限；函数体 **50 行**上限（超出拆子函数）。仓库无 clang-format 配置，人工遵循。
- **K&R 混合大括号**：函数体左大括号另起一行；控制语句左大括号同行。C89 风格变量置块首；未用参数 `(void)name;`；空判条件逐一加括号 `(ptr == NULL) || (len == 0)`。
- **禁止魔数**（G.CNS.02）：`UPPER_SNAKE_CASE` 宏/枚举/`static const`；例外：布尔 0/1、循环下标、头文件已有常量（如 `HC_SUCCESS`）。
- C 文件：C99 + `securec.h`（只用 `memset_s/memcpy_s` 等安全函数）。C++ 文件（IPC/SA/NAPI/测试）：`OHOS` 命名空间，禁异常与 RTTI；多态经 C 函数指针 v-table，不用 C++ virtual。
- 头文件包含顺序：系统头 → `securec.h` 靠前 → 工程头；测试代码 gtest/gmock 最先；被 C++ 引用的 C 头一律 `extern "C" { }` 包裹。
- 命名：C 函数 `snake_case`、C++ 方法 `PascalCase`（如 `InitDeviceAuthService()`/`OnStart()`）；局部 `snake_case`、全局 `g_` 前缀（`peerUdid`/`g_groupAuthManager`）；结构体 typedef `PascalCase`、枚举/宏 `UPPER_SNAKE_CASE`（`DeviceGroupManager`/`FIELD_APP_ID`）；文件 `snake_case.c`；包含保护 `UPPER_SNAKE_CASE_H`；IPC 服务侧函数按模块前缀（`IpcServiceGm*`、`DevAuthGetReal*`）。
- 错误码三层不得混用，统一返回 `int32_t`：核心层 `HC_*` 十六进制（`device_auth_defines.h`：`HC_SUCCESS=0`、`HC_ERR_INVALID_PARAMS=0x00000002`、`HC_ERR_JSON_FAIL=0x00002001`），公共层 `CLIB_*` 负值（`clib_error.h`），HAL 层 `HAL_*` 负值（`hal_error.h`）。入参尽早校验 + `LOGE()`；每条错误路径释放资源；init 用 `RETURN_IF_INIT_FAILED`。
- 内存：仅 `HcMalloc(size, val)/HcFree()`；敏感缓冲区释放前必须 `FreeAndCleanKey()`（先 memset_s 清零再 free）。成对模式：`CreateJson()/FreeJson()`、`CreateString()/DeleteString()`。
- 日志：`LOGE/LOGI/LOGD`；UDID/key 打印需 `PRINT_SENSITIVE_DATA()` 门控。
- 关键模式：v-table 单例（`GetGmInstance()`、`GetLoaderInstance()`）；参数经 `CJson`（`json_utils.h`）以 JSON 传递；特性开关 `ENABLE_ISO/EC_SPEKE/DL_SPEKE/PSEUDONYM/ACCOUNT_AUTH_ISO`。
- 测试：`HWTEST_F(类名, 用例名00N, TestSize.Level0)`；类名 `PascalCase`+`Test`；mock 文件 `*_mock.c` 置于 `test/mock_inner/`、`test/mock_ext/`，经 `.gni`/测试 `BUILD.gn` 替换；TDD 框架位于 `test/unittest/tdd_framework/`。

## 项目约束

### 安全关键约束（红线，改动必查）

**Do not（禁止）：**
- 直接调 `Huks*/Hks*/mbedtls` 做加密、解密、MAC、HKDF、签名、验签、密钥协商、密钥导入/生成/删除——必须经 `GetLoaderInstance()` 的 `AlgLoader`。
- 私钥/对称密钥值落盘或出进程：长期密钥一律别名（`isAlias=true`）入 HUKS；仅公钥可传明文 blob。
- 临时密钥 blob 用毕不释放：必须配对 `FreeAndCleanKey()`；JSON 内敏感字段（sessionKey/pinCode/authCode）删除/转发前 `ClearSensitiveStringInJson()`。
- 自行 `fopen` 读写文件：必须走 `HcFileOpen/Read/Write/Close/Remove`，写后 `SetSecurityLabel(path, SECURITY_LABEL_S2)`，保持目录 0700/0711、文件 0640。
- 新增硬编码盐/因子/种子；协议要求固定值时注释指向 Hichain 协议规范章节（历史固定盐清单与明文旁路风险面见 `crypto-alg-loader-huks.md`，勿扩大）。
- 日志输出 PIN、PSK、session key、verify 报文明文。
- 在 session_manager 持锁路径（`ProcessDevSession` 全链）引入阻塞操作（死锁）。

**Ask before（修改前必须确认）：**
- 修改 handshake 报文结构、TLV 字段 tag/order、IPC methodId/Parcel 序列化顺序（跨设备/跨版本兼容性）。
- 修改 `HC_*` 错误码取值或 v-table 槽位（对外 ABI）。
- 触碰 PIN/凭据/DAS 账号 token 链路（需安全评审；PIN 明文残留现状见 `identity-credentials.md`）。
- 修改 SA 卸载保护（critical count）配对、`InitDeviceAuthService` 初始化/`CleanAllModules` 回滚顺序。

### 公共 API 约束

- 本项目仅两个公开面：`interfaces/inner_api/device_auth.h`（standard/small native C）与 `interfaces/inner_api/deviceauth_lite/hichain.h`（mini）。禁止修改已发布函数签名、参数/返回值类型、错误码语义；扩展一律放 `device_auth_ext.h`。
- 旧版 API 名（`DoAuthConnection/DoBindTargetDevice/DoPublishDeviceCapability` 等）在本版本不存在，勿按旧文档臆造。

### 架构约束

- 协议算法层与策略层分离：auth_sub_session/dev_session_v2 决定"用哪个协议/哪份 PSK"，protocol_lib 只做报文与算钥；协议库内部不得取凭据。
- legacy 与 V2 双轨并存是现状：新功能只进 V2/session_manager；修 legacy 前先确认只影响 V1 兼容/账号路径。
- V1/V2 分轨判据（`IsSupportSessionV2/IsMetaNode/IsV1SessionMsg`）与 `HC_ERR_NO_CANDIDATE_GROUP` 降级兜底不得改写语义。
- 参数统一经 `CJson` JSON 传递，不得为"省性能"改传裸指针跨 v-table 边界。
