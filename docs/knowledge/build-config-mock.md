# 构建配置、特性开关与 mock 机制知识

## OS 等级选择（三级：mini/small/standard）

`deviceauth_env.gni:48-57`：`ohos_lite && liteos_m → default_config/mini/config.gni`；`ohos_lite(其他) → small`；非 lite → `standard`。可用 `deviceauth_feature_config`（`deviceauth_env.gni:26`）整体替换配置目录。组件名 `@ohos/device_auth` v4.0.2（`bundle.json:2/22/4`）。

- standard 全开：`default_config/standard/config.gni:14-42`（session_v2/v1、account、pseudonym、identity_service、p2p bind/auth lite+standard 协议、DL 384 位素数、`max_auth_session_count=10` 等）。
- mini 关闭 session_v2/pseudonym/account/identity_service（`default_config/mini/config.gni:16-40`）；small 介于两者、无 pseudonym。
- 强制告警即错误 flags：`deviceauth_env.gni:32-46`（-Werror/-Wall/...），standard 另有 cfi/ubsan。
- mini 与 standard 的接口/实现整体分叉：mini 走 `frameworks/deviceauth_lite` + `interfaces/inner_api/deviceauth_lite/hichain.h` + lite HUKS 适配，**不经 IPC/SA**。

## C 宏 ENABLE_\* 定义点（源码裁剪的真实开关）

GN 布尔在 `services/deviceauth.gni` 转成 C 宏并**同时切换源文件**：

- `ENABLE_PSEUDONYM :360`——并控制是否编入 `privacy_enhancement/mk_agree` 源（关闭时换 mock `:364-366`）。
- session_v2 块 `:371-405`：`ENABLE_P2P_BIND_ISO/ENABLE_P2P_BIND_DL_SPEKE(=DL_SPEKE)/ENABLE_P2P_BIND_EC_SPEKE/ENABLE_ISO :392/ENABLE_EC_SPEKE :400/ENABLE_AUTH_CODE_IMPORT/ENABLE_PUB_KEY_EXCHANGE/ENABLE_SAVE_TRUSTED_INFO`。
- `ENABLE_ACCOUNT_AUTH_ISO` 单独在 `services/deviceauth_account.gni:17`。
- **关键边界**：关闭特性时 `.gni` 编入的是 `services/*/src/mock/*.c` 空实现（如 `:53-58 identity_operation_mock`、`:149 os_account_adapter_mock`、`:176-180 sa_load_on_demand_mock`）。**给真实实现加新接口时，必须同步给对应 mock 加同名空实现，否则 mini/small/无特性构建直接链接失败。**

## 测试期 mock（两套机制，别混）

1. **特性裁剪 mock**：见上，`.gni` 按开关选源文件。
2. **单测替换 mock**：各测试 `BUILD.gn` 设 `mock_inner_path = "//base/security/device_auth/test/mock_inner"` 加入 include_dirs，并把真实源换成 mock 源（同目录 mock 头优先命中）——例 `test/unittest/services/privacy_enhancement/BUILD.gn:19`、`mini_session_manager/BUILD.gn:27-41`（换 hc_types/hc_mutex/string_util/hc_time）；`test/mock_ext/BUILD.gn:3` 目前是外部依赖占位空 group。
3. **TDD 框架**：`test/unittest/tdd_framework/tdd_framework.gni` 统一 import `deviceauth.gni` 按模块生成 TDD 目标（对应 `auth_sub_session_test/iso_protocol_test/...` 分模块测试）；夹具在 `tdd_helper/`：`memory_mock`（HcMalloc 失败注入）/`memory_monitor`（泄漏检查）/`exception_controller`（异常分支驱动）/`dev_info_mock`；公共桩 `common/src/`。

## 新文件/新目标的接入清单

新增 `.c/.cpp`：加入 `services/deviceauth.gni` 相应源列表（含 mock 分支）；新增可编译目标：写 `BUILD.gn` 并在 `bundle.json` component 分组登记；新增测试：仿 `test/unittest/*` 现有子目录（聚合入口 `test/BUILD.gn:46-47`）。
