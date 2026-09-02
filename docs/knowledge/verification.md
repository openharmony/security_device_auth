# 验证与测试知识（本机构建 + UT + 板侧）

## 构建验证

编译必须在 OpenHarmony 根目录（`/home/openharmony_local`）执行，禁止在本子目录直接跑 gn/ninja：

```bash
./build.sh --product-name rk3568 --build-target deviceauth_service_build   # 最常改的服务层
./build.sh --product-name rk3568 --build-target deviceauth_sdk_build       # 客户端 SDK
./build.sh --product-name rk3568 --build-target deviceauth_build           # 全量
./build.sh --product-name rk3568 --build-target deviceauth_test_build      # 全部测试
```

本仓库提供 skill：`build-test`（nohup 后台编译 + 轮询 + 审查 out/rk3568 build.log/error.log）。**-Werror 环境下任何 warning 即失败，须修复不得抑制。**

## 单元测试

- 套件目标（见 AGENTS.md 测试命令）：`deviceauth_llt/device_auth_func_test/deviceauth_unit_test/device_auth_identity_service_test/device_auth_interface_test/device_auth_ipc_test/light_auth_test/identity_service_ipc_test/dfx_operation_common_test`；TDD 分模块：`iso_protocol_test/auth_sub_session_test/ec_speke_protocol_test/dl_speke_protocol_test/expand_sub_session_test/auth_code_import_test/pub_key_exchange_test/save_trusted_info_test/creds_manager_test/perform_dumper_test/os_account_adapter_test/mini_session_manager_test`；公共库：`hc_types_test/json_utils_test/hc_string_test/hc_log_test/fuzztest`。
- 跑法：编译目标后用 `--gtest_filter=类名.用例名*` 过滤，产物在 `out/rk3568/<...>/`。
- 本仓库提供 skill：`run-ut`（nohup 跑 UT + 轮询 + 解析 report/task_log.log，失败/crash 从 result 目录取堆栈）。

## 改动→测试映射

| 改动位置 | 至少运行 |
| --- | --- |
| services/session_manager（含 v2 协议） | 对应 TDD 模块测试 + `deviceauth_llt` |
| services/legacy / identity_service | `creds_manager_test`、`device_auth_identity_service_test`、`deviceauth_llt` |
| frameworks / IPC / SA | `device_auth_ipc_test`、`light_auth_test`、`identity_service_ipc_test` |
| common_lib / deps_adapter | 对应 `hc_*_test`、`json_utils_test`、`deps_adapter_test` |
| 报文解析类入口 | 追加 `test/fuzztest/` 对应目标 |
| 特性开关相关（mock 分支） | 换 OS 等级目标构建通过（mini/small 至少跑一遍对应 build-target） |

## 完成标准

任务完成当且仅当：1) 相关 build-target 编译通过；2) 受影响测试目标通过（贴 gtest 输出摘要）；3) 新增逻辑有对应用例（`HWTEST_F(..., TestSize.Level0/1)`）；4) 触发 `AGENTS.md` 安全清单检查项时逐条声明结论。

## 无法本机验证时的处理

涉及跨设备组网、软总线、真实 HUKS/TEE、多用户切换的改动本机无法闭环时：明确列出需板侧验证的场景与预期日志关键字（hisysevent 见 `hisysevent.yaml`，LOGE 关键字用模块前缀），标记为"需人工板侧验证"，不要声称已验证。
