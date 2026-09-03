# IPC / 客户端 SDK / SA 生命周期知识

本文记录客户端到 SA 的调用与回调链路。仓库**没有 ClientDevAuth 类**；客户端 = `frameworks/src/ipc_sdk.c`（v-table 组装）+ 平台相关 `frameworks/src/{lite,standard}/`；服务端类叫 `ServiceDevAuth`、代理叫 `ProxyDevAuth`。

## 客户端（standard/small）

- `frameworks/src/ipc_sdk.c`：`InitIpcGmMethods():789-815` 把 `DeviceGroupManager` v-table 各槽位指向 `IpcGm*`（IPC 实现）；每次调用前 `RegisterDevAuthCallbackIfNeed()`（如 `:273`）保证 SA 重启后补注册回调；appId→回调上下文缓存 `g_ipcProxyCbList:53`；identity_service 客户端平行一份 `frameworks/src/identity_service_ipc_sdk.c`。
- proxy/stub：`standard/ipc_dev_auth_proxy.cpp`（`DoCallRequest/RetryLoadDeviceAuthSa/ServiceRunning :32/:64/:78`，经 `SystemAbilityManagerClient::GetSystemAbility(DEVICE_AUTH_SERVICE_ID)`）↔ `standard/ipc_dev_auth_stub.cpp`（`ServiceDevAuth::OnRemoteRequest` 按 methodId 查 callMap）；接口码 `frameworks/inc/standard/dev_auth_ipc_interface_code.h`；服务侧 handler 表 `frameworks/src/ipc_service_common.c:64+`（`IpcServiceGm*`）。
- lite（small/liteos IPC）：纯 C + `IpcIo`，`GetDefaultFeatureApi(serviceName)` 取 `IClientProxy`（`lite/ipc_dev_auth_proxy.c:30-47`），无 SA 按需加载概念；服务端注册走 `ipc_service_lite.c:94-131 main()+AddDevAuthServiceToManager`。
- mini：**无 IPC**。`frameworks/deviceauth_lite` 即 mini 版 client API（in-process hichain 库），网络报文交用户回调 `hichain->cb.transmit`（`source/hichain.c:182`）。

## 回调回传链路（standard，改回调必查全链）

SA 内 `IpcGaCbOnTransmit` 等 → Encode（`standard/ipc_adapt.cpp:1115-1160`）→ `ServiceDevAuth::ActCallback()`（`ipc_dev_auth_stub.cpp:431-445`，查 `g_cbStub[]` 远端对象，分 SYNC/ASYNC）→ `ProxyDevAuthCb::DoCallBack()`（`ipc_callback_proxy.cpp:28-53`，`DEV_AUTH_CALLBACK_REQUEST`）→ 客户端 `StubDevAuthCb::OnRemoteRequest`（`ipc_callback_stub.cpp:50-72`）→ `ProcCbHook()`（`ipc_adapt.cpp:1083`）按 `CB_ID_*` 查 stubTable 派发到用户 `DeviceAuthCallback`。断连清理 `DevAuthDeathRecipient::OnRemoteDied`（`ipc_dev_auth_stub.cpp:449`）。**新增回调 = 补 CB_ID + stubTable 项 + Encode/Decode 两端，漏一端表现为回调静默丢失。**

## SA 生命周期

- **`device_auth_service.cpp` 不存在**。SA 生命周期在 `frameworks/src/deviceauth_sa.cpp`：`REGISTER_SYSTEM_ABILITY_BY_ID(DeviceAuthAbility, SA_ID_DEVAUTH_SERVICE, true):105`；`OnStart():162`＝限 1 工作线程(:166)→`InitDeviceAuthService()`(:168)→`MainRescInit()`(:174)→`SaAddMethodMap()`(:182，注册 `g_ipcCallMaps:54-103` 全部 `IpcService*`)→`Publish(this)`(:186)→监听内存管理 SA(:192)→`DelayUnload()`(:193)；`OnRemoteRequest:205`（token 校验、`isUnloading_` 拒载）；`OnIdle:237`（`GetCriticalCnt()>0` 拒绝 unload）；`OnStop:248` 逆序销毁。
- `services/sa/src/` 只是支撑件：`critical_handler.cpp`（临界计数 `IncreaseCriticalCnt:39/GetCriticalCnt:63`，防会话中途被卸载——**长操作开始/结束必须配对加计数**）、`unload_handler.cpp`（`DelayUnload:60`）、`cache_common_event_handler.cpp`（开机缓存事件重放）。SA 描述 `services/sa/sa_profile/4701.json`（process=deviceauth_service、on-demand、libdeviceauth_service.z.so）。
- 客户端按需加载：`frameworks/sdk/sa_load_on_demand/src/sa_load_on_demand.cpp`——`SubscribeDeviceAuthSa():87` 经 `sa_listener`（`OnAdd/OnRemoveSystemAbility:25/:32`）订阅 SA 上线/下线，上线重放缓存回调并置 `g_devAuthSaIsActive`；拿不到 SA 时 `ProxyDevAuth::RetryLoadDeviceAuthSa` 主动拉起。

## SA 内运行时（services/frameworks）

- 模块任务框架：`src/module/dev_auth_module_manager.c:241 InitModules/:291 AddAuthModulePlugin`，业务统一口 `CreateTask:184/ProcessTask:206`（按 DAS_MODULE/ACCOUNT_MODULE 路由到 legacy authenticators）。
- 任务队列：`src/task_manager/task_manager.c:23 PushTask`（任务基类 v-table 驱动，session 异步入口最终落到这里）。
- 适配/支撑子目录：`os_account_adapter`（前台用户/锁屏查询，带 `_mock` 目录）、`permission_adapter`（token 校验）、`account_subscriber`+`account_task_manager`（账号事件）、`net_observer`、`hiview_adapter`（hisysevent/UE 上报 `src/hiview_adapter/hisysevent_adapter.cpp`，事件定义在仓库根 `hisysevent.yaml`）、`plugin_adapter`（外部插件桥，含 account_auth_plugin）、`security_label_adapter`（见 `data-storage-files.md`）。**这些模块关闭特性或被测试时链接同名 `*_mock` 目录实现（见 `build-config-mock.md`）。**
