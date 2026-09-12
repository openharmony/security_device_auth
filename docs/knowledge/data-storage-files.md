# 文件读写与数据存储知识

本文记录持久化清单与格式约束，新增文件读写必读。

## 统一入口

`HcFileOpen/Read/Write/Close/Remove`（`deps_adapter/os_adapter/interfaces/{linux,liteos}/hc_file.h:35-44/39-44`）。

- linux 实现 `impl/src/linux/hc_file.c`：读 `fopen "rb"`(:65)；写路径不存在则逐级 `mkdir 0700`(S_IRWXU, :52)，`fopen "wb+"` 后 `fchmod 0640`(:66-82)；`remove`(:192)。
- liteos/mini 实现 `impl/src/liteos/hc_file_posix.c`：读 `open O_RDONLY`(:73)，写 `O_RDWR|O_CREAT|O_TRUNC 0640`(:90)，目录 `mkdir 0600`(:57)；另一版 `hc_file.c` 走 `UtilsFileOpen:36`（LiteOS 私有 FS）。
- liteos `hc_dev_info.c:44` 的 CE 路径返回 NULL（mini/small 无 CE 概念）。
- **禁止自行 `fopen`/`open` 新文件**。

## 安全标签

`SetSecurityLabel(path, SECURITY_LABEL_S2)` 不在 os_adapter，在 `services/frameworks/src/security_label_adapter/security_label_adapter.c:63`（xattr "s2"），由各数据层在 HcFile 写后调用（group:468/505、cred:368/405、op:202/277、pseudonym:240、token 管理器）。**新文件必须补调用，否则 SELinux 标签缺失拒绝访问。** 同目录有 mock 版供测试替换。

## 文件清单

| 文件名 | 目录 | 业务流程 | 读写点 |
|---|---|---|---|
| `hcgroup.dat` / `hcgroup<uid>.dat` / CE `<el2>/<uid>/deviceauth/hcgroup.dat` | DE `/data/service/el1/public/deviceauth` | 组/受信设备 TLV 库（仅 UDID/authId 标识与别名引用，密钥本体在 HUKS） | `group_data_manager.c`：`LoadOsAccountDb:518`/`SaveOsAccountDb:1694`/`InitDatabase:1860`/`ReadParcelFromFile:460`/`SaveParcelToFile:497`；路径三态 `GetOsAccountInfoPathCe:196`/`GetOsAccountInfoPathDe:210` 由 `IsOsAccountSupported():230` 选择；DE→CE 迁移合并 `:558-582` |
| `hccredential.dat`/`hccredential<uid>.dat` | 同上 | 凭据元数据 TLV（算法/别名；密钥值本体在 HUKS） | `credential_data_manager.c`：`LoadOsAccountCredDb:418`/`LoadDevAuthCredDb:522`（扫 `hccredential*.dat:538-540`）/`SaveOsAccountCredDb:1353`/`InitCredDatabase:1504`；CE 路径 :159-166、DE :179-183 |
| `hcoperation.dat` | CE 为主 | API 操作审计记录 | `operation_data_manager.c`：路径 :182-188、`SaveParcelToFile:194`、`LoadOperations:325`、`InitOperationDataManager:735` |
| `account_data_sym%d.dat` / `account_data_asy%d.dat` | `.../deviceauth/account` | 账号配对 token（JSON，仅 userId/deviceId 等非密钥标识） | `legacy/authenticators/account_related/creds_manager/sym_token_manager.c:66-92/181/228`；`asy_token_manager.c:138-164/301/348` |
| `pseudonym_data.dat`/`<n>.dat` | `.../deviceauth/pseudonym` | 匿名 ID 记录 | `privacy_enhancement/src/pseudonym_manager.c:185-208/238` |
| `AUTH_STORAGE_PATH/hcgroup.dat`、`.../account` | mini liteos 存储分区 | lite 组数据/账号 | `frameworks/deviceauth_lite/.../hc_dev_info.c:41-56` |
| HUKS 密钥存储 | huks 服务自管 | 密钥持久化 | mini 初始化失败时 `HcFileRemove(GetStoragePath())` 恢复：`impl/src/mini/huks_adapter_diff_impl.c:25-69` |

## TLV 格式

文件 = `HcParcel` 序列化的 TLV 库；解析框架 `common_lib/interfaces/hc_tlv_parser.h` 的 `DECLARE_TLV_STRUCT`；凭据专用 `cred_tlv_parser.h:44-68`（`DECLARE/BEGIN/END_CRED_TLV_STRUCT_DEFINE`）。结构体：`TlvGroupElement` 10 字段（`group_data_manager.c:39-50`）、`TlvCredentialElement` 17 字段（`credential_data_manager.c:36`，tag 0x0001）。**新增字段只可追加 tag、不可重排/复用旧 tag，读写两端需兼容老文件。**

新增 TLV 字段铁律（群组/凭据/操作三库通用）：

- **`DECLARE_TLV_STRUCT(N)` 计数同步**：N 是硬编码成员数（`group_data_manager.c:39` 当前为 10），加成员必须 +1；忘改 = offset 数组越界写，静默内存破坏，比编译错误更难查。
- **新字段必须独立新 tag**（群组表下一空闲 `0x400B`，设备表 `0x4109`）；**严禁塞进 `DevAuthFixedLenInfo`（tag 0x4106）等定长结构**——定长解析强校验 `length == sizeof(data)`（`hc_tlv_parser.h:98`），改动即双向不兼容，后果是整个账号 DB 被丢弃（`LoadOsAccountDb:534-539` 直接 return）、全部信任关系丢失。真实先例：commit `7df14c1a` 把 upgradeFlag 塞进定长结构犯错，`eff3e98b` 以独立 tag `0x4108` 修复。
- **双向兼容靠 TLV 机制而非版本号**：解码固定非 strict（`group_data_manager.c:442` `DecodeTlvMessage` 传 false），旧文件缺新 tag 时成员取 memset 默认值（默认值必须语义安全，如 0=关闭）；旧代码读新文件时未知 tag 走 `ParseAndSkipTlvUnknownNode`（`hc_tlv_parser.c:176-196`）跳过。version 字段（0x6001）恒写 1 且读取侧从不校验，**不要做版本分支**。
- **加字段六处同步**：entry 结构体成员（`group_data_manager.h:31-42`）→ TLV 结构体+计数（`:38-50`）→ tag 表（`:88-99`）→ 打包 `SetGroupElement`（`:790`）→ 解包 `GenerateGroupEntryFromTlv`（`:311`）→ 深拷贝 `GenerateGroupEntryFromEntry`（`:239`）；漏深拷贝 = AddGroup/Query 链路丢值。
- 测试须含 round-trip（写入→`SaveOsAccountDb`→重载比对）与旧格式兼容用例（参照 `hc_tlv_parser_test.cpp:406/431`）；测试前先清残留库（参照 `save_trusted_info_test.cpp:85` `DeleteDatabase`）。
- `frameworks/deviceauth_lite/`（旧 mini hichainsdk）走 HUKS 存储、不用本 TLV 库，持久化字段改动与其无关。

## 进程/权限

`services/deviceauth_service.cfg`：SA 以 uid/gid `deviceauth` 运行，SELinux `u:r:deviceauth_service:s0`；`/data/service/el1/public/deviceauth{,/account,/pseudonym}` 由 init 创建 **0711 deviceauth:deviceauth**；CE `/data/service/el2/<uid>` 由账号系统隔离。目录基底常量 `impl/src/linux/hc_dev_info.c:49`(CE)/:54(DE)。
