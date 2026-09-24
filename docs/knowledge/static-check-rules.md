# 静态检查规则与修复知识（CI codeCheck）

> GitCode CI 门禁的「静态检查」（codeCheck）对 MR 改动文件执行规则扫描，结果以 `noPass`/`pass` 体现。本文汇总 device_auth 仓历次 MR 中遇到的全部规则、触发条件与修复模式，供后续快速对照修复。配套的提交/CI 流程见 `contribution-workflow.md`，编译/测试口径见 `verification.md`。

## 门禁机制与报告判读

- **报告获取**：CI bot 在 PR 评论中给出 `dcp.openharmony.cn/workbench/cicd/detail/<id>/runlist?pop=codecheck&taskId=MR_<id>` 链接；附件 JSON 常保存为 `静态检查问题.json`。
- **JSON 结构不固定**：可能是 `{count, defects:[...]}` 单页、多页拼接（多个 JSON 对象首尾相连，需 `JSONDecoder.raw_decode` 逐段解析），或顶层数组 `[{defectId, defectDetailList:[{...}]}, ...]`。解析前先看首字符（`{` vs `[`）。
- **count 与实际条数**：`count` 是任务总缺陷数，`defects` 数组可能只含一页（如 count=77 但数组仅 20 条），需翻页或多次取全。
- **defectLevel / isIntolerable**：level 1=严重、2=中等、3=轻微；`isIntolerable` 标记是否不可容忍。**实测：即便 level-2/3 tolerable 缺陷也会导致 `noPass`**——「静态检查成功」要求 MR 引入的缺陷全部修复或合理标记，不能仅靠「tolerable」放行。
- **扫描范围**：增量扫描 MR diff 内的文件（含非编译文件，如未接入 BUILD.gn 的 `.cpp`、`.py`、`.md`）。死码文件会被扫描——直接删除或移出分支。

## 规则总览

| 规则 | 触发 | 修复模式 |
| --- | --- | --- |
| G.STD.01-CPP | C 标准头 `stdio.h/stdlib.h/string.h/errno.h/time.h` | `.cpp` 改用 `cstdio/cstdlib/cstring/cerrno/ctime`（POSIX 头 `unistd.h/pthread.h/sys/*` 保留） |
| G.EXP.35-CPP | `NULL` 作空指针 | 全量 `NULL` → `nullptr` |
| G.EXP.14-CPP | C 风格 cast `(T*)x` `(T)x` | `void*→T*`/枚举/整型用 `static_cast`；不相关指针间用 `reinterpret_cast` |
| G.CNS.02 | 难以理解的字面量（魔数） | 提取 `#define UPPER_SNAKE` 或 `static const`；例外：布尔 0/1、循环下标、已有常量 |
| G.CTL.03 | `for(;;)`/`while(true)` 循环条件恒真 | 改 `while (keepLoop)` 变量条件驱动，退出处置 `keepLoop=false` |
| G.FUN.01-CPP | 函数参数过多（>5） | 传结构体指针 / 内部派生常量；如 `E2eBridgeInit` 11→5 |
| G.PRE.02-CPP | 函数式宏 `#define F(x) ...` | 转 `static inline` 函数（C++ 段内）；含 `return` 的框架宏属例外 |
| G.PRE.10 | 宏引用宏外部局部变量（如 `ret`） | 宏转函数并显式带参（`retv`），消除外部依赖 |
| G.FUD.05 / 超大深度函数 | 嵌套 >4 层 / 深度 >4 | guard clause 早返回 + 提取 helper 降低嵌套 |
| 超大函数[C++] | nbnc（非空非注释行）>50 | 拆子函数；注意 nbnc 计法含签名与大括号，拆分时留余量（目标 ≤45） |
| 超大圈复杂度[C++] | 圈复杂度 >20 | 拆子函数；注意 `if/else if/else/for/while/case/?/&&/||` 各 +1，`do{}while(0)` 宏展开也计入 |
| G.FUU.01 | 函数返回值未处理（`fprintf`/`setvbuf`） | 加 `(void)` 显式丢弃，或 `if (ret != 0)` 检查 |
| G.FUU.09 | 使用 `realloc()` | `malloc` + `memcpy_s(!=EOK)` + `free` 手动扩容 |
| G.FUU.11 | 安全函数返回值未检查（`(void)snprintf_s/memcpy_s`） | `if (snprintf_s(...) < 0)` / `if (memcpy_s(...) != EOK)` 检查 |
| G.MEM.01 | `malloc(size)` 前未校验 size | 校验 size 非 0、不超上限、不溢出（`size+1 < size` 判溢出） |
| G.STD.04-CPP | 保存 `std::string::c_str()` 返回指针到裸指针 | 不存局部 `const char*`，直接内联进调用表达式 |
| G.RES.06-CPP | lambda 默认捕获 `[&]`/`[=]` | 显式捕获 `[&var]` |
| G.FMT.04-CPP | 同行多语句声明/赋值 `if(c){A;B;}` | 每语句单独一行 |
| G.FMT.05-CPP | 行宽 >120 | 折行；长 `__attribute__((visibility))` 用对象式宏（如 `#define E2E_EXPORT ...`）缩写 |
| G.FMT.05(python) | import 不在模块顶部 | 移到 docstring 后、全局常量前，按字母序 |
| WordsTool.doc1 | 中文多义词歧义（某鉴权链路常用词兼有「标定」含义） | 改无歧义同义词；工具按**子串**匹配，复合词内仍命中须彻底替换 |
| WordsTool.297（双字母） | 特定双字母子串（hex/UDID 误报） | hex 改引常量名；示例 UDID 选无该子串的值 |
| WordsTool.206/204 | 特定 C 库/C++ 运行库名（文件名误报） | 文件名不可改——若属无关文件则移出本分支 |

## 修复要点

### 函数式宏 → inline 函数（G.PRE.02 + G.PRE.10）

带参检查宏（如 `E2E_*CHECK(cond, api)`，printf 里引用外部 `ret`）是高频双触发源。统一改法：

```cpp
/* 替代：#define E2E_CCHECK(cond, api) do{ if(cond){...}else{printf(...,ret);} }while(0) */
static inline void E2eCcheck(int32_t retv, bool cond, const char *api)
{
    if (cond) { g_pass++; printf("...PASS..."); }
    else { g_fail++; printf("...FAIL ret=%d...", retv); }
}
/* 调用：E2eCcheck(ret, ret == HC_SUCCESS, "api"); */
```

头文件中的宏若需类型泛化，用 `template<typename A, typename E>` inline 函数，置于 `extern "C" {}` 之后的 `#ifdef __cplusplus` 段。

### snprintf → snprintf_s（不安全函数 → G.FUU.11）

`snprintf` 触发「不安全函数」，改 `snprintf_s` 后又触发「返回值未检查」。正确终态：

```cpp
if (snprintf_s(buf, sizeof(buf), sizeof(buf), fmt, ...) < 0) {
    buf[0] = '\0';  /* 截断/失败时清空 */
}
```

`snprintf_s(buf, n, n, fmt, ...)` 当 `count>=destMax` 走 else 分支等价 `snprintf`（核查 `bounds_checking_function/src/vsnprintf_s.c:54`）。批量重复调用收敛进 helper（如 `SetReportStr`），将受检点从 N 处降为 1 处。

### memcpy_s / memset_s 返回检查

```cpp
if (memcpy_s(dst, dstMax, src, n) != EOK) { return; }  /* EOK=0，定义于 securec.h */
```

注意：产品库大量 `(void)memset_s`/`(void)memcpy_s` 是既有写法，但 MR 新增/改动行会被 codeCheck 标记，须改为受检形式。

### 魔数（G.CNS.02）批量替换

asyncStatus 状态机值（0/1/2/3）散布全文件，统一在头文件定义 `E2E_ASYNC_WAITING/TRANSMIT/FINISH/ERROR` 后用 sed 批量替换 `asyncStatus = N` / `asyncStatus == N` / `st == N` / `WaitAsync(...) != N`。超时字面量（1000/2000）同理定义 `E2E_SYNC_STEP_MS/E2E_CREATEGROUP_WAIT_MS`。sed 时用 `'/^#define/!s/.../...'` 排除宏定义行。

### 超大函数拆分策略

- 按逻辑段提取 `static` helper（CREATE/QUERY/IMPORT 各一段），主函数仅编排。
- 拆分后用 `sed -n '/^static.*Func/,/^}/p' | grep -vE '^\s*$|^\s*/\*|^\s*\*|^\s*//' | grep -c '\S'` 复核 nbnc ≤50（留余量到 45，因计数法含签名/大括号）。
- 拆分易把 `if(c){A;B;}` 同行多语句（G.FMT.04）展开为多行，反而使 nbnc 回升——拆分与拆行同步进行。

### WordsTool 误报处理

- 工具按**子串**匹配，不区分上下文：hex 字面量、示例 UDID 中的特定双字母序列会被标记。
- hex 常量在文档中改引常量名（如 `E2E_FRAME_MAGIC`）而非字面量；代码中的 `#define` hex 不被扫描（仅扫 `.md`）。
- 文件名误报（如 loader 动态库路径、C++ 运行库 `.so`）不可改——若该文件不属本 MR 主题，移出分支（fork master 仍保留）。

## 本地预检

提交前对受影响 `.cpp` 跑（host gcc，非 OHOS 工具链，仅查语法/告警，不验证链接）：

```bash
B=<OHOS 整树根>; ROOT=$B/base/security/device_auth
INC="-I test/e2e_verify/inc \
  -I $B/third_party/bounds_checking_function/include -I $B/third_party/cJSON \
  -I $ROOT/interfaces/inner_api -I $ROOT/services/frameworks/inc \
  -I $ROOT/common_lib/interfaces \
  -I $ROOT/deps_adapter/key_management_adapter/interfaces \
  -I $ROOT/deps_adapter/os_adapter/interfaces"
g++ -std=c++17 -fsyntax-only -Wall $INC <file.cpp>   # EXIT 0 + 无 error 即过语法
```

快速自查清单（grep）：

```bash
# 函数式宏（排除对象式）
grep -rnE "#define [A-Z_]+\(" *.cpp | grep -v "对象式宏名"
# nbnc >50 函数
for f in *.cpp; do sed -n '/^static\|^int \|^void /,/^}/p' "$f" | grep -cvE '^\s*$|^\s*/\*|^\s*\*|^\s*//'; done
# 残留 (void)snprintf_s / realloc / NULL / for(;;) / 行宽>120
grep -rn "(void)snprintf_s\|(void)memcpy_s\|realloc(\|NULL\b\|for *(;;)\|[^.]realloc" *.cpp
awk 'length>120' *.cpp
```

门禁仍以 CI `静态检查` 标签为准（`静态检查成功`/`noPass`）；本地预检只降轮次、不替代 CI。
