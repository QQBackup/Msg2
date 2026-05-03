# Msg2.0.db 解析 — IDA Pro (IM.dll) 与样例数据对照

本文档随分析逐步更新。分析目标：为 QQ 2010 时代 `Msg2.0.db` 的归档/转可读格式，理清**客户端如何解析**该库及侧录目录结构。

---

## 1. 分析环境与二进制

| 项 | 值 |
|----|----|
| **IDB** | `.../msg2.0/QQ2010/Bin/IM.dll.i64` |
| **模块** | `IM.dll`（主聊天/消息相关逻辑集中于此） |
| **ImageBase** | `0x31000000` |
| **输入路径（构建机）** | `C:\Users\...\Desktop\QQ2010\Bin\IM.dll` |

MCP `server_health`：分析已完成（`auto_analysis_ready: true`），Hex-Rays 可用。

---

## 2. 文件层：Msg2.0.db 不是“裸 SQLite 单文件”

### 2.1 物理格式

- 对样例 `msg2.0/Msg2.0.db` 执行 `file` 与 `xxd`：头部为 **`D0 CF 11 E0 A1 B1 1A E1`**，即 **复合文档 / OLE 结构化存储（Compound File Binary, CFB）** 魔数。
- 与“纯自定义二进制”不同，Windows 上通过 **`StgOpenStorage`** 以 `IStorage` / `IStream` COM 接口访问。

### 2.2 与标准 OLE 读库的对照（重要）

- 使用 Python `olefile` 打开同一路径的 `Msg2.0.db` 时抛出 **`OSError: incorrect DIFAT`**。
- 可能原因（需后续用 Windows/原始解密链验证，不限于一种）：
  - 文件经 **TX 加密层** 或 **非标准扩展** 处理，导致 FAT/DIFAT 与规范不一致；
  - 文件截断/损坏；
  - 或需先经 **`Matrix.dat` + `TXEncryptMgr`** 得到可读存储（见第 5 节）。
- **结论**：归档管线应同时保留 **`Msg2.0.db`、`Matrix.dat`、`seqbase.dat`、侧录目录**，不能只假设“任意 OLE 库可直接枚举流”。

---

## 3. 虚拟路径：`UserDataMsgStorage:` → Msg2.0.db

### 3.1 挂载点（`sub_3103E5C0`，日志上下文 `MsgStorage`）

反编译逻辑概要：

1. `Util::Sys::GetGlobalDataUsersDir` → 拼出用户目录，再拼 **`Msg2.0.db`**（源码字符串为 **`Msg2.0.db`**，与磁盘大小写可能不一致）。
2. **`FS::AddFileSystem(2, "UserDataMsgStorage:" 对应宽字符路径)`**  
   将类型 `2` 的文件系统命名空间挂到**真实文件**上。
3. 同时用 **`OSRoot:`** 前缀与 `FS::IsFileExist` 检查文件是否存在；失败时走备份/重命名（`MsgBackFile` + GUID + `.db`）、`ImportWizard` 配置等分支。

**含义**：客户端内访问消息库时，并不是直接写死盘符路径，而是通过 **`UserDataMsgStorage:\...`** 与内部 **`FS`** 层，最终落到 **`Msg2.0.db` 的 OLE 存储**。

**QQ2009 注记**：**`UserDataMsgStorage:` 与盘上 `Msg2.0.db` 的 `AddFileSystem(2, …)` 注册** 在静态 xref 中出现在 **`KernelUtil.dll`**（**`sub_60A3F970`**，**§19**），**不是** **`IM.dll`** 对 **`?AddFileSystem@FS@@`** 的调用点。§3.1 仍以 **QQ2010 `IM.dll`** 的 **`MsgStorage`** 逻辑为据；**2009** 上 **`IM.dll`** 主要在 **前缀已挂好后** 做 **`CombineQNC` / 建目录 / 开流**。

### 3.2 按“通道名”建子目录（`sub_3102D560`）

- 对传入的名称（如 **`buddy` / `group` / …**）执行 **`FS::CombineQNC(L"UserDataMsgStorage:", name)`**，然后 **`FS::CreateDirectoryW`**，要求 **`FS::IsDirectoryExist`** 成功。
- **与用户磁盘目录一致**：样例根目录下存在 **`buddy/`、`discuss/`、`group/`、`mobile/`、`system/`**，与代码中的通道名一一对应。

---

## 4. 消息路由：五类存储名 → 不同解析入口（`sub_3102F7F0`）

该函数根据对象内 **`CTXBSTR`（偏移约 `this+12`）** 与 UTF-16 字面量比较，分发到不同处理函数，最后统一调用：

**`Util::Msg::TranslateOldMsgToMsgPack(...)`**  
（旧缓冲区 → `ITXMsgPack`，便于上层展示或导出）

| 存储名（宽字符串） | 调用链 |
|-------------------|--------|
| **`buddy`** | `sub_3102E8F0` / `sub_3102F150`（是否临时会话由参数 `a2` 分支） |
| **`group`** | `sub_3102EE60`，并置标志供后续使用 |
| **`discuss`** | `sub_3102EB40`，并置标志 |
| **`system`** | `sub_3102F3A0` |
| **`mobile`** | `sub_3102F5A0` |
| 其他 | 清理并返回失败 |

**含义**：`Msg2.0.db` **内部或镜像目录上**，同一 OLE 树下用 **服务类目录名** 区分会话类型；解析二进制布局前先按 **buddy/group/discuss/system/mobile** 分流。

### 4.1 Buddy 旧消息体示例（`sub_3102E8F0`）

- 从 `ITXData` 取 **`bSelfMsg`** 等字段，从缓冲中解析 **GBK 或 BIG5** 文本（`Util::Convert::GBKToUnicode` / `BIG5ToUnicode`），写入 **`strSender`、`strSenderShowName`** 等到 **`CTXStringW`/MsgPack**。
- 后续还有 **`sub_31002B90`** 处理附加块，说明 **一条记录 = 头 + 可选尾块**，属 QQ 私有 TLV/分段格式（需结合更多函数拆解字节）。

---

## 5. 加密与 Matrix.dat（`sub_31042D80`）

当路径经 **`CTXStringW::MakeLower`** 后包含 **`msg2.0.db`**（且不为 **`msgss.db`**）时：

1. **`FS::CombineQNC(..., L"Matrix.dat")`** 得到与消息库同根的密钥/封印文件路径；
2. **`TXEncryptMgr::CreateDataStorage`** 创建数据存储接口；
3. 通过 **`bufSvrSealEnc`** 等 **BSTR 键** 从存储对象读写配置；

**归档启示**：若导出工具绕过 **`TXEncryptMgr`**，可能无法打开 **`IStorage`** 或内部流；需复现 **`Matrix.dat` + seal** 语义（逆向工作量独立于 OLE）。

---

## 6. OLE 打开封装（`sub_31287E10`）

```c
// 语义摘要（Hex-Rays）
BOOL sub_31287E10(int ctxStringPath, IStorage **ppstgOpen) {
  const WCHAR *p = CTXStringW::operator wchar_t const *(ctxStringPath);
  return StgOpenStorage(p, ..., 0x12, 0, 0, ppstgOpen) >= 0 && *ppstgOpen;
}
```

- **`grfMode = 0x12`**：对应 `STGM_READ | STGM_SHARE_DENY_WRITE`（典型只读独占写）。
- **调用方包括**（xref）：`sub_31281C90`（转换准备）、`sub_31283AD0`、`sub_31285E80` 等 **ConvertSS2CD / 迁移** 工具链。

---
4. **`sub_31010F20`** 校验/`sub_310EBAA0` 清理。

## 7. `info.db` 内嵌库：魔数分支（`sub_31285C50`）

**`sub_31285E80`（`CTXConvertSS2CDMgr::GetMsgRecordUinList`）**：

- 将 **`this+19` + `info.db`** 拼路径，`FS::SplitQNC` 后 **`sub_31287E10`** 打开 **`IStorage`**；
- 再 **`sub_31285C50(ppstgOpen, L"User\\Account.db", ...)`** 与 **`Group\\Basic.db`**，从存储树读取 **好友 QQ 号列表 / 群列表**（日志：`Get Buddy List` / `Get Group List`）。

**`sub_31285C50` 行为摘要**：

- **`sub_31288170`**：在父存储上 **`OpenStream`**（失败打日志 `FileHelp::ReadStream`）；
- 取流首 **4 字节**，与两常量比较（注意 **小端序 int**）：
  - **`16860244` → `0x01014454`，内存字节序 `54 44 01 01`** → 与样例 **`Matrix.dat`** 文件头 **`54 44 01 01`**（可视作 **`"TD"` + 版本类字段**）一致 → 走 **`sub_31285AD0`**；
  - **`16860750` → `0x0101464E`，内存字节序 `4E 46 01 01`** → 走 **`sub_31285820`**。

**结论**：**`info.db` 内的嵌套 DB** 并非随意扩展名，而是带 **固定 4 字节类型标签** 的 **TX 私有容器**；与 **`Matrix.dat`** 共享同类签名前缀。

---

## 8. 另一路 OLE：自定义表情 / 导入（`sub_311FF6F0`）

该函数同样 **`StgOpenStorage`**，但典型子路径为：

- 存储 **`config`** → 流 **`Face.Xml`**（读入后字符串替换 `>` / `<FILE ORG>` 等）；
- 存储 **`Files`**；
- **`CUSTOMFACE` / `CUSTOMFACEGROUP`** 下迭代 **`FACE`** 子项与 **`Util::Data`/`ITXData`**。

对应 **表情/导入向导**，与 **日常 buddy 文本消息** 路径不同，但证明 **IM.dll 大量依赖 OLE 层次遍历**。

---

## 9. 与用户样例目录的对照验证

路径：`.../stale-reader-encrypted/msg2.0/`

| 观察 | 与二进制一致性 |
|------|----------------|
| 根下 **`buddy/`、`discuss/`、`group/`、`mobile/`、`system/`** | 与 **`sub_3102F7F0`** / **`sub_3102D560`** 中 **`buddy`、`discuss`、`group`、`mobile`、`system`** 字面量一致 |
| **`buddy/<UIN>/content.dat`、`index.dat`、`info.dat`** | 与 OLE **`IStream` 落盘或导出文件** 的典型三重划分一致（内容 / 索引 / 元信息）；具体字段待继续跟 **`FS::`** 与 **`OpenStream`** 命名 |
| **`Matrix.dat`** 头 **`54 44 01 01`** | 与 **`sub_31285C50`** 中 **`16860244`** 分支魔数一致 |
| **`lastmsginfo.dat`** 头 **`54 41 01 01`** | 另一类 **`TX`** 签名（`TA`），需单独 xref |

### 9.1 路径拼接的确凿代码（`sub_3102FDB0`）

该函数用 **`FS::CombineQNC`** 构造：

1. **`UserDataMsgStorage:`** + **`\\`** + 第一段目录名 **`a2`**（长度 &lt; 0x20 宽字符） + **`\\`** + 第二段目录名 **`a3`**（长度 &lt; 0x20）；
2. 在其上再拼 **`\\index.dat`**、**`\\content.dat`**，并 **`FS::CreateFileW`** 打开（失败时换标志 **`4098`** 重试）。

因此磁盘上的：

**`buddy\<QQ号>\index.dat`**、**`buddy\<QQ号>\content.dat`**

与虚拟路径：

**`UserDataMsgStorage:\buddy\<QQ号>\index.dat`**

**完全同源**（`discuss` / `group` 等同理）。**`info.dat`** 未在此函数出现，应由其它入口创建（待 xref）。

迁移工具 **`CTXConvertSS2CDMgr::RepairMsgByType`** 使用 **`%s\%s\content.dat`** / **`index.dat`**，与上述双层目录模型一致。

---

## 10. 归档为“人类可读”的可行工程路径（基于当前逆向）

1. **容器层**：实现或使用 **`StgOpenStorage`**，若失败则实现 **`TXEncryptMgr` + `Matrix.dat`** 后再 OLE（与 **`sub_31042D80`、`sub_31287E10`** 对齐）。
2. **索引层**：按 **`buddy/`、`group/`、`discuss/`、`system/`、`mobile/`** 分桶，再按 **UIN / 群号** 子目录解析 **`index.dat` / `content.dat`**。
3. **语义层**：对每条记录跑 **`Util::Msg::TranslateBuddyMsgToMsgPack` / `TranslateOldBuddyMsgToMsgPack`** 同类逻辑，或静态复现其 **`CTXBuffer`** 布局（需继续向下拆解 **`sub_31037800`** 等）。
4. **文本编码**：注意 **`GBK`/`BIG5`** 分支（**`sub_3102E8F0`**），导出 UTF-8 时需标明原始代码页。

---

## 11. 下一步（待写入后续段落）

- [x] **`content.dat` / `index.dat`**：已在 **`sub_3102FDB0`**、`RepairMsgByType` 确认 **`UserDataMsgStorage:\<通道>\<UIN>\`** 模板。
- [x] **`info.dat`**：见 **§12**（**`TXEncryptMgr::CreateDataStorage`** + 按通道/会话路径拼接；与 **`SNSFileSystem:\info.dat`** 区分）。
- [x] **`seqbase.dat`、`lastmsginfo.dat`**：见 **§12**（**`MsgStorage`** 初始化读入 + **定时器回写 `lastmsginfo`**；**`seqbase`** 为序列基线/水位相关二进制）。
- [x] **Linux 下 OLE**：已用 **Wine + MinGW 生成的 `msg2ole_extract.exe`**（逻辑同源 **`QQMgrMsg_src/ComFileExtr.cpp`**）成功 **`StgOpenStorage`** 打开样例 **`Msg2.0.db`** 并递归解压出 **`buddy/`** 等树；同一文件 **Python `olefile`** 仍报 **`incorrect DIFAT`**（走的不是 Win32 OLE）。

---

## 12. `info.dat` / `seqbase.dat` / `lastmsginfo.dat` 如何读写（IM.dll）

以下地址均以 **ImageBase `0x31000000`** 为模块基址；函数名为 IDA 默认名。

### 12.1 三条虚拟路径（消息库根）

在 **`sub_31041020`**（某 **`MsgStorage` 辅助类构造函数**）中，成员 **`this+5`、`this+6`** 被设为：

| 成员 | 构造方式 | 语义 |
|------|-----------|------|
| **`this+5`** | **`FS::CombineQNC(L"UserDataMsgStorage:", L"seqbase.dat")`** | 全局序列基线文件 **`seqbase.dat`**（OLE 根下的流/顶层文件） |
| **`this+6`** | **`FS::CombineQNC(L"UserDataMsgStorage:", L"lastmsginfo.dat")`** | 最近一条消息摘要/索引 **`lastmsginfo.dat`** |

二者**不**经过 **`TXEncryptMgr`** 包裹，而是直接 **`FS`** 路径（与 **`Matrix.dat`** 密钥流分离）；与 **`buddy/...` 子目录**下的 **`info.dat`** 打开方式不同。

### 12.2 `seqbase.dat` / `lastmsginfo.dat`：初始化读 + 定时写

**`sub_3103F5D0`**（日志上下文 **`MsgStorage`**）在 **`sub_3103E5C0`** 成功挂载 **`Msg2.0.db`** 之后：

1. **`FS::CreateFileW`** 打开 **`this+5`**（**`seqbase.dat`**），通过 **`ITXFile`** 虚表读长度；若有效载荷长度为 **0**，打日志 **`seqbase size = 0`**（字符串 **`aSeqbaseSize0`**），并走一套 **GUID `3EDD1723-0FF2-4DD8-A6F9-8576D8FF4561`** 相关的默认/修复分支（与 **`sub_3103F450`** 枚举的对象列表配合——疑似空库初始化或解密占位）。
2. 再 **`CreateFileW`** 打开 **`this+6`**（**`lastmsginfo.dat`**），把内容解析进 **`this+15`** 上的 **`ITXArray`**（**`Util::Data::CreateTXArray`**），供内存侧维护「最近消息」集合。
3. 调用 **`TXTimer::SetInterval(0xEA60, this+11, ...)`**，即约 **60 秒**周期触发 **`this+11`** 上的回调。

定时回调 **`sub_31040470`**（由 **`sub_31040A70`** 指向）：

- 在 **`*(this+2)`** 置位且 **`sub_310411B0`**（读取 **`this+8`** 标志）通过时，遍历 **`this+12` / `this+13`** 处的链表结构，按 **`CTXBSTR`** 键与 **`ITXFile`**/`ITXBuffer`** 协作做待同步项处理（日志 **`MsgStorage`**）；分支内含 **`sub_31040070`** 迭代、`sub_3103D840` 删除节点等典型「队列 drain」形态。
- 若 **`this+15`**（**`lastmsginfo`** 对应的 **`ITXArray`**）非空：再次 **`FS::CreateFileW`** 打开 **`this+6`**，把 **`ITXArray`** 序列化进 **`ITXBuffer`**，经 **`ITXFile`** 虚表 **写入/提交**（多处 **`vtable+52` / `+60` / `+80`** 组合符合「取缓冲 → 写文件 → 收尾」）。

**结论**：**`lastmsginfo.dat`** 在运行期被 **周期性写回**；**`seqbase.dat`** 在初始化阶段重点读取（长度校验 + 空文件分支）；二者共同支撑 **消息序号基线与「最后一条消息」展示/同步**，与 **`sub_3102FDB0`** 的 **`index.dat`/`content.dat`** 会话正文索引形成分工。

### 12.3 `info.dat`（会话级）：`TXEncryptMgr` 封装的两套路径

**按会话目录**（与磁盘 **`buddy\<UIN>\info.dat`** 一致）：

- **`sub_3102E700`** / **`sub_3102E7D0`**：格式化 **`L"%s%s\\%s\\info.dat"`**，参数为 **`UserDataMsgStorage:`** + **`this+12`** + **`this+16`** 两段宽字符串（通道名 + UIN/子 ID），再 **`TXEncryptMgr::CreateDataStorage`**。二者唯一差别是对 **`ITXDataStorage`** 虚表调用偏移 **+12** 与 **+16**（可理解为 **读/查询** 与 **写/更新** 或 **两种 COM 方法** 成对出现）。

**按通道根目录**（仅一层子名）：

- **`sub_3102D660`** / **`sub_3102D720`**：**`UserDataMsgStorage:\` + `this+8` 的 `CTXBSTR`** + **`\info.dat`**，同样 **`CreateDataStorage`**，虚表 **+16** / **+12** 成对。

以上说明 **`info.dat`** 并非裸 **`CreateFileW`**，而是 **经 `TXEncryptMgr` 的 `ITXDataStorage`**，与 **`Matrix.dat`** 封印链一致（参见上文 **§5**）。

### 12.4 易混淆同名：`SNSFileSystem:\info.dat`

**`sub_31274220`** 在 **`Infocenter.db`** 目录上挂载 **`SNSFileSystem:`**，再访问 **`SNSFileSystem:\info.dat`**（小写 **`info.dat`** 字面量在 **`aInfoDat_1`**）。若不存在则 **`CreateFileW`** 并写入 **`dwFileVersion`** 等 **`ITXData`**。这是 **资讯中心/SNS**，与 **`Msg2.0.db`** 树内 **`buddy\...\info.dat`** **不是同一条业务线**；归档时勿混用解析器。

### 12.5 迁移工具中的三文件

**`sub_31285240`**（**`CSS2CD` / `RepairMsgDb`**）：依次对 **`PrefixString + Matrix.dat`**、**`+ seqbase.dat`**、**`+ lastmsginfo.dat`** 调用 **`sub_31282C70`** 做修复，再 **`sub_31285030`** 处理 **`buddy`/`group`**，并调用 **`CTXConvertSS2CDMgr::RepairMsgByType`**。说明 **`seqbase`/`lastmsginfo`/`Matrix`** 在版本迁移时被视作 **同一批关键侧车文件**。

---

## 13. 命令行解压工具 `msg2ole_extract`（基于 QQMgrMsg_src）

路径：**`ai-work/msg2ole_extract/`**

- **源码**：`msg2ole_extract.cpp` — 从 **`ComFileExtr::ExtrDB` / `OnStart`** 抽出 **`IStorage::EnumElements` → 子存储建目录、流写文件**，去掉 MFC/`CDialog`，改为 **`wmain`** 参数：**`<Msg2.0.db>` `<输出目录>`**。
- **构建**：`make`（依赖 **`x86_64-w64-mingw32-g++`**），链接 **`-static -lole32 -luuid -lshell32`**，避免 Wine 下缺 **`libwinpthread-1.dll`**。
- **运行（Linux）**：`wine msg2ole_extract.exe <db路径> <输出目录>`（Wine 可接受 Unix 路径）。
- **样本结果**：对 **`stale-reader-encrypted/msg2.0/Msg2.0.db`** 解压得到 **`buddy\<UIN>\index.dat|content.dat|info.dat`** 等，与已有侧录目录结构一致。

---

## 14. `index.dat` / `content.dat` 容器与 buddy 明文体内层（直至可解析文本）

### 14.1 索引：`index.dat`

每条记录 **8 字节**：**`uint32 LE` 标记字 + `uint32 LE` 数值**。

标记字 **不是** UTF-16 双宽字符串，而是 **小端 32 位整数**，其 **低 16 位**为两段 **ASCII**：**`<标点><0x3a ':'>`**。实测常量：

| `uint32`（十六进制） | 可视 |
|---------------------|------|
| **`0x00003A2D`** | **`-:`**（字节序列 **`2D 3A 00 00`**） |
| **`0x00003A2E`** | **`.:`** |
| **`0x00003A2F`** | **`/:`** |

典型 **三条**（好友会话样本 **`buddy/1002598880`**）：

- **`-:`** → **`0`**  
- **`.:`** → **第一块载荷字节数**（与 **`content.dat`** 首部 **`uint32`** 相等，如 **`0x166` = 358**）  
- **`/:`** → **第二块相关长度**；与盘上 **`content.dat`** 对照：**`/: == len(文件) - 4 - .:` 数值 + 4`**（第二块前另有 **`uint32` 长度**类开销时与 **`/:`** 差 **4** 字节对齐）

极小会话（如 **`buddy/498795657`**）只有 **8 字节**索引，第一条 **`uint32`** 非上述 magic（如 **`0x1EC8`**），表示 **缩略/占位索引**，与 **`content.dat`** 首块内的 **`uint32`** 对应同一元数据。

### 14.2 正文容器：`content.dat`

两种外层模式（由首部 **`uint32`** 与 **`len(文件)`** 关系判定）：

1. **单块文件**：首部 **`uint32 == len(文件)`**，_payload = **`raw[4:]`**（总长含头部 4 字节）。  
2. **双块文件**：首部 **`uint32 == L1 < len(文件)`**，第一块体 **`raw[4:4+L1]`**，余 **`raw[4+L1:]`** 为第二块。

每块内部常见：**前 4 字节常为 `0`**，随后在 **偏移 4** 出现 **packed 标记** **`2D 3A 00 00`**（**`-:`**）或 **`2E 3A 00 00`**（**`.:`**），其后为 **密文**（需 **`Matrix.dat` + `TXEncryptMgr`** 解密后才能得到 buddy 体内层）。

### 14.3 Buddy 消息明文体内层（`sub_3102E8F0`，解密/反序列化之后）

指向 **`ITXData`** 子对象 **`v6`** 时：

| 偏移（相对 `v6`） | 含义 |
|------------------|------|
| **`[0:4]`** | 保留 / 未在本函数使用的字段 |
| **`[4]`** | **`uint8`**，与 **`bSelfMsg`** 等一起参与 UI 逻辑 |
| **`[5:9]`** | **`int32 LE`** **`L`**，**文本字节长度**（x86 **非对齐**加载） |
| **`[9:9+L]`** | **GBK / BIG5** 正文（由调用方 **`a1`** 选择 **`GBKToUnicode` / `BIG5ToUnicode`**） |
| 之后 | 可选 **`int32` 长度 + 字节块** 链，经 **`sub_31002B90`** 写入扩展 **`ITXBuffer`** |

### 14.4 工具与验证状态

- **脚本**：**`ai-work/msg2_parser/msg2_session_parse.py`**  
  - **`--self-test`**：对 **合成** buddy 内层字节流解析出 **`你好`**（**GB18030**），验证字段布局。  
  - **`<index.dat> <content.dat>`**：打印 **索引三元组**、**单块/双块**划分、**`-:` / `.:`** 偏移；对多样本校验 **`.:` == 首块长`、`/:` == 尾块相关长度 + 4**。  
- **加密**：当前样本 **`content.dat`** 在标记 **`-:` / `.:`** 之后为 **高熵密文**；在实现 **`TXEncryptMgr` + `Matrix.dat`（TD `54 44 01 01`）** 解密链之前，**无法从磁盘单独还原 UTF-8 聊天正文**。归档管线需在解密后接上 **`parse_buddy_plain_inner`** 同类逻辑。

---

## 修订记录

| 日期 | 内容 |
|------|------|
| 2026-05-02 | 初稿：IM.dll 中 Msg2.0.db / UserDataMsgStorage / 五类通道 / StgOpenStorage / Matrix.dat & 魔数 / 样例目录对照 / olefile 失败记录 |
| 2026-05-02 | 增补 **`sub_3102FDB0`** 路径模板、`RepairMsgByType`、**`sub_31285C50`** 魔数与 **`Matrix.dat`** 头对应关系 |
| 2026-05-02 | **`msg2ole_extract`**：MinGW CLI + Wine 实测解压 **`Msg2.0.db`** |
| 2026-05-02 | **§12**：**`info.dat` / `seqbase.dat` / `lastmsginfo.dat`** 读写链（**`sub_31041020`、`sub_3103F5D0`、`sub_31040470`、`sub_3102E700`/E7D0、D660/D720、`sub_31285240`**） |
| 2026-05-02 | **§14**：**`index.dat`/`content.dat`** packed 标记 **`0x3A2D`/`2E`/`2F`**、双块长度关系；**buddy** 内层 **`sub_3102E8F0`**；**`msg2_session_parse.py`** 实测交叉验证；密文依赖 **Matrix/TX** |
| 2026-05-02 | **§15**：**`TXEncryptMgr`** 在 **`Common.dll`**；**`Matrix.dat`** 双前缀；密钥字段 **`bufSvrSealEnc`/`bufPwdHashOne`/`buf16byteSessionKey`**；**CLSID** **`{49DB3AB8-7E8B-DAF8-D45F-C0DF-00000000}`**；**`ITXEncrypt`+12**；**`content.dat`** 经 **`ITXEncrypt`** 而非 **`FS` 透明解密** |
| 2026-05-02 | **§16**：**`Common.dll`** — **`Init`** = **MD5(flags∥16B)**；**`sub_30001CF0`** = **XXTEA**；**`sub_30002340`** = **XXTEA 信封**；Seal 字段 **`bufSvrSealEnc`** 等；**`MachineGuid`** 链路与 **XOR 表** **`byte_302078F0`** |
| 2026-05-02 | **§16.7**：**静态钉扎** — **`QueryEncrypt`→`sub_300990F0`→工厂 QI**（**`off_301B9FB0`/`unk_301B9FC8`**）；**`ITXEncrypt` `+12`** = **`sub_30095FA0`→`sub_30001FA0`**（加密）；**`+16`** = **`sub_30095FE0`→`sub_30095E10`→`sub_30002340`**（信封解密）；修正 **§15.5–15.6** 对 **`+12`** 的笼统表述 |
| 2026-05-03 | **§17**：QQ2009 **`MsgMgr.dll`** — **`Msg2.0.db`** 字面量仅 **`sub_61E4B590`** / 向导 **`sub_61E4D460`**；**`sub_61E60420`** 串联初始化；**`sub_61E5A690`** → **`FS::SetExitDelConfig(UserDataMsgStorage:, …)`** 与 **`bClrearMsgExit`**；QQ2009 **`IM.dll`** **`RemoveFileSystem`** 枚举无 **`UserDataMsgStorage:`** |
| 2026-05-03 | **§18**：QQ2009 **`Common.dll`** — **`SetExitDelConfig`/`GetExitDelConfig`** → **`sub_604AEA20`/`sub_604AE9E0`** → vtbl **`+0x6C`/`+0x68`** → **`sub_604B34E0`/`sub_604B34B0`**（**`this+0x30`**）；析构 **`sub_604A7480`** 在标志非 0 时对 **`CTXStringW(this+8)`** 调用 **`DeleteFileW`**（常为 **`Msg2.0.db`** 路径）；**`off_6057FEA0` vs `off_6057F940`**；MsgMgr 五处 **`AddFileSystem`** 无 **`UserDataMsgStorage:`**；**`Matrix.dat`** 经 **`IM.dll` + `TXEncryptMgr`**，**ExitDel 不按名删 `Matrix.dat`**，并列文件时 **`Matrix.dat` 多数仍保留** |
| 2026-05-03 | **§19**：QQ2009 **`KernelUtil.dll`** — **`FS::AddFileSystem(2, <Msg2.0.db 全路径>, L"UserDataMsgStorage:", …)`** 与 **`Info.db` → `UserDataInfoStorage:`** 均在 **`sub_60A3F970`**；**`RemoveFileSystem(UserDataMsgStorage:)`** 等见 **`sub_60A3F970`** 开头与 **`sub_60A37CB0`**；与 **§15.3** 两套 **`Matrix.dat`**、**§18.5** **`IM.dll` 仅消费挂载** 对齐 |

---

## 15. `TXEncryptMgr`：模块边界、API、密钥来源与解密链（IM.dll → Common.dll）

本节目标：弄清 **谁在何处实现加解密**、**密钥从哪些结构化字段来**、**与 `Matrix.dat` / 会话文件如何衔接**。结论：**对称算法与 `TXEncryptMgr` 本体不在 `IM.dll`，而在导入模块 `Common.dll`**；离线还原正文必须在 **`Common.dll` + `Matrix.dat` + 登录阶段密钥材料** 三条线索上继续。

### 15.1 实现位置（确凿）

对 **`IM.dll`** 的导入表枚举：**`TXEncryptMgr::QueryEncrypt` / `CreateDataStorage` / `AddEncryptInfo` / `Init`** 均从 **`Common`** 模块导入（IDA：`module idx 0` → **`Common.dll`**）。因此：

- **逆向「算法本体」**：应打开 **`QQ2010/Bin/Common.dll`**（与其它 Tencent 客户端同名 DLL 无关——必须以本安装目录为准）。
- **`IM.dll`** 仅持有 **调用序列**、**GUID**、**`ITXData` / `ITXEncrypt` 上的缓冲区搬运**。

### 15.2 面向归档的核心 API（导入符号）

| 修饰名（Mangling） | 语义（根据调用点归纳） |
|-------------------|------------------------|
| **`?CreateDataStorage@TXEncryptMgr@@YAJPB_WPAPAUITXDataStorage@@@Z`** | `HRESULT CreateDataStorage(wchar_t const *virtualOrOsPath, ITXDataStorage **pp)` — 打开 **`Matrix.dat`** 等路径对应的 **`ITXDataStorage`**（键值型文档接口，非裸 `CreateFileW`）。 |
| **`?AddEncryptInfo@TXEncryptMgr@@YAJU_GUID@@PAUITXDataStorage@@PAUITXSvrSealCrypto@@PAUITXEncUIGetPass@@PAUITXCallback@@H@Z`** | 把 **`GUID`（加密实现 CLSID）**、`Matrix` 打开的 **`ITXDataStorage`**、**`Util::SvrSeal::CreateSvrSeal`** 得到的 **`ITXSvrSealCrypto`**、可选密码 UI、回调等 **绑定到全局加密管理器**。 |
| **`?Init@TXEncryptMgr@@YAXKPAUITXBuffer@@@Z`** | `void Init(unsigned long flags, ITXBuffer *pwdOrMaterial)` — 见 **`sub_31022140`**：材料来自 **`bufPwdHashOne`**（见下）。 |
| **`?QueryEncrypt@TXEncryptMgr@@YAJU_GUID@@PAPAUITXEncrypt@@@Z`** | `HRESULT QueryEncrypt(GUID const &, ITXEncrypt **pp)` — 按 **固定 CLSID** 取出 **`ITXEncrypt`** 实例，供消息包装 **加密/解密**（见 **§15.5**）。 |

### 15.3 `Matrix.dat` 的两套挂载（勿混淆）

| 路径前缀 | 典型拼接 | 函数线索 | 用途 |
|----------|-----------|----------|------|
| **`UserDataMsgStorage:\Matrix.dat`** | **`FS::CombineQNC(..., L"Matrix.dat")`** | **`sub_31041510`**（`PerfStand.InitUserFileSystem`）、**`sub_31042D80`** | **消息库侧**：与 **`Msg2.0.db`** 同逻辑根的 **`Matrix.dat`**；**`sub_31042D80`** 在读 **`bufSvrSealEnc`**（见 **§15.4**）前创建该存储。 |
| **`UserDataInfoStorage:\Matrix.dat`** | 同上，前缀不同 | **`sub_31021BE0`**（PreLogin） | **账号信息侧**：与 **`Info.db`** / **`bufPwdHashOne`** 初始化 **`TXEncryptMgr::Init`** 相关；**`Util::SvrSeal::CreateSvrSeal(2, …)`**（类型 **`2`**）。 |

**与物理挂载（QQ2009）**：**`KernelUtil.dll`** 的 **`sub_60A3F970`** 依次 **`AddFileSystem`**：**`UserDataRoot:`**（类型 **`1`**）→ **`Msg2.0.db` 全路径 + `UserDataMsgStorage:`**（类型 **`2`**）→ **`Info.db` 全路径 + `UserDataInfoStorage:`**（类型 **`2`**）（字面量 **`Msg2.0.db`** / **`Info.db`** 与 **`aUserdatamsgsto_0`** / **`aUserdatainfost_0`** 同函数内成对出现）。因此 **§15.3** 两前缀下的 **`Matrix.dat`** 各落在 **两套用户数据根旁的两个独立文件**（通常与 **`Msg2.0.db`** / **`Info.db`** 并列目录），**不是** **`Msg2.0.db` 复合文档内部的两个同名流**。

消息初始化路径 **`sub_31041510`** 调用 **`Util::SvrSeal::CreateSvrSeal(1, …)`**（类型 **`1`**），再 **`AddEncryptInfo`** —— 与登录侧 **类型 2** 区分，表示 **两套 Seal 上下文**（同一 API，不同实例/用途）。

### 15.4 密钥与封印材料（`ITXData` 字段名 — 来自宽字符串字面量）

下列名称均在 **`IM.dll`** 中以 **`CTXBSTR` + `ITXDataStorage`/`ITXDataRead` vtable 偏移 `+68`**（按属性名读写缓冲区）等形式出现：

| 字段名 | 出现场景 | 作用（推断级别） |
|--------|-----------|------------------|
| **`bufSvrSealEnc`** | **`sub_31042D80`**（路径含 **`msg2.0.db`** 时） | 从 **`UserDataMsgStorage:` + `Matrix.dat`** 的 **`ITXDataStorage`** 读取；随后 **`sub_31010F20`** 校验 — **服务端封印扩展**，与消息加密链路绑定。 |
| **`bufPwdHashOne`** | **`sub_31022140`** | 读出后放入 **`TXEncryptMgr::Init`**；与 **本地口令/二次哈希** 相关（具体哈希算法在 **`Common.dll`**）。 |
| **`buf16byteSessionKey`** | **`sub_3101CF30`**（登录） | **`Util::Data::GetTXDataBuf`** → **`CTXBuffer`**；配合 **`Util::Time::SetServerTime`** — **16 字节会话密钥**，显然参与后续 **`ITXEncrypt`** 或 Seal **密钥派生**。 |
| **`bufSigLastLoginInfo`** | 同上 | 另一块与上次登录相关的 **签名/绑定缓冲**，用于 **`TXEncryptMgr`** / Seal **完整性或密钥封装**。 |
| **`cPassSeqID`** | **`sub_3101CF30`** | 登录 **`ITXData`** 上的 **`uint8`**；与 **`Util::SvrSeal::CheckKeyID(..., ITXEncrypt *)`** 搭配 — **密钥序号/版本**，用于校验 **`ITXEncrypt`** 是否与当前 **`Matrix.dat`** / 封印一致。 |

**离线含义**：仅有 **`buddy/.../content.dat`** 而不具备 **`Matrix.dat`** + **`buf16byteSessionKey`/`bufSvrSealEnc`/`bufPwdHashOne`** 中已在磁盘落库的材料，**无法在纯 Python 内还原明文** —— 必须先复现 **`Common.dll`** 中的 **派生与解密**。

### 15.5 固定 CLSID 与 `ITXEncrypt` 用法（消息加密）

多处 **`TXEncryptMgr::QueryEncrypt`** 之前写入同一 **`GUID`** 常量：

- **`*(QWORD*)&guid.Data1 = 0xDAF87E8B49DB3AB8`**
- **`*(DWORD*)&guid.Data4[0] = -542260844`** → 无符号 **`0xDFC05FD4`**
- 若 **`Data4` 后 4 字节为 0**，则规范字符串为：**`{49DB3AB8-7E8B-DAF8-D45F-C0DF-00000000}`**（Python `uuid.UUID(bytes_le=…)` 验证）。

**`sub_31030080` / `sub_31033B40`**（消息打包写会话存储）在 **`QueryEncrypt`** 成功后：

- 调 **`ITXEncrypt` vtable 第一个接口方法（相对接口指针偏移 `+12`，紧接在 `IUnknown` 三个槽之后）**：在 **`Common.dll` 工厂虚表 `off_301B9F70`** 上对应 **`sub_30095FA0`**（见 **§16.7**）→ **`sub_30095CD0`** → **`sub_30001FA0`** —— **加密写盘**（**不是** **`sub_30002340` 信封解密链**）。
- 头部拼接 **`Util::Msg::GetMsgTime`**、**`GetMsgRand32`**，再 **`sub_31040B60` / `sub_3103DE60`** 写入 **`index.dat`/`content.dat` 对应路径**。

**读档 / 解密复原**应对 **`ITXEncrypt` 上下一槽（工厂虚表里为偏移 `+16`）**：**`sub_30095FE0`** → **`sub_30095E10`** → **`sub_30002340`**（见 **§16.7**）。

### 15.6 `content.dat` 与 `TXEncryptMgr` 的关系（重要）

**`sub_3102FDB0`** 对 **`index.dat` / `content.dat`** 仅 **`FS::CreateFileW`** — **不在此处调用 `TXEncryptMgr`**。结合 **§14** 的高熵密文：

- **磁盘上的密文** = 上层已用 **`ITXEncrypt`**（或等价链路）处理后的字节，再写入 **`ITXFile`**。
- **解密入口不在 `FS::CreateFileW`**，而在 **读出 `ITXBuffer` 之后**、进入 **`TranslateOldMsgToMsgPack` / `sub_3102E8F0`** 之前 —— 走 **`ITXEncrypt`** 上 **`sub_30095FE0` 槽位**（相对 **`IUnknown` 为 `+16`**）→ **`sub_30002340`**（实现位于 **`Common.dll`**；与 **`+12` 写加密槽** **不对称**，见 **§16.7**）。

### 15.7 迁移工具中的 TD / NF 容器（非算法，属封装格式）

**`sub_31285C50`**：读流首 4 字节，区分 **`16860244` (`54 44 01 01`，TD)** 与 **`16860750` (`4E 46 01 01`，NF)**；TD 分支 **`sub_31285AD0`**（日志 **`CTXConvertSS2CDMgr::LoadFromTDFile`**）把 **`ITXBuffer`** 解成 **`ITXData`** 字段（跳过 **`pExtraInfo`**）。这是 **数据库迁移时的文档解析**，**不是** `TXEncryptMgr` 内部对称算法本身；真正加密仍由 **`Common.dll`** 提供。

### 15.8 移植 vs `ctypes`/`Wine` 调用现有 DLL（工程建议）

| 路线 | 条件 | 说明 |
|------|------|------|
| **完整移植** | 在 **`Common.dll`** 中核对 **`MD5`/`XXTEA`/`sub_30002340` 信封**与 **`Matrix`** 字段派生（见 **§16**） | 已确认 **非 AES/RC4**：会话侧对称核心是 **XXTEA（64-bit 块）** + **自定义二进制信封**； **`ITXEncrypt` 虚函数体内**仍需对照 **`Common.dll`** 内对应类的 xref。 |
| **就地调用** | Linux 上 **`wine`** + 拷贝 **`Common.dll` + 依赖 DLL** + 最小桩还原 **`FS`/`UserDataMsgStorage` 映射** | 通过 **`ctypes.cdll.LoadLibrary`** 取导出符号（注意 **thiscall/stdcall** 与 **`HRESULT`**）；仍需 **有效 `Matrix.dat` 与密钥材料**，否则 **`Init`/`QueryEncrypt`** 失败。 |
| **务实取证** | 在 **Windows / Wine** 里跑 **`QQ.exe` + 钩子** 截 **`ITXEncrypt` +12** 出入参 | 可比静态逆向更快拿到 **明文缓冲与密钥长度**。 |

对称算法骨架见 **§16**。**`QueryEncrypt` → `ITXEncrypt` → `sub_30002340` 的静态钉扎见 §16.7**（已完成）。下一步工程验证：在 **`buf==1` 信封 + `this+31` 密钥** 与 **`buddy/.../content.dat`** 切片之间 **对齐帧边界** 实测。

---

## 16. `Common.dll`：`TXEncryptMgr::Init`、MD5、XXTEA 与信封解密（IDA 已加载 **`Common.dll.i64`**）

**模块基址**：**`0x30000000`**。导出 **`TXEncryptMgr`**：`Init` **`0x300990D0`**，`QueryEncrypt` **`0x300995B0`**，`AddEncryptInfo` **`0x300998A0`**，`CreateDataStorage` **`0x3009A110`**。

### 16.1 `TXEncryptMgr::Init` → **MD5(`uint32` flags ∥ 16 字节材料)**

**`sub_30098DE0`**（**`Init`** 本体）：若 **`ITXBuffer`** 提供的载荷长度 **`Size == 16`**：

1. **`sub_30001000`**：初始化标准 **MD5** 状态向量 — **`0x67452301`、`0xEFCDAB89`、`0x98BADCFE`、`0x10325476`**（与 RFC 1321 **IV** 一致）。
2. **`sub_300016C0`**：依次 **`MD5_update(flags, 4)`**、**`MD5_update(payload, 16)`**。
3. **`sub_30001A80`**：**MD5 结尾填充与摘要**，把 **16 字节摘要**写回 **`TXEncryptMgr` 全局状态**（供后续 **`QueryEncrypt` / Seal** 使用）。

即：**口令/会话种子经过「4 字节标志 + 16 字节二进制」再 **MD5**，不是裸用 16 字节当对称密钥。**

### 16.2 **`sub_30001CF0`**：单块 **XXTEA 解密**（64-bit 块 + 128-bit 密钥）

反编译特征：

- 输入 **`uint32 v4, v5`** 经 **`_byteswap_ulong`** 做大端置换后与 **4×32-bit 密钥字 `v8[0..3]`** 交替迭代；
- 循环变量 **`v6`** 初值 **`0xE3779B90`**（即 **`0x9E3779B9 * 16`**），每轮 **`v6 += 0x9E3779B9`**，共 **16 轮**；
- 更新式含 **`(x + (y<<4))`、`(y>>5)`** 形式的 **XXTEA** 典型混合。

结论：**腾讯在此处使用 Corrected Block TEA（XXTEA）对一个 **8 字节块**解密；密钥材料为 **紧跟调用点的 16 字节（四 dword）**。

### 16.3 **`sub_30002340`**：基于 XXTEA 的 **变长二进制信封**（密文解析）

在 **`a2 % 8 == 0`** 且 **`a2 >= 16`** 前提下：

- 先用密钥 **`a3`（128-bit）** 调 **`sub_30001CF0`** 派生 **8 字节工作态 `v27`**；
- 根据首部 **`v27[0] & 7`** 计算实际明文长度并写回 **`a5`**；
- 将 **`a1`** 指向的缓冲区解释为：**版本/类型字节 `*a1 == 1`**（与 **`sub_30095E10`** 中判断一致）+ **后续 8 字节对齐密文**；
- 内层双重循环：**XXTEA 反馈式 XOR**（块链），把解密结果写入 **`a4`**。

该函数被 **`sub_30095E10`**（封装 **`ITXBuffer`** → 明文 **`CTXBuffer`**）、**`sub_300D5F70`**、以及 **`sub_3000C5C0`**（读 **`txssogbcf.db`**）等多处调用。

### 16.4 Seal / **`Matrix.dat`** 上下文初始化（**`sub_300960A0`** / **`sub_30097FF0`**）

**`sub_300996F0`**（**`AddEncryptInfo`** 主体）在注册 GUID 对应的链表节点后，调用 **`sub_300960A0`**（最后一参非 0）或 **`sub_30097FF0`**（最后一参为 0），从挂载的 **`ITXDataStorage`** 读出字段并完成 **16 字节会话密钥材料**写入对象偏移 **`this+31`…**：

典型 **`ITXData` 键名**（宽字符串）：**`bValidInit`**、**`bSysLocalHash`**、**`bufRandKeyEnc`**、**`bufSvrSealEnc`**；另有 **`buffrLocalPasswdHash`**、**`buffLocalAnswerHash`**、**`bufLocalHash1`** 等分支（本地口令/密保路径）。

**`sub_30097FF0`** 中若缺失服务端封印：用 **`Util::Sys::Random`** 与 **`CoCreateGuid`** 对 **`this+31`..** 做 **XOR 混淆**，并可经 **`sub_30095CD0`** 写入 **`bufRandKeyEnc`**；若存在 **`bufSvrSealEnc`**：打日志 **`PerfStand.DecryptMsg.Begin`**，并调用 **`ITXSvrSealCrypto::vtable+16`**（**`DecryptMsg`** 语义）把封印解密进缓冲。

### 16.5 旁路：`MachineGuid` → XXTEA → XOR 表（**`sub_3000BA00`** + **`sub_3000C5C0`**）

**`sub_3000BA00`**：读注册表 **`HKLM\SOFTWARE\Microsoft\Cryptography\MachineGuid`**，经自定义 **base36 风格映射表** **`"FGDEBC@A-JKHI-…"`** 折叠成 **16 字节**，作为 **`sub_30002340`** 的 **`sub_3000BA00(&v30)` 密钥输入**。

**`sub_3000C5C0`**：成功解密后，对明文逐字节 **`^= byte_302078F0[2 * (i & 0x3F)]`** — **128 字节查找表**再混淆一层。

### 16.6 与 **`content.dat`** 对接：解密链 **vs** 写盘加密链

已证实：**对称基元为 **MD5（密钥派生）** + **XXTEA（块密码）** + **`sub_30002340`（自定义信封）****。  
**读档解密**与 **`IM.dll` 写盘时调用的 `+12` 槽** **不是同一条函数链**：**`+12` → 加密（`sub_30001FA0`）**；**解密信封 → `sub_30095FE0` 槽 → `sub_30002340`**。详见 **§16.7**。

### 16.7 **静态钉扎**：**`TXEncryptMgr::QueryEncrypt` → `ITXEncrypt` → `sub_30002340` / `sub_30001FA0`**（**`Common.dll.i64`**，**ImageBase `0x30000000`**）

下列结论来自 **反汇编 + 交叉引用**，**无运行依赖**。

#### 16.7.1 **`QueryEncrypt` 本体**

- **`TXEncryptMgr::QueryEncrypt`** → **`sub_300995B0`** → **`sub_300990F0`**（**`0x300990F0`**）。
- **`sub_300990F0`**：在 **`this+0x14`** 起的 **GUID 链表**上按 **`sub_30098F70`** 查找节点；命中后取 **`(list_node + 0x1C)`** 处的 **ATL 类厂对象指针**，且  
  **`call dword ptr [eax]` → `call dword ptr [edx]`**（**`0x3009919c`–`0x300991a7`**）：等价于 **`factory->lpVtbl[0](factory, &unk_301B9FC8, ppITXEncrypt)`** —— **`AtlInternalQueryInterface`**（**`sub_30098810`**），**对象映射表**为 **`off_301B9FB0`**（**`0x301B9FB0`**），内嵌 **IID / 类对象 vtable** 指针 **`unk_301B9FC8`**（**`0x301B9FC8`**）。

#### 16.7.2 **类厂虚表（加密对象由此 QI 出来）**

- **类厂 `vtable`**：**`off_301B9F70`**（**`0x301B9F70`**）。
- **`[0]` `sub_30098810`**：`AtlInternalQueryInterface` 包装。
- **`[3]` `sub_30095FA0`**、**`[4]` `sub_30095FE0`**：两条 **实例方法桩**（与 **`IUnknown` 后第一个、第二个接口槽**对齐讨论 **§15.5**）。

#### 16.7.3 **密钥门闸 `*(this+0x1C)` 与材料 `this+0x1F`**

- **`sub_30095FA0` / `sub_30095FE0`** 汇编一致：**`cmp byte ptr [this+1Ch], 0`**（**`0x30095fa6` / `0x30095fe6`**）；为假则 **`HRESULT 0x8000FFFF`**。
- 两函数均在 **`add eax, 1Fh`** 后把 **`this+0x1F`**（**31**）压栈作 **`sub_30095CD0` / `sub_30095E10`** 的 **第三参** —— 即 **16 字节密钥材料指针**（与 **§16.4** **`this+31`** 叙述一致）。

#### 16.7.4 **写加密槽 `sub_30095FA0` → `sub_30001FA0`（不经 `sub_30002340`）**

- **`sub_30095FA0`** → **`sub_30095CD0`**。
- **`sub_30095CD0`**：从 **`ITXBuffer` vtable `+48` / `+52`** 取指针与长度；核心变换 **`sub_30001FA0`**（**`0x30001FA0`**）—— **LCG（`214013` / `2531011`）+ 多轮按字节混淆**，循环内调 **`sub_30001C60`**（**`0x30001C60`**）。  
- **`sub_30001C60`**：**XXTEA「加密方向」单块混合**（与 **`sub_30001CF0` 解密**成对），**xref 上不接 **`sub_30002340`****。

#### 16.7.5 **解密信封槽 `sub_30095FE0` → `sub_30095E10` → `sub_30002340`**

- **`sub_30095FE0`** → **`sub_30095E10`**（**`0x30095E10`**）。
- **`sub_30095E10`**：**`ITXBuffer` vtable `+48` / `+52`** 取缓冲；若 **`*pb == 1`**（**`0x30095e8b`**）则 **`sub_30002340(v10+1, len-1, key, …)`**（**`0x30095ebc`**）。  
- **`sub_30002340`** 内部 **`call sub_30001CF0`**（**XXTEA 解密**，**`0x30002393`** 等）—— 与 **§16.2–16.3** 一致。

#### 16.7.6 **结论（回答「`ITXEncrypt` 是否钉到 `sub_30002340`」）**

| 槽位（相对 **`IUnknown`，x86） | 代表函数 | 是否调用 **`sub_30002340`** | 备注 |
|----------------------------------|----------|-------------------------------|------|
| **`+12`** | **`sub_30095FA0`** | **否** | → **`sub_30095CD0`** → **`sub_30001FA0`**（**PRNG + `sub_30001C60`**） |
| **`+16`** | **`sub_30095FE0`** | **是**（经 **`sub_30095E10`**） | **`sub_30002340`**，且要求 **信封首字节 `1`** |

因此：**静态分析已确定** **`sub_30002340`** 落在 **`ITXEncrypt` 工厂虚表相邻的「下一接口方法」**，与 **`IM.dll` 写路径常用的 `+12`（加密）不是同一实现**；从 **`content.dat` 还原正文应对齐 **`sub_30095E10`/`sub_30002340`** 的缓冲语义（**version byte + 8 字节对齐体 + `this+31` 密钥**）。

---

## 17. QQ2009 `MsgMgr.dll`：向导里的 `Msg2.0.db`、`UserDataMsgStorage:` 与 `FS::SetExitDelConfig`（IDA MCP）

**IDB**：`.../msg2.0/QQ2009/Bin/MsgMgr.dll.i64`。本节与 **§3–§5** 的 **`IM.dll` 主链路**并列：MsgMgr 侧重 **UI / 导入向导与 FS 初始化**，**无** `Matrix.dat` 字面量（`strings -el` / IDA 文本检索均为负）。

### 17.1 `Msg2.0.db` 在 MsgMgr 中的位置：**消息导入向导**，非主打开路径

- **`sub_61E4B590`**（地址以 QQ2009 IDB 为准）：按对象内模式字段分支；在 **分支 2** 中构造 **`SelfUin` 子目录**，依次探测字面量 **`Msg2.0.db`、`MsgSS.db`、`MsgEx.db`**，通过 **`Util::Misc::CombinePath`**、**`FS::CombineQNC`** 与 **`FS::IsFileExist` / `FS::IsDirectoryExist`** 选出存在的路径并写入对象内 **`CTXStringW` 字段**（供导入 UI 使用）。
- **唯一代码引用**来自 **`sub_61E4D460`**：在向导状态 **20**（界面串 **`Import_Msg_Btn_Next`**）下调用 **`sub_61E4B590`**，随后继续表情目录、定时器、导入进度等逻辑。
- **结论**：此处 **`Msg2.0.db`** 服务于 **「消息导入」对话框**，与 **`IM.dll`** 中挂载 **`UserDataMsgStorage:`** 并配合 **`TXEncryptMgr`** 打开在线消息库 **不是同一条主链路**。

### 17.2 用户根初始化入口 **`sub_61E60420`**

- 参数为 **`wchar_t *`** 用户目录；依次调用 **`sub_61E5A690`** → **`sub_61E5CB10`** → **`sub_61E5FD30`** → **`sub_61E5D1D0`** → **`sub_61E59F40`**。
- 对该函数的 xref 主要来自 **数据（导出 / COM 注册）**，符合「上层传入用户路径做一次批量初始化」的形态。

### 17.3 **`UserDataMsgStorage:` 与退出清理：`FS::SetExitDelConfig` + `bClrearMsgExit`**

初始化函数 **`sub_61E5A690`** 在前期完成 **`QQOldConfigDb:`、`ComQQ\SysData.dat`** 等与 **`FS::AddFileSystem` / `CreateFileW` / `RemoveFileSystem`** 相关的挂载后，从配置 **`ITXData`** 读取键 **`bClrearMsgExit`**（二进制字面量拼写为 `bClrear…`，语义为 **ClearMsgExit** 一类开关）。条件满足时调用：

**`FS::SetExitDelConfig(L"UserDataMsgStorage:", flag)`**（**`Common.dll`**：**`?SetExitDelConfig@FS@@YAHPB_WH@Z`**）。

**含义**：是否在 **进程退出** 时对虚拟前缀 **`UserDataMsgStorage:`** 做「按配置的删除 / 清理」**由配置与 Common 实现共同决定**，并非 MsgMgr 写死；是否等价于删除盘上 **`Matrix.dat`**，需在 **`Common.dll` 内对该 API 反编译** 才能钉死。

### 17.4 与 QQ2009 **`IM.dll`** 中 **`RemoveFileSystem`** 的对照

对 **`IM.dll`** 内 **`FS::RemoveFileSystem`** 全部调用点核对字面量，仅出现 **`CheckMsg:`、`ExportMsg:`、`ImportMsg:`、Hummer* 临时挂载、`UserCustomFace:`** 等，**未出现** 对 **`UserDataMsgStorage:`** 的 **`RemoveFileSystem`**。**QQ2009** 上对 **`UserDataMsgStorage:`** 等前缀的 **`RemoveFileSystem`** 出现在 **`KernelUtil.dll`**（**`sub_60A3F970`** 开头、**`sub_60A37CB0`**，**§19**）。与 **§17.3** 的可配置退出清理不矛盾；细节在 **Common** 层。

---

## 18. QQ2009：`Common.dll` 内 `FS::SetExitDelConfig` / ExitDel 全链路；与 `Matrix.dat` 是否被删（IDA MCP，2026-05）

以下地址均以 **QQ2009 `Common.dll.i64`** 为准，**ImageBase `0x60400000`**（与 QQ2010 **`Common.dll`** 基址 **不同**，勿混用 §15–§16 的 **`0x300…`** 符号）。

### 18.1 导出 API：薄封装

| 导出 | 地址（约） | 行为 |
|------|------------|------|
| **`?SetExitDelConfig@FS@@YAHPB_WH@Z`** | **`0x604AA300`** | **`sub_604A6450()`** 取/建 FS 单例（**`dword_605C00C8`**；首次 **`operator new`**、构造、**`Util::Misc::AddToDeadQueue(2, sub_604A6310, …)`**）；再 **`call sub_604AEA20`**，传入 **虚拟前缀宽字符串**、**整型 flag**。 |
| **`?GetExitDelConfig@FS@@YAHPB_WPAH@Z`** | **`0x604AA2E0`** | 同样 **`sub_604A6450`**，再 **`call sub_604AE9E0`**，把结果写入调用方 **`int*`**。 |

### 18.2 按前缀查找挂载项后写「开关」：`sub_604AEA20` / `sub_604AE9E0`

- **`sub_604AC510`**：在带 **`EnterCriticalSection`** 的向量里用 **`CTXStringW::CompareNoCase`** 匹配已注册的 **虚拟盘前缀**（如 **`UserDataMsgStorage:`**）。
- 命中项 **`entry+0x0C`** 指向 **具体挂载实现对象** **`impl*`**；**`impl*`** 首 dword 为 **vtable**。
- **Set**：**`call [vtable + 0x6C]`**，参数 **`(impl*, int flag)`**，**HRESULT 语义**，**`< 0` 视为失败**（反汇编 **`mov eax, [ecx+6Ch]` / `call eax`**）。
- **Get**：**`call [vtable + 0x68]`**，参数 **`(impl*, int *out)`**。

**本层无 `Matrix.dat`、`DeleteFileW`、`RemoveFileSystem` 字面量**——只做「给**这一条已注册挂载**打一个 ExitDel 标志」。

### 18.3 OLE 挂载类虚表：`off_6057FEA0` 上 **`+0x68` / `+0x6C`** 的钉扎实现

**`FS::AddFileSystem`**（**`sub_604AF2B0`**）在 **类型为 2（OLE/结构化存储）** 时通过 **`sub_604ABE40`** 构造对象，其 vtable 为 **`off_6057FEA0`**。

对该 vtable 按槽位读取（32 位 **dword** 槽）：

| 槽（字节偏移） | 函数 | 行为摘要 |
|----------------|------|-----------|
| **`+0x68`** | **`sub_604B34B0`** | **`*out = *(_DWORD *)(this + 48)`**，即读 **`this + 0x30`**。 |
| **`+0x6C`** | **`sub_604B34E0`** | **`*(_DWORD *)(this + 48) = flag`**，即写 **`this + 0x30`**。 |

另：**`TXEncryptMgr::CreateDataStorage`** 用的 **`sub_604A4930`** 小包装类虚表 **`off_6057F940`** 槽位布局不同（例如 **`+0x6C`** 曾落到 **`sub_604A8150`**），**勿与 OLE 挂载类混淆**。

### 18.4 退出时谁 **`DeleteFileW`**：**`sub_604A5000` → `sub_604A7480`**

- **`sub_604A6310`**（**DeadQueue**）：只做 FS 单例析构前的收尾（**`sub_604AF230`** 清注册表向量等），**不是**按 ExitDel 删某个文件名。
- **`sub_604A5000`**（scalar deleting dtor）：换 vtbl、释放全局引用后 **`call sub_604A7480`**。
- **`sub_604A7480`**（大块清理逻辑节选）：在释放内部链表与 **`this+0x0C`** 上 COM 引用之后，判断 **`this + 0x30`**（即 **§18.3** 的 ExitDel  dword）：  
  **`v7 = (*(_DWORD *)(this + 48) == 0)`**；**`if (!v7)`**（即 **标志非 0**）时取 **`CTXStringW(this + 8)`** 的宽路径，**`DeleteFileW`** **一次**。

**含义**：ExitDel 生效时删除的是 **挂载实现对象里 **`this+8` 记录的那一条物理路径**——对消息 OLE 场景通常是 **`Msg2.0.db` 的完整路径（复合文档文件）**，**不是**在同一析构函数里再按文件名删除 **`Matrix.dat`**。

### 18.5 `MsgMgr.dll`（QQ2009）：**`bClrearMsgExit` → `SetExitDelConfig(UserDataMsgStorage:, …)`**；**`AddFileSystem` 字面量不含该前缀**

- **`sub_61E5A690`**：读配置键 **`bClrearMsgExit`**（字面量约 **`0x61E8A6BC`**）；成功则 **`push flag`**、**`push offset "UserDataMsgStorage:"`**（约 **`0x61E5B013`**），调用 **`FS::SetExitDelConfig`**。
- 对 **`?AddFileSystem@FS@@`** 在 MsgMgr 内的 xref（如 **`0x61E59FB2`、`0x61E5A71A`、`0x61E5CB94`、`0x61E5D242`、`0x61E5FDB4`**）核对：**均为 `QQOldConfigDb:`、`QQOldUserDataDb:`、`QQOldUserDb:`、`QQOldCQQApplicationConfigDb:` 等与 `UserDataMsgStorage:` 无关的前缀**。
- 将 **`UserDataMsgStorage:`** 挂到 **磁盘上 `Msg2.0.db` 全路径** 的 **`FS::AddFileSystem(2, …)`** 在 **`KernelUtil.dll`** 的 **`sub_60A3F970`**（**§19**），**不在** **`IM.dll`** / **`MsgMgr.dll`**。
- **`IM.dll`** 在挂载已生效后负责 **子路径**（如 **`sub_60638A60`** **`CombineQNC` + `CreateDirectoryW`**；**`sub_6063B290`** **`CreateFileW` 打开 `index.dat`/`content.dat`** 等）。

### 18.6 `IM.dll`（QQ2009）：**`Matrix.dat` 与 **`Msg2.0.db`** 并列使用；与 ExitDel 删除目标不同

- **`sub_60647120`**：**`FS::CombineQNC(L"UserDataMsgStorage:", L"Matrix.dat")`** → **`TXEncryptMgr::CreateDataStorage`**（与 **`sub_606475A0`** 等在路径含 **`msg2.0.db`** 时分支一致）。
- **`Matrix.dat`** 走 **`TXEncryptMgr`** 小对象虚表（**`off_6057F940`** 那条链），与 **§18.3–18.4** 里 **`off_6057FEA0` + `sub_604A7480`** 的「删 **`this+8` 单路径**」**不是同一条析构语义**。

### 18.7 结论：**ExitDel 触发后 `Matrix.dat` 还在不在？**

- **若盘上 `Matrix.dat` 与 `Msg2.0.db` 是两个独立文件**（常见）：**`sub_604A7480` 只对 `this+8` 指向的那一个路径调用一次 `DeleteFileW`**，通常对应 **`Msg2.0.db`**；**不会在同一函数内再删名为 `Matrix.dat` 的文件**。因此 **`Matrix.dat` 多数仍会留在目录中**（除非另有整目录删除、手工删除或其它未在本次静态路径中出现的清理代码）。
- **§17.3** 中「是否等价于删 **`Matrix.dat`**」——**按当前钉死的 Common 实现**：**不等价**；删的是 **OLE 挂载绑定的单一路径（常为 `Msg2.0.db`）**，**不是**并列的 **`Matrix.dat`**。

---

## 19. QQ2009 `KernelUtil.dll`：`UserDataMsgStorage:` / `UserDataInfoStorage:` 的真实 **`AddFileSystem`**；与 **`RemoveFileSystem`**

**IDB**：`.../msg2.0/QQ2009/Bin/KernelUtil.dll.i64`。本节钉 **「虚拟前缀对应哪条物理路径」** 的 **注册点**；与 **§3**（QQ2010 **`IM.dll`** 内的 **`MsgStorage`** 叙事）、**§17–§18**（MsgMgr / Common / **`IM.dll`** 消费侧）互补。

### 19.1 为何不在 **`IM.dll`** 里看到 **`AddFileSystem(..., L"UserDataMsgStorage:", …)`**

对 **`IM.dll`（QQ2009）** 的 **`?AddFileSystem@FS@@`** xref 核对：**`CheckMsg:`、`ExportMsg:`、`OldVer*:`、`UserCustomFace:`、`SNSFileSystem:`** 等 **均无** 字面量 **`UserDataMsgStorage:`**。  
**`UserDataMsgStorage:`** 在 **`IM.dll`** 中 **仅** 与 **`CombineQNC` / `CreateDirectoryW` / `TXEncryptMgr::CreateDataStorage`** 等同现——前提是 **进程更早** 已完成 **FS 注册**。

### 19.2 **`sub_60A3F970`**：先 **`RemoveFileSystem`**，再 **`UserDataRoot:`**，再 **`Msg2.0.db` → `UserDataMsgStorage:`**，再 **`Info.db` → `UserDataInfoStorage:`**

函数开头对 **`UserDataRoot:`、`UserDataMsgStorage:`、`UserDataInfoStorage:`** 等 **一批前缀** 调用 **`FS::RemoveFileSystem`**（与 **§17.4**「**`IM.dll`** 不卸 **`UserDataMsgStorage:`**」**不矛盾**——卸载在这里做）。

随后 **`Util::Sys::GetGlobalDataUsersDir`**、**`CTXStringW::Format(L"%lu", UIN)`**、**`operator+`**（含 **`\\`**）拼出 **用户数据目录**；再：

1. **`FS::AddFileSystem(1, …, L"UserDataRoot:", 0, 0)`**（**`FILESYSTEM_TYPE` = 1**；字面量 **`aUserdataroot_0`**）。
2. **`operator+`** 接上 **`Msg2.0.db`**（字面量 **`aMsg20Db`**）得到 **OLE 文件全路径**，再 **`FS::AddFileSystem(2, <该宽路径>, L"UserDataMsgStorage:", 0, 0)`**（**类型 2**；字面量 **`aUserdatamsgsto_0`**）。
3. 同理 **`Info.db`**（**`aInfoDb`**）+ **`FS::AddFileSystem(2, …, L"UserDataInfoStorage:", …)`**（**`aUserdatainfost_0`**），以及 **`Misc.db`** 等后续挂载（同函数内连续 **`push 2` + `AddFileSystem`** 块）。

**结论**：**`UserDataMsgStorage:`** 在磁盘上绑定的是 **当前用户目录下的 `Msg2.0.db`（CFB 复合文档）的绝对路径**；**`UserDataInfoStorage:`** 绑定 **`Info.db`**。这与 **§15.3** 两套 **`Matrix.dat`** 的前缀划分一致（**消息树 vs 账号信息树**）。

### 19.3 **`sub_60A37CB0`**：成批 **`RemoveFileSystem`**（含 **`UserDataMsgStorage:`**）

在构造 **全局 / 用户目录** 相关 **`CTXStringW`** 之后，对 **`UserDataRoot:`、`UserDataMsgStorage:`、`UserDataInfoStorage:`** 等 **连续调用 `RemoveFileSystem`**（字面量 **`aUserdataroot`**、**`aUserdatamsgsto`** 等），形态为 **「切换账号 / 重建 FS 前清空注册」** 一类逻辑。

### 19.4 与 **`Matrix.dat`、`ExitDel`** 的衔接（只读归纳）

- **`Msg2.0.db`** 与 **`Matrix.dat`** **仍是两个不同角色**：前者是 **OLE 挂载目标**（**§18.4**：**`DeleteFileW` 常指向 `this+8` → `Msg2.0.db`**）；后者走 **`TXEncryptMgr`** 小对象链（**§18.6**），**ExitDel** 路径不会按文件名删除 `Matrix.dat`。
- **`UserDataInfoStorage:`** 侧 **`Matrix.dat`** 不在 **`Msg2.0.db`** 目录内；归档时需 **分别复制** 两套前缀旁（或与 **`Info.db`**/**`Msg2.0.db`** 并列）的 **`Matrix.dat`**（见 **§15.3** 增补段）。

---
