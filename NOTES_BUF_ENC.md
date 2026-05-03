# bufSvrSealEnc 加密链 — 探索进展（工作笔记）

本文档记录对 **`bufSvrSealEnc`（`Matrix.dat` 内 `ITXData` 键）所使用加密/编码算法** 的静态分析进展、已确认事实与未闭合问题。与主笔记 `NOTES.md` 第 5、15、16 节衔接。

**分析日期**：2026-05-02  
**主要 IDB / MCP 实例**（多 IDA 进程同时存在时经 `list_instances` / `select_instance` 切换）：

| 端口 | 模块 | 基址 | 说明 |
|------|------|------|------|
| 13338 | `Common.dll` | `0x30000000` | `TXEncryptMgr`、`sub_30097FF0`、ITX 缓冲与通用算法 |
| 13339 | `KernelUtil.dll` | `0x31800000` | `Util::SvrSeal::CreateSvrSeal`、`CheckKeyID`、ATL 模块 |
| 13337 | `IM.dll` | （用户侧打开） | 调用侧：`Matrix.dat`、`AddEncryptInfo`、登录封印 |

---

## 1. 已确认：`Common.dll` 侧语义（磁盘字段 ≠ 明文）

### 1.1 数据来源与命名

- `Matrix.dat` 经 **`TXEncryptMgr::CreateDataStorage`** 映射为 **`ITXDataStorage`**，键值 **`bufSvrSealEnc`**（字面量在 `Common.dll` 约 **`0x301b9ea4`**）。
- 字段名后缀 **`Enc`**，与同文件中 **`bufRandKeyEnc`** 等并列，表示盘上多为 **编码/加密后的二进制**，而非 UTF-16 明文属性串。

### 1.2 解密调用链（虚函数）

在 **`sub_30097FF0`**（`TXEncryptMgr::AddEncryptInfo` 注册节点后的上下文初始化）中：

- 若存在 **`bufSvrSealEnc`**：写日志 **`PerfStand.DecryptMsg.Begin`**（字面量约 **`0x301b9ef4`**），随后对 **`ITXSvrSealCrypto`/`ITXIMSvrSealCrypto`** 实例调用 **虚表偏移 `+0x10`（第 4 个槽：IUnknown 之后约 `DecryptMsg` 语义）**，输入为从存储读出的 **`ITXBuffer`**，外加 **`this+23`** 一类上下文指针。
- **`Common.dll` 在此处不显式展开对称算法体**：算法实现在 **Seal COM 对象** 所指模块内。

### 1.3 与「_randKeyEnc / XXTEA 信封」路径的区别

- **`bufRandKeyEnc`** 分支可走 **`sub_300960A0`** → **`sub_30095E10`** → **`sub_30002340`**（已在 `NOTES.md` §16 对齐为 **XXTEA + 自定义二进制信封**）。
- **`bufSvrSealEnc`** 分支依赖 **`ITXSvrSealCrypto::vtable+0x10`**，**不**从同一段 `sub_30095E10` 的 xref 树直接得出与 `sub_30002340` 的必然同一性；需单独跟进 **KernelUtil（或 manifest 指向的其它 DLL）** 内 **DecryptMsg** 实现。

---

## 2. 已确认：`KernelUtil.dll` 与 `CreateSvrSeal`

### 2.1 导出与工厂

- **`?CreateSvrSeal@SvrSeal@Util@@YAJEPAPAUITXIMSvrSealCrypto@@@Z`**  
  - IDA 中函数入口约 **`0x3182bed0`**（随 IDB 可能有符号差异）。
- **`CreateSvrSeal`** 逻辑概要：
  1. 调用 **`sub_31820310(&unk_318680A4, &unk_318680A4, a2)`**，两次同一指针。
  2. **`unk_318680A4`** 处 16 字节 GUID（LE）解析为：**`{EDC5158A-8148-401A-9F2B-A72863BCA24A}`**。
  3. **`sub_31820310`** 通过 **`Util::Core::GetPlatformCore`** 取得 **`ITXCore*`**，再 **`vtable+0x1C`**（字节偏移 **28**）创建实例（等价 **`CreateInstance(CLSID, IID, ppv)`** 形态）。
  4. 成功后对所得对象 **`vtable+0x14`（字节偏移 20）** 调用 **`(*obj)(..., Util::SvrSeal* type)`**，完成 **Init/绑定** 一类初始化。

### 2.2 CLSID 与磁盘检索

- 在 **`KernelUtil.dll`** 裸文件中 **`find_bytes`** 仅命中 **一处** 该 CLSID 常量（与 **`unk_318680A4`** 一致），未发现 **`Common.dll`** 内嵌同一 16 字节（至少在已扫 IDB 下无匹配）。
- **推论**：封印实现的 **最终 coclass** 由 **平台 Core + 组件注册** 解析，不一定在 **`Common.dll`** 内静态存放同一 GUID 常量。

### 2.3 ATL / `DllGetClassObject`

- **`DllGetClassObject`** → **`AtlComModuleGetClassObject(&unk_31883614, ...)`**。
- **`DllRegisterServer`**（约 **`sub_3182E5C0`**）走 **`AtlComModuleRegisterServer`**；对象映射表 **`unk_31883614`** 在 IDA 里可能显示为 **未初始化/bss 形态**（依赖运行时或加载填充），静态dump需谨慎。

### 2.4 `CheckKeyID@SvrSeal@Util`

- 导出 **`?CheckKeyID@SvrSeal@Util@@YAHEPAUITXEncrypt@@@Z`**（约 **`0x3182bdd0`**）。
- 反编译可见对 **`ITXEncrypt`** 的 **`vtable+0x30` / `+0x34`** 调用，用于 **密钥序号/版本与当前 `ITXEncrypt` 实例一致性** 检查；与 **`bufSvrSealEnc` 字节级解密算法** 不是同一条「展开公式」线索，但证明 **Seal 链路与 `ITXEncrypt` 全局对象绑定**。

---

## 3. `Common.dll`：`ITXCore` / 组件清单（影响 coclass 实际所在 DLL）

### 3.1 全局 Core 单例

- **`dword_30209054`**：平台 **`ITXCore`**（或等价 **`ITXPlatformCore`**）指针，在 **`sub_30019CA0`** 等路径上赋值（「platform」字符串、`sub_30022100`、`sub_30021B10` 等）。

### 3.2 `CTXComponentMgr` 与 XML `components`

- **`sub_30013110`**（由 **`sub_300155C0`** → **`sub_30015370`** 等链触发）解析 **`components` / `component` / `clsname` / `clsid` / `dllname` / `exit-order`** 等节点。
- 对每个 component：**`Util::Com::GuidFromString`** 读 **CLSID**，读 **`dllname`**，并在内部表中登记 **`sub_30012F20`** 生成的条目（含 **`exit-order`**）。
- **含义**：**`EDC5158A-…` 的实现 DLL 不一定写死在 `KernelUtil`**；应以运行时 **`platform/components` 类 XML**（及 **`CreateObjectFromDllFile`** 路径）为准。静态仅见 **`KernelUtil`** 导出 **`CreateSvrSeal`**，**DecryptMsg 本体**仍可能在 **同一 DLL 的 ATL 类**或 **manifest 指向的另一 DLL**。

---

## 4. 离线 PE / 静态扫描（辅助 IDA）

### 4.1 `KernelUtil.dll`

- **`objdump -p`**：**无** `CryptDecrypt` / `BCrypt` 等现代 WinCrypto 导入条目出现在简短 grep 结果中；**`ADVAPI32`** 存在（多为 **注册表**）。
- **`strings`**：**未发现** `DecryptMsg`、`PerfStand`、`MachineGuid` 等与封印直接对应的明文日志串（符号表里仅有 **`CreateSvrSeal`** / **`CheckKeyID`** 等导出修饰名）。
- **字节搜索**：对 XXTEA 常用常量 **`0x9E3779B9`**（LE **`b9 79 37 9e`**）**未**在样本中命中（不排除算法常量展开形式不同或代码在其它 DLL）。

### 4.2 vtable / `.rdata` 扫描踩坑

- 曾用脚本扫描 **`.rdata` 内指向 `.text` 的指针** 得到大量候选；其中 **`0x31804dac` 起** 一组指针疑似 **ATL 对象 vtable**（含 **`0x3182e590`、`0x3182e500`…** 等），但后续用 **`get_bytes(0x31804dac)`** 时读到的是 **`.text` 指令字节**，说明 **VA 与段归属** 必须以 IDA / 节表为准，不能单靠「看起来像 VA」的线性偏移。
- **结论**：vtable 与 **`DecryptMsg`** 的最终对应关系 **需在 IDA 里对 coclass 逐槽标注** 后才能定论；当前阶段 **未完成** 该最后一步。

---

## 5. IDA MCP 工具侧限制（记录便于后续会话）

- **`imports_query` / `survey_binary`**：在当前 **IDA 9.2** + MCP 插件环境下触发 **`ida_nalt.enum_import_names` 回调签名**错误（`imp_cb` 参数不匹配），导致 **无法一键拉分类 import**。
- **`enum_import_names` 手写回调**：在 **`py_eval`** 沙箱里 **嵌套函数闭包** 对外层变量捕获不稳定；改用 **`imp_cb.results=[]` 挂在函数对象上** 等方式可规避（若后续需批量枚举 import）。
- **`list_instances` / `select_instance`**：多 IDA 实例场景下必须先 **`select_instance(port=…)`** 再调用分析工具，否则会路由到错误 IDB。

---

## 6. 当前结论（面向「用什么加密」这一问题）

| 层级 | 结论 |
|------|------|
| **磁盘语义** | **`bufSvrSealEnc`** 存的是 **需经 `ITXSvrSealCrypto::DecryptMsg`（vtable +0x10）处理的密文/封装**，不是可直接阅读的明文。 |
| **算法位置** | **对称/哈希的具体循环不在 `Common.dll` 的 `sub_30097FF0` 内展开**；实现在 **`ITXIMSvrSealCrypto`** 实现类中（由 **`CreateSvrSeal` + ITXCore 工厂** 给出）。 |
| **CLSID** | 工厂使用的 CLSID 为 **`{EDC5158A-8148-401A-9F2B-A72863BCA24A}`**（`KernelUtil` **`unk_318680A4`**）。 |
| **是否已命名为「AES / RSA / XXTEA」** | **仍无**单一 FIPS 式命名。**`DecryptMsg` 本体**（**§8.6**：`IM.dll` **`sub_31061A40`**）走 **`bufSigSession`/`bufPwdForConn` + `CTXCommPack` + `ITXEncrypt::vtable+12`**，属 **产品内会话封印管道**，不是裸 **AES**/**XXTEA** 标签。 |
| **与 `DecodeHash`/`Decode16` 的关系** | **`DecodeHash`/`Decode16`** 在 **`Common.dll`** 另有定义（**§8.2 / §8.3**），且被 **`IM.dll`** 多处 **非封印** 代码调用；**已钉死的 `DecryptMsg` 路径不以 `DecodeHash` 为主**。若盘上某些字段仍是 **23 字符哈希外观串**，才可能单独走 **`DecodeHash`**。 |
| **与 `bufRandKeyEnc` 的 XXTEA 信封关系** | **不能等同**（`sub_30097FF0` 对 Seal 只走 **vtable+0x10** → **`sub_310620F0`**，不经 **`sub_30002340`**）。 |
| **密钥从哪来（概要）** | **盘上**：**`bufSigSession`、`bufPwdForConn`、`bufPwdHashOne`、`buf16byteSessionKey`、`cPassSeqID`** 等与 **`Matrix`/登录** 同源；**运算侧**：**`TXEncryptMgr::Init` → MD5(flags∥16B)→ `ITXEncrypt`**（详见 **`NOTES.md` §15–§16**）；**`DecryptMsg`** 只 **组装并投递** 到 **`ITXEncrypt`**，见 **§8.8**。 |

---

## 7. 建议的下一步（留给后续 IDA 会话）

1. **`IM.dll.i64`（优先）**：`IM.dll` 的 **`.rdata` GUID 表**（约 VA **`0x3130782c`** 起含本 CLSID）说明 **coclass 与主程序同仓注册** 的可能性大。对 **实现 `ITXIMSvrSealCrypto` 的 CComObject** 做 **RTTI/ATL 头** 或 **vtable 扫**：定位 **`vtable+0x10`** 的 **具体函数地址** 并反编译，确认是否 **仅** 调 `Encode::DecodeHash` / `Decode16` + `ITXBuffer` 搬运。
2. **`KernelUtil.dll.i64`**：仅 **`CreateSvrSeal` + `ITXCore::vtable+0x1C` 工厂** 引用该 CLSID；**PE 内无** 其它指向 `unk_318680A4` 的指针，**KernelUtil 未必承载 `DecryptMsg` 体**。
3. ~~对锁定的 **`DecryptMsg` 实现**……~~ **已钉死：见 §8.6**（`IM.dll` **`sub_310620F0` → `sub_31061A40`**，走 **`ITXEncrypt`** 与 **`bufSigSession`/`bufPwdForConn`**，**不是** 以 **`DecodeHash`** 为主路径）。
4. 若用户可提供 **platform/components 类 XML** 或 **安装目录清单**，与 **§8.4** 交叉验证 coclass 实际所在 PE。

---

## 8. 续分析摘记（`Common.dll` / `IM.dll` / `Encode`）

### 8.1 `sub_30097FF0` 对 Seal 的调用形态（精化）

- **`this+0x0C`**（即伪代码里的 `*(this+3)`）为 **`ITXSvrSealCrypto*`**。
- 解密分支：`(*(int (__stdcall **)(int, int, int))(*(_DWORD *)seal + 16))(seal, outBuf, ctx)` —— **第三个参数** 来自 **`this+0x5C`**（`this+23` 若按 `_DWORD*` 计）。
- 与先前笔记一致：**虚表偏移 `+0x10`** = **IUnknown 之后第一个接口方法**（本文仍按业务语义称其为 **`DecryptMsg` 槽位**）。

### 8.2 `Util::Encode::DecodeHash`（`Common.dll`，`?DecodeHash@Encode@Util@@YAHPAPAUITXBuffer@@ABVCTXStringW@@@Z`，入口约 **`0x30006680`**）

- **前置条件**：宽字符串 **长度必须恰好为 23**；逐字符映射到字母表 **`0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ~@$%`(){}[]_`** 中的 **索引**（小写先转大写再查）。
- **输出**：通过 **`Util::Data::CreateTXBuffer`** 分配 **`ITXBuffer`**，再 **`vtable+0x38`**（字节 **56**）写入 **固定 16 字节** 载荷。
- **算法本质**：在索引序列上做 **类似逐位借位/混合进制（反编译中可见与 48 相关的乘加）**，把 **23 个「数位」压成 16 字节**；属 **自定义编码**，**不是** 分组密码或 XXTEA。

### 8.3 `Util::Encode::Decode16`（`Common.dll`，入口约 **`0x30005e20`**）

- **偶数长度** 十六进制宽字符串 → 二进制：字符按 **`| 0x20`** 规范化，`0-9` / `a-f` 拆 **半字节** 拼字节串，再写入 **`CTXBuffer`/`ITXBuffer`**。
- 即工程语境下的 **「Decode16」= 十六进制解码**。

### 8.4 CLSID 在 `IM.dll` 中的出现方式

- **裸扫**：同一 16 字节（LE）不仅存在于 **`KernelUtil`** 的 **`unk_318680A4`**，也存在于 **`IM.dll` 文件偏移 `0x30782c`**（VA **`0x3130782c`**），且 **前后均有其它 GUID**（**hex 上下文**见本会话 `xxd`），符合 **进程内 COM/TLB 注册块** 特征。
- **`Common.dll`**：在该样本上 **未发现** 该 CLSID 原始字节串。
- **推论**：**封印 coclass 的实现与 IM 主模块强相关**；仅凭 **`KernelUtil::DllGetClassObject`** 不能断言 **`DecryptMsg` 体在 KernelUtil**。

### 8.5 `IM.dll` 与 `Encode` 导入（辅助判断）

- **`IM.dll`** 同时导入 **`Util::Encode::DecodeHash`、`Decode16`、`Encode16`** 与 **`KernelUtil::CreateSvrSeal`**（`objdump -p` 已核对）。
- **`DecodeHash`/`Decode16`** 被 **大量非封印业务** 调用（图片、`FACEROAM_*` 等）。**封印 COM 路径（§8.6）核心不在 `DecodeHash`**；§8.2/§8.3 仍描述磁盘上其它「哈希外观串」场景可用的 **`Common.dll`** 原语。

### 8.6 `IM.dll`：`ITXSvrSealCrypto` 实现与 **`DecryptMsg`（vtable +0x10）实钉**

**IDA**：已 **`select_instance(port=13337)`**（`IM.dll.i64`）。

- **CLSID** 第二处：`find_bytes` 命中 **`0x31319520`**（与 **`0x3130782c`** 并列）；**`0x313194fc`** 处有指向 **`0x31319520`** 的数据引用（ATL **对象映射 / registry** 线索）。
- **实现对象 vtable**：**`off_313194E0`**（构造里 **`sub_31062210`** 写入 **`*this = &off_313194E0`**）。
- **槽位（节选）**：
  - **`+0x00`**：`sub_310621F0`（**QueryInterface** 一类）
  - **`+0x04`**：`0x312902B0`（**AddRef** 桩）
  - **`+0x08`**：`sub_310621C0`（**Release** 一类）
  - **`+0x0C`**：**`sub_31062010`** —— 内部 **`call sub_31061A40`** 前 **`push 1`**（与 **`push 0`** 分支相对，属 **另一接口方法**，如 **EncryptMsg / Init** 语义需再对符号表）。
  - **`+0x10`**：**`sub_310620F0`** —— **`call sub_31061A40`** 前 **`push 0`**（**解密侧**）；即 **`Common.dll` `sub_30097FF0` 里 `(*(seal+16))(seal, …)` 命中此处时，对应本槽**。
- **`sub_310620F0`（stdcall，`retn 0Ch`）**：校验 **`arg_4`、`arg_8`**；**`this+0x18`** 为空时才继续；**`ecx=this`** 调 **`sub_31061A40`**，栈上第二参为 **`0`**，第三参来自 **`arg_4`**（输入 **`ITXBuffer`**）；成功时对 **`this+0x18`** 做 **`AtlComPtrAssign(arg_8)`**。
- **`sub_31061A40`（核心）**：从 **`unk_313086F0`** 打开 **`ITXData`**，读 **`bufSigSession`**、**`bufPwdForConn`**（宽键名与 **`sub_31002AD0`** 字面量一致）；把 **`bufSvrSealEnc` 侧传入的缓冲区** 与上述字段 **打包进 `ITXData`**（含 **`cType`/`cAppType`/`cKeyID`/`bufData`/`bufOrgBuf`**、`CTXCommPack` 等）；最终 **`(*(*ITXEncrypt)+12)(…)`** —— 即 **`ITXEncrypt` 虚表偏移 `0x0C`**，四参数调用（与 **`NOTES.md`** 里 **`ITXEncrypt` +12** 的讨论一致）。**主线是「会话封印包 + 加密管道提交」**，**不是** **`Util::Encode::DecodeHash` 单独解码器**。

### 8.7 样本 `msg2.0/Matrix.dat`（用户目录）

- 路径：**`/msg2.0/Matrix.dat`**，约 **168 字节**；文件头 **`54 44 01 01`（`TD…`）**，后为 **UTF-16 属性块** 与 **二进制段**（**`xxd` 可见 `…c1 c3 c1 c2…` 起的一截密文状数据**）。完整键级解析需 **`ITXDataStorage`** 读取逻辑或专用解析脚本；与 **`bufSvrSealEnc`** 字段需对照 **`TXEncryptMgr::CreateDataStorage`** 打开的同一存储语义。

### 8.8 「密钥从哪来」（回答口令/对称材料出处）

**结论分两层，避免混为一谈：**

1. **`DecryptMsg` / `sub_31061A40` 里没有单独生成一条「封印专用密钥文件」**  
   它做的是：从 **`unk_313086F0`** 打开的 **`ITXData`** 读出 **`bufSigSession`、`bufPwdForConn`**（与同一份 **`Matrix.dat` / UserData 存储** 上的其它键并列），再与 **`bufSvrSealEnc`** 读出的 **`ITXBuffer`** 一起封装进 **`ITXData`**，最后调用 **`ITXEncrypt` 的 `vtable+0x0C`（+12）**。也就是说：**封印路径消耗的「密钥相关字节」一部分直接来自盘上这些键**，另一部分来自 **`ITXEncrypt` 对象内部已在别处初始化好的状态**。

2. **真正做对称变换（如 NOTES.md §16 所述 **MD5 派生 + XXTEA + 信封**）时用的「根状态」在 `Common.dll` 的 `ITXEncrypt` 上**  
   - **`TXEncryptMgr::Init`**：对 **`flags（4B）∥ payload（16B）`** 做 **MD5**，得到后续 **`QueryEncrypt`/`ITXEncrypt`** 使用的密钥素材链（见 **`NOTES.md` §16.1**）。  
   - **16B payload** 的来源在同一笔记 **`§15`**：**`bufPwdHashOne`**（口令二次哈希类二进制）、登录拿到的 **`buf16byteSessionKey`** 等 **账号/Matrix 字段**，经 **`IM.dll`** 侧 **`TXEncryptMgr::Init`** 灌进去——**不是** `DecryptMsg` 里突然从空气里来的。  
   - **`KernelUtil::CheckKeyID(..., ITXEncrypt*)`**：把 **`Matrix` 上的 `cPassSeqID`**（密钥序号）与 **`ITXEncrypt` 内部版本**对齐（见 **`NOTES_BUF_ENC.md` §2.4**），防止 **盘上封印数据与当前内存里的密钥代数不一致**。

**一句话**：**盘上**与封印同食的材料包括 **`bufSvrSealEnc`、`bufSigSession`、`bufPwdForConn`、`bufPwdHashOne`、`buf16byteSessionKey`、`cPassSeqID`** 等；**真正展开对称算法的密钥派生在 `TXEncryptMgr::Init` → `ITXEncrypt`**（**`Common.dll`**），**`IM.dll` 的 `DecryptMsg` 只是把 Matrix 里若干缓冲塞进 `ITXEncrypt` 管道，而不是单独持有一条名曰「SvrSealKey」的常量。**

---

## 9. 交叉引用（主笔记）

- `NOTES.md` **§5 / §15 / §16**：`Matrix.dat`、`TXEncryptMgr`、`bufSvrSealEnc`、`PerfStand.DecryptMsg`、`XXTEA`/`MD5` Init、 **`ITXEncrypt` +12** 与 **`ITXSvrSealCrypto` +16** 讨论。
- **`DecryptMsg` 实现**：已在本文 **§8.6** 与 **`IM.dll`** **`off_313194E0[+0x10]` → `sub_310620F0` → `sub_31061A40`** 对齐；**`bufRandKeyEnc`/`sub_30002340` XXTEA 信封** 仍为 **另一条链**（见 `NOTES.md` §16）。
