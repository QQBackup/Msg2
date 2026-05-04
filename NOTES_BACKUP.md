# QQ MSG DB / `.bak` 离线解密 — 逆向笔记备份

> 目的：记录 KernelUtil / Common.dll 路径、`MSG0` 外扩头、以及 TD 容器与虚表槽位核对，便于后续续作。

## IDA / MCP 使用

- 切到 **Common.dll** 实例后（`list_instances` / `select_instance`，本机曾用端口 **13342**），先 **`server_warmup`**（含 `wait_auto_analysis`、缓存），再 **`entity_query` / `func_query` / `disasm` / `decompile` / `py_eval`**；少用大范围 **`search_text`**（曾对 MCP 代理超时）。
- **`get_bytes` 读到全 0**：多半是 **当前活动 IDB 不是目标 DLL**，重新 `select_instance` 到 Common 后再读 `.rdata`。

## KernelUtil：`sub_318DD084`（MSG DB header / `MSG0` 路径）

- 在 **`Util::Data::CreateTXData`**（作用于 `*(this + 0x14)`）、**`CreateTXBuffer`**、**`SQLiteHeader::GetMsgDBHeaderBuffer`** 之后，存在：
  - `mov eax, [esi]`（`esi` 指向对象首 dword，一般为 **vtbl**）
  - **`call dword ptr [eax + 114h]`**，栈上 **`ITXBuffer*`** 已就绪。
- **偏移 `+0x114`**：若把 vtbl 当作连续 `DWORD[]`，则 **槽索引 = 0x114 / 4 = 69**。

### 与 `CCmdCodecBase::DecodeBuffer` 的关系

- **不是**同一张表里的小偏移示例：在 Common 里某 codec vtable 上 **`DecodeBuffer` 约在 index 3（+0x0C）**，与 **`+0x114`** 无关；不要把“解码 buffer”直接套到这条虚调用上。

## Common.dll：`Util::Data::CreateTXData` 产物与 vtable

- 核对 **`IID_ITXData`** 实现的主 vtable起始 **`0x3016EBCC`**（槽 0 指向如 **`sub_30033AC0`** 一类）。
- 在该 vtable 上，**槽 69（+0x114）→ `sub_3002F995`**。
- **`sub_3002F995` 反编译形态**：`InterlockedDecrement`、计数归零后通过 **`(*obj + 460)`** 一类路径销毁 —— **更像 `Release`/引用计数**，不像“解析 header 进字段树”。

### 开放问题（槽位 vs 语义）

- KernelUtil 里 **`GetMsgDBHeaderBuffer` → `call [vtbl+0x114]`** 在表面上像“喂 buffer 给 `ITXData`”，但静态 vtable 在 **+0x114** 处指向 **Release 类**逻辑，存在 **不匹配**，可能原因包括：
  - 运行时 **并非**上述 **`0x3016EBCC`** 这张表；
  - **`this` / 接口指针调整**（多接口、非对象首址）导致 **`+0x114` 语义变化**；
  - **`CreateTXData` 实际具体类型**与假设的“简单 `ITXData`”不一致。

### 同表其它“较大”槽位（便于对照）

- 槽 **84（+0x150）**：`sub_3002F5FB`（内部再对 **`*(a1+20)`** 走 **`+68`** 转发）。
- 槽 **85（+0x154）**：`sub_3002F643`（与 **`Util::Data`** / **`ITXArrayRead`** 相关包装）。
- 槽 **57（+0xE4）**：`sub_300A2D0A` —— 也是典型 **Release 形态**（`InterlockedDecrement` + **`+12`** 销毁路径）。

## QQ 二进制 “文档” 格式（TD / QD）

- 大型解析入口例：**`sub_30032CA8`**、**`sub_300329B8`** 等，对容器 magic / 版本 / 记录条数有统一读法，并在多处通过 **`ITXData`** 的多种偏移（如 **`+0xCC`、`+0xD0`、…、`+0x118`、`+0x1A0` …**）写字段 —— 属于“从打包 blob 填充 `ITXData`”家族。
- **`sub_300329B8`** 一类会对 **`TD`** 头做检查（如首字节 **`T`**、次字节 **`D`**）。

## 本地样本：`BAK_FILE/msg0_headerbuf.bin`

- 提取的 `MSG0` payload **头部十六进制**以 **`54 44 01 01 ...`** 开头 → ASCII **`TD`**，与 **TD 容器**一致（与部分路径里的 **`QD`** 检查不同）。

## 离线解密链（工程含义）

1. **弄清 `*(owner + 0x14)` 经 `CreateTXData` 得到的具体类型与真实 vtable**（必要时动态断在 `call [eax+114h]` 前看 **`[esi]`**）。
2. **按 TD 记录解析 `msg0_headerbuf.bin`**（优先 **`sub_300329B8` / `sub_30032CA8` 家族**），抽出 **`bufRandKeyEnc`** 等密封字段。
3. 延续 KernelUtil 侧已识别的链路：**`buffrLocalPasswdHash`（16 字节）→ TEA 解 `bufRandKeyEnc`** → 再对齐 **SQLite 页/载荷** 加密（若仍有）。

## 关键符号 / 地址索引

| 区域 | 名称 / 说明 |
|------|-------------|
| KernelUtil | `sub_318DD084`，`SQLiteHeader::GetMsgDBHeaderBuffer` |
| Common | `Util::Data::CreateTXData`；`sub_30032CA8`、`sub_300329B8`；vtable **`0x3016EBCC`**；**槽 69 → `sub_3002F995`** |
| 样本 | `BAK_FILE/msg0_headerbuf.bin`（**`TD`** 头） |
