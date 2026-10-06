# 做梦 · 环境检测 (dream-compose)

一款基于 Jetpack Compose + Material 3 的 Android 设备环境检测工具，覆盖 **355 项**离线/在线检测点，帮助判断设备是否存在 Root、Hook、模拟器、多开、隐藏应用等异常环境。

## 功能特性

### 检测覆盖
- **系统属性**：Verified Boot、dm-verity、OEM 锁、构建签名、安全补丁级别
- **Root 路径**：44 条 SU/Magisk/KSU/APatch 特征路径全量扫描
- **Root 管理器**：Magisk、KernelSU、APatch、Zygisk、Riru、LSPosed 模块检测
- **高危文件**：外挂样本、作弊目录、温控模块、篡改痕迹
- **属性检测**：pihooks、pixelprops、spoof 等改机/伪装属性
- **异常进程**：可疑守护进程、Frida/GDB、Shizuku、HMA 隐藏进程
- **应用检测**：高危包、工具包、虚拟化/双开、风险目录扫描
- **隐藏应用(HMA)**：电池白名单/无障碍/默认应用/系统服务/进程命令行多通道交叉比对 + 用户安装/路径APK/禁用冻结三源交叉比对
- **SELinux**：enforce 状态、策略版本、本进程 context、access 节点可读性
- **挂载**：可疑挂载源、overlay 覆盖、挂载间隙、bind/overlay 统计
- **反调试/内存**：TracerPid、NSpid、可疑端口、rwxp 段、maps 注入特征
- **Hook 注入**：进程注入库扫描、zygote 注入检查
- **内核**：已加载模块、kptr_restrict、cmdline 启动参数
- **模拟器/多开**：QEMU 属性、仿真设备节点、native bridge、cgroup 容器
- **TEE/密钥**：Verified Boot、Play Integrity、硬件 KeyStore、keybox、StrongBox
- **日志痕迹**：logcat/dmesg AVC 审计、root/hook 痕迹、崩溃目录
- **高级探针**：KSU 侧信道、属性全量扫描、netlink、zygote 链、OBB 一致性、smaps 统计
- **在线检测**：证书吊销列表(CRL)、外网连通性、DNS 解析、TLS 证书链校验

### 技术栈
- **UI**：Jetpack Compose + Material 3 (Edge-to-Edge)
- **架构**：单 Activity + Compose 状态管理 + Coroutines 后台检测
- **minSdk**：26 (Android 8.0)
- **targetSdk**：34 (Android 14)

## 下载

前往 [Releases](../../releases) 下载最新 APK。

## 构建

项目使用 GitHub Actions 自动构建，每次 push 到 main 分支会自动编译 Debug + Release APK。

本地构建要求：
- JDK 17
- Android SDK 34
- Gradle 8.7

```bash
gradle assembleDebug
gradle assembleRelease
```

## 误报修复记录

### v1.2.22
**风险应用探测能力修复（包可见性）**
- Manifest 新增 `QUERY_ALL_PACKAGES` 权限：解决 Android 11+ 包可见性限制导致 `getInstalledPackages()`/`getInstalledApplications()` 仅返回少量可见包、扫不到 Alpha/Scene/爱玩机工具箱/KernelSU 等已装风险应用的问题。
- 说明：安全检测仅凭包名 + 应用元数据即可判定风险应用，无需读取 `/data/app` 下的 APK 文件（该目录受 root 保护，普通文件管理器同样不可读）。
- 检测点总数不变（离线 349 / 总量 355）。

### v1.2.21
**HMA 输入法误报修复（#152/#156）**
- 输入法良性白名单升级为前缀模糊匹配：微信输入法 `com.tencent.wetype`、百度输入法 `com.baidu.input*`、搜狗输入法 `com.sohu.inputmethod*`、Gboard `com.google.android.inputmethod*`、讯飞/QQ 输入法等。
- 修复逻辑缺陷：默认输入法包名仅代表「系统选中的输入法」，不能作为「应用被隐藏」的证据；命中良性输入法直接输出 INFO 基线日志并跳过可疑判定。
- HMA 三源交叉比对同步过滤良性输入法/已知组件，消除输入法误报为隐藏应用的问题。

**风险应用探测失效修复**
- 应用枚举改为双数据源：`getInstalledPackages()` + `getInstalledApplications(GET_META_DATA)` 并读取 App 元数据（标签），应对包名改名/包可见性导致的探测失效。
- 探测目标：Alpha(Magisk Alpha)、爱玩机工具箱(`com.byyoung.setting`/`com.nenya.aiwanji`)、Scene(`com.omarea.vtools`)、KernelSU 管理器(`me.weishu.kernelsu`/`com.rifsxd.ksunext` 等)。
- KernelSU 增加底层痕迹探测：`/data/adb/ksud`、su 二进制、内核属性标记、`/dev/ksu`、dmesg，不只依赖 APP 包名。
- 判定策略：单独匹配包名/标签仅算弱证据，≥2 条来源独立证据才 SUSPECT，防止误报。

**新增检测点（聚合判定，弱特征仅日志、多证据聚合）**
- 春秋附录B 风险路径/文件全量扫描、春秋附录C 系统属性基线。
- 外挂驱动检测：可疑 `.ko` 驱动文件、内核模块驱动签名、`/dev` 外挂节点、驱动模块目录。
- 扫盘检测：跨高风险目录扫描作弊/工具特征文件，异常则报错、无则报没问题。
- 路径检测：su 二进制、可疑挂载、隐藏 `.ext` 目录、`/system` 可写、debug_ramdisk，异常则报错、无则报没问题。
- UID 检测：当前 UID、能力位 CapEff、补充组、异常 UID 应用、可调试应用，异常则报错、无则报没问题。
- 硬件认证完整性、Keystore 完整性（鉴权路径时延侧信道/别名隔离/AES-GCM 篡改 tag 负例）、内核身份与运行时完整性。
- 风险工具多证据聚合探测（包名/标签元数据/KSU 底层痕迹/进程，≥2 证据聚合）。

**版本与总量**
- 版本升级至 v1.2.21（versionCode 23）；离线检测点增至 349、总量 355。
- 底部导航：关闭联网检测时完全隐藏「在线检测」Tab，仅保留「离线检测 / 设置」；开启后完整展示 3 个 Tab；本地/在线进度与结果完全隔离。

### v1.2.20
**UI 流程修复**
- 关闭「联网检测」开关后，底部导航不再显示「在线检测」标签页；开启后才出现。
- 在线检测改为**完全独立流程**：在线页提供独立的「开始在线检测」按钮与独立进度条/结果列表，不再与本地检测串在同一次启动里，修复开启后无法正常联网检测的问题。
- 本地检测与联网检测各自独立引擎实例、独立进度、独立结果列表，互不覆盖开关状态。

**新增探针（5 项，弱特征仅日志、多证据聚合）**
- 内核版本基线、ro.debuggable/ro.secure 调试属性基线、Seccomp 过滤状态。
- 调试状态聚合：ro.debuggable=1 与 TracerPid>0 两条独立证据才告警。
- /system 挂载只读校验（弱特征）。

### v1.2.19
**降灵敏度调整（5 处）**
- #172 mountinfo：单纯命中 `hide/spoof` 标记仅记录日志（厂商系统原生挂载常见），需叠加 magisk/ksu/overlay/bind 等第二证据才聚合告警。
- #219 全盘异常目录名：单特征仅记录，不再单独 SUSPECT，需其他独立风险证据聚合。
- #228 可疑系统服务：`scene/proxy/clash` 等弱特征单命中仅日志，仅 frida/xposed/magisk/ksu/apatch/shizuku 等强证据才告警。
- #236 KeyStore：仅存在软件型密钥但 TEE 硬件背书正常 → 仅日志；仅当 TEE 硬件背书校验失败才告警。
- #246 KO 时延侧信道：阈值由 >1.6 上调至 >5，≤5 仅 INFO；即使 >5 也不单点 SUSPECT，需其他证据聚合。

**新增检测（10 项，弱特征仅日志、多证据聚合）**
- 启动链基线：verified-boot/vbmeta 状态、cmdline bootargs、security-patch vendor/system 一致性。
- Native 注入/Hook 聚合：maps 关键字 + TracerPid + LD_PRELOAD，≥2 证据才告警。
- SELinux 运行模式、内核模块残留指纹（弱特征）。
- ART/Xposed 运行时痕迹、调试/Frida 端口聚合（≥2 证据）。
- 系统目录可写性试探、现代 root 二进制路径扫描（仅日志采集）。

**UI / 设置 / 联网**
- 结果列表双输出：判定理由默认可见、完整日志默认折叠展开；M3 LazyColumn 卡片。
- 新增 M3 设置页：「启用联网检测」开关（默认关闭，DataStore 持久化），页脚放置本项目开源仓库链接。
- 本地 / 在线检测进度完全隔离：分别显示「本地检测：xx%」「在线检测：xx%」；开关关闭时不初始化、不发起任何网络请求，联网结果独立列表。

### v1.2.18
- **修复 #320 应用组件隐藏探测大面积误报**：原实现遍历全部应用组件，把系统组件、普通应用组件（厂商工具、普通 App 组件等）resolve 失败一律计入，在多台设备上误报上百个包。现改为**只针对已知风险应用列表（高危/工具包/虚拟化/春秋黑名单）做组件隐藏交叉判定**，系统应用与普通第三方应用一律不参与；日志缩短为只列异常风险包名。
- **优化 ADB 多通道状态判定**：`init.svc.adbd=running` 是每台设备常驻系统服务、不代表开启 USB 调试，原逻辑据此误报。现改为仅「`adb_enabled=1` 且 `ro.adb.secure=0`」两条独立证据同时命中才 SUSPECT；仅开启调试但带授权保护降为 LOW。
- **修正检测项总数常量**：报告头部离线/总数与实际输出对齐（离线 324 项 / 总计 330 项）。

### v1.2.17
**修复项**
- 修复 #257：厂商原厂系统应用被 hook/作弊关键字误判为 ABNORMAL 风险应用；新增包名白名单（通配前缀 `cn.nubia.*`、精确 `com.redteamobile.virtual.softsim`），命中白名单仅记录日志，不再输出 ABNORMAL
- 废弃旧 #155：移除仅靠 PackageManager 两种查询模式数量差值直接判定 SUSPECT 的逻辑（厂商系统自带禁用包会造成误触发），由新 HMA 三源交叉检测替代
- 彻底删除旧 #318：移除 `service list` 总行数与包总数相减的 HMA 多通道包数对比探针（service list 含大量 HAL/AIDL/Vendor 底层服务，非 APK 包名，探针失效），不再注册/不再出现在报告

**新增检测项**
- HMA 三组数据源交叉比对：用户安装 / 路径扫描APK / 系统禁用冻结集合差集运算；差集在禁用集内仅备注不告警；仅当「路径有 + 用户无 + 禁用无」三者同时满足才输出 SUSPECT；SDK≥34 无权限遍历安装目录时输出能力受限文本，禁止告警
- 应用组件隐藏探测：activity/receiver/service/content-provider 在 PM 可查但 resolve 解析失败，多条跨包命中才 SUSPECT
- 包签名多源一致性校验：PM 签名 vs APK 文件签名摘要不一致才 SUSPECT，APK 读取失败仅日志
- su 特征聚合汇总：su 二进制 + su 属性 + su uid0 进程，≥2 项独立特征同时命中才 SUSPECT
- persist.\* 属性篡改残留收集：收集非出厂常见 persist 键值对，仅日志供人工研判，不自动告警
- Zygisk/Shamiko 间接痕迹聚合：mountinfo/maps/environ/modules 多痕迹，≥2 项才 SUSPECT

### v1.2.11
- 修复 Android 16 AppZygote 导致的 zygote 进程链误报
- 修复厂商 HAL 服务（goodix/zte/btaudio）被误判为隐藏应用
- 修复 dalvik.vm.dex2oat 原生属性被误判为篡改残留
- 修复 OBB 沙盒视图不一致误报
- 修复大内存机型 smaps 匿名内存阈值过低误报
- 修复 fdinfo mnt_id 权限不足被误判为挂载隐藏
- 修复 Android 16 未知来源全局开关误报

### v1.2.10
- 排除应用自身 debuggable 检测误报
- uid=1000(system)/2000(shell) 不再判异常，仅 root(uid=0) 告警
- 国行 GMS 缺失/限制文件不再误报
- 高通/联发科系统服务白名单

## License

MIT
