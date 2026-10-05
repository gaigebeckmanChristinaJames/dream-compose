# 做梦 · 环境检测 (dream-compose)

一款基于 Jetpack Compose + Material 3 的 Android 设备环境检测工具，覆盖 **294 项**离线/在线检测点，帮助判断设备是否存在 Root、Hook、模拟器、多开、隐藏应用等异常环境。

## 功能特性

### 检测覆盖
- **系统属性**：Verified Boot、dm-verity、OEM 锁、构建签名、安全补丁级别
- **Root 路径**：44 条 SU/Magisk/KSU/APatch 特征路径全量扫描
- **Root 管理器**：Magisk、KernelSU、APatch、Zygisk、Riru、LSPosed 模块检测
- **高危文件**：外挂样本、作弊目录、温控模块、篡改痕迹
- **属性检测**：pihooks、pixelprops、spoof 等改机/伪装属性
- **异常进程**：可疑守护进程、Frida/GDB、Shizuku、HMA 隐藏进程
- **应用检测**：高危包、工具包、虚拟化/双开、风险目录扫描
- **隐藏应用(HMA)**：电池白名单/无障碍/默认应用/系统服务/进程命令行五通道交叉比对
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
