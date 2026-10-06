package com.zuomeng.app;

import android.content.Context;
import android.content.Intent;
import android.content.pm.ActivityInfo;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.content.pm.ProviderInfo;
import android.content.pm.ServiceInfo;
import android.content.pm.Signature;
import android.media.MediaDrm;
import android.os.Build;
import android.provider.Settings;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyInfo;
import android.security.keystore.KeyProperties;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.regex.Pattern;

import javax.crypto.KeyGenerator;

/**
 * 做梦环境检测引擎 v1.2.21
 * 整合：zuomeng_check.sh 34 节 + 春秋检测(Chunqiu)全部检测项(含附录A/B/C) + DuckDetector 15 大检测域可行探针
 * 检测点总数约 250，全部在子线程执行；需要 root/native 的探针以"受限(LOW)"级别如实记录。
 */
public class DetectionEngine {

    /** 实时进度回调：每个检测点完成后触发 */
    public interface ProgressListener {
        void onProgress(DetectionResult result, int done, int total, String category, String title);
    }

    /** 检测点总数：离线检测点 + 联网检测点，与 run()/runOnline() 实际输出一致 */
    public static final int TOTAL = 355;
    /** 离线检测点（第一页，不联网） */
    public static final int TOTAL_OFFLINE = 349;
    /** 联网检测点（第二页） */
    public static final int TOTAL_ONLINE = 6;

    private final Context ctx;
    private final List<DetectionResult> results = new ArrayList<>();
    private int cn = 0;
    private int clean = 0, found = 0, warn = 0, low = 0;
    private ProgressListener listener;

    public static class Report {
        public List<DetectionResult> results;
        public int total, clean, found, warn, low;
        public String buildTime;
    }

    public DetectionEngine(Context ctx) { this.ctx = ctx; }

    private DetectionResult.Level level(int code) {
        if (code == 1) return DetectionResult.Level.ABNORMAL;
        if (code == 2) return DetectionResult.Level.SUSPECT;
        if (code == 3) return DetectionResult.Level.LOW;
        return DetectionResult.Level.NORMAL;
    }

    private void r(String cat, String title, String log, int code) {
        cn++;
        DetectionResult.Level l = level(code);
        switch (l) {
            case ABNORMAL: found++; break;
            case SUSPECT: warn++; break;
            case LOW: low++; break;
            default: clean++;
        }
        DetectionResult dr = new DetectionResult(cn, cat, title, log, l);
        results.add(dr);
        if (listener != null) listener.onProgress(dr, cn, TOTAL, cat, title);
    }

    /**
     * 带判定理由的输出（满足“完整日志 + 判定理由”双字段规范）。
     * reason 仅对 SUSPECT/ABNORMAL 写入；NORMAL/INFO 保持可空，由上层给出默认文本。
     */
    private void rW(String cat, String title, String log, int code, String reason) {
        r(cat, title, log, code);
        if (reason != null && !reason.isEmpty() && !results.isEmpty()) {
            DetectionResult last = results.get(results.size() - 1);
            if (last.level == DetectionResult.Level.SUSPECT || last.level == DetectionResult.Level.ABNORMAL) {
                last.reason = reason;
            }
        }
    }

    // ============ 基础 IO 帮助方法 ============

    private String read(String path) {
        StringBuilder sb = new StringBuilder();
        try {
            BufferedReader br = new BufferedReader(new FileReader(path));
            String line;
            while ((line = br.readLine()) != null) sb.append(line).append('\n');
            br.close();
        } catch (IOException e) { return null; }
        return sb.toString();
    }

    private boolean exists(String p) { return new File(p).exists(); }

    private String prop(String k) {
        try {
            Class<?> c = Class.forName("android.os.SystemProperties");
            java.lang.reflect.Method m = c.getMethod("get", String.class);
            Object v = m.invoke(null, k);
            return v == null ? null : v.toString();
        } catch (Exception e) { return null; }
    }

    /** 执行 shell 命令并返回输出（4 秒超时保护） */
    private String shExec(String cmd) {
        try {
            Process p = new ProcessBuilder("sh", "-c", cmd).redirectErrorStream(true).start();
            long deadline = System.currentTimeMillis() + 4000;
            StringBuilder sb = new StringBuilder();
            BufferedReader br = new BufferedReader(new InputStreamReader(p.getInputStream()));
            String line;
            while ((line = br.readLine()) != null) {
                sb.append(line).append('\n');
                if (System.currentTimeMillis() > deadline) { p.destroy(); break; }
            }
            br.close();
            try { p.waitFor(); } catch (InterruptedException ignored) {}
            return sb.toString();
        } catch (IOException e) { return null; }
    }

    private String readSetting(String ns, String key) {
        try {
            if ("global".equals(ns)) return Settings.Global.getString(ctx.getContentResolver(), key);
            if ("secure".equals(ns)) return Settings.Secure.getString(ctx.getContentResolver(), key);
            if ("system".equals(ns)) return Settings.System.getString(ctx.getContentResolver(), key);
        } catch (Exception ignored) {}
        return null;
    }

    private boolean isInstalled(String pkg) {
        try { ctx.getPackageManager().getPackageInfo(pkg, 0); return true; }
        catch (PackageManager.NameNotFoundException e) { return false; }
    }

    private int countLines(String s) {
        if (s == null || s.isEmpty()) return 0;
        int n = 0; for (int i = 0; i < s.length(); i++) if (s.charAt(i) == '\n') n++;
        return n;
    }

    private int countDirs(String p) { File f = new File(p); return f.exists() && f.isDirectory() ? (f.list() == null ? 0 : f.list().length) : 0; }

    private int countOccurrences(String s, String sub) { int c = 0, i = 0; while ((i = s.indexOf(sub, i)) >= 0) { c++; i += sub.length(); } return c; }

    /** 开关值显示：1/0 → 开启/未开启，null → 不可读 */
    private String onOff(String v) {
        if (v == null) return "不可读";
        return "1".equals(v) ? "开启" : "未开启";
    }

    // ============ 批量检测帮助方法（每个方法只输出一行） ============

    private void pathAny(String cat, String title, int code, String... paths) {
        StringBuilder h = new StringBuilder();
        for (String p : paths) if (exists(p)) h.append(p).append(' ');
        r(cat, title, h.length() > 0 ? "命中:" + h.toString().trim() : "相关路径均不存在", h.length() > 0 ? code : 0);
    }

    private void propSet(String cat, String title, String key, int code) {
        String v = prop(key);
        r(cat, title, (v != null && !v.isEmpty()) ? key + "=" + v : key + " 未设置", (v != null && !v.isEmpty()) ? code : 0);
    }

    private void procK(String cat, String title, int code, String... keywords) {
        String ps = shExec("ps -A 2>/dev/null");
        StringBuilder h = new StringBuilder();
        String lower = ps == null ? "" : ps.toLowerCase();
        for (String k : keywords) if (lower.contains(k)) h.append(k).append(' ');
        r(cat, title, h.length() > 0 ? h.toString().trim() : "未发现", h.length() > 0 ? code : 0);
    }

    private String anyPropSet(String... keys) {
        StringBuilder h = new StringBuilder();
        for (String k : keys) { String v = prop(k); if (v != null && !v.isEmpty()) h.append(k).append('=').append(v).append(' '); }
        return h.toString().trim();
    }

    private String kernelVersion() {
        String v = read("/proc/version");
        if (v != null) {
            String[] f = v.trim().split("\\s+");
            if (f.length >= 3) return f[2];
            return v;
        }
        String p = prop("ro.kernel.version");
        return p != null ? p : "不可读";
    }

    // ============ 常量表：脚本 + 春秋附录 + Duck 特征 ============

    private static final String[][] SU_PATHS = {
        {"/sbin/su","SU /sbin/su"}, {"/system/bin/su","SU /system/bin/su"},
        {"/system/xbin/su","SU /system/xbin/su"}, {"/system/bin/daemonsu","SU daemonsu"},
        {"/system/xbin/daemonsu","SU xbin daemonsu"}, {"/system/bin/.su","SU hidden .su"},
        {"/system/sbin/su","SU system sbin"}, {"/vendor/bin/su","SU vendor"},
        {"/data/su","SU /data"}, {"/cache/su","SU /cache"},
        {"/data/local/su","SU local"}, {"/data/local/bin/su","SU local bin"},
        {"/data/local/xbin/su","SU local xbin"}, {"/sbin/daemonsu","SU sbin daemon"},
        {"/system/app/Superuser.apk","Superuser.apk"}, {"/system/app/SuperSU.apk","SuperSU.apk"},
        {"/system/app/Magisk.apk","Magisk.apk"}, {"/system/app/Xposed.apk","Xposed.apk"},
        {"/system/priv-app/Magisk","priv-app Magisk"}, {"/system/priv-app/SuperSU","priv-app SuperSU"},
        {"/system/etc/init.d","init.d 目录"}, {"/vendor/etc/init.d","vendor init.d 目录"},
        {"/data/adb/magisk","adb/magisk"}, {"/data/adb/ksu","adb/ksu"},
        {"/data/adb/ap","adb/ap"}, {"/data/adb/modules","adb/modules(已装模块)"},
        {"/data/adb/zygisk","adb/zygisk"}, {"/data/adb/riru","adb/riru"},
        {"/data/adb/lspd","adb/lspd(LSPosed)"}, {"/data/adb/tricky_store","adb/tricky_store"},
        {"/sdcard/.magisk","sdcard/.magisk"}, {"/sdcard/recovery","sdcard/recovery"},
        {"/system/recovery-from-boot.p","recovery-from-boot"}, {"/system/bin/.ext","bin/.ext"},
        {"/system/xbin/.ext","xbin/.ext"}, {"/system/etc/.installed_su",".installed_su"},
        {"/data/adb/service.d","adb/service.d"}, {"/data/adb/modules_update","adb/modules_update"},
        {"/data/adb/overlay","adb/overlay"},
        {"/vendor/xbin/su","vendor xbin su"}, {"/su/bin/su","su/bin su"},
        {"/system/bin/.ext/.su","system .ext/.su"}, {"/system/xbin/.ext/.su","system xbin .ext/.su"},
        {"/system/usr/we-need-root","we-need-root(usr)"}, {"/system/xbin/we-need-root","we-need-root(xbin)"},
        {"/system/.ext/.su","system/.ext/.su"}, {"/apex/com.android.virt/bin/su","APEX virt su"}
    };

    private static final String[] PROC_NAMES = {
        "magiskd","zygiskd","ksud","apd","daemonsu","supolicy","supersu","phhsu",
        "tricky_store","frida-server","gdb-server","busybox","riru_daemon","magisk","lspd",
        "hidemyapplist","memu-vbox","sepolicy-helper"
    };

    private static final String[] HIGH_PKGS = {
        "com.topjohnwu.magisk","io.github.vvb2060.magisk","me.weishu.kernelsu",
        "com.byyoungset.kernelsu","me.bmax.apatch","com.rifsxd.ksunext","io.github.a13e300.ksuwebui",
        "eu.chainfire.supersu","com.noshufou.android.su","com.koushikdutta.superuser",
        "org.lsposed.manager","org.lsposed.lspd","org.lsposed.lspatch","de.robv.android.xposed.installer",
        "com.tsng.hidemyapplist","com.tsng.pzyhrx.hma","me.simpleHook","com.qq.qcxm",
        "com.padi.hook.hookqq","github.tornaco.android.thanos","com.lerist.fakelocation",
        "com.silverlab.app.deviceidchanger.free","com.zhufucdev.motion_emulator",
        "moe.shizuku.privileged.api","moe.shizuku.manager","io.github.jark006.susfs4ksu"
    };

    private static final String[] WEAK_PKGS = {
        "com.sevtinge.hyperceiler","com.omarea.vtools","io.github.qauxv",
        "com.fankes.enforcehighrefreshrate","com.fankes.tsbattery","top.sacz.timtool",
        "com.hchen.appretention","com.luckyzyx.luckytool","com.modify.installer",
        "com.byyoung.setting","com.parallel.space","com.termux","net.dinglisch.android.tasker",
        "com.arlosoft.macrodroid"
    };

    private static final String[] VIRT_PKGS = {
        "com.swift.virtual","io.va.exposed","com.lody.virtual","com.parallel.space",
        "com.vphone.gaia","com.didi.virtual","com.qihoo.magic","com.jiubang.commerce"
    };

    private static final String[] MOUNT_SUS = { "/data/adb", "magisk", "ksu", "apatch", "tricky", "frida", "zygisk" };

    private static final String[] ACCESS_SUS = {
        "magisk","hook","root","auto","click","scene","frida","shizuku","macro","touch","debug","keyboard","input","swipe","shell"
    };

    private static final String[] MAPS_SUS = { "zygisk", "lspd", "lsposed", "riru", "xposed", "frida", "gum-js", "libhook", "whale", "substrate", "edxp", "pif" };

    private static final String[] EMU_DEVS = {
        "/dev/socket/qemud","/dev/qemu_pipe","/dev/goldfish_pipe","/dev/socket/genyd","/sys/qemu_trace",
        "/dev/socket/baseband_genyd","/system/lib/libc_malloc_debug.so"
    };

    private static final String[] EMU_BINS = {
        "/system/bin/qemu","/system/bin/qemu-system-armel","/system/bin/microvirt","/system/bin/vbox",
        "/system/bin/vmsystem","/system/bin/ttVM","/system/bin/nox","/system/bin/memu",
        "/system/lib/libdroid.so","/system/lib64/libdroid.so","/system/lib/libhoudini.so","/system/lib/libndk_translation.so"
    };

    private static final String[][] PORT_KEYS = {
        {":4444","4444"}, {":5555","5555"}, {":8080","8080"}, {":9999","9999"},
        {":27183","27183"}, {":55556","55556"}, {":5000","5000"}, {":5900","5900"},
        {":6401","6401"}, {":22222","22222"}, {":27042","27042"}, {":1234","1234"},
        {":13AD","5037(adb)"}, {":814C","33100(frpc)"}
    };

    /** 春秋附录A：风险/黑名单包名(85) */
    private static final String[] CHUNQIU_A = {
        "cn.android.x","cn.aodlyric.xiaowine","cn.geektang.privacyspace","cn.kwaiching.hook",
        "cn.myflv.monitor.noactive","cn.myflv.noactive","com.apocalua.run","com.byyoung.setting",
        "com.coderstory.toolkit","com.cshlolss.vipkill","com.ddm.qute","com.demo.serendipity",
        "com.didjdk.adbhelper","com.dna.tools","com.example.ourom","com.fankes.enforcehighrefreshrate",
        "com.fankes.tsbattery","com.fkzhang.wechatxposed","com.fuck.android.rimet",
        "com.github.tianma8023.xposed.smscode","com.hchen.appretention","com.hchen.switchfreeform",
        "com.houvven.impad","com.kooritea.fcmfix","com.lerist.fakelocation","com.luckyzyx.luckytool",
        "com.modify.installer","com.nnnen.plusne","com.omarea.vtools","com.padi.hook.hookqq",
        "com.qq.qcxm","com.rifsxd.ksunext","com.rkg.IAMRKG","com.sevtinge.hyperceiler",
        "com.shatyuka.zhiliao","com.silverlab.app.deviceidchanger.free","com.sukisu.ultra",
        "com.suqi8.oshin","com.syyf.quickpay","com.tencent.JYNB","com.tencent.jingshi","com.termux",
        "com.tsng.hidemyapplist","com.tsng.pzyhrx.hma","com.twifucker.hachidori","com.wei.vip",
        "com.wn.app.np","com.xayah.databackup.foss","com.yuanwofei.cardemulator.pro",
        "com.yxer.packageinstalles","com.zhufucdev.motion_emulator","dialog.box","dknb.con",
        "dknb.coo8","github.tornaco.android.thanos","have.fun","io.github.Retmon403.oppotheme",
        "io.github.a13e300.ksuwebui","io.github.qauxv","io.github.vvb2060.magisk","kk.dk.anqu",
        "lin.xposed","me.bingyue.IceCore","me.gm.cleaner","me.plusne","me.simpleHook",
        "me.teble.xposed.autodaily","miko.client","moe.fuqiuluo.portal","name.monwf.customiuizer",
        "nep.timeline.freezer","nep.timeline.re_telegram","one.yufz.hmspush","org.lsposed.lspatch",
        "org.lsposed.lspd","org.lsposed.manager","ru.maximoff.apktool","top.bienvenido.saas.i18n",
        "top.hookvip.pro","top.sacz.timtool","tornaco.apps.shortx.ext","vn.kwaiching.tao",
        "xzr.hkf","xzr.konabess","zako.zako.zako"
    };

    // ============ 主流程 ============

    public Report run() { return run(null); }

    public Report run(ProgressListener progressListener) {
        this.listener = progressListener;

        // 预取一次共享数据，避免重复 IO
        String psAll = shExec("ps -A 2>/dev/null");
        String mounts = read("/proc/self/mounts");
        String mountinfo = read("/proc/self/mountinfo");
        String mapsSelf = read("/proc/self/maps");
        String statusSelf = read("/proc/self/status");
        String netTcp = read("/proc/net/tcp");
        String logcatEvents = shExec("logcat -d -b events -t 300 2>/dev/null");
        String logcatAll = shExec("logcat -d -t 300 2>/dev/null");
        String dmesgOut = shExec("dmesg 2>/dev/null");
        String serviceOut = shExec("service list 2>/dev/null");
        String cmdline = read("/proc/cmdline");
        String cpuinfo = read("/proc/cpuinfo");

        // ===== 1. 系统属性 / 机型 / 固件 =====
        String cat = "系统属性";
        String vb = prop("ro.boot.verifiedbootstate");
        if ("green".equals(vb)) r(cat,"验证启动状态(Verified Boot)","state=green 启动已验证",0);
        else if ("yellow".equals(vb)||"orange".equals(vb)) r(cat,"验证启动状态(Verified Boot)","state="+vb+" 异常启动/自定义ROM",2);
        else if ("red".equals(vb)) r(cat,"验证启动状态(Verified Boot)","state=red 严重异常",1);
        else r(cat,"验证启动状态(Verified Boot)","state="+(vb==null?"不可读":vb),0);
        String vm = prop("ro.boot.veritymode");
        if (vm != null) r(cat,"dm-verity","veritymode="+vm, "enforcing".equals(vm)?0:1);
        else r(cat,"dm-verity","veritymode=不可读",0);
        String fl = prop("ro.boot.flash.locked");
        r(cat,"OEM 锁(flash.locked)","flash.locked="+fl, "1".equals(fl)?0:2);
        r(cat,"vbmeta 设备状态","device_state="+prop("ro.boot.vbmeta.device_state"),0);
        r(cat,"OEM 解锁支持","ro.oem_unlock_supported="+prop("ro.oem_unlock_supported"),
                "1".equals(prop("ro.oem_unlock_supported"))?2:0);
        String dg = prop("ro.debuggable");
        r(cat,"ro.debuggable(调试)","ro.debuggable="+dg,"1".equals(dg)?2:0);
        r(cat,"ro.build.type","type="+prop("ro.build.type"),
                "eng".equals(prop("ro.build.type"))||"userdebug".equals(prop("ro.build.type"))?2:0);
        String tag = prop("ro.build.tags");
        r(cat,"构建签名(tags)","tags="+tag,"release-keys".equals(tag)?0:2);
        String model = prop("ro.product.model");
        String vmodel = prop("ro.product.vendor.model");
        r(cat,"机型属性(model)","model="+model+" vendor="+vmodel,
                (model!=null&&vmodel!=null&&!model.equals(vmodel))?2:0);
        String dev = prop("ro.product.device");
        String fp = prop("ro.build.fingerprint");
        r(cat,"指纹与 device 一致性","device="+dev+" fp="+(fp==null?"":fp),
                (fp!=null&&dev!=null&&fp.contains(dev))?0:2);
        boolean fpGeneric = fp != null && (fp.contains("generic")||fp.contains("sdk_gphone")||fp.contains("test-keys"));
        r(cat,"指纹 generic/测试签名","fp="+(fp==null?"":fp), fpGeneric?1:0);
        r(cat,"安全补丁日期","security_patch="+prop("ro.build.version.security_patch"),0);
        r(cat,"CPU/GPU 厂商","hardware="+prop("ro.hardware")+" board="+prop("ro.board.platform")
                +" soc="+prop("ro.soc.model"),0);
        String abi = prop("ro.product.cpu.abi");
        r(cat,"CPU ABI(仿真器)","abi="+abi, (abi!=null&&(abi.contains("x86")||abi.contains("x86_64")))?1:0);
        r(cat,"ro.secure(安全)", "ro.secure="+prop("ro.secure"), "0".equals(prop("ro.secure"))?2:0);
        String selProp = prop("ro.build.selinux") != null ? prop("ro.build.selinux") : prop("ro.boot.selinux");
        r(cat,"SELinux 构建属性","selinux="+selProp, (selProp!=null&&selProp.toLowerCase().contains("permissive"))?1:0);
        r(cat,"warranty_bit(保修熔断)","warranty_bit="+prop("ro.boot.warranty_bit"), "1".equals(prop("ro.boot.warranty_bit"))?2:0);
        String avb = prop("ro.boot.vbmeta.avb_version");
        r(cat,"AVB 版本","avb_version="+avb, (avb!=null&&avb.contains("2.0"))?2:0);
        String digest = prop("ro.boot.vbmeta.digest");
        r(cat,"Boot Hash(vbmeta.digest)","digest="+digest, (digest!=null&&digest.replace("0","").isEmpty())?2:0);
        r(cat,"证书链锁状态(secureboot)","ro.secureboot.lockstate="+prop("ro.secureboot.lockstate"),
                "unlocked".equals(prop("ro.secureboot.lockstate"))?1:0);
        String sc1 = prop("ro.serialno"), sc2 = prop("ro.boot.serialno");
        r(cat,"串号多源一致性","serialno="+sc1+" boot.serialno="+sc2,
                (sc1!=null&&sc2!=null&&!sc1.equals(sc2))?2:0);

        // ===== 2. SU / Root 二进制路径族 =====
        cat = "Root 路径";
        for (String[] s : SU_PATHS) r(cat,"风险路径:"+s[0], exists(s[0])?"存在":"不存在", exists(s[0])?1:0);
        // 空 su 占位文件（文件存在但大小为 0 的隐藏痕迹）
        String[] emptySu = {"/system/bin/su","/system/xbin/su","/data/adb/ap/bin/su","/data/adb/ksu/bin/su"};
        boolean emptyHit = false;
        for (String p : emptySu) { File f = new File(p); if (f.exists() && f.length() == 0) emptyHit = true; }
        r(cat,"空 su 占位文件","系统 su 路径空文件"+(emptyHit?"存在":"均无"), emptyHit?2:0);

        // ===== 3. Root 管理器目录/数据库 =====
        cat = "Root 管理器";
        pathAny(cat,"Magisk 特征库", 1, "/data/adb/magisk.db","/data/adb/magisk_denylist.db","/data/adb/denylist","/data/magisk","/cache/magisk","/data/magisk.img");
        pathAny(cat,"KernelSU 特征库", 1, "/data/adb/ksu.db","/data/adb/ksud","/data/adb/ksu/bin/su","/data/adb/ap/bin/su","/data/adb/apd","/dev/ksu");
        pathAny(cat,"Zygisk 模块目录", 2, "/data/adb/modules/zygisk_next","/data/adb/modules/zygisk-next","/data/adb/modules/zygisk_lsposed","/data/adb/modules/zygisk_selinux_hide");
        pathAny(cat,"Riru 模块目录", 2, "/data/adb/modules/riru-core","/data/adb/modules/riru_lsposed","/data/adb/modules/riru_shizuku");
        pathAny(cat,"LSPosed 模块目录", 2, "/data/adb/modules/lsposed","/data/adb/modules/zygisk_lsposed","/data/adb/modules/riru_lsposed","/data/adb/lspd");
        pathAny(cat,"TrickyStore 配置", 2, "/data/adb/tricky_store/target.txt","/data/adb/tricky_store/security_patch.txt","/data/adb/tricky_store/cur_patch_level.json");
        pathAny(cat,"元模块(Hybrid-Mount)", 2, "/data/adb/modules/meta-hybrid-mount","/data/adb/modules/hybrid-mount");
        String bpf = read("/sys/fs/bpf");
        r(cat,"KSU loop/bpf 特征", "/dev/ksu="+exists("/dev/ksu")+" bpf含ksu="+(bpf!=null&&bpf.contains("ksu")), (exists("/dev/ksu")||(bpf!=null&&bpf.contains("ksu")))?1:0);

        // ===== 4. Native Root 特征 =====
        cat = "Native Root";
        procK(cat,"KSU 守护进程", 1, "ksud","kernelsu","ksu");
        procK(cat,"APatch/KernelPatch 进程", 1, "apatchd","kpatchd","superkey","apd");
        procK(cat,"Magisk 守护进程", 1, "magiskd");
        procK(cat,"su_daemon/rirud/supersu", 1, "phh-su","su_daemon","rirud","supersu","daemonsu");
        String modsLower = "";
        String mods = read("/proc/modules");
        if (mods != null) modsLower = mods.toLowerCase();
        boolean susKmod = modsLower.contains("magisk")||modsLower.contains("ksu")||modsLower.contains("apatch")
                ||modsLower.contains("susfs")||modsLower.contains("selinux_hook")||modsLower.contains("zygisk");
        r(cat,"可疑内核模块签名", mods!=null?(countLines(mods)+"个模块"+(susKmod?"· 命中可疑签名":"")):"不可读", susKmod?2:0);
        String kv = kernelVersion();
        boolean dirtyK = kv.contains("-Dirty")||kv.contains("-custom")||kv.contains("-ksu")||kv.contains("-apatch")||kv.contains("-gki")||kv.contains("-GKI");
        r(cat,"内核版本/自编译特征", "uname="+kv+(dirtyK?" · 非官方内核":""), dirtyK?2:0);
        String susfsProp = anyPropSet("persist.sys.susfs.hide","persist.sys.susfs.option","persist.sys.susfs.path");
        r(cat,"SUSFS 内核特征", susfsProp.isEmpty()?"未见 susfs 特征":"属性残留:"+susfsProp, susfsProp.contains("susfs")?2:0);

        // ===== 5. 高危文件/目录（春秋附录B + 脚本第4节） =====
        cat = "高危文件";
        pathAny(cat,"外挂样本/作弊目录", 1,
                "/data/A内核.ini","/data/BingHPJY/pz.cfg","/data/BingPUBG","/data/Dit驱动","/data/HPX","/data/HPY",
                "/data/js","/data/js.sh","/data/物资.txt","/data/南瓜三角洲公益最新版本.sh");
        pathAny(cat,"/data/local/tmp 载体与样本", 1,
                "/data/local/tmp/A内核公益-和平精英0215x1","/data/local/tmp/A内核公益-和平精英0215x1(1)",
                "/data/local/tmp/A内核公益-和平精英0215x1(2)","/data/local/tmp/android_server","/data/local/tmp/android_server64",
                "/data/local/tmp/gdbserver","/data/local/tmp/luckys","/data/local/tmp/horae_control.log",
                "/data/local/tmp/simpleHook","/data/local/tmp/mount_mask","/data/local/tmp/scriptTMP");
        pathAny(cat,"/data/local/tmp 工具与钩子", 2,
                "/data/local/tmp/yshell","/data/local/tmp/resetprop","/data/local/tmp/cleaner_starter",
                "/data/local/tmp/encore_logo.png","/data/local/tmp/Surfing_update","/data/local/tmp/HyperCeiler",
                "/data/local/tmp/DisabledAllGoogleServices");
        pathAny(cat,"调度/温控模块特征", 2,
                "/data/encore/default_cpu_gov","/data/encore/custom_default_cpu_gov","/data/gpu_freq_table.conf",
                "/data/swap_config.conf","/data/system/junge/","/data/nh.ko","/data/nh2","/data/nh3","/data/nh4","/data/nh5",
                "/dev/cpuset/AppOpt");
        pathAny(cat,"系统篡改痕迹", 1,
                "/data/system/AppRetention","/data/system/Freezer/","/data/system/NoActive/","/data/system/HPX",
                "/data/system/HPY","/data/system/liboxmem.so","/data/system/xydriver.ko","/data/local/stryker/",
                "/data/local/luckys","/data/local/MIO","/data/local/中野三玖","/data/dna");
        // 国行设备原生 GMS 限制文件不判异常
        {
            boolean gmsF = exists("/my_product/etc/permissions/oplus_google_cn_gms_features.xml")
                    || exists("/system/etc/permissions/google.cn.gms.xml")
                    || exists("/product/etc/permissions/google.cn.gms.xml")
                    || exists("/my_product/etc/permissions/google.cn.gms.xml")
                    || exists("/system/etc/sysconfig/google.xml") == false
                    || exists("/system/etc/sysconfig/google_build.xml") == false;
            r(cat,"GMS 屏蔽特征", gmsF?"国行原生 GMS 限制(正常)":"未见", 0);
        }
        pathAny(cat,"MT管理器/改机痕迹", 1,
                "/storage/emulated/0/MT2/","/sdcard/fart","/sdcard/Download/dexdump/",
                "/sdcard/Download/com.niunaijun.blackdexa64_logcat.txt","/storage/emulated/0/Android/Clash/",
                "/storage/emulated/0/Android/HChai/","/storage/emulated/0/Android/Yume-Yunyun/",
                "/storage/emulated/0/Android/naki/","/storage/emulated/0/Documents/advanced/",
                "/storage/emulated/0/Download/advanced/","/storage/emulated/0/TpTestReport/screenOn/OK/0/",
                "/storage/emulated/0/rlgg/","/storage/emulated/0/弱隐.sh","/storage/emulated/0/落叶配置",
                "/storage/emulated/elgg");
        // /data/local/tmp 元数据（春秋 Suspicious Surroundings a/b/c + denied）
        String tmpStat = shExec("stat -c '%U:%G %i %a' /data/local/tmp 2>/dev/null");
        if (tmpStat != null && !tmpStat.trim().isEmpty()) {
            String[] tf = tmpStat.trim().split("\\s+");
            boolean ownerOk = tf.length >= 1 && tf[0].contains("shell");
            r(cat,"/data/local/tmp 属主/属组", "stat="+tmpStat, ownerOk?0:2);
            long inode = -1; String mode = "";
            if (tf.length >= 2) { try { inode = Long.parseLong(tf[1]); } catch (NumberFormatException ignored) {} }
            if (tf.length >= 3) mode = tf[2];
            r(cat,"/data/local/tmp inode 异常(b)", "inode="+(inode<0?"?":inode), inode > 10000 ? 2 : 0);
            r(cat,"/data/local/tmp 权限(c)", "perm="+(mode.isEmpty()?"?":mode), ("771".equals(mode))?0:2);
        } else {
            r(cat,"/data/local/tmp 属主/属组", "不可读或目录不存在", 0);
            r(cat,"/data/local/tmp inode 异常(b)", "不可读或目录不存在", 0);
            r(cat,"/data/local/tmp 权限(c)", "不可读或目录不存在", 0);
        }
        r(cat,"/data/local/tmp 可访问性", shExec("ls /data/local/tmp 2>/dev/null")!=null?"可读":"不可读/不存在", 0);

        // ===== 6. 系统属性·伪装/调试开关（春秋附录C + 脚本第5/22节） =====
        cat = "属性检测";
        propSet(cat,"persist.logd.size(日志缓冲)", "persist.logd.size", 2);
        propSet(cat,"persist.logd.size.crash", "persist.logd.size.crash", 2);
        propSet(cat,"persist.logd.size.main", "persist.logd.size.main", 2);
        propSet(cat,"persist.logd.size.system", "persist.logd.size.system", 2);
        propSet(cat,"pihooks 屏蔽 GMS", "persist.sys.pihooks.disable.gms", 1);
        String phResid = anyPropSet("persist.sys.pihooks_BRAND","persist.sys.pihooks_DEVICE","persist.sys.pihooks_MODEL",
                "persist.sys.pihooks_MANUFACTURE","persist.sys.pihooks_PRODUCT","persist.sys.pihooks_RELEASE",
                "persist.sys.pihooks_SDK_INT","persist.sys.pihooks_DEVICE_INIT");
        r(cat,"pihooks 改机型残留(属性组)", phResid.isEmpty()?"未设置":phResid, phResid.isEmpty()?0:2);
        propSet(cat,"pixelprops.gms", "persist.sys.pixelprops.gms", 2);
        propSet(cat,"pixelprops.gapps", "persist.sys.pixelprops.gapps", 2);
        propSet(cat,"pixelprops.google", "persist.sys.pixelprops.google", 2);
        propSet(cat,"pixelprops.gphotos", "persist.sys.pixelprops.gphotos", 2);
        propSet(cat,"spoof.gms(伪装GMS)", "persist.sys.spoof.gms", 2);
        propSet(cat,"Vold 数据隔离(双开痕迹)", "persist.sys.vold_app_data_isolation_enabled", 2);
        propSet(cat,"春秋 path_hide 标记", "persist.chunqiu.path_hide", 2);
        propSet(cat,"dex2oat-flags(ART 修改)", "dalvik.vm.dex2oat-flags", 2);
        propSet(cat,"core_platform_api_policy", "persist.debug.dalvik.vm.core_platform_api_policy", 2);
        String susfs2 = anyPropSet("persist.sys.susfs.hide","persist.sys.susfs.option","persist.sys.susfs.path","persist.sys.susfs.logging");
        r(cat,"susfs 隐藏属性残留", susfs2.isEmpty()?"未设置":susfs2, susfs2.isEmpty()?0:2);

        // ===== 7. 异常进程 =====
        cat = "异常进程";
        StringBuilder psh = new StringBuilder();
        String psLower = psAll == null ? "" : psAll.toLowerCase();
        for (String n : PROC_NAMES) if (psLower.contains(n)) psh.append(n).append(' ');
        r(cat,"可疑守护进程", psh.length()>0?psh.toString():"未运行", psh.length()>0?1:0);
        procK(cat,"LSPosed/Xposed 框架进程", 1, "lspd","edxp","xposed","lsp");
        procK(cat,"Shizuku 进程", 2, "shizuku","rish");
        procK(cat,"Scene/调度工具进程", 2, "scene","omarea","vtools");
        procK(cat,"Thanox 服务", 2, "tornaco","thanox","shortx");
        procK(cat,"HMA/隐藏应用进程", 2, "hidemyapplist","pzyhrx","hma");
        procK(cat,"frida/gdb/调试服务器", 1, "frida","gum-js","gdb-server","lldb-server","android_server");
        String rootPs = procsByUser("root");
        r(cat,"root 进程 (UID 0)", rootPs, rootPs.startsWith("未发现")?0:2);
        String shellPs = procsByUser("shell");
        r(cat,"shell 进程 (UID 2000)", shellPs, shellPs.startsWith("未发现")?0:2);
        r(cat,"运行进程总数", countLines(psAll)+"个",0);
        boolean auditRoot = logcatEvents != null && logcatEvents.contains("audit") &&
                (logcatEvents.contains("ksu")||logcatEvents.contains("magisk")||logcatEvents.contains("apatch"));
        r(cat,"AVC 审计日志 root 痕迹", auditRoot?"审计日志命中 root context":"未见", auditRoot?2:0);

        // ===== 8. 应用检测 =====
        cat = "应用检测";
        StringBuilder hp = new StringBuilder();
        for (String pkg : HIGH_PKGS) if (isInstalled(pkg)) hp.append(pkg).append(' ');
        r(cat,"高危包(root/hook/作弊)", hp.length()>0?hp.toString():"未安装", hp.length()>0?1:0);
        StringBuilder wp = new StringBuilder();
        for (String pkg : WEAK_PKGS) if (isInstalled(pkg)) wp.append(pkg).append(' ');
        r(cat,"常见工具包(可能误报)", wp.length()>0?wp.toString():"未安装", wp.length()>0?2:0);
        StringBuilder vp = new StringBuilder();
        for (String pkg : VIRT_PKGS) if (isInstalled(pkg)) vp.append(pkg).append(' ');
        r(cat,"虚拟化/双开应用", vp.length()>0?vp.toString():"未发现", vp.length()>0?2:0);
        StringBuilder cqa = new StringBuilder();
        for (String pkg : CHUNQIU_A) if (isInstalled(pkg)) cqa.append(pkg).append(' ');
        r(cat,"春秋附录A 风险包(85)", cqa.length()>0?cqa.toString():"未安装", cqa.length()>0?2:0);
        String riskScan = riskAppScan();
        r(cat,"风险应用目录扫描(Android/data)", riskScan, riskScan.startsWith("未发现")||riskScan.equals("不可读")?0:2);
        r(cat,"Root 管理器可见性", rootMgrIntentProbe(), 0);

        // ===== 9. 异常应用 =====
        cat = "异常应用";
        String[] dbg = debuggableApps();
        r(cat,"可调试应用 (debuggable)", "已开启调试 " + dbg[0] + " 个" + (dbg[1].isEmpty() ? "" : " · " + dbg[1]), dbg[1].isEmpty()?0:2);
        String[] auid = abnormalUidApps();
        r(cat,"异常 UID 应用 (root/system/shell)", "发现 " + auid[0] + " 个" + (auid[1].isEmpty() ? "" : " · " + auid[1]), auid[1].isEmpty()?0:2);

        // ===== 10. UID / 能力位 =====
        cat = "UID";
        String ud = uidDesc();
        int uidCode = ud.startsWith("uid=0") ? 1 : (ud.contains("共享系统UID") ? 2 : 0);
        r(cat,"当前进程 UID", ud, uidCode);
        String uc = uidConsistency();
        r(cat,"UID 一致性校验", uc, uc.contains("不一致")?2:0);
        String gc = gidConsistency();
        r(cat,"GID 一致性校验", gc, gc.contains("不一致")?2:0);
        String capEff = statusLine(statusSelf,"CapEff");
        boolean capEffBad = capEff != null && !"0000000000000000".equals(capEff.trim());
        r(cat,"能力位 CapEff", "CapEff="+(capEff==null?"不可读":capEff.trim()), capEffBad?2:0);
        String capPrm = statusLine(statusSelf,"CapPrm");
        boolean capPrmBad = capPrm != null && !"0000000000000000".equals(capPrm.trim());
        r(cat,"能力位 CapPrm", "CapPrm="+(capPrm==null?"不可读":capPrm.trim()), capPrmBad?2:0);
        String groups = statusLine(statusSelf,"Groups");
        boolean susGroup = groups != null && (groups.contains(" 0 ")||groups.contains(" 1000 ")||groups.contains(" 2000 "));
        r(cat,"补充组检查", "Groups="+(groups==null?"不可读":groups.trim()), susGroup?2:0);

        // ===== 11. 系统应用 / 安装器 / 无障碍 =====
        cat = "系统应用";
        String inst = null;
        for (String p : new String[]{"com.google.android.packageinstaller","com.android.packageinstaller"})
            if (isInstalled(p)) inst = p;
        r(cat,"系统安装器(PackageInstaller)", inst!=null?inst:"缺失/被替换", inst!=null?0:2);
        String ipath = installerPath();
        r(cat,"安装器路径异常", ipath, ipath.contains("/data/app")?1:0);
        r(cat,"系统内置应用数量", "priv-app="+countDirs("/system/priv-app"),0);
        String sas = systemAppSuspect();
        r(cat,"系统内置可疑应用", sas, sas.startsWith("未发现")?0:1);
        String store = storePresent();
        r(cat,"应用商店存在", store.equals("未发现")?store:store, 0);
        r(cat,"packages.xml 完整性", read("/data/system/packages.xml")!=null?"存在":"不可读", 0);
        r(cat,"第三方应用数量", thirdPartyCount()+"个", 0);
        cat = "无障碍";
        String acc = null;
        try { acc = Settings.Secure.getString(ctx.getContentResolver(), "enabled_accessibility_services"); } catch (Exception ignored) {}
        if (acc != null && !acc.isEmpty()) {
            boolean sus = false;
            for (String k : ACCESS_SUS) if (acc.toLowerCase().contains(k)) { sus = true; break; }
            r(cat,"无障碍服务", acc, sus?1:2);
        } else r(cat,"无障碍服务","未开启",0);

        // ===== 12. 系统设置 =====
        cat = "系统设置";
        String devOpt = readSetting("global","development_settings_enabled");
        r(cat,"开发者选项", onOff(devOpt), "1".equals(devOpt)?2:0);
        String adbEn = readSetting("global","adb_enabled");
        r(cat,"USB 调试(ADB)", onOff(adbEn), "1".equals(adbEn)?2:0);
        String mockLoc = readSetting("secure","mock_location");
        r(cat,"模拟定位开关", onOff(mockLoc), "1".equals(mockLoc)?1:0);
        String unkSrc = readSetting("secure","install_non_market_apps");
        r(cat,"未知来源安装", onOff(unkSrc)+" (Android10+按应用授权,全局开关仅记录)", 0);
        String usbTrace = readSetting("secure","adb_port");
        r(cat,"ADB 端口配置", usbTrace!=null?usbTrace:"未配置", 0);

        // ===== 12.5 深层探测（越过表层，反 HMA 隐藏应用） =====
        cat = "隐藏应用(HMA)";
        String bw = batteryWhitelistHidden();
        r(cat,"电池优化白名单(Doze)→隐藏应用", bw, bw.contains("隐藏/残留")?2:0);
        String ah = accessibilityHiddenApps();
        r(cat,"无障碍组件→包名交叉比对", ah, ah.contains("隐藏/残留")?2:0);
        String da = defaultAppsHidden();
        r(cat,"默认应用/角色→包名交叉比对", da, da.contains("隐藏/残留")?2:0);
        String sh = servicesHiddenApps();
        r(cat,"系统服务列表→包名交叉比对", sh, sh.contains("隐藏/残留")?2:0);
        String ph = procHiddenApps();
        r(cat,"进程/命令行→包名交叉比对", ph, ph.contains("隐藏/残留")?2:0);
        // 新HMA三组数据源交叉比对（用户安装 / 路径扫描APK / 系统禁用冻结），替换旧#155计数对比与旧#318多通道包数对比
        String hma = hmaThreeSourceCrossCheck();
        int hmaLevel = hma.startsWith("【能力受限】") ? 0 : (hma.contains("HMA疑似隐藏应用") ? 2 : 0);
        r(cat,"HMA三源交叉比对(用户安装/路径APK/禁用冻结)", hma, hmaLevel);
        String hid = hiddenAppSummary();
        r(cat,"隐藏应用综合判定", hid, hid.startsWith("发现")?2:0);

        // ===== 13. SELinux =====
        cat = "SELinux";
        String enforce = read("/sys/fs/selinux/enforce");
        if (enforce != null) r(cat,"SELinux enforce", enforce.trim().startsWith("1")?"enforcing":"permissive(降级)", enforce.trim().startsWith("1")?0:1);
        else r(cat,"SELinux 节点","不可读",0);
        String pv = read("/sys/fs/selinux/policyvers");
        r(cat,"policyvers", "policyvers="+(pv==null?"不可读":pv.trim()), 0);
        String ownCtx = read("/proc/self/attr/current");
        boolean ctxBad = ownCtx != null && (ownCtx.contains("magisk")||ownCtx.contains("ksu")||ownCtx.contains("apatch")||ownCtx.contains(":su:"));
        r(cat,"本进程 SELinux context", "context="+(ownCtx==null?"不可读":ownCtx.trim()), ctxBad?1:0);
        String accessNode = read("/sys/fs/selinux/access");
        r(cat,"selinuxfs access 可读性(异常判据)", accessNode!=null?"可读(疑似策略被改)":"拒绝访问(正常)", accessNode!=null?2:0);
        r(cat,"selinuxfs 挂载状态", exists("/sys/fs/selinux")?"已启用":"未启用(SELinux 关闭)", exists("/sys/fs/selinux")?0:1);
        String gen = shExec("getenforce 2>/dev/null");
        boolean genRd = gen != null && !gen.trim().isEmpty();
        r(cat,"getenforce", !genRd?(isOem()?"不可读(系统权限拦截,ColorOS 常见,无 root 正常)":"不可读(无权限,正常)"):gen.trim(),
                (!genRd)?0:("enforcing".equalsIgnoreCase(gen.trim())?0:1));
        String dk = read("/sys/fs/selinux/deny_unknown");
        r(cat,"deny_unknown", dk==null?"不可读":dk.trim(), (dk!=null&&!"1".equals(dk.trim()))?2:0);
        r(cat,"selinux status 节点", read("/sys/fs/selinux/status")!=null?"可读":"不可读", 0);

        // ===== 14. 挂载 / 命名空间 =====
        cat = "挂载";
        StringBuilder mh = new StringBuilder();
        if (mounts != null) for (String k : MOUNT_SUS) if (mounts.contains(k)) mh.append(k).append(' ');
        r(cat,"挂载源含可疑关键字", mh.length()>0?"mount 命中:"+mh.toString().trim():"未命中", mh.length()>0?2:0);
        boolean sysRw = mounts != null && mounts.contains(" /system ") && mounts.matches("(?s).* /system .*\\brw\\b.*");
        r(cat,"/system 挂载权限", sysRw?"rw(系统可写)":"ro/正常", sysRw?1:0);
        boolean overlaySys = false;
        if (mountinfo != null) for (String l : mountinfo.split("\n")) {
            int d = l.indexOf(" - ");
            if (d < 0) continue;
            String[] hf = l.substring(0, d).trim().split("\\s+");
            String[] tf = l.substring(d + 3).trim().split("\\s+");
            if (hf.length >= 5 && tf.length >= 1 && "overlay".equals(tf[0])
                    && (hf[4].equals("/system")||hf[4].equals("/vendor")||hf[4].equals("/product"))) { overlaySys = true; break; }
        }
        r(cat,"overlay 覆盖系统分区", overlaySys?"overlay 命中系统分区":"未见", overlaySys?2:0);
        boolean tmpfsSys = false;
        if (mounts != null) for (String l : mounts.split("\n")) {
            String[] f = l.trim().split("\\s+");
            if (f.length >= 3 && "tmpfs".equals(f[2]) && (f[1].equals("/system")||f[1].equals("/vendor"))) { tmpfsSys = true; break; }
        }
        r(cat,"tmpfs 覆盖系统分区", tmpfsSys?"tmpfs 覆盖 /system/vendor":"未见", tmpfsSys?2:0);
        String mGap = mountGapCheck(mountinfo);
        r(cat,"挂载 ID 间隙", mGap, mGap.startsWith("存在")?2:0);
        int bindCount = mountinfo == null ? 0 : countOccurrences(mountinfo, " bind ");
        int ovCount = mountinfo == null ? 0 : countOccurrences(mountinfo, " overlay ");
        r(cat,"bind/overlay 挂载统计", "bind="+bindCount+" overlay="+ovCount, (bindCount+ovCount)>30?2:0);
        r(cat,"by-name 分区表", "分区="+countDirs("/dev/block/by-name")+"个", 0);
        String mis = mountinfoSuspicious(mountinfo);
        r(cat,"mountinfo 异常条目", mis, mis.startsWith("命中")?2:0);

        // ===== 15. 反调试 / 内存 / 端口 =====
        cat = "反调试/内存";
        String tp = statusLine(statusSelf,"TracerPid");
        tp = tp == null ? "0" : tp.trim();
        r(cat,"反调试 TracerPid","TracerPid="+tp, "0".equals(tp)?0:1);
        String nspid = statusLine(statusSelf,"NSpid");
        boolean nspidBad = nspid != null && nspid.trim().split("\\s+").length >= 3;
        r(cat,"NSpid 层级(容器/多开)", "NSpid="+(nspid==null?"不可读":nspid.trim()), nspidBad?2:0);
        StringBuilder ports = new StringBuilder();
        if (netTcp != null) {
            for (String[] pk : PORT_KEYS) if (netTcp.contains(pk[0])) ports.append(pk[1]).append(' ');
        }
        r(cat,"可疑端口监听", ports.length()>0?ports.toString().trim():"未监听", ports.length()>0?2:0);
        boolean rwxp = mapsSelf != null && mapsSelf.contains("rwxp");
        r(cat,"可执行写映射(rwxp)", rwxp?"存在 rwxp 段":"未见", rwxp?2:0);
        StringBuilder mapHit = new StringBuilder();
        if (mapsSelf != null) { String ml = mapsSelf.toLowerCase(); for (String k : MAPS_SUS) if (ml.contains(k)) mapHit.append(k).append(' '); }
        r(cat,"maps 注入特征(zygisk/xposed/frida)", mapHit.length()>0?mapHit.toString().trim():"未见", mapHit.length()>0?2:0);
        boolean memfdHook = mapsSelf != null && mapsSelf.toLowerCase().contains("memfd:");
        r(cat,"memfd 匿名内存映射", memfdHook?"存在 memfd 映射":"未见", 0);
        int anonRw = anonRwCount(mapsSelf);
        r(cat,"匿名 rw 映射段", "anon-rw="+anonRw+"段", anonRw>120?2:0);
        int fdn = fdCount();
        r(cat,"fd 句柄数量", fdn<0?"不可读":fdn+"个", fdn>200?2:0);
        r(cat,"映射段总数", mapsSelf==null?"不可读":countLines(mapsSelf)+"段", 0);

        // ===== 16. Hook 注入库（全进程扫描） =====
        cat = "Hook 注入";
        StringBuilder hookLib = new StringBuilder();
        File proc = new File("/proc");
        File[] pids = proc.listFiles();
        if (pids != null) {
            int c = 0;
            for (File f : pids) {
                if (!f.getName().matches("\\d+")) continue;
                String maps = read(f.getPath()+"/maps");
                if (maps == null) continue;
                String ml = maps.toLowerCase();
                boolean hit = false;
                for (String k : MAPS_SUS) if (ml.contains(k)) { hit = true; break; }
                if (hit) { hookLib.append(f.getName()).append(' '); if (++c > 8) break; }
            }
        }
        r(cat,"进程 hook 注入库", hookLib.length()>0?hookLib.toString():"未发现", hookLib.length()>0?1:0);
        String zygoteMaps = read("/proc/zygote/maps");
        String zyHit = zygoteMaps==null?"":zygoteMaps.toLowerCase();
        boolean zyBad = zyHit.contains("zygisk")||zyHit.contains("xposed")||zyHit.contains("frida")||zyHit.contains("lspd");
        r(cat,"zygote 进程注入检查", zygoteMaps==null?"不可读":(zyBad?"命中注入":"未见"), zyBad?1:0);

        // ===== 17. 内核 / 启动参数 =====
        cat = "内核";
        r(cat,"已加载内核模块", mods!=null?countLines(mods)+"个":"不可读",0);
        String kptr = read("/proc/sys/kernel/kptr_restrict");
        r(cat,"kptr_restrict", "kptr="+(kptr==null?"不可读":kptr.trim()), (kptr!=null&&"0".equals(kptr.trim()))?2:0);
        boolean permissiveCmd = cmdline != null && cmdline.contains("selinux=permissive");
        r(cat,"cmdline selinux=permissive", permissiveCmd?"命中":"未见", permissiveCmd?1:0);
        boolean orangeCmd = cmdline != null && (cmdline.contains("androidboot.verifiedbootstate=orange")||cmdline.contains("androidboot.verifiedbootstate=red"));
        r(cat,"cmdline 启动状态", orangeCmd?"orange/red 命中":"未见", orangeCmd?1:0);
        boolean warrantyCmd = cmdline != null && cmdline.contains("androidboot.warranty_bit=1");
        r(cat,"cmdline warranty_bit", warrantyCmd?"命中":"未见", warrantyCmd?2:0);

        // ===== 18. 模拟器 / 虚拟化 / 多开 =====
        cat = "模拟器/多开";
        r(cat,"qemu 属性", "ro.kernel.qemu="+prop("ro.kernel.qemu"), "1".equals(prop("ro.kernel.qemu"))?1:0);
        pathAny(cat,"仿真器设备节点", 1, EMU_DEVS);
        pathAny(cat,"仿真器二进制", 1, EMU_BINS);
        String hw = prop("ro.hardware");
        boolean hwEmu = hw != null && (hw.contains("qemu")||hw.contains("ranchu")||hw.contains("goldfish")||hw.contains("genymotion")
                ||hw.contains("bluestacks")||hw.contains("ldplayer")||hw.contains("nox")||hw.contains("memu")||hw.contains("ttvm"));
        r(cat,"硬件仿真特征", "hardware="+hw, hwEmu?1:0);
        String nb = prop("ro.dalvik.vm.native.bridge");
        r(cat,"native bridge(翻译执行)", "native.bridge="+(nb==null?"未设置":nb), (nb!=null&&!nb.isEmpty()&&!"0".equals(nb))?1:0);
        String cg = read("/proc/self/cgroup");
        boolean cgOk = cg != null && (Pattern.matches("(?s).*0::/uid_\\d+/pid_\\d+.*", cg) || Pattern.matches("(?s).*0::/apps/uid_\\d+/pid_\\d+.*", cg) || cg.contains("/uid/"));
        r(cat,"cgroup 容器/多开判定", cg==null?"不可读":cg.trim().replace('\n',' '), cgOk?0:2);
        String chars = prop("ro.build.characteristics");
        r(cat,"build.characteristics", "chars="+chars, (chars!=null&&chars.contains("emulator"))?1:0);
        boolean cpuEmu = cpuinfo != null && (cpuinfo.contains("goldfish")||cpuinfo.contains("ranchu")||cpuinfo.contains("qemu")||cpuinfo.contains("vbox")||cpuinfo.contains("Virtual"));
        r(cat,"cpuinfo 仿真特征", cpuEmu?"命中仿真关键字":"未见", cpuEmu?1:0);
        String svcEmu = serviceOut==null?"":serviceOut.toLowerCase();
        boolean svcEmuHit = svcEmu.contains("goldfish")||svcEmu.contains("qemu")||svcEmu.contains("genyd")||svcEmu.contains("ranchu");
        r(cat,"系统服务仿真特征", svcEmuHit?"命中仿真服务":"未见", svcEmuHit?2:0);
        String pty = shExec("ls /dev/pts 2>/dev/null | wc -l");
        r(cat,"PTY 终端痕迹", "pty="+(pty==null?"不可读":pty.trim())+"个", 0);

        // ===== 19. Bootloader / TEE / 密钥 =====
        cat = "TEE/密钥";
        r(cat,"① Verified Boot 绿", "state="+vb, "green".equals(vb)?0:1);
        r(cat,"② Play Integrity 服务", playServicesPresent()?"Google Play 服务存在":"国行无 GMS(正常)", playServicesPresent()?0:0);
        r(cat,"③ 硬件密钥(KeyStore)", hardwareKeyStore()?"硬件背书 OK":"软件/不可用", hardwareKeyStore()?0:2);
        String keybox = read("/data/adb/tricky_store/keybox.xml");
        if (keybox != null) {
            int keys = countOccurrences(keybox, "<AndroidAttestKey");
            r(cat,"keybox 密钥数量", "keybox.xml 含密钥 "+keys+" 个", keys>0?0:2);
            boolean aosp = keybox.toLowerCase().contains("testkey")||keybox.toLowerCase().contains("aosp");
            r(cat,"keybox AOSP 测试密钥", aosp?"含测试密钥":"未见测试密钥", aosp?1:0);
            int open = countOccurrences(keybox, "<AndroidAttestKey"), close = countOccurrences(keybox, "</AndroidAttestKey>");
            r(cat,"keybox 结构完整性", "开标签="+open+" 闭标签="+close, (open>0&&open==close)?0:1);
        } else {
            r(cat,"keybox 密钥文件", "未找到(无TrickyStore)", 0);
            r(cat,"keybox AOSP 测试密钥", "未见(无keybox)", 0);
            r(cat,"keybox 结构完整性", "未见(无keybox)", 0);
        }
        pathAny(cat,"Keystore 数据目录", 0, "/data/keystore","/data/misc/keystore","/data/misc/keychain");
        boolean soterPkg = isInstalled("com.tencent.soter.server");
        String ss = prop("ro.soter.keystore_status");
        boolean ssAbn = ss != null && !ss.isEmpty();
        r(cat,"Soter 服务(四象限)", "服务程序="+(soterPkg?"存在":"不存在")+" 属性="+(ssAbn?ss:"未设置"),
                (ssAbn&&soterPkg)?2:0);
        pathAny(cat,"TEE 库与目录", 0, "/system/lib64/libtee_soter.so","/vendor/lib64/libteec.so","/vendor/lib64/hw/keystore.soter.so","/system/lib64/libkeystore.so","/system/lib/hw/keystore.default.so");
        String bc = bootConsistency();
        r(cat,"BL 多源一致性", bc, bc.startsWith("一致")?0:2);

        // ===== 20. 吊销联网 → 已移至 runOnline()（第二页联网检测） =====

        // ===== 21. 日志痕迹 =====
        cat = "日志痕迹";
        boolean avcHit = logcatEvents != null && logcatEvents.contains("avc: denied");
        r(cat,"logcat audit AVC 记录", avcHit?"存在 AVC denied":"未见", avcHit?2:0);
        String la = logcatAll == null ? "" : logcatAll.toLowerCase();
        boolean lspHit = la.contains("lspd")||la.contains("xposed")||la.contains("magiskd")||la.contains("frida");
        r(cat,"logcat root/hook 痕迹", lspHit?"日志命中":"未见", lspHit?2:0);
        String dm = dmesgOut == null ? "" : dmesgOut.toLowerCase();
        boolean dmHit = dm.contains("magisk")||dm.contains("ksud")||dm.contains("apatch")||dm.contains("frida")||dm.contains("zygisk")||dm.contains("susfs");
        r(cat,"dmesg root 痕迹", dmHit?"dmesg 命中":"未见(可能无权限)", dmHit?2:0);
        r(cat,"崩溃/审计痕迹目录", "tombstones="+countDirs("/data/tombstones")+" dropbox="+countDirs("/data/system/dropbox")+" anr="+(exists("/data/anr")?1:0), 0);
        r(cat,"adb_keys 授权密钥", exists("/data/misc/adb/adb_keys")?"存在(USB调试授权)":"不存在", exists("/data/misc/adb/adb_keys")?2:0);
        r(cat,"packages.orig 备份", exists("/data/system/packages.orig")?"存在(包列表曾变动)":"不存在", 0);
        String hosts = read("/etc/hosts");
        r(cat,"hosts 自定义条目", hostsCount(hosts)+"条", hostsCount(hosts)>5?2:0);
        r(cat,"LSPosed 运行日志", exists("/data/adb/lspd/log")?"存在":"不存在", exists("/data/adb/lspd/log")?1:0);

        // ===== 22. 异常路径 / 文件扫描 =====
        cat = "异常路径";
        String rootLs = shExec("ls -A / 2>/dev/null");
        StringBuilder rootHit = new StringBuilder();
        if (rootLs != null) for (String l : rootLs.split("\n")) {
            String t = l.trim();
            if (t.isEmpty()||t.equals("system")||t.equals("data")||t.equals("vendor")||t.equals("product")||t.equals("sbin")||t.equals("sdcard")||t.equals("storage")||t.equals("proc")||t.equals("dev")||t.equals("sys")||t.equals("system_ext")||t.equals("apex")||t.equals("init")||t.equals("bin")||t.equals("etc")||t.equals("lib")||t.equals("lib64")||t.equals("mnt")||t.equals("odm")||t.equals("oem")||t.equals("metadata")||t.equals("cache")||t.equals("acct")||t.equals("config")||t.equals("debug_ramdisk")||t.equals("d")||t.equals("first_stage_ramdisk")||t.equals("persist")||t.equals("postinstall")||t.equals("overlay")||t.equals("recovery")||t.equals("res")||t.equals("root")||t.equals("sepolicy")||t.equals("service_contexts")||t.equals("charger")) continue;
            if (t.startsWith("su")||t.contains("magisk")||t.contains("ksu")||t.contains("apatch")||t.contains("tricky")||t.contains("hook")||t.contains("cheat")||t.contains("payload")||t.contains("root")||t.contains("bypass")) rootHit.append(t).append(' ');
        }
        r(cat,"根目录异常条目", rootHit.length()>0?rootHit.toString().trim():"未见", rootHit.length()>0?1:0);
        String adbLs = shExec("ls -a /data/adb 2>/dev/null");
        boolean adbHit = adbLs != null && (adbLs.contains("magisk")||adbLs.contains("ksu")||adbLs.contains("ap")||adbLs.contains("modules")||adbLs.contains("lspd"));
        r(cat,"/data/adb 内容", adbLs==null||adbLs.trim().isEmpty()?"不存在或不可读":adbLs.replace('\n',' ').trim(), adbHit?1:0);
        String susDir = shExec("find /data/local /data /sdcard /storage/emulated/0 -maxdepth 3 -type d 2>/dev/null | grep -iE '/(root|su$|magisk|ksu$|apatch|tricky|hidden|hide|payload|clone|virtual|proxy|hook|spoof|backup|tmp_tool)' | head -8");
        boolean susDirHit = susDir != null && !susDir.trim().isEmpty();
        // 单特征：仅记录日志，不单独 SUSPECT；需搭配其他独立风险证据聚合
        r(cat,"全盘异常目录名", susDirHit ? susDir.replace('\n',' ').trim()+" (单特征仅记录,需其他独立证据聚合,不计风险分)" : "未见", 0);
        String writableSys = shExec("find /system /vendor /product -maxdepth 2 -type d -perm -o+w 2>/dev/null | head -6");
        r(cat,"系统目录可写", writableSys==null||writableSys.trim().isEmpty()?"未见":writableSys.replace('\n',' ').trim(), writableSys!=null&&!writableSys.trim().isEmpty()?1:0);
        String symLink = shExec("find /system /vendor /product -maxdepth 4 -type l 2>/dev/null | grep -iE '/su$|magisk|ksu|apatch|root|tricky|hook' | head -6");
        r(cat,"可疑符号链接", symLink==null||symLink.trim().isEmpty()?"未见":symLink.replace('\n',' ').trim(), symLink!=null&&!symLink.trim().isEmpty()?2:0);
        String binFiles = shExec("find /data/local/tmp /sdcard /storage/emulated/0/Download -maxdepth 3 -type f \\( -name '*.bin' -o -name '*.ko' -o -name '*.elf' -o -name '*.dex' -o -name '*.dat' \\) 2>/dev/null | grep -iE 'root|su$|magisk|ksu|apatch|hook|spoof|key|payload|bypass|driver|内核' | head -6");
        r(cat,"ko/dex/bin 异常文件", binFiles==null||binFiles.trim().isEmpty()?"未见":binFiles.replace('\n',' ').trim(), binFiles!=null&&!binFiles.trim().isEmpty()?3:0);

        // ===== 23. CPU/GPU/固件深度 =====
        cat = "CPU/GPU";
        int cores = cpuinfo == null ? 0 : countOccurrences(cpuinfo, "processor\t:");
        if (cores == 0) cores = cpuinfo == null ? 0 : countOccurrences(cpuinfo, "processor :");
        r(cat,"CPU 核心数", cores>0?cores+"核":"不可读", 0);
        String cpuModel = "";
        if (cpuinfo != null) for (String l : cpuinfo.split("\n")) if (l.startsWith("Hardware")) { cpuModel = l.substring(l.indexOf(':')+1).trim(); break; }
        r(cat,"CPU Hardware 型号", cpuModel.isEmpty()?"不可读":cpuModel, 0);
        pathAny(cat,"软件渲染器(SwiftShader/ANGLE)", 1, "/system/lib64/egl/libGLES_swiftshader.so","/system/lib/egl/libGLES_swiftshader.so","/system/lib64/egl/libEGL_swiftshader.so","/vendor/lib64/egl/libGLES_swiftshader.so");
        r(cat,"EGL/GPU 属性", "egl="+prop("ro.hardware.egl")+" gralloc="+prop("ro.hardware.gralloc"), 0);
        r(cat,"vendor 安全补丁", "vendor_patch="+prop("ro.vendor.build.security_patch"), 0);

        // ===== 24. 系统服务 / 杂项 =====
        cat = "系统服务";
        StringBuilder svcHit = new StringBuilder();
        StringBuilder svcWeak = new StringBuilder();
        if (serviceOut != null) {
            String svcLow = serviceOut.toLowerCase();
            for (String k : new String[]{"frida","lspd","xposed","magisk","ksu","apatch","shizuku","thanox","tricky","zygisk"})
                if (svcLow.contains(k)) svcHit.append(k).append(' ');
            for (String k : new String[]{"scene","clash","proxy"})
                if (svcLow.contains(k)) svcWeak.append(k).append(' ');
        }
        String svcLog;
        boolean svcAlert;
        if (svcHit.length() > 0) {
            svcLog = "命中:" + svcHit.toString().trim()
                    + (svcWeak.length() > 0 ? " [弱特征佐证:" + svcWeak.toString().trim() + "]" : "");
            svcAlert = true;
        } else if (svcWeak.length() > 0) {
            svcLog = "弱特征仅记录:" + svcWeak.toString().trim()
                    + " (scene proxy等可能为残留/同名/厂商原生行为,单特征不告警,需其他root/篡改证据聚合)";
            svcAlert = false;
        } else { svcLog = "未见"; svcAlert = false; }
        r(cat,"可疑系统服务", svcLog, svcAlert?2:0);
        r(cat,"服务列表总数", serviceOut==null?"不可读":countLines(serviceOut)+"个", 0);
        String initComm = read("/proc/1/comm");
        r(cat,"init 进程", initComm==null?"不可读":initComm.trim(), (initComm!=null&&!initComm.trim().equals("init"))?2:0);
        String hn = read("/proc/sys/kernel/hostname");
        r(cat,"hostname", "hostname="+(hn==null?"不可读":hn.trim()), 0);
        String misc = read("/proc/misc");
        r(cat,"/proc/misc 设备数", misc==null?"不可读":countLines(misc)+"个", 0);

        // ===== 25. 高级探针（真实实现：Java/shell 可达的探测全部落地） =====
        cat = "高级探针";
        String side = timingSideChannel();
        r(cat,"KSU/APatch 鉴权侧信道(时延比)", side, side.contains("疑似")?2:0);
        String pfs = propFullScan();
        r(cat,"属性区全量扫描(空洞/残留)", pfs, pfs.startsWith("命中")?2:0);
        String totalProps = shExec("getprop 2>/dev/null | wc -l");
        r(cat,"系统属性总数", totalProps==null?"不可读":totalProps.trim()+"个", 0);
        String kd = keystoreDepth();
        r(cat,"KeyStore 硬件安全级别(KeyInfo)", kd, kd.startsWith("TEE_FAIL")?2:0);
        r(cat,"KeyStore attestation 尝试", attestationProbe(), 0);
        r(cat,"StrongBox 安全元件", strongBoxProbe(), 0);
        String nl = netlinkCheck();
        r(cat,"netlink raw socket 统计", nl, nl.contains("异常")?2:0);
        String pc = ppidChain();
        r(cat,"zygote 进程链溯源", pc, pc.contains("异常")?2:0);
        String obb = obbMultiView();
        r(cat,"OBB 多视图一致性", obb, obb.contains("不一致")?2:0);
        String sm = smapsAnonCheck();
        r(cat,"smaps 匿名内存统计", sm, sm.contains("异常膨胀")?2:0);
        String fdmi = fdinfoMntCheck();
        r(cat,"fdinfo mnt_id 采样", fdmi, fdmi.startsWith("mnt_id 异常")?2:0);

        // ===== 25.5 KO 侧信道（内核模块：名称扫描 + 可读性 + 时延） =====
        cat = "KO侧信道";
        String sysMod = shExec("ls /sys/module 2>/dev/null");
        StringBuilder koHit = new StringBuilder();
        int modN = 0;
        if (sysMod != null) {
            for (String m : sysMod.split("\\s+")) {
                if (m.trim().isEmpty()) continue;
                modN++;
                String ml = m.toLowerCase(Locale.US);
                if (ml.contains("susfs")||ml.contains("kpatch")||ml.contains("apatch")||ml.contains("ksu")
                        ||ml.contains("tricky")||ml.contains("zygisk")||ml.contains("magisk")||ml.contains("selinux_hook"))
                    koHit.append(m).append(' ');
            }
        }
        r(cat,"/sys/module 内核模块扫描", sysMod==null?"不可读":(modN+" 个模块"+(koHit.length()>0?" · 可疑:"+koHit.toString().trim():"")), koHit.length()>0?2:0);
        String pm2 = read("/proc/modules");
        r(cat,"/proc/modules 可读性", pm2!=null?(countLines(pm2)+" 个模块(普通应用可读,策略异常开放)"):"不可读(正常)", 0);
        try {
            double r1 = ((double) statTime(new File("/data/adb"))) / Math.max(1.0, (double) statTime(new File("/system/etc/hosts")));
            // 阈值上调：延时比 >5 才视为可疑候选；≤5 仅 INFO 不告警。即使 >5 也不单点 SUSPECT，需其他独立证据聚合。
            boolean cand = r1 > 5.0;
            String sideLog = "stat时延比=" + String.format(Locale.US,"%.2f",r1)
                    + (cand ? " → 可疑候选(>5,仅记录,需其他独立证据聚合,不单点告警)" : " (≤5,INFO不告警)");
            r(cat,"KO 时延侧信道(/data/adb)", sideLog, cand?3:0);
        } catch (Exception e) { r(cat,"KO 时延侧信道(/data/adb)", "探测失败:"+e.getClass().getSimpleName(), 0); }

        // ===== 26. Zygisk / AP 超级密钥 / 侧信道补充 =====
        cat = "Zygisk/AP";
        pathAny(cat,"Zygisk/Shamiko 实现模块", 2, "/data/adb/modules/shamiko","/data/adb/modules/zygisk_shamiko",
                "/data/adb/modules/zygisk_next","/data/adb/modules/zygisk-next","/data/adb/zygisk");
        pathAny(cat,"AP 超级密钥(superkey)", 1, "/data/adb/ap/superkey","/data/adb/ap/bin/superkey",
                "/data/adb/kpatch/superkey","/data/adb/superkey");
        String zyProp = anyPropSet("persist.sys.zygisk.enabled","persist.sys.zygisk.next","ro.zygisk");
        r(cat,"Zygisk 属性痕迹", zyProp.isEmpty()?"未设置":zyProp, zyProp.isEmpty()?0:2);

        // ===== 27. 越权 / 漏洞探测（尝试读取受保护路径，能读到即策略异常） =====
        cat = "越权探测";
        String pkgXml = shExec("cat /data/system/packages.xml 2>/dev/null | head -c 120");
        r(cat,"受保护路径 packages.xml", pkgXml==null||pkgXml.isEmpty()?"拒绝访问(正常)":"可读! "+pkgXml.replace('\n',' ').trim(), (pkgXml!=null&&!pkgXml.isEmpty())?1:0);
        String adbMods = shExec("ls /data/adb/modules 2>/dev/null | head -5");
        r(cat,"受保护路径 /data/adb/modules", adbMods==null||adbMods.trim().isEmpty()?"拒绝访问/不存在":"可读! "+adbMods.replace('\n',' ').trim(), (adbMods!=null&&!adbMods.trim().isEmpty())?1:0);
        String adbKeys = shExec("ls -la /data/misc/adb/adb_keys 2>/dev/null | head -2");
        r(cat,"受保护路径 adb_keys", adbKeys==null||adbKeys.trim().isEmpty()?"拒绝访问/不存在":"可读! "+adbKeys.replace('\n',' ').trim(), (adbKeys!=null&&!adbKeys.trim().isEmpty())?2:0);
        String p1maps = shExec("head -c 120 /proc/1/maps 2>/dev/null");
        r(cat,"跨进程 /proc/1/maps 可读", p1maps==null||p1maps.trim().isEmpty()?"拒绝访问(正常)":"可读! 跨进程泄漏", (p1maps!=null&&!p1maps.trim().isEmpty())?2:0);
        String p1cmd = shExec("cat /proc/1/cmdline 2>/dev/null | tr '\\0' ' '");
        r(cat,"跨进程 /proc/1/cmdline", p1cmd==null||p1cmd.trim().isEmpty()?"拒绝访问":"可读: "+p1cmd.trim(), 0);

        // ===== 28. UID 深度 =====
        cat = "UID";
        String u4 = uidFourColumns();
        r(cat,"Uid 四列一致性(r/e/s/f)", u4, u4.contains("不一致")?2:0);

        // ===== 29. 风险应用 / Hook 深度 =====
        cat = "风险应用";
        String uah = userAppHookScan();
        r(cat,"用户应用 hook/作弊关键字", uah, uah.startsWith("未发现")?0:2);
        String sah = systemAppHookScan();
        r(cat,"系统应用 hook/作弊关键字", sah, sah.startsWith("未发现")?0:1);
        String apk = deepApkScan();
        r(cat,"APK 安装包分析(路径/包名)", apk, apk.startsWith("未见")?0:2);
        String shc = shContentScan();
        r(cat,"SH 脚本内容分析", shc, shc.startsWith("未见")?0:2);
        String img = imgScan();
        r(cat,"IMG 镜像文件扫描", img, img.startsWith("未见")?0:2);

        // ===== 30. 无障碍 / 系统应用增强 =====
        cat = "无障碍";
        String acc2 = null;
        try { acc2 = Settings.Secure.getString(ctx.getContentResolver(), "enabled_accessibility_services"); } catch (Exception ignored) {}
        int accN = 0;
        if (acc2 != null && !acc2.isEmpty()) accN = acc2.split(":").length;
        r(cat,"无障碍服务数量", accN==0?"未开启":accN+" 个", accN>3?2:0);
        String ime = readSetting("secure","enabled_input_methods");
        boolean imeBad = ime != null && (ime.toLowerCase().contains("hook")||ime.toLowerCase().contains("macro"));
        r(cat,"输入法钩子检测", ime==null||ime.isEmpty()?"未启用":ime, imeBad?2:0);
        cat = "系统应用";
        r(cat,"/system/app 应用数", countDirs("/system/app")+"个", 0);
        r(cat,"/product 内置应用数", "priv-app="+countDirs("/product/priv-app")+" app="+countDirs("/product/app"), 0);
        r(cat,"系统应用总数", systemAppCount()+"个", 0);

        // ===== 31. 挂载间隙补充 =====
        cat = "挂载";
        String pg = peerGroupGap(mountinfo);
        r(cat,"peer-group 挂载组间隙", pg, pg.contains("间隙")?2:0);

        // ===== 32. DRM / 低风险扫描（命中才标低风险） =====
        cat = "DRM";
        r(cat,"Widevine 安全等级", widevineLevel(), 0);
        cat = "低风险扫描";
        String sf = scanFiles();
        r(cat,"可读路径 sh/apk/img 异常文件", sf, sf.startsWith("未发现")?0:3);
        String koBin = shExec("find /data/local/tmp /sdcard /storage/emulated/0/Download -maxdepth 3 -type f \\( -name '*.bin' -o -name '*.ko' -o -name '*.elf' -o -name '*.dex' -o -name '*.dat' \\) 2>/dev/null | grep -iE 'root|su$|magisk|ksu|apatch|hook|spoof|key|payload|bypass|driver|内核' | head -6");
        r(cat,"ko/dex/bin 二进制扫描", koBin==null||koBin.trim().isEmpty()?"未见":koBin.replace('\n',' ').trim(), (koBin!=null&&!koBin.trim().isEmpty())?3:0);

        // ===== 33. Bootloader / OEM / 第三方 Recovery(TWRP) 深度 =====
        cat = "BL/OEM/TWRP";
        r(cat,"bootloader 版本", "ro.bootloader="+prop("ro.bootloader"), 0);
        r(cat,"A/B 槽位", "slot="+prop("ro.boot.slot_suffix"), 0);
        r(cat,"vbmeta 校验参数", "avb="+prop("ro.boot.vbmeta.avb_version")+" hash="+prop("ro.boot.vbmeta.hash_alg"), 0);
        String ab = cmdlineAndroidBoot();
        r(cat,"cmdline androidboot 全参数", ab, (ab.contains("orange")||ab.contains("red")||ab.contains("permissive")||ab.contains("unlocked"))?2:0);
        String oem1 = readSetting("global","oem_unlock_allowed");
        String oem2 = prop("sys.oem_unlock_allowed");
        r(cat,"OEM 解锁设置", "settings="+oem1+" sys="+oem2, "1".equals(oem1)||"1".equals(oem2)?2:0);
        pathAny(cat,"TWRP/第三方 Recovery 痕迹", 2, "/sdcard/TWRP","/sdcard/twrp","/data/media/0/TWRP","/cache/recovery",
                "/cache/twrp","/data/adb/twrp","/sdcard/OrangeFox","/sdcard/orangefox","/sdcard/pitchblack","/data/local/tmp/twrp");
        r(cat,"install-recovery 状态", exists("/system/bin/install-recovery.sh")?"存在(传统包)":"不存在(A/B 或第三方移除)", 0);
        pathAny(cat,"boot.img/刷机残留", 2, "/sdcard/boot.img","/storage/emulated/0/boot.img","/sdcard/recovery.img","/storage/emulated/0/recovery.img","/sdcard/vbmeta.img");

        // ===== 34. 设备信息完整日志 =====
        cat = "设备信息";
        r(cat,"品牌/制造商/型号", "brand="+prop("ro.product.brand")+" mfr="+prop("ro.product.manufacturer")+" model="+prop("ro.product.model"), 0);
        r(cat,"完整指纹", "fingerprint="+prop("ro.build.fingerprint"), 0);
        r(cat,"系统版本", "android="+prop("ro.build.version.release")+" sdk="+prop("ro.build.version.sdk")+" patch="+prop("ro.build.version.security_patch"), 0);
        r(cat,"baseband 基带", "baseband="+prop("gsm.version.baseband")+" expect="+prop("ro.build.expect.baseband"), 0);
        r(cat,"内存 RAM", memTotal(read("/proc/meminfo")), 0);
        String df = shExec("df -h /data 2>/dev/null | tail -1");
        r(cat,"存储空间(/data)", df==null||df.trim().isEmpty()?"不可读":df.trim(), 0);
        r(cat,"构建时间", "date="+prop("ro.build.date")+" utc="+prop("ro.build.date.utc"), 0);
        String up = read("/proc/uptime");
        r(cat,"开机时长", up==null?"不可读":(up.trim().split("\\s+")[0]+" 秒"), 0);

        // ===== 35. 内核深度检测（多源一致性 + 自定义内核特征） =====
        cat = "内核深度";
        String uname = shExec("uname -a 2>/dev/null");
        String procVer = read("/proc/version");
        String kernelVer = uname != null && !uname.isEmpty() ? uname.trim() : (procVer != null ? procVer.trim() : "不可读");
        r(cat,"完整内核版本(uname -a)", kernelVer, 0);
        // 自定义内核标记：emoji/中文/Telegram/@mention
        StringBuilder kernelSusp = new StringBuilder();
        if (kernelVer != null) {
            if (kernelVer.matches(".*[\\x{1F300}-\\x{1F9FF}\\x{2600}-\\x{26FF}].*")) kernelSusp.append("emoji标记 ");
            if (kernelVer.matches(".*[\\u4e00-\\u9fff].*")) kernelSusp.append("中文字符 ");
            if (kernelVer.toLowerCase().matches(".*(tg|telegram|@[a-z0-9_]{3,}).*")) kernelSusp.append("TG/提及标记 ");
            if (kernelVer.toLowerCase().matches(".*(xkernel|custom|wismela|akfn|skyline|blu_spark|elementalx).*")) kernelSusp.append("第三方内核名 ");
        }
        r(cat,"自定义内核特征", kernelSusp.length()>0?kernelSusp.toString().trim():"官方内核", kernelSusp.length()>0?2:0);
        // kptr_restrict
        String kptrVal = read("/proc/sys/kernel/kptr_restrict");
        r(cat,"kptr_restrict", kptrVal==null?"不可读":kptrVal.trim(), kptrVal!=null&&"0".equals(kptrVal.trim())?2:0);
        // 内核版本多源一致性
        String unameR = shExec("uname -r 2>/dev/null");
        String sysOsrel = read("/proc/sys/kernel/osrelease");
        String verMismatch = "";
        if (unameR != null && sysOsrel != null && !unameR.trim().isEmpty() && !sysOsrel.trim().isEmpty()
                && !unameR.trim().equals(sysOsrel.trim())) {
            verMismatch = "uname="+unameR.trim()+" vs sysctl="+sysOsrel.trim();
        }
        r(cat,"内核版本多源一致性", verMismatch.isEmpty()?"一致":verMismatch, verMismatch.isEmpty()?0:2);
        // CVE-2024-43093 补丁状态
        String secPatch = prop("ro.build.version.security_patch");
        boolean cvePatched = false;
        if (secPatch != null) {
            try {
                String[] parts = secPatch.split("-");
                if (parts.length >= 2) {
                    int year = Integer.parseInt(parts[0]);
                    int month = Integer.parseInt(parts[1]);
                    cvePatched = year > 2024 || (year == 2024 && month >= 8);
                }
            } catch (Exception ignored) {}
        }
        r(cat,"CVE-2024-43093补丁", cvePatched?"已修复(patch="+secPatch+")":"可能未修复(patch="+secPatch+")", cvePatched?0:3);

        // ===== 36. SELinux 多通道验证 =====
        cat = "SELinux增强";
        // 通道1：文件系统读取 enforce
        String enforceF = read("/sys/fs/selinux/enforce");
        // 通道2：getenforce 命令
        String getEnforce = shExec("getenforce 2>/dev/null");
        // 通道3：proc/self/attr/current
        String selfCtx = read("/proc/self/attr/current");
        // 综合判定
        int selinuxStatus = 0;
        String selinuxDetail = "enforce文件="+(enforceF==null?"不可读":enforceF.trim())
                +" getenforce="+(getEnforce==null?"不可读":getEnforce.trim());
        if (enforceF != null && "0".equals(enforceF.trim())) selinuxStatus = 1;
        else if (getEnforce != null && getEnforce.trim().toLowerCase().contains("permissive")) selinuxStatus = 1;
        else if (getEnforce != null && getEnforce.trim().toLowerCase().contains("disabled")) selinuxStatus = 1;
        r(cat,"SELinux多通道状态", selinuxDetail, selinuxStatus);
        // policy 文件存在性
        boolean policyExists = exists("/sys/fs/selinux/policy");
        r(cat,"SELinux policy节点", policyExists?"policy节点存在":"policy节点不可读", 0);
        // load_policy seqno（策略被修改的标志）
        String loadSeq = read("/sys/fs/selinux/load_policy");
        r(cat,"SELinux load_policy", loadSeq==null?"不可读":loadSeq.trim(), 0);
        // 本进程 context 检查
        boolean ctxSusp = selfCtx != null && (selfCtx.contains("magisk")||selfCtx.contains("ksu")||selfCtx.contains("apatch")||selfCtx.contains(":su:"));
        r(cat,"本进程SELinux context", selfCtx==null?"不可读":selfCtx.trim(), ctxSusp?1:0);

        // ===== 37. ADB 深度探测（反 HMA 隐藏） =====
        cat = "ADB深度";
        // 通道1：全局 settings
        String adbGlobal = readSetting("global","adb_enabled");
        // 通道2：adbd socket
        boolean adbdSocket = exists("/dev/socket/adbd");
        // 通道3：init.svc.adbd 属性
        String adbdSvc = prop("init.svc.adbd");
        // 通道4：ro.adb.secure
        String adbSecure = prop("ro.adb.secure");
        // 通道5：service list 中 adb 服务
        String svcList = shExec("service list 2>/dev/null | grep -i adb");
        // 通道6：USB 状态
        String usbState = shExec("cat /sys/class/android_usb/android0/state 2>/dev/null || cat /sys/class/udc/*/state 2>/dev/null");
        // 综合判定（降低误报）：init.svc.adbd=running 是每台设备常驻的系统服务，不代表 ADB 已开启，不作为判定依据。
        // 仅当「用户实际开启USB调试(adb_enabled=1)」与「ADB无需授权(ro.adb.secure=0)」两条独立证据同时命中才 SUSPECT；
        // 仅开启调试但保持授权保护(secure=1)时降为 LOW 记录，不输出 SUSPECT。
        boolean adbUserEnabled = "1".equals(adbGlobal);
        boolean adbInsecure = "0".equals(adbSecure);
        int adbLevel;
        if (adbUserEnabled && adbInsecure) adbLevel = 2;          // ADB 已开启且无授权保护（真正可疑）
        else if (adbUserEnabled && !adbInsecure) adbLevel = 3;    // 已开启调试但带授权保护（低风险记录）
        else adbLevel = 0;                                        // 未开启调试 / adbd 常驻服务为正常
        r(cat,"ADB多通道状态", "settings="+adbGlobal+" adbd_service="+adbdSvc+" socket="+(adbdSocket?"存在":"无")+" secure="+adbSecure+(adbLevel==0?"(adbd常驻服务,非ADB开启标志)":""), adbLevel);
        r(cat,"adbd socket节点", adbdSocket?"/dev/socket/adbd存在":"无adbd socket", 0);
        r(cat,"ADB USB状态", usbState==null||usbState.trim().isEmpty()?"不可读":usbState.trim(), 0);
        // adb_keys 授权文件深度扫描
        String adbKeysDeep = shExec("ls -la /data/misc/adb/ 2>/dev/null");
        r(cat,"adb授权目录", adbKeysDeep==null||adbKeysDeep.trim().isEmpty()?"不可读/空":adbKeysDeep.replace('\n',' ').trim(), (adbKeysDeep!=null&&adbKeysDeep.contains("adb_keys")&&!adbKeysDeep.contains("0 0"))?2:0);

        // ===== 38. 深度路径扫描（越权/异常文件） =====
        cat = "深度路径";
        // 敏感系统路径扫描
        String[] sensitivePaths = {
            "/data/misc/adb/adb_keys", "/data/property", "/dev/__properties__",
            "/data/adb", "/data/local/tmp", "/data/misc/user/0",
            "/system/bin/su", "/system/xbin/su", "/sbin/su",
            "/vendor/bin/su", "/debug_ramdisk", "/data/debug",
            "/data/nand", "/data/.magic", "/data/.su",
            "/proc/1/root/system/bin/su"
        };
        StringBuilder pathHit = new StringBuilder();
        for (String p : sensitivePaths) {
            if (exists(p)) {
                try {
                    java.io.File f = new java.io.File(p);
                    if (f.canRead() && !p.equals("/data/adb") && !p.equals("/data/local/tmp") && !p.equals("/dev/__properties__")) {
                        pathHit.append(p).append("(可读) ");
                    }
                } catch (Exception ignored) {}
            }
        }
        r(cat,"敏感路径可读性(仅记录)", pathHit.length()>0?pathHit.toString().trim():"全部不可读(正常)", 0);
        // /proc/1/root 越权探测
        String proc1Root = shExec("ls /proc/1/root/system/bin/ 2>/dev/null | head -5");
        r(cat,"/proc/1/root越权探测", proc1Root==null||proc1Root.trim().isEmpty()?"拒绝访问(正常)":"可读! "+proc1Root.replace('\n',' ').trim(), (proc1Root!=null&&!proc1Root.trim().isEmpty())?1:0);
        // /data 顶层异常文件扫描
        String dataTop = shExec("ls -la /data/ 2>/dev/null | grep -vE '^d|^total' | head -10");
        r(cat,"/data顶层异常文件", dataTop==null||dataTop.trim().isEmpty()?"不可读":dataTop.replace('\n',' ').trim(), 0);
        // /sdcard 隐藏文件扫描
        String sdcardHidden = shExec("ls -la /sdcard/ 2>/dev/null | grep '^\\.' | head -5");
        r(cat,"/sdcard隐藏文件", sdcardHidden==null||sdcardHidden.trim().isEmpty()?"无隐藏文件":sdcardHidden.replace('\n',' ').trim(), 0);
        // 公开路径异常二进制
        String publicBin = shExec("find /sdcard/Download /sdcard/Documents -maxdepth 2 -type f \\( -name '*.sh' -o -name '*.su' -o -name '*.magisk' -o -name '*.patch' \\) 2>/dev/null | head -5");
        r(cat,"公开路径异常脚本", publicBin==null||publicBin.trim().isEmpty()?"未见":publicBin.replace('\n',' ').trim(), publicBin!=null&&!publicBin.trim().isEmpty()?2:0);

        // ===== 39. 新增检测点 =====
        cat = "补充检测";
        // build.prop 指纹一致性
        String bpFp = prop("ro.build.fingerprint");
        String bpBuild = read("/system/build.prop");
        String bpMatch = "不可读";
        if (bpBuild != null && bpFp != null) {
            bpMatch = bpBuild.contains(bpFp) ? "build.prop指纹一致" : "不一致! fingerprint="+bpFp;
        }
        r(cat,"build.prop指纹一致性", bpMatch, bpMatch.startsWith("不一致")?2:0);
        // 设备管理员应用
        int deviceAdmins = 0;
        try {
            var admins = ctx.getSystemService(android.app.admin.DevicePolicyManager.class).getActiveAdmins();
            if (admins != null) deviceAdmins = admins.size();
        } catch (Exception ignored) {}
        r(cat,"设备管理员应用数量", deviceAdmins==0?"无":deviceAdmins+"个", deviceAdmins>3?2:0);
        // 已安装应用总数
        int totalPkgs = 0, thirdPkgs = 0;
        try {
            var apps = ctx.getPackageManager().getInstalledApplications(0);
            totalPkgs = apps.size();
            for (var ai : apps) if ((ai.flags & android.content.pm.ApplicationInfo.FLAG_SYSTEM) == 0) thirdPkgs++;
        } catch (Exception ignored) {}
        r(cat,"已安装应用统计", "总="+totalPkgs+" 第三方="+thirdPkgs, 0);
        // 内核编译器信息
        String procVersion = read("/proc/version");
        String compiler = "不可读";
        if (procVersion != null) {
            if (procVersion.contains("clang")) compiler = "clang编译";
            else if (procVersion.contains("gcc")) compiler = "gcc编译";
            else compiler = procVersion.length()>60?procVersion.substring(0,60):procVersion;
        }
        r(cat,"内核编译器", compiler, 0);
        // 开发者选项中的ADB授权计数
        String adbKeysCount = shExec("ls /data/misc/adb/ 2>/dev/null | wc -l");
        r(cat,"ADB授权密钥数量", adbKeysCount==null?"不可读":adbKeysCount.trim()+"个", 0);

        // ===== Momo风格检测点 =====
        // su 可执行权限检测：不仅存在，还要检查是否有可执行位
        String suExec = shExec("which su 2>/dev/null || command -v su 2>/dev/null");
        r(cat,"su可执行程序检测", suExec==null||suExec.trim().isEmpty()?"未找到su可执行程序":"找到su: "+suExec.trim(), (suExec!=null&&!suExec.trim().isEmpty())?1:0);
        // Magisk模块修改文件深度检测
        String magiskMods = shExec("ls /data/adb/modules/ 2>/dev/null | grep -v '^$' | head -10");
        boolean magiskModHit = magiskMods != null && !magiskMods.trim().isEmpty()
                && !magiskMods.contains("空") && !magiskMods.contains("不存在");
        r(cat,"Magisk模块修改文件", magiskModHit?"已安装模块: "+magiskMods.replace('\n',' ').trim():"无Magisk模块", magiskModHit?1:0);
        // Magisk 核心二进制检测
        boolean magiskBin = exists("/data/adb/magisk/magisk64") || exists("/data/adb/magisk/magisk32")
                || exists("/sbin/magisk") || exists("/system/bin/magisk");
        r(cat,"Magisk核心二进制", magiskBin?"检测到Magisk二进制":"未检测到Magisk", magiskBin?1:0);
        // 包管理服务异常检测
        String pmService = shExec("service list 2>/dev/null | grep -i package");
        boolean pmOk = pmService != null && pmService.contains("package");
        r(cat,"包管理服务状态", pmOk?"正常(package service存在)":"异常! "+(pmService==null?"无响应":pmService.trim()), pmOk?0:1);
        // Bootloader 锁定状态综合
        String flashLocked = prop("ro.boot.flash.locked");
        String vbState = prop("ro.boot.vbmeta.device_state");
        boolean blUnlocked = "0".equals(flashLocked) || "unlocked".equals(vbState);
        r(cat,"Bootloader锁定状态综合", "flash.locked="+flashLocked+" vbmeta="+vbState, blUnlocked?1:0);
        // 调试模式综合检测
        boolean debugOn = "1".equals(prop("ro.debuggable"))
                || "userdebug".equals(prop("ro.build.type"))
                || "eng".equals(prop("ro.build.type"));
        r(cat,"调试模式综合状态", "ro.debuggable="+prop("ro.debuggable")+" type="+prop("ro.build.type"), debugOn?1:0);

        // ===== Duck-Detector风格高级检测 =====
        cat = "高级交叉验证";
        // Bootloader/Verified Boot 一致性交叉验证
        String verifiedBootState = prop("ro.boot.verifiedbootstate");
        String flashLock = prop("ro.boot.flash.locked");
        String vbmetaDigest = prop("ro.boot.vbmeta.digest");
        boolean blMismatch = false;
        String blDetail = "vb_state="+verifiedBootState+" flash_locked="+flashLock+" digest="+(vbmetaDigest==null?"空":vbmetaDigest.substring(0,Math.min(16,vbmetaDigest.length()))+"...");
        // green状态但flash未锁 = 矛盾
        if ("green".equals(verifiedBootState) && !"1".equals(flashLock)) blMismatch = true;
        // unlocked状态但vbmeta.digest存在 = 矛盾
        if ("orange".equals(verifiedBootState) && vbmetaDigest != null && !vbmetaDigest.replace("0","").isEmpty()) blMismatch = true;
        r(cat,"Bootloader完整性交叉验证", blDetail, blMismatch?1:0);
        // TEE Attestation 一致性：verifiedBootHash存在但vbmeta.digest为空 = 矛盾
        String vbHash = prop("ro.boot.vbmeta.device_state");
        boolean attestMismatch = vbmetaDigest == null || vbmetaDigest.replace("0","").isEmpty();
        r(cat,"TEE Attestation一致性", "vbmeta_digest="+(attestMismatch?"空(异常)":"存在"), attestMismatch?1:0);
        // Package Inventory 数量异常检测
        int pkgCount = 0;
        try { pkgCount = ctx.getPackageManager().getInstalledPackages(0).size(); } catch (Exception ignored) {}
        boolean pkgTooSmall = pkgCount > 0 && pkgCount < 20; // 正常手机至少几十上百个包
        r(cat,"包数量异常检测", "已安装包数="+pkgCount+(pkgTooSmall?" (过少!疑似HMA过滤)":""), pkgTooSmall?2:0);
        // 旧#318 HMA多通道包数对比（service list 总行数 vs PM 包数减法）已整体移除：
        // service list 输出含大量 HAL/AIDL/Vendor 底层服务，并非 APK 应用包名，探针失效，由新 HMA 三源交叉比对替代
        // Native Root 弱信号汇总
        int weakSignals = 0;
        StringBuilder weakDetail = new StringBuilder();
        // 挂载漂移
        String mountList = read("/proc/self/mounts");
        if (mountList != null && mountList.contains("magisk")) { weakSignals++; weakDetail.append("mount含magisk "); }
        // cgroup 异常
        String cgroupContent = read("/proc/self/cgroup");
        if (cgroupContent != null && cgroupContent.contains("magisk")) { weakSignals++; weakDetail.append("cgroup含magisk "); }
        // 属性残留
        String allProps = shExec("getprop 2>/dev/null | grep -i magisk");
        if (allProps != null && !allProps.trim().isEmpty()) { weakSignals++; weakDetail.append("属性残留 "); }
        // /proc/self/maps 残留
        String mapsContent = read("/proc/self/maps");
        if (mapsContent != null && mapsContent.contains("magisk")) { weakSignals++; weakDetail.append("maps含magisk "); }
        r(cat,"Native Root弱信号汇总", weakSignals>0?weakDetail.toString().trim()+" ("+weakSignals+"个弱信号)":"无弱信号", weakSignals>=2?2:0);

        // /data/app/ 包名交叉验证：文件系统存在 vs PackageManager可见
        // HMA隐藏应用后PackageManager查不到，但APK文件仍在/data/app/下
        String dataAppScan = dataAppPackageCrossCheck();
        r(cat,"/data/app包名交叉验证(HMA检测)", dataAppScan,
                dataAppScan.startsWith("风险")?1:(dataAppScan.startsWith("HMA")?2:0));

        // ===== v1.2.17 新增检测点（全部遵守降误报策略：单点仅日志，多点聚合才告警） =====
        cat = "v1.2.17 新增";
        String compHidden = componentHiddenProbe();
        r(cat,"应用组件隐藏探测", compHidden, compHidden.startsWith("风险应用组件异常")?2:0);
        String sigMs = signatureMultiSource();
        r(cat,"包签名多源一致性校验", sigMs, sigMs.startsWith("签名不一致")?2:0);
        String suAgg = suFeatureAggregate();
        r(cat,"su特征聚合汇总检测", suAgg, suAgg.startsWith("su特征聚合:多特征命中")?2:0);
        String persistCol = persistPropCollection();
        r(cat,"persist.*属性残留收集", persistCol, 0);
        String zsTrace = zygiskShamikoTrace();
        r(cat,"Zygisk/Shamiko间接痕迹聚合", zsTrace, zsTrace.startsWith("Zygisk/Shamiko痕迹聚合:多特征命中")?2:0);

        // ===== v1.2.19 新增检测点（多维度补强；弱特征仅日志，≥2 独立证据才聚合告警；读失败→能力受限） =====
        cat = "v1.2.19 新增";
        // 1) 启动链 & 完整性（基线日志采集，异常需多证据）
        String vbState19 = prop("ro.boot.verifiedbootstate");
        String vbDev19 = prop("ro.boot.vbmeta.device_state");
        String flashLocked19 = prop("ro.boot.flash.locked");
        String buildTags19 = prop("ro.build.tags");
        r(cat,"启动链 verified-boot/vbmeta 基线",
                "verifiedbootstate=" + (vbState19==null?"不可读":vbState19)
                + " vbmeta_dev=" + (vbDev19==null?"不可读":vbDev19)
                + " flash_locked=" + (flashLocked19==null?"不可读":flashLocked19)
                + " build_tags=" + (buildTags19==null?"不可读":buildTags19), 0);
        String cmdline19 = read("/proc/cmdline");
        r(cat,"kernel cmdline bootargs 基线", cmdline19==null?"不可读":cmdline19.trim(), 0);
        String secPatch19 = prop("ro.build.version.security_patch");
        String vendorPatch19 = prop("ro.vendor.build.security_patch");
        r(cat,"security-patch vendor/system 一致性", "system=" + secPatch19 + " vendor=" + vendorPatch19, 0);

        // 2)+4)+5) 共享：/proc/self/maps 与 status/environ 一次读取
        String maps19 = read("/proc/self/maps");
        String status19 = read("/proc/self/status");
        int tracerPid = 0;
        if (status19 != null) for (String l : status19.split("\n"))
            if (l.startsWith("TracerPid:")) { try { tracerPid = Integer.parseInt(l.trim().split("\\s+")[1]); } catch (Exception ignored) {} }
        // Native 注入/Hook 痕迹聚合（maps 关键字 + TracerPid + LD_PRELOAD）
        int natHits = 0; StringBuilder natDetail = new StringBuilder();
        if (maps19 != null) {
            String ml = maps19.toLowerCase();
            for (String k : new String[]{"frida","gum-js-loop","linjector","lspd","riru","sandhook","epic","edxposed"})
                if (ml.contains(k)) { natHits++; natDetail.append(k).append(' '); }
        }
        if (tracerPid > 0) { natHits++; natDetail.append("TracerPid=").append(tracerPid).append(' '); }
        String env19 = read("/proc/self/environ");
        if (env19 != null && env19.toLowerCase().contains("ld_preload")) { natHits++; natDetail.append("LD_PRELOAD "); }
        r(cat,"Native注入/Hook痕迹聚合",
                natHits==0 ? "未检出独立注入痕迹" : natDetail.toString().trim() + " (" + natHits + "个独立证据)",
                natHits>=2 ? 2 : 0);

        // 3) SELinux & 内核痕迹（弱特征仅记录）
        String enforce19 = shExec("getenforce 2>/dev/null");
        r(cat,"SELinux 运行模式", enforce19==null?"能力受限(getenforce 不可执行)":enforce19.trim()+" (弱特征,Permissive需配合其他证据)", 0);
        String modules = read("/proc/modules");
        r(cat,"内核模块残留指纹", modules==null ? "能力受限(普通应用不可读 /proc/modules)" : "可读("+countLines(modules)+"个,策略偏开放,仅记录)", 0);

        // ART/Xposed 运行时痕迹（弱特征，不单点告警）
        int artHits = 0; StringBuilder artDetail = new StringBuilder();
        if (maps19 != null) {
            String ml = maps19.toLowerCase();
            if (ml.contains("lspd")||ml.contains("edxposed")||ml.contains("riru")) { artHits++; artDetail.append("maps-Xposed "); }
        }
        r(cat,"ART/Xposed 运行时痕迹",
                artHits==0 ? "未检出独立Xposed运行时痕迹" : artDetail.toString().trim()+" ("+artHits+"个,需聚合)",
                artHits>=2 ? 2 : 0);

        // 调试/Frida 痕迹聚合（TracerPid + 27042端口）
        int dbgHits = 0; StringBuilder dbgDetail = new StringBuilder();
        if (tracerPid > 0) { dbgHits++; dbgDetail.append("ptrace被调试 "); }
        String tcp = read("/proc/net/tcp");
        if (tcp != null && tcp.contains("69A2")) { dbgHits++; dbgDetail.append("Frida默认端口27042 "); }
        r(cat,"调试/Frida痕迹聚合",
                dbgHits==0 ? "未检出调试/Frida痕迹" : dbgDetail.toString().trim()+" ("+dbgHits+"个独立证据)",
                dbgHits>=2 ? 2 : 0);

        // 6) 系统目录可写性试探（弱特征）
        boolean sysWritable = new File("/system").canWrite();
        r(cat,"系统目录可写性试探", "/system canWrite=" + sysWritable + (sysWritable ? " (弱特征,需聚合)" : " (正常只读)"), 0);

        // 7) 传统 root 二进制路径（仅日志采集，不单点告警）
        String suPaths = shExec("for p in /system/bin/su /system/xbin/su /debug_ramdisk/su /sbin/su; do [ -e $p ] && echo -n \"$p \"; done 2>/dev/null");
        r(cat,"现代root二进制路径扫描", (suPaths==null||suPaths.trim().isEmpty()) ? "未见" : suPaths.trim()+" (仅日志采集,不单点告警)", 0);

        // ===== v1.2.20 新增（调试/启动链弱特征基线，多证据聚合） =====
        cat = "v1.2.20 新增";
        String kver20 = read("/proc/version");
        r(cat,"内核版本基线", kver20==null?"不可读":kver20.trim(), 0);
        String dbgProp20 = prop("ro.debuggable");
        String secureProp20 = prop("ro.secure");
        r(cat,"调试/安全属性基线", "ro.debuggable="+dbgProp20+" ro.secure="+secureProp20+" (弱特征,仅记录)", 0);
        String st20b = read("/proc/self/status");
        String seccomp20 = "不可读";
        if (st20b != null) for (String l : st20b.split("\n")) if (l.startsWith("Seccomp:")) { seccomp20 = l.trim(); break; }
        r(cat,"Seccomp 过滤状态", seccomp20, 0);
        // 调试状态聚合：ro.debuggable=1 与 TracerPid>0 两条独立证据才告警
        int dbgAgg20 = 0; StringBuilder dbgAggD20 = new StringBuilder();
        if ("1".equals(dbgProp20)) { dbgAgg20++; dbgAggD20.append("ro.debuggable=1 "); }
        int tp20b = 0;
        if (st20b != null) for (String l : st20b.split("\n")) if (l.startsWith("TracerPid:")) { try { tp20b = Integer.parseInt(l.trim().split("\\s+")[1]); } catch (Exception ignored) {} }
        if (tp20b > 0) { dbgAgg20++; dbgAggD20.append("TracerPid=").append(tp20b).append(' '); }
        r(cat,"调试状态聚合", dbgAgg20==0 ? "未检出独立调试迹象" : dbgAggD20.toString().trim()+" ("+dbgAgg20+"个独立证据)", dbgAgg20>=2?2:0);
        String mi20 = read("/proc/mounts");
        boolean sysRo20 = mi20 != null && mi20.contains(" /system ") && mi20.contains("ro,");
        r(cat,"/system 挂载只读校验", "/system 只读="+(mi20==null?"不可读":sysRo20)+" (弱特征,需聚合)", 0);

        // ===== v1.2.21 新增：风险应用探测修复 + 春秋附录 + 外挂驱动 + 扫盘/路径/UID + 认证·Keystore·内核完整性 =====
        cat = "v1.2.21 新增";
        String tkRisk = toolkitRiskAggregate();
        int tkLv = detLevel(tkRisk);
        rW(cat,"风险工具多证据聚合探测", tkRisk, tkLv, aggReason("风险工具多证据聚合探测", tkRisk));
        String cqRisk = chunqiuRiskPaths();
        int cqLv = detLevel(cqRisk);
        rW(cat,"春秋附录B 风险路径/文件扫描", cqRisk, cqLv, aggReason("春秋附录B 风险路径/文件扫描", cqRisk));
        String cqProps = chunqiuPropsCoverage();
        r(cat,"春秋附录C 系统属性基线", cqProps, 0);
        String cheat = cheatDriverProbe();
        int chLv = detLevel(cheat);
        rW(cat,"外挂驱动检测", cheat, chLv, aggReason("外挂驱动检测", cheat));
        String disk = diskScanProbe();
        int dkLv = detLevel(disk);
        rW(cat,"扫盘检测(高危文件跨目录)", disk, dkLv, aggReason("扫盘检测", disk));
        String path = pathScanProbe();
        int ptLv = detLevel(path);
        rW(cat,"路径检测(挂载/su/可写系统目录)", path, ptLv, aggReason("路径检测", path));
        String uid = uidScanProbe();
        int udLv = detLevel(uid);
        rW(cat,"UID检测(UID/能力位/一致性)", uid, udLv, aggReason("UID检测", uid));
        String att = attestationDepthProbe();
        int atLv = detLevel(att);
        rW(cat,"硬件认证完整性", att, atLv, aggReason("硬件认证完整性", att));
        String ks = keystoreIntegrityProbe();
        int ksLv = detLevel(ks);
        rW(cat,"Keystore完整性(时序/隔离/负例)", ks, ksLv, aggReason("Keystore完整性", ks));
        String kern = kernelIdentityProbe();
        int knLv = detLevel(kern);
        rW(cat,"内核身份与运行时完整性", kern, knLv, aggReason("内核身份与运行时完整性", kern));

        Report rep = new Report();
        rep.results = results;
        rep.total = cn; rep.clean = clean; rep.found = found; rep.warn = warn; rep.low = low;
        rep.buildTime = Build.TIME + "";
        return rep;
    }

    /** 联网检测（第二页）：证书吊销 ×2 + 网络工具 + 外网连通性 + DNS + TLS 证书链 */
    public Report runOnline(ProgressListener progressListener) {
        this.listener = progressListener;
        String cat = "吊销联网";
        r(cat,"证书吊销列表(attestation CRL)", fetchCRL("https://android.googleapis.com/attestation/status"), 0);
        r(cat,"中间证书吊销(intermediate CRL)", fetchCRL("https://android.googleapis.com/attestation/intermediate_status"), 0);
        String tools = shExec("for t in curl wget openssl getprop settings; do command -v $t >/dev/null 2>&1 && echo -n \"$t \"; done 2>/dev/null");
        r(cat,"网络/TLS 工具可用性", tools==null||tools.trim().isEmpty()?"均不可用":tools.trim(), 0);
        cat = "联网检测";
        r(cat,"外网连通性(gstatic 204)", httpStatus("https://connectivitycheck.gstatic.com/generate_204"), 0);
        r(cat,"DNS 解析测试", dnsResolve(), 0);
        r(cat,"TLS 证书链校验", tlsChainCheck(), 0);
        Report rep = new Report();
        rep.results = results;
        rep.total = cn; rep.clean = clean; rep.found = found; rep.warn = warn; rep.low = low;
        rep.buildTime = Build.TIME + "";
        return rep;
    }

    // ============ 专项检测方法 ============

    private String statusLine(String status, String key) {
        if (status == null) return null;
        for (String l : status.split("\n")) if (l.startsWith(key + ":")) return l.substring(key.length()+1);
        return null;
    }

    private String nsCompare(String ns) {
        // 必须 readlink 取符号链接目标（如 mnt:[4026531840]）；FileReader 读 ns 链接会返回空串导致误判
        String self = shExec("readlink /proc/self/ns/" + ns + " 2>/dev/null");
        String init = shExec("readlink /proc/1/ns/" + ns + " 2>/dev/null");
        if (self == null || init == null || self.trim().isEmpty() || init.trim().isEmpty()) return "不可读(视为正常)";
        return self.trim().equals(init.trim()) ? "与 init 一致" : "与 init 不同(容器/多开)";
    }

    private String mountGapCheck(String mountinfo) {
        if (mountinfo == null) return "不可读";
        int prev = -1, gap = 0;
        for (String l : mountinfo.split("\n")) {
            String[] f = l.trim().split("\\s+");
            if (f.length < 4) continue;
            try {
                int id = Integer.parseInt(f[0]);
                if (prev >= 0 && id - prev > 1) gap++;
                prev = id;
            } catch (NumberFormatException ignored) {}
        }
        // 阈值 ≥3：厂商 ROM 偶发 1-2 处 ID 跳跃属正常，不再误报
        return gap > 2 ? ("存在挂载 ID 间隙 " + gap + " 处(疑似隐藏挂载)") : "挂载 ID 连续";
    }

    private String mountinfoSuspicious(String mountinfo) {
        if (mountinfo == null) return "不可读";
        StringBuilder strong = new StringBuilder();
        StringBuilder weak = new StringBuilder();
        String ml = mountinfo.toLowerCase();
        // 强证据：root/hook 相关挂载路径
        for (String k : new String[]{"magisk","ksu","apatch","tricky","zygisk","frida","/data/adb"})
            if (ml.contains(k)) strong.append(k).append(' ');
        // 弱证据：hide/spoof 标记（厂商系统原生挂载常见，单特征不告警）
        for (String k : new String[]{"hide","spoof"})
            if (ml.contains(k)) weak.append(k).append(' ');
        if (strong.length() > 0) {
            return "命中:" + strong.toString().trim()
                    + (weak.length() > 0 ? " [弱特征佐证:" + weak.toString().trim() + "]" : "");
        }
        if (weak.length() > 0) {
            return "弱特征仅记录:" + weak.toString().trim()
                    + " (hide标记可能为厂商系统原生挂载行为,单特征不告警,需叠加overlay/bind/root挂载路径等第二证据)";
        }
        return "未见异常";
    }

    private int anonRwCount(String maps) {
        if (maps == null) return 0;
        int n = 0;
        for (String l : maps.split("\n")) {
            if (l.startsWith("rw-p") || l.startsWith("rwxp")) {
                String[] f = l.trim().split("\\s+");
                if (f.length <= 5) n++;
                else if (f[5].equals("/") || f[5].isEmpty()) n++;
            }
        }
        return n;
    }

    private int fdCount() {
        String o = shExec("ls /proc/self/fd 2>/dev/null | wc -l");
        if (o == null) return -1;
        try { return Integer.parseInt(o.trim()); } catch (NumberFormatException e) { return -1; }
    }

    private String gidConsistency() {
        try {
            String st = read("/proc/self/status");
            if (st == null) return "不可读";
            for (String line : st.split("\n")) {
                if (line.startsWith("Gid:")) {
                    String[] p = line.trim().split("\\s+");
                    if (p.length >= 2) {
                        int real = Integer.parseInt(p[1]);
                        int myUid = android.os.Process.myUid();
                        return real == myUid ? "一致 (gid=" + real + ")" : "不一致! /proc=" + real + " myUid=" + myUid;
                    }
                }
            }
            return "未找到 Gid 字段";
        } catch (Exception e) { return "校验失败:" + e.getClass().getSimpleName(); }
    }

    /** 扫描已安装应用中开启了调试标记(FLAG_DEBUGGABLE)的应用，排除自身 */
    private String[] debuggableApps() {
        try {
            String selfPkg = ctx.getPackageName();
            List<ApplicationInfo> apps = ctx.getPackageManager().getInstalledApplications(0);
            StringBuilder names = new StringBuilder();
            int n = 0;
            for (ApplicationInfo ai : apps) {
                if (ai.packageName.equals(selfPkg)) continue; // 排除自身
                if ((ai.flags & ApplicationInfo.FLAG_DEBUGGABLE) != 0) {
                    if (n < 3) names.append(ai.packageName).append(' ');
                    n++;
                }
            }
            return new String[]{ String.valueOf(n), names.toString().trim() };
        } catch (Exception e) { return new String[]{"?", ""}; }
    }

    /** 扫描使用 root(uid=0) 共享 UID 的异常应用；uid=1000(system)/2000(shell) 为正常系统 UID，不判异常 */
    private String[] abnormalUidApps() {
        try {
            List<ApplicationInfo> apps = ctx.getPackageManager().getInstalledApplications(0);
            StringBuilder names = new StringBuilder();
            int n = 0;
            for (ApplicationInfo ai : apps) {
                int uid = ai.uid % 100000;
                if (uid == 0) { // 仅 root(uid=0) 算异常；system(1000)/shell(2000) 是正常系统 UID
                    if (n < 3) names.append(ai.packageName).append("(uid=").append(uid).append(") ");
                    n++;
                }
            }
            return new String[]{ String.valueOf(n), names.toString().trim() };
        } catch (Exception e) { return new String[]{"?", ""}; }
    }

    /** 统计 ps 输出中指定 USER 的进程，返回数量与示例名称 */
    private String procsByUser(String user) {
        StringBuilder hit = new StringBuilder();
        int n = 0;
        String ps = shExec("ps -A 2>/dev/null");
        if (ps != null) for (String line : ps.split("\n")) {
            String[] f = line.trim().split("\\s+");
            if (f.length >= 2 && user.equals(f[0])) {
                if (n < 6) hit.append(f[f.length - 1]).append(' ');
                n++;
            }
        }
        return n > 0 ? (n + " 个 · " + hit.toString().trim()) : "未发现";
    }

    /** 当前进程 UID 及类型描述 */
    private String uidDesc() {
        int uid = android.os.Process.myUid();
        String kind;
        if (uid == 0) kind = "root 特权";
        else if (uid == 1000) kind = "system";
        else if (uid == 2000) kind = "shell";
        else if ((uid % 100000) < 10000) kind = "共享系统UID";
        else kind = "普通应用";
        return "uid=" + uid + " (" + kind + ")";
    }

    /** 校验 /proc/self/status 中真实 UID 与 Process.myUid() 是否一致（反伪装/反注入） */
    private String uidConsistency() {
        try {
            String st = read("/proc/self/status");
            if (st == null) return "不可读";
            for (String line : st.split("\n")) {
                if (line.startsWith("Uid:")) {
                    String[] p = line.trim().split("\\s+");
                    if (p.length >= 2) {
                        int real = Integer.parseInt(p[1]);
                        return real == android.os.Process.myUid()
                                ? "一致 (uid=" + real + ")"
                                : "不一致! /proc=" + real + " myUid=" + android.os.Process.myUid();
                    }
                }
            }
            return "未找到 Uid 字段";
        } catch (Exception e) { return "校验失败:" + e.getClass().getSimpleName(); }
    }

    private boolean playServicesPresent() {
        try { return ctx.getPackageManager().getPackageInfo("com.google.android.gms", 0) != null; }
        catch (Exception e) { return false; }
    }

    private boolean hardwareKeyStore() {
        try {
            KeyGenerator kg = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore");
            KeyGenParameterSpec spec = new KeyGenParameterSpec.Builder("zuomeng_probe", KeyProperties.PURPOSE_ENCRYPT)
                    .setBlockModes(KeyProperties.BLOCK_MODE_GCM).setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                    .build();
            kg.init(spec); kg.generateKey();
            KeyStore ks = KeyStore.getInstance("AndroidKeyStore");
            ks.load(null);
            return ks.containsAlias("zuomeng_probe");
        } catch (Exception e) { return false; }
    }

    private String fetchCRL(String url) {
        HttpURLConnection c = null;
        try {
            c = (HttpURLConnection) new URL(url).openConnection();
            c.setConnectTimeout(4000); c.setReadTimeout(6000);
            c.setRequestProperty("Accept-Encoding", "identity");
            int code = c.getResponseCode();
            if (code != 200) return "HTTP "+code;
            InputStream in = c.getInputStream();
            BufferedReader br = new BufferedReader(new InputStreamReader(in, StandardCharsets.UTF_8));
            StringBuilder sb = new StringBuilder(); String line; int n=0;
            while ((line = br.readLine()) != null && n < 8000) { sb.append(line); n++; }
            br.close();
            String body = sb.toString();
            return "已拉取("+body.length()+"B) 吊销条目≈"+countOccurrences(body,"keyId")+countOccurrences(body,"serialNumber");
        } catch (Exception e) { return "联网失败:"+e.getMessage(); }
        finally { if (c != null) c.disconnect(); }
    }

    /** 外网连通性：HTTP 204 探针 */
    private String httpStatus(String url) {
        HttpURLConnection c = null;
        try {
            c = (HttpURLConnection) new URL(url).openConnection();
            c.setConnectTimeout(6000); c.setReadTimeout(6000);
            c.setRequestMethod("GET"); c.setInstanceFollowRedirects(true);
            int code = c.getResponseCode();
            InputStream in = c.getInputStream(); in.close();
            return "HTTP " + code + (code == 204 ? " (连通正常)" : "");
        } catch (Exception e) { return "连接失败:" + e.getClass().getSimpleName(); }
        finally { if (c != null) c.disconnect(); }
    }

    /** DNS 解析测试 */
    private String dnsResolve() {
        try {
            java.net.InetAddress[] a = java.net.InetAddress.getAllByName("dns.google");
            StringBuilder sb = new StringBuilder();
            for (java.net.InetAddress i : a) sb.append(i.getHostAddress()).append(' ');
            return "dns.google → " + sb.toString().trim();
        } catch (Exception e) { return "解析失败:" + e.getClass().getSimpleName(); }
    }

    /** TLS 证书链校验：HTTPS 握手成功即证书链有效，自签/被替换会握手失败 */
    private String tlsChainCheck() {
        javax.net.ssl.HttpsURLConnection c = null;
        try {
            c = (javax.net.ssl.HttpsURLConnection) new URL("https://www.google.com/generate_204").openConnection();
            c.setConnectTimeout(6000); c.setReadTimeout(6000);
            c.setRequestMethod("HEAD");
            int code = c.getResponseCode();
            return "HTTP " + code + " · TLS 握手成功(证书链校验通过)";
        } catch (Exception e) { return "TLS 校验失败:" + e.getClass().getSimpleName(); }
        finally { if (c != null) c.disconnect(); }
    }

    private String widevineLevel() {
        try {
            MediaDrm md = new MediaDrm(UUID.fromString("16A0CDBA-BF6A-4F92-90E6-8A9BCB6C6D25"));
            byte[] level = md.getPropertyByteArray("securityLevel");
            md.close();
            return "securityLevel="+new String(level);
        } catch (Exception e) { return "不可用(需 DRM 权限/无 Widevine)"; }
    }

    private String scanFiles() {
        StringBuilder sb = new StringBuilder();
        String[] dirs = {"/sdcard","/storage/emulated/0/Download","/data/local/tmp"};
        String[] pat = {".sh",".apk",".img",".ko",".dex",".bin"};
        for (String d : dirs) {
            File dir = new File(d);
            if (!dir.isDirectory()) continue;
            File[] fs = dir.listFiles();
            if (fs == null) continue;
            for (File f : fs) {
                String n = f.getName().toLowerCase();
                for (String p : pat) if (n.endsWith(p)) {
                    if (n.contains("root")||n.contains("su")||n.contains("hook")||n.contains("payload")||n.contains("magisk")||n.contains("ksu")||n.contains("cheat")||n.contains("bypass"))
                        sb.append(f.getPath()).append('|');
                    break;
                }
            }
        }
        return sb.length()>0?sb.toString():"未发现异常文件";
    }

    private String installerPath() {
        try {
            ApplicationInfo ai = ctx.getPackageManager().getApplicationInfo(
                    "com.google.android.packageinstaller", 0);
            return ai.sourceDir;
        } catch (Exception e) {
            try {
                ApplicationInfo ai2 = ctx.getPackageManager().getApplicationInfo(
                        "com.android.packageinstaller", 0);
                return ai2.sourceDir;
            } catch (Exception e2) { return "未安装"; }
        }
    }

    private String systemAppSuspect() {
        StringBuilder h = new StringBuilder();
        String[] dirs = {"/system/app","/system/priv-app"};
        String[] keys = {"magisk","supersu","superuser","xposed","lspd","lucky","hook","cheat","ksu","apatch","susfs","monkey","fakelocation","root"};
        for (String d : dirs) {
            File dir = new File(d);
            if (!dir.isDirectory()) continue;
            File[] fs = dir.listFiles();
            if (fs == null) continue;
            for (File f : fs) {
                String n = f.getName().toLowerCase();
                for (String k : keys) if (n.contains(k)) { h.append(f.getName()).append(' '); break; }
            }
        }
        return h.length() > 0 ? h.toString().trim() : "未发现";
    }

    private String storePresent() {
        String[] stores = {"com.coolapk.market","com.tencent.android.qqdownloader","com.wandoujia.phoenix2","com.huawei.appmarket","com.xiaomi.market","com.oppo.market","com.bbk.appstore"};
        for (String s : stores) if (isInstalled(s)) return s;
        return "未发现";
    }

    private String thirdPartyCount() {
        try {
            List<ApplicationInfo> apps = ctx.getPackageManager().getInstalledApplications(0);
            int n = 0;
            for (ApplicationInfo ai : apps) if ((ai.flags & ApplicationInfo.FLAG_SYSTEM) == 0) n++;
            return String.valueOf(n);
        } catch (Exception e) { return "?"; }
    }

    private String riskAppScan() {
        File d = new File("/storage/emulated/0/Android/data");
        File[] fs = d.listFiles();
        if (fs == null) return "不可读";
        StringBuilder h = new StringBuilder();
        int n = 0;
        for (File f : fs) {
            String name = f.getName();
            if (name.indexOf('.') <= 0) continue;
            for (String p : CHUNQIU_A) if (p.equals(name)) { h.append(name).append(' '); n++; break; }
        }
        return n > 0 ? (n + " 个 · " + h.toString().trim()) : "未发现";
    }

    private String rootMgrIntentProbe() {
        StringBuilder h = new StringBuilder();
        for (String p : HIGH_PKGS) if (isInstalled(p)) { h.append(p).append(' '); break; }
        return h.length() > 0 ? "已装:"+h.toString().trim() : "未见 root 管理器";
    }

    private String bootConsistency() {
        String f1 = prop("ro.boot.flash.locked");
        String f2 = prop("ro.boot.verifiedbootstate");
        String f3 = prop("ro.boot.vbmeta.device_state");
        boolean locked = "1".equals(f1);
        boolean green = "green".equals(f2);
        boolean lockedState = "locked".equals(f3);
        int consistent = 0;
        if (f2 != null && !green) consistent++;
        if (f3 != null && !lockedState) consistent++;
        return (locked && consistent == 0) ? "一致(locked+green)" : "不一致! flash.locked="+f1+" state="+f2+" vbmeta="+f3;
    }

    private int hostsCount(String hosts) {
        if (hosts == null) return 0;
        int n = 0;
        for (String l : hosts.split("\n")) {
            String t = l.trim();
            if (t.startsWith("127.0.0.1")||t.startsWith("0.0.0.0")) n++;
        }
        return n;
    }

    // ============ 深层探测：反 HMA 隐藏应用（走 HMA 拦不到的通道） ============

    /** 包名或包名前缀是否可见/已知（处理 :persistent/.uid 等进程名后缀；含禁用与卸载残留） */
    private boolean pkgVisible(String token) {
        String t = token;
        while (true) {
            if (isInstalled(t) || pkgKnown(t)) return true;
            int last = t.lastIndexOf('.');
            if (last <= 0) return false;
            t = t.substring(0, last);
            if (t.indexOf('.') < 0) return false;
        }
    }

    /** 包是否在系统中存在（含禁用组件/卸载残留）——用于排除“禁用系统应用”误报 */
    /** 已知系统服务/厂商组件白名单：这些包名即使 PackageManager 查不到也不算隐藏应用 */
    private static final Set<String> SVC_WHITELIST = new HashSet<>(java.util.Arrays.asList(
            "com.qualcomm.qti", "com.qti", "vendor.qti", "org.codeaurora", "com.qti.ims",
            "com.qualcomm.fastdormancy", "com.qualcomm.location", "com.qualcomm.services.location",
            "com.qti.dcvs", "com.qti.perfdump", "com.qti.modem", "com.qualcomm.msim",
            "com.mediatek", "com.mediatek.imscmd", "mediatek", "com.mediatek.ims",
            "vendor.goodix", "vendor.zte", "vendor.btaudio_intermediate", "vendor.nxp",
            "vendor.huawei", "vendor.oppo", "vendor.vivo", "vendor.xiaomi", "vendor.oneplus",
            "vendor.nubia", "vendor.redmagic", "android", "com.android",
            "com.android.systemui", "com.android.phone", "com.android.settings",
            "com.android.bluetooth", "com.android.nfc", "com.android.location.fused",
            "com.android.providers.media", "com.google.android", "com.google.android.gms",
            "com.google.android.gsf", "media.", "telephony.", "drm.", "memtrack.",
            "android.hardware.", "vendor."
    ));

    /** 已知良性应用白名单（输入法等常用 App）：即使 PackageManager 因包可见性查不到，也不算 HMA 隐藏 */
    private static final Set<String> HMA_BENIGN = new HashSet<>(java.util.Arrays.asList(
            "com.tencent.wetype",                 // 微信输入法
            "com.baidu.input", "com.baidu.inputmethod", "com.baidu.ime",  // 百度输入法
            "com.sohu.inputmethod.sogou",        // 搜狗输入法
            "com.iflytek.inputmethod",           // 讯飞输入法
            "com.google.android.inputmethod.latin", // Gboard
            "com.tencent.qqpinyin"               // QQ输入法
    ));

    private boolean pkgKnown(String pkg) {
        String n = pkg.toLowerCase();
        // 良性 App 白名单（输入法等）：包可见性限制下查不到也不算隐藏
        if (HMA_BENIGN.contains(n)) return true;
        // 输入法类 App 前缀/模式匹配：覆盖各厂商与版本变体（微信/百度/搜狗/讯飞/QQ/Gboard 等），
        // 它们常作为 default_input_method 出现，包可见性下查不到属正常，不算 HMA 隐藏
        if (n.contains("inputmethod") || n.contains("input_method")
                || n.startsWith("com.baidu.input") || n.startsWith("com.sohu.inputmethod")
                || n.startsWith("com.tencent.qqpinyin") || n.startsWith("com.tencent.wetype")
                || n.startsWith("com.iflytek.inputmethod") || n.startsWith("com.google.android.inputmethod")
                || n.endsWith(".ime") || n.contains(".ime.")) return true;
        // 高通/联发科/系统服务白名单：这些组件通常不作为独立 APK 安装，不算隐藏
        for (String wl : SVC_WHITELIST) {
            if (n.startsWith(wl.toLowerCase())) return true;
        }
        try {
            ctx.getPackageManager().getApplicationInfo(pkg,
                    PackageManager.MATCH_UNINSTALLED_PACKAGES | PackageManager.MATCH_DISABLED_COMPONENTS);
            return true;
        } catch (Exception e) { return false; }
    }

    /** 通道1：电池优化白名单（Doze）——HMA 通常拦不到 Settings 读取 */
    private String batteryWhitelistHidden() {
        Set<String> seen = new HashSet<>();
        Set<String> hidden = new HashSet<>();
        String[] keys = {"power_save_whitelist", "power_save_whitelist_apps"};
        for (String k : keys) {
            String v = readSetting("global", k);
            if (v == null || v.isEmpty()) continue;
            for (String p : v.split(",")) {
                p = p.trim();
                if (p.isEmpty() || p.indexOf('.') <= 0) continue;
                seen.add(p);
                if (!pkgKnown(p)) hidden.add(p);
            }
        }
        return seen.isEmpty() ? "白名单为空/不可读"
                : ("白名单 " + seen.size() + " 个" + (hidden.isEmpty() ? "" : " · 隐藏/残留 " + hidden.size() + " 个: " + join(hidden)));
    }

    /** 通道2：无障碍服务组件——启用的无障碍服务包名必须可见 */
    private String accessibilityHiddenApps() {
        String acc = readSetting("secure", "enabled_accessibility_services");
        if (acc == null || acc.isEmpty()) return "未开启无障碍";
        Set<String> hidden = new HashSet<>();
        int n = 0;
        for (String c : acc.split(":")) {
            c = c.trim();
            int i = c.indexOf('/');
            if (i <= 0) continue;
            String pkg = c.substring(0, i);
            n++;
            if (!pkgKnown(pkg)) hidden.add(pkg);
        }
        return "服务 " + n + " 个" + (hidden.isEmpty() ? "" : " · 隐藏/残留 " + hidden.size() + " 个: " + join(hidden));
    }

    /** 通道3：默认应用 / RoleManager 角色——角色持有者必须可见 */
    private String defaultAppsHidden() {
        Set<String> hidden = new HashSet<>();
        String[] keys = {"default_input_method", "dialer_default_application", "sms_default_application",
                "bluetooth_headset_default_application", "emergency_affordance"};
        for (String k : keys) {
            String v = readSetting("secure", k);
            if (v == null || v.isEmpty()) continue;
            String pkg = v;
            int i = v.indexOf('/');
            if (i > 0) pkg = v.substring(0, i);
            if (pkg.indexOf('.') > 0 && !pkgKnown(pkg)) hidden.add(pkg);
        }
        try {
            Class<?> rmCls = Class.forName("android.app.role.RoleManager");
            Object rm = ctx.getSystemService("role");
            if (rm != null) {
                java.lang.reflect.Method m = rmCls.getMethod("getRoleHolders", String.class);
                String[] roles = {"android.app.role.HOME","android.app.role.BROWSER","android.app.role.ASSISTANT",
                        "android.app.role.DIALER","android.app.role.SMS","android.app.role.EMERGENCY"};
                for (String role : roles) {
                    Object res = m.invoke(rm, role);
                    if (res instanceof List) {
                        List<?> holders = (List<?>) res;
                        for (Object o : holders) {
                            String p = String.valueOf(o);
                            if (!pkgKnown(p)) hidden.add(p);
                        }
                    }
                }
            }
        } catch (Exception ignored) {}
        return hidden.isEmpty() ? "默认应用/角色均可见" : "隐藏/残留 " + hidden.size() + " 个: " + join(hidden);
    }

    /** 通道4：system service 列表——只比对“包名/组件”格式的应用服务（含 / ），纯系统服务名跳过 */
    private String servicesHiddenApps() {
        String svc = shExec("service list 2>/dev/null");
        if (svc == null || svc.trim().isEmpty()) return "不可读";
        Set<String> hidden = new HashSet<>();
        for (String line : svc.split("\n")) {
            String t = line.trim();
            int i = t.indexOf('\t');
            if (i >= 0) t = t.substring(i + 1).trim();
            int j = t.indexOf(' ');
            if (j > 0) t = t.substring(0, j);
            int k = t.indexOf('/');
            if (k <= 0) continue; // media.aaudio / telephony.registry 等纯系统服务名不参与比对
            String pkg = t.substring(0, k);
            if (pkg.indexOf('.') <= 0 || pkg.startsWith("android.")) continue;
            if (!pkgKnown(pkg)) hidden.add(pkg);
        }
        return hidden.isEmpty() ? "服务包名均可见" : "隐藏/残留 " + hidden.size() + " 个: " + join(hidden);
    }

    /** 通道5：/proc 进程命令行——正在运行的隐藏应用进程 */
    private String procHiddenApps() {
        Set<String> hidden = new HashSet<>();
        Set<String> all = new HashSet<>();
        File proc = new File("/proc");
        File[] pids = proc.listFiles();
        if (pids != null) {
            int scanned = 0;
            for (File f : pids) {
                if (!f.getName().matches("\\d+")) continue;
                String cmd = read(f.getPath() + "/cmdline");
                if (cmd == null) continue;
                String c = cmd.replace('\0', ' ').trim();
                scanned++;
                for (String t : c.split("\\s+")) {
                    if (t.length() < 6 || t.indexOf('.') <= 0 || !t.matches("[A-Za-z0-9_.:]+")) continue;
                    int ci = t.indexOf(':');
                    if (ci > 0) t = t.substring(0, ci);
                    all.add(t);
                    if (t.startsWith("com.android.")||t.startsWith("android.")||t.startsWith("com.google.android.")
                            ||t.startsWith("vendor.")||t.startsWith("qti.")||t.startsWith("com.qualcomm.")
                            ||t.startsWith("com.nxp.")||t.startsWith("com.mediatek.")||t.startsWith("com.miui.")
                            ||t.startsWith("com.huawei.")||t.startsWith("com.oppo.")||t.startsWith("com.vivo.")
                            ||t.startsWith("com.xiaomi.")||t.startsWith("com.samsung.")||t.startsWith("com.asus.")
                            ||t.startsWith("com.oneplus.")||t.startsWith("com.realme.")||t.startsWith("persist.")
                            ||t.startsWith("media.")||t.startsWith("telephony.")||t.startsWith("drm.")
                            ||t.startsWith("memtrack.")||t.startsWith("tracing.")||t.startsWith("vivo_")
                            ||t.startsWith("mtk")||t.startsWith("aaudio")||t.startsWith("mtsf")
                            ||t.startsWith("bluetooth.")) continue;
                    if (!pkgVisible(t)) hidden.add(t);
                }
                if (scanned > 400) break;
            }
        }
        return hidden.isEmpty() ? ("进程可见(" + all.size() + " 包名样 token)") : "隐藏/残留 " + hidden.size() + " 个: " + join(hidden);
    }

    /** 综合判定：汇总所有通道发现的隐藏/残留应用 */
    private String hiddenAppSummary() {
        Set<String> all = new HashSet<>();
        String bw = batteryWhitelistHidden();
        if (bw.contains("隐藏/残留")) { String[] p = bw.split(": "); if (p.length > 1) for (String s : p[1].split(" ")) all.add(s); }
        String ah = accessibilityHiddenApps();
        if (ah.contains("隐藏/残留")) { String[] p = ah.split(": "); if (p.length > 1) for (String s : p[1].split(" ")) all.add(s); }
        String da = defaultAppsHidden();
        if (da.contains("隐藏/残留")) { String[] p = da.split(": "); if (p.length > 1) for (String s : p[1].split(" ")) all.add(s); }
        String sh = servicesHiddenApps();
        if (sh.contains("隐藏/残留")) { String[] p = sh.split(": "); if (p.length > 1) for (String s : p[1].split(" ")) all.add(s); }
        String ph = procHiddenApps();
        if (ph.contains("隐藏/残留")) { String[] p = ph.split(": "); if (p.length > 1) for (String s : p[1].split(" ")) all.add(s); }
        return all.isEmpty() ? "未发现隐藏应用" : "发现 " + all.size() + " 个疑似隐藏/残留应用: " + join(all);
    }

    /**
     * /data/app/ 包名交叉验证：
     * 1. 扫描 /data/app/ 下的目录名提取包名
     * 2. 对比 PackageManager 已安装包名
     * 3. /data/app有但PM无 = HMA隐藏应用
     * 4. 包名命中风险列表 = 风险应用
     */
    private String dataAppPackageCrossCheck() {
        try {
            // 1. 获取 PackageManager 可见的所有包名
            Set<String> pmPkgs = new HashSet<>();
            try {
                var pkgs = ctx.getPackageManager().getInstalledPackages(0);
                for (var pi : pkgs) pmPkgs.add(pi.packageName);
            } catch (Exception ignored) {}

            // 2. 扫描 /data/app/ 目录
            String ls = shExec("ls /data/app/ 2>/dev/null");
            if (ls == null || ls.trim().isEmpty()) return "/data/app不可读(正常)";

            Set<String> diskPkgs = new HashSet<>();
            for (String entry : ls.split("\n")) {
                entry = entry.trim();
                if (entry.isEmpty()) continue;
                // /data/app/ 下目录格式通常为：com.example.pkg-xxxxxxxx==/base.apk
                // 提取 == 之前的部分作为包名
                int idx = entry.indexOf("==");
                if (idx > 0) entry = entry.substring(0, idx);
                // 去掉数字后缀（如 -AbCd1234EfGh==）
                int dashIdx = entry.lastIndexOf('-');
                if (dashIdx > 0 && dashIdx > entry.indexOf('.')) {
                    String suffix = entry.substring(dashIdx + 1);
                    // 后缀看起来像随机串（大小写字母+数字混合，长度8-16）
                    if (suffix.length() >= 8 && suffix.length() <= 16 && suffix.matches("[A-Za-z0-9_\\-]+")) {
                        entry = entry.substring(0, dashIdx);
                    }
                }
                if (entry.contains(".")) diskPkgs.add(entry);
            }

            if (diskPkgs.isEmpty()) return "未扫描到包名";

            // 3. 对比：磁盘有但PM没有 = HMA隐藏
            Set<String> hmaHidden = new HashSet<>();
            Set<String> riskyPkgs = new HashSet<>();
            for (String diskPkg : diskPkgs) {
                boolean inPm = false;
                for (String pmPkg : pmPkgs) {
                    if (pmPkg.equals(diskPkg)) { inPm = true; break; }
                }
                if (!inPm) hmaHidden.add(diskPkg);
                // 检查是否命中风险包列表
                for (String hp : HIGH_PKGS) if (hp.equals(diskPkg)) { riskyPkgs.add(diskPkg); break; }
                for (String wp : WEAK_PKGS) if (wp.equals(diskPkg)) { riskyPkgs.add(diskPkg); break; }
            }

            // 4. 生成结果
            StringBuilder sb = new StringBuilder();
            if (!riskyPkgs.isEmpty()) {
                sb.append("风险应用: ").append(join(riskyPkgs));
            }
            if (!hmaHidden.isEmpty()) {
                if (sb.length() > 0) sb.append("; ");
                sb.append("HMA隐藏应用(文件存在但PM不可见): ").append(join(hmaHidden));
            }
            if (sb.length() == 0) {
                return "一致(" + diskPkgs.size() + "个包名全部匹配)";
            }
            return sb.toString();
        } catch (Exception e) {
            return "受限:" + e.getClass().getSimpleName();
        }
    }

    /**
     * 新HMA三组数据源交叉比对（替代旧#155计数对比 与 旧#318 service list 包数对比）：
     * ① 用户侧第三方已安装应用集合（PackageManager）
     * ② 路径扫描 APK 安装目录提取包名集合（文件系统，必须捕获权限拒绝异常）
     * ③ 系统禁用/冻结/停用应用集合（PackageManager + GET_DISABLED_COMPONENTS）
     * 判定：三组集合两两差集逐条打印；差集包落在③禁用集内仅备注不告警；
     * 仅当 ②有 且 ①无 且 ③无 三者同时满足才输出 SUSPECT(HMA疑似隐藏应用)。
     */
    private String hmaThreeSourceCrossCheck() {
        Set<String> userPkgs = new HashSet<>();
        Set<String> disabledPkgs = new HashSet<>();
        // 数据源① + ③：一次遍历 PackageManager
        try {
            List<ApplicationInfo> apps = ctx.getPackageManager()
                    .getInstalledApplications(PackageManager.GET_DISABLED_COMPONENTS);
            for (ApplicationInfo ai : apps) {
                if ((ai.flags & ApplicationInfo.FLAG_SYSTEM) == 0) userPkgs.add(ai.packageName);
            }
            // ③ 系统禁用/冻结/停用：用公开 API getApplicationEnabledSetting 判定（禁用包可能不在常规安装列表）
            for (ApplicationInfo ai : apps) {
                try {
                    int st = ctx.getPackageManager().getApplicationEnabledSetting(ai.packageName);
                    if (st == PackageManager.COMPONENT_ENABLED_STATE_DISABLED
                            || st == PackageManager.COMPONENT_ENABLED_STATE_DISABLED_USER
                            || st == PackageManager.COMPONENT_ENABLED_STATE_DISABLED_UNTIL_USED) {
                        disabledPkgs.add(ai.packageName);
                    }
                } catch (Exception ignored) {}
            }
        } catch (Exception e) {
            return "受限(PackageManager 不可读):" + e.getClass().getSimpleName();
        }

        // 数据源②：路径扫描 APK 安装目录，从 APK 提取包名；捕获权限拒绝/读取失败异常
        Set<String> diskPkgs = new HashSet<>();
        String[] dirs = {"/data/app", "/system/app", "/system/priv-app", "/product/app",
                "/product/priv-app", "/vendor/app"};
        boolean dataAppUnreadable = false;
        for (String d : dirs) {
            File dir = new File(d);
            if (!dir.isDirectory()) { if (d.equals("/data/app")) dataAppUnreadable = true; continue; }
            File[] files = null;
            try { files = dir.listFiles(); } catch (Exception ignored) { files = null; }
            if (files == null) {
                if (d.equals("/data/app")) dataAppUnreadable = true;
                continue;
            }
            for (File apk : files) {
                String pkg = apkPkgName(apk.getPath()); // APK 读取失败仅日志，不告警
                if (pkg != null && pkg.indexOf('.') > 0) diskPkgs.add(pkg);
            }
        }
        // SDK>=34：访问 APK 安装目录无权限 → 路径比对维度失效，禁止输出任何告警
        if (dataAppUnreadable && Build.VERSION.SDK_INT >= 34) {
            return "【能力受限】Android沙盒限制，当前应用无权限遍历安装目录，路径比对维度失效";
        }

        // 1. 三组集合两两差集，打印每一条差异具体包名（供人工复核）
        StringBuilder diff = new StringBuilder();
        Set<String> allDiff = new HashSet<>();
        for (String p : diskPkgs)    if (!userPkgs.contains(p))     { allDiff.add(p); diff.append("②有①无:").append(p).append(' '); }
        for (String p : disabledPkgs) if (!userPkgs.contains(p))    { allDiff.add(p); diff.append("③有①无:").append(p).append(' '); }
        for (String p : diskPkgs)    if (!disabledPkgs.contains(p)) { allDiff.add(p); diff.append("②有③无:").append(p).append(' '); }

        // 2/3. 判定：差集包在③禁用集内 → 备注不告警；②有①无③无三者同时命中 → SUSPECT
        // v1.2.21：良性输入法/已知系统组件（微信/百度/搜狗/Gboard 等）即使 PM 因包可见性查不到，
        // 也不是“应用被隐藏”的证据，命中后标记 INFO 基线备注，跳过 SUSPECT，避免输入法误报。
        StringBuilder note = new StringBuilder();
        StringBuilder sus = new StringBuilder();
        for (String p : allDiff) {
            if (disabledPkgs.contains(p)) {
                note.append(p).append("(属系统禁用/冻结包,为系统原生行为,不一定为HMA隐藏) ");
            }
            if (diskPkgs.contains(p) && !userPkgs.contains(p) && !disabledPkgs.contains(p)) {
                if (pkgKnown(p)) {
                    note.append(p).append("(良性输入法/已知组件,默认选中或包可见性正常,非HMA隐藏,仅INFO基线) ");
                    continue;
                }
                sus.append(p).append(' ');
            }
        }

        StringBuilder out = new StringBuilder();
        out.append("差集明细:").append(diff.length() > 0 ? diff.toString().trim() : "无差异");
        if (note.length() > 0) out.append(" | 备注:").append(note.toString().trim());
        if (sus.length() > 0) out.append(" | HMA疑似隐藏应用:").append(sus.toString().trim());
        return out.toString();
    }

    private String join(Set<String> set) {
        StringBuilder sb = new StringBuilder();
        for (String s : set) { sb.append(s).append(' '); if (sb.length() > 300) break; }
        return sb.toString().trim();
    }

    // ============ 厂商误报白名单 ============

    /** 厂商原生组件（非第三方风险软件），在风险应用/hook 扫描中直接跳过 */
    private static final Set<String> OEM_WHITELIST = new HashSet<>();
    static {
        OEM_WHITELIST.add("com.oplus.virtualcomm");
        OEM_WHITELIST.add("com.oplus.virtualcomm2");
        OEM_WHITELIST.add("com.oplus.virtualcomm3");
        OEM_WHITELIST.add("com.oplus.synergy");
        OEM_WHITELIST.add("com.oplus.cosa");
        OEM_WHITELIST.add("com.oplus.obc");
    }

    /**
     * 系统应用包名白名单（#257 修复）：支持通配前缀匹配。
     * 命中白名单的包仅记录日志文本，绝对禁止输出 ABNORMAL 异常等级，不能被标记为风险应用。
     * 前缀匹配：cn.nubia.* ；精确匹配：com.redteamobile.virtual.softsim
     */
    private static final String[] APP_PKG_WHITELIST_PREFIXES = { "cn.nubia." };
    private static final Set<String> APP_PKG_WHITELIST_EXACT = new HashSet<>(java.util.Arrays.asList(
            "com.redteamobile.virtual.softsim"
    ));

    /** 是否命中系统应用白名单（通配前缀 + 精确匹配） */
    private boolean isAppPkgWhitelisted(String pkg) {
        String n = pkg.toLowerCase();
        for (String p : APP_PKG_WHITELIST_PREFIXES) if (n.startsWith(p)) return true;
        return APP_PKG_WHITELIST_EXACT.contains(n);
    }

    /** OPPO/一加/realme 系机型（用于去除厂商原生误报） */
    private boolean isOem() {
        String f = prop("ro.build.fingerprint");
        String m = prop("ro.product.manufacturer");
        String b = prop("ro.product.brand");
        String s = (f == null ? "" : f) + " " + (m == null ? "" : m) + " " + (b == null ? "" : b);
        String l = s.toLowerCase(Locale.US);
        return l.contains("oppo") || l.contains("oplus") || l.contains("oneplus") || l.contains("realme");
    }

    // ============ 高级探针（真实实现） ============

    /** KSU/APatch 鉴权路径时延比：KSU kprobe hook newfstatat/faccessat 使目标路径 stat 变慢 */
    private String timingSideChannel() {
        try {
            File target = new File("/data/adb/ksu");
            File control = new File("/data/adb/ap");
            File neutral = new File("/system/etc/hosts");
            double rt = 0, ra = 0;
            for (int r = 0; r < 3; r++) {
                rt += statTime(target) / Math.max(1, statTime(neutral));
                ra += statTime(control) / Math.max(1, statTime(neutral));
            }
            rt /= 3; ra /= 3;
            boolean sus = (target.exists() && rt > 1.3) || (control.exists() && ra > 1.3);
            return "ksu时延比=" + String.format(Locale.US, "%.2f", rt)
                    + " ap时延比=" + String.format(Locale.US, "%.2f", ra)
                    + (target.exists() || control.exists() ? " (目标路径存在)" : " (目标路径不存在)")
                    + (sus ? " → 疑似 KSU/APatch 内核鉴权补丁" : "");
        } catch (Exception e) { return "探测失败:" + e.getClass().getSimpleName(); }
    }

    private long statTime(File f) {
        long s = System.nanoTime();
        for (int i = 0; i < 40; i++) { f.exists(); f.length(); f.isDirectory(); }
        return System.nanoTime() - s;
    }

    /** 属性区全量扫描：getprop 全量拉取，命中 root/hook 相关属性名或值 */
    private String propFullScan() {
        String out = shExec("getprop 2>/dev/null");
        if (out == null || out.trim().isEmpty()) return "不可读";
        StringBuilder h = new StringBuilder();
        String[] keys = {"magisk","ksu","apatch","frida","xposed","tricky","susfs","zygisk",
                "spoof","pihooks","pixelprops","superkey","hook"};
        for (String line : out.split("\n")) {
            String l = line.toLowerCase();
            // 白名单：ART/dalvik 原生属性不算可疑
            if (l.contains("dalvik.vm.dex2oat") || l.contains("dalvik.vm.image-dex2oat")) continue;
            if (l.contains("dalvik.vm.heapsize") || l.contains("dalvik.vm.startup")) continue;
            boolean hit = false;
            for (String k : keys) if (l.contains(k)) { hit = true; break; }
            // dex2oat 单独处理：只查 dex2oat-flags 这种被篡改的标志，不查 Xms/Xmx 等原生参数
            if (!hit && l.contains("dex2oat") && !l.contains("dex2oat-flags")) continue;
            if (hit) {
                String v = line.trim();
                if (h.indexOf(v) < 0 && h.length() < 400) h.append(v).append('\n');
            }
        }
        return h.length() > 0 ? "命中:\n" + h.toString().trim() : "未见可疑属性";
    }

    /** KeyStore 硬件安全级别：KeyInfo.isInsideSecureHardware / getSecurityLevel
     *  判定：仅软件型密钥但 TEE 硬件背书正常 → 仅日志不告警；仅当 TEE 硬件背书校验失败才告警 */
    private String keystoreDepth() {
        try {
            KeyGenerator kg = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore");
            KeyGenParameterSpec spec = new KeyGenParameterSpec.Builder("zuomeng_hw", KeyProperties.PURPOSE_ENCRYPT)
                    .setBlockModes(KeyProperties.BLOCK_MODE_GCM).setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                    .build();
            kg.init(spec); kg.generateKey();
            KeyStore ks = KeyStore.getInstance("AndroidKeyStore");
            ks.load(null);
            Key key = ks.getKey("zuomeng_hw", null);
            boolean secure = false; int lvl = -1;
            if (key instanceof KeyInfo) {
                KeyInfo ki = (KeyInfo) key;
                secure = ki.isInsideSecureHardware();
                lvl = ki.getSecurityLevel();
            }
            // TEE 硬件背书校验：能否正常生成受 TEE 保护的密钥
            boolean teeOk = true;
            try {
                KeyGenerator kg2 = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore");
                KeyGenParameterSpec sp2 = new KeyGenParameterSpec.Builder("zuomeng_tee", KeyProperties.PURPOSE_ENCRYPT)
                        .setBlockModes(KeyProperties.BLOCK_MODE_GCM).setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                        .build();
                kg2.init(sp2); kg2.generateKey();
            } catch (Exception teeE) { teeOk = false; }
            int softCount = secure ? 0 : 1;
            String base = "硬件背书=" + secure + " 安全级别=" + lvl + " 软件密钥数=" + softCount
                    + " TEE背书=" + (teeOk ? "正常" : "校验失败");
            return teeOk ? ("TEE_OK:" + base + " (仅软件密钥,TEE正常,不告警)")
                         : ("TEE_FAIL:" + base + " (TEE硬件背书校验失败)");
        } catch (Exception e) { return "受限:" + e.getClass().getSimpleName(); }
    }

    /** attestation 尝试：普通应用无 android:attestation 权限，成功即异常 */
    private String attestationProbe() {
        try {
            KeyGenParameterSpec spec = new KeyGenParameterSpec.Builder("zuomeng_att", KeyProperties.PURPOSE_SIGN)
                    .setDigests(KeyProperties.DIGEST_SHA256)
                    .setAttestationChallenge("zuomeng".getBytes())
                    .build();
            KeyGenerator kg = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_RSA, "AndroidKeyStore");
            kg.init(spec); kg.generateKey();
            KeyStore ks = KeyStore.getInstance("AndroidKeyStore");
            ks.load(null);
            java.security.cert.Certificate[] chain = ks.getCertificateChain("zuomeng_att");
            return chain != null ? ("attestation 链长度=" + chain.length + " (异常开放)") : "无证书链";
        } catch (Exception e) { return "受限(需 device owner):" + e.getClass().getSimpleName(); }
    }

    /** StrongBox 安全元件探测 */
    private String strongBoxProbe() {
        try {
            KeyGenerator kg = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore");
            KeyGenParameterSpec spec = new KeyGenParameterSpec.Builder("zuomeng_sb", KeyProperties.PURPOSE_SIGN)
                    .setDigests(KeyProperties.DIGEST_SHA256)
                    .setIsStrongBoxBacked(true).build();
            kg.init(spec); kg.generateKey();
            KeyStore ks = KeyStore.getInstance("AndroidKeyStore");
            ks.load(null);
            return ks.containsAlias("zuomeng_sb") ? "StrongBox 可用" : "StrongBox 不可用";
        } catch (Exception e) { return "无 StrongBox:" + e.getClass().getSimpleName(); }
    }

    /** netlink raw socket 统计：过量 = VPN/代理/抓包工具 */
    private String netlinkCheck() {
        String nl = read("/proc/net/netlink");
        if (nl == null) return "不可读";
        int n = Math.max(0, countLines(nl) - 1);
        return "raw netlink socket=" + n + " 个" + (n > 40 ? " (异常偏多)" : "");
    }

    /** zygote 进程链溯源：self→zygote→init，断链 = 容器/注入；Android16 AppZygote 截断不判异常 */
    private String ppidChain() {
        StringBuilder sb = new StringBuilder();
        int pid = android.os.Process.myPid();
        for (int i = 0; i < 6 && pid > 0; i++) {
            String stat = read("/proc/" + pid + "/stat");
            if (stat == null) break;
            int a = stat.indexOf('('), b = stat.lastIndexOf(')');
            if (a < 0 || b <= a) break;
            String comm = stat.substring(a + 1, b);
            sb.append(comm).append('←');
            String[] f = stat.substring(b + 1).trim().split("\\s+");
            if (f.length < 2) break;
            try { pid = Integer.parseInt(f[1]); } catch (Exception e) { break; }
        }
        String chain = sb.toString();
        boolean ok = chain.contains("zygote") || chain.contains("app_process");
        // Android16 AppZygote 机制：普通应用读不到完整父链，不判异常
        boolean truncatedByPermission = chain.length() < 30 && !ok;
        if (truncatedByPermission) {
            return chain + " (Android16 AppZygote 链截断,正常)";
        }
        return chain + (ok ? " (正常 zygote 链)" : " (异常: 未溯源到 zygote)");
    }

    /** OBB 多视图一致性：Java / 路径 / shell 三种视图互相印证；沙盒权限隔离导致的差异不判异常 */
    private String obbMultiView() {
        try {
            File j = ctx.getObbDir();
            String pkg = ctx.getPackageName();
            File v1 = new File("/storage/emulated/0/Android/obb/" + pkg);
            File v2 = new File("/data/media/0/Android/obb/" + pkg);
            boolean b1 = j != null && j.exists(), b2 = v1.exists(), b3 = v2.exists();
            String ls = shExec("ls /storage/emulated/0/Android/obb/" + pkg + " 2>/dev/null");
            boolean b4 = ls != null && !ls.trim().isEmpty();
            int n = (b1 ? 1 : 0) + (b2 ? 1 : 0) + (b3 ? 1 : 0) + (b4 ? 1 : 0);
            if (n == 0 || n == 4) return "OBB 各视图一致(" + n + "/4)";
            // 普通应用沙盒隔离：/data/media 视图天然不可见，不算拦截
            if (!b3 && (b1 || b2)) {
                return "OBB 沙盒视图隔离(java=" + b1 + " /storage=" + b2 + ",/data/media不可见,正常)";
            }
            return "OBB 视图不一致! java=" + b1 + " /storage=" + b2 + " /data/media=" + b3 + " shell=" + b4 + " → 疑似拦截";
        } catch (Exception e) { return "受限:" + e.getClass().getSimpleName(); }
    }

    private static final Pattern SMAPS_ADDR = Pattern.compile("^[0-9a-f]+-[0-9a-f]+ ");

    /** smaps 匿名内存统计：区域数与总 Rss，异常膨胀 = 注入载荷；大内存机型动态阈值 */
    private String smapsAnonCheck() {
        String s = read("/proc/self/smaps");
        if (s == null) return "不可读";
        long rss = 0;
        int regions = 0;
        for (String l : s.split("\n")) {
            if (l.startsWith("Rss:")) {
                String[] f = l.trim().split("\\s+");
                if (f.length >= 2) try { rss += Long.parseLong(f[1]); } catch (Exception ignored) {}
            } else if (SMAPS_ADDR.matcher(l).find()) regions++;
        }
        // 大内存手机(12GB+)正常 Compose 应用可达 4000+ 区域，阈值提高到 6000
        boolean huge = regions > 6000 || rss > 2500000;
        return "区域=" + regions + " 总Rss=" + (rss / 1024) + "MB" + (huge ? " → 异常膨胀" : "");
    }

    /** fdinfo mnt_id 采样：fd 的挂载点不在 mountinfo 中 = 挂载被隐藏；普通应用权限不足大量读失败不判异常 */
    private String fdinfoMntCheck() {
        String mi = read("/proc/self/mountinfo");
        if (mi == null) return "不可读";
        Set<Integer> valid = new HashSet<>();
        for (String l : mi.split("\n")) {
            String[] f = l.trim().split("\\s+");
            if (f.length >= 1) try { valid.add(Integer.parseInt(f[0])); } catch (Exception ignored) {}
        }
        File fdd = new File("/proc/self/fdinfo");
        File[] fs = fdd.listFiles();
        if (fs == null) return "不可读";
        int bad = 0, total = 0, readable = 0;
        for (File f : fs) {
            String c = read(f.getPath());
            if (c == null) continue;
            total++;
            boolean hasMntId = false;
            for (String l : c.split("\n")) if (l.startsWith("mnt_id:")) {
                hasMntId = true;
                try { int id = Integer.parseInt(l.substring(7).trim()); if (!valid.contains(id)) bad++; } catch (Exception ignored) {}
            }
            if (hasMntId) readable++;
        }
        // 权限不足场景：大量 fd 读不到 mnt_id，不判挂载隐藏
        if (readable == 0) return "fdinfo mnt_id 受限(无权限,正常)";
        double badRatio = total > 0 ? (double) bad / total : 0;
        // 超过 70% 异常 = 权限问题，不是真的挂载隐藏
        if (badRatio > 0.7) return "mnt_id 读取受限(" + bad + "/" + total + " 异常,权限不足,正常)";
        return bad > 0 ? ("mnt_id 异常 " + bad + "/" + total + " 个(挂载被隐藏)") : ("mnt_id 全部一致(" + total + " 个 fd)");
    }

    /** Uid 四列(r/e/s/f)一致性：进程 UID 被切换时的破绽 */
    private String uidFourColumns() {
        String st = read("/proc/self/status");
        if (st == null) return "不可读";
        for (String line : st.split("\n")) {
            if (line.startsWith("Uid:")) {
                String[] p = line.trim().split("\\s+");
                if (p.length >= 5) {
                    boolean same = p[1].equals(p[2]) && p[2].equals(p[3]) && p[3].equals(p[4]);
                    return same ? "四列一致(" + p[1] + ")" : "四列不一致! r=" + p[1] + " e=" + p[2] + " s=" + p[3] + " f=" + p[4];
                }
            }
        }
        return "未找到 Uid 字段";
    }

    /** 用户应用包名 hook/作弊关键字 */
    private String userAppHookScan() {
        StringBuilder h = new StringBuilder();
        StringBuilder wl = new StringBuilder();
        String[] keys = {"hook","xposed","frida","cheat","macro","lucky","deviceid","spoof","clone",
                "virtual","hidemyapp","magisk","ksu","apatch","noactive","freezer","fakelocation","autoclick"};
        try {
            List<ApplicationInfo> apps = ctx.getPackageManager().getInstalledApplications(0);
            for (ApplicationInfo ai : apps) {
                if ((ai.flags & ApplicationInfo.FLAG_SYSTEM) != 0) continue;
                if (OEM_WHITELIST.contains(ai.packageName)) continue;
                String n = ai.packageName.toLowerCase();
                boolean hit = false;
                for (String k : keys) if (n.contains(k)) { hit = true; break; }
                if (!hit) continue;
                // 命中系统应用白名单：仅记录日志，不标记为风险应用
                if (isAppPkgWhitelisted(ai.packageName)) { wl.append(ai.packageName).append(' '); continue; }
                h.append(ai.packageName).append(' ');
            }
        } catch (Exception ignored) {}
        if (h.length() > 0) return h.toString().trim();
        if (wl.length() > 0) return "未发现（白名单命中已忽略: " + wl.toString().trim() + "）";
        return "未发现";
    }

    /** 系统应用包名 hook/作弊关键字（强关键字全量命中；弱关键字仅对非 OEM 应用生效，避免厂商组件误报） */
    private String systemAppHookScan() {
        StringBuilder h = new StringBuilder();
        StringBuilder wl = new StringBuilder();
        String[] strong = {"magisk","supersu","superuser","ksu","apatch","xposed","lspd","lsposed","frida"};
        String[] weak = {"hook","fakelocation","deviceid","cloner","virtual","hide"};
        try {
            List<ApplicationInfo> apps = ctx.getPackageManager().getInstalledApplications(0);
            for (ApplicationInfo ai : apps) {
                if ((ai.flags & ApplicationInfo.FLAG_SYSTEM) == 0) continue;
                if (OEM_WHITELIST.contains(ai.packageName)) continue;
                String n = ai.packageName.toLowerCase();
                boolean oem = n.startsWith("com.oplus.")||n.startsWith("com.vivo.")||n.startsWith("com.xiaomi.")
                        ||n.startsWith("com.huawei.")||n.startsWith("com.oppo.")||n.startsWith("com.oneplus.")
                        ||n.startsWith("com.realme.")||n.startsWith("com.samsung.")||n.startsWith("com.miui.")
                        ||n.startsWith("com.coloros.")||n.startsWith("com.bbk.")||n.startsWith("com.iqoo.")
                        ||n.startsWith("com.transsion.")||n.startsWith("com.oplus.");
                boolean hit = false;
                for (String k : strong) if (n.contains(k)) { hit = true; break; }
                if (!hit && !oem) for (String k : weak) if (n.contains(k)) { hit = true; break; }
                if (!hit) continue;
                // 命中系统应用白名单：绝对禁止输出 ABNORMAL，仅记录日志，不标记为风险应用
                if (isAppPkgWhitelisted(ai.packageName)) { wl.append(ai.packageName).append(' '); continue; }
                h.append(ai.packageName).append(' ');
            }
        } catch (Exception ignored) {}
        if (h.length() > 0) return h.toString().trim();
        if (wl.length() > 0) return "未发现（白名单命中已忽略: " + wl.toString().trim() + "）";
        return "未发现";
    }

    /** APK 安装包分析：解析包名，/data/local/tmp 或命中黑名单即异常 */
    private String deepApkScan() {
        StringBuilder h = new StringBuilder();
        File[] roots = {new File("/sdcard"), new File("/storage/emulated/0/Download"),
                new File("/storage/emulated/0/Documents"), new File("/data/local/tmp")};
        for (File d : roots) {
            if (!d.isDirectory()) continue;
            File[] fs = d.listFiles();
            if (fs == null) continue;
            for (File f : fs) {
                String n = f.getName().toLowerCase();
                if (n.endsWith(".apk")) {
                    String pkg = apkPkgName(f.getPath());
                    boolean bad = f.getPath().contains("/data/local/tmp") || (pkg != null && riskPkg(pkg));
                    if (bad) h.append(f.getName()).append('(').append(pkg == null ? "无法解析" : pkg).append(") ");
                }
            }
        }
        return h.length() > 0 ? "异常安装包:" + h.toString().trim() : "未见异常安装包";
    }

    private String apkPkgName(String path) {
        try {
            PackageInfo pi = ctx.getPackageManager().getPackageArchiveInfo(path, 0);
            return pi == null ? null : pi.packageName;
        } catch (Exception e) { return null; }
    }

    private boolean riskPkg(String pkg) {
        if (OEM_WHITELIST.contains(pkg)) return false;
        if (isAppPkgWhitelisted(pkg)) return false;
        for (String p : CHUNQIU_A) if (p.equals(pkg)) return true;
        String n = pkg.toLowerCase();
        return n.contains("hook")||n.contains("cheat")||n.contains("xposed")||n.contains("frida")
                ||n.contains("magisk")||n.contains("ksu")||n.contains("apatch")||n.contains("deviceid")
                ||n.contains("fakelocation")||n.contains("virtual")||n.contains("clone");
    }

    /** SH 脚本内容分析：依次读每个 .sh，命中 root 关键字即风险 */
    private String shContentScan() {
        StringBuilder h = new StringBuilder();
        File[] roots = {new File("/sdcard"), new File("/storage/emulated/0/Download"),
                new File("/storage/emulated/0/Documents"), new File("/data/local/tmp")};
        String[] keys = {"magisk","ksu","apatch","resetprop","mount --bind","frida","xposed",
                "chattr","superkey","zygisk","su -c","setuid","/system/bin/su"};
        for (File d : roots) {
            if (!d.isDirectory()) continue;
            File[] fs = d.listFiles();
            if (fs == null) continue;
            for (File f : fs) {
                String n = f.getName().toLowerCase();
                if (!n.endsWith(".sh")) continue;
                String content = read(f.getPath());
                if (content == null) continue;
                String cl = content.toLowerCase();
                boolean hit = false;
                for (String k : keys) if (cl.contains(k)) { hit = true; break; }
                if (hit) h.append(f.getName()).append(' ');
            }
        }
        return h.length() > 0 ? "可疑 sh: " + h.toString().trim() : "未见可疑 sh";
    }

    /** IMG 镜像文件扫描：存在即风险（payload/刷机镜像） */
    private String imgScan() {
        StringBuilder h = new StringBuilder();
        File[] roots = {new File("/sdcard"), new File("/storage/emulated/0/Download"),
                new File("/storage/emulated/0/Documents"), new File("/data/local/tmp")};
        for (File d : roots) {
            if (!d.isDirectory()) continue;
            File[] fs = d.listFiles();
            if (fs == null) continue;
            for (File f : fs) if (f.getName().toLowerCase().endsWith(".img")) h.append(f.getName()).append(' ');
        }
        return h.length() > 0 ? h.toString().trim() : "未见 img 镜像";
    }

    /** 系统应用总数 */
    private String systemAppCount() {
        try {
            List<ApplicationInfo> apps = ctx.getPackageManager().getInstalledApplications(0);
            int n = 0;
            for (ApplicationInfo ai : apps) if ((ai.flags & ApplicationInfo.FLAG_SYSTEM) != 0) n++;
            return String.valueOf(n);
        } catch (Exception e) { return "?"; }
    }

    /** peer-group 挂载组间隙：peer 组 ID 跳跃 = 隐藏挂载 */
    private String peerGroupGap(String mountinfo) {
        if (mountinfo == null) return "不可读";
        List<Integer> ids = new ArrayList<>();
        for (String l : mountinfo.split("\n")) {
            String[] f = l.trim().split("\\s+");
            if (f.length < 4) continue;
            if (!"-".equals(f[2])) try { ids.add(Integer.parseInt(f[2])); } catch (Exception ignored) {}
        }
        if (ids.size() < 3) return "peer-group 参考不足";
        java.util.Collections.sort(ids);
        int gap = 0;
        for (int i = 1; i < ids.size(); i++) if (ids.get(i) - ids.get(i - 1) > 1) gap++;
        return gap >= 3 ? ("peer-group 间隙 " + gap + " 处") : "peer-group 连续(" + ids.size() + " 组)";
    }

    /** cmdline 中全部 androidboot.* 启动参数 */
    private String cmdlineAndroidBoot() {
        String c = read("/proc/cmdline");
        if (c == null) return "不可读";
        StringBuilder h = new StringBuilder();
        for (String t : c.trim().split("\\s+")) if (t.startsWith("androidboot.")) h.append(t).append(' ');
        return h.length() > 0 ? h.toString().trim() : "无 androidboot 参数";
    }

    /** /proc/meminfo MemTotal → GB */
    private String memTotal(String meminfo) {
        if (meminfo == null) return "不可读";
        for (String l : meminfo.split("\n")) if (l.startsWith("MemTotal:")) {
            String[] f = l.trim().split("\\s+");
            if (f.length >= 2) try { return (Long.parseLong(f[1]) / 1048576) + " GB"; } catch (Exception e) { return l.trim(); }
        }
        return "不可读";
    }

    // ============ v1.2.21 新增：风险应用探测修复（Alpha/爱玩机工具箱/Scene/KernelSU 管理器） ============

    /**
     * 风险工具多证据聚合探测。
     * 目标：Alpha(Magisk Alpha / 阿尔法面具)、爱玩机工具箱、Scene(骁龙工具箱)、KernelSU 管理器。
     * 双数据源枚举 getInstalledPackages(0) + getInstalledApplications(GET_META_DATA) 并读取 App 元数据(标签)，
     * 应对“包名改名 / 包可见性限制”导致的探测失效；KernelSU 底层痕迹(/data/adb/ksud、su 二进制、内核属性标记)
     * 独立于 APP 包名，不依赖管理器 App 是否可见。
     * 降误报：单条弱证据(仅包名命中 / 仅标签命中 / 仅单条底层痕迹)只记录日志，不告警；
     * ≥2 条来源独立的证据同时命中才 SUSPECT。权限不足/读取失败 → 输出【能力受限】，不告警。
     */
    private String toolkitRiskAggregate() {
        StringBuilder out = new StringBuilder();
        int evidence = 0;
        StringBuilder evDetail = new StringBuilder();

        // ---- 证据组1：双源应用枚举 + 元数据(App 标签)，全部捕获异常，读失败仅记录 ----
        Set<String> installed = new HashSet<>();
        Map<String, String> labelByPkg = new HashMap<>();
        int pmFail = 0;
        try {
            List<PackageInfo> pis = ctx.getPackageManager().getInstalledPackages(0);
            for (PackageInfo pi : pis) installed.add(pi.packageName);
        } catch (Exception e) { pmFail++; }
        try {
            List<ApplicationInfo> ais = ctx.getPackageManager().getInstalledApplications(PackageManager.GET_META_DATA);
            for (ApplicationInfo ai : ais) {
                installed.add(ai.packageName);
                try {
                    CharSequence l = ai.loadLabel(ctx.getPackageManager());
                    if (l != null && l.length() > 0) labelByPkg.put(ai.packageName, l.toString());
                } catch (Exception ignored) {}
            }
        } catch (Exception e) { pmFail++; }
        if (pmFail >= 2) {
            return "【能力受限】PackageManager 两次枚举均不可读(可见性/权限受限)，跳过应用聚合判定；已尝试 getInstalledPackages + getInstalledApplications(GET_META_DATA)";
        }
        out.append("双源枚举包数=").append(installed.size());

        // 目标候选包名（包名可能被改名，故同时用标签元数据识别）
        String[][] TARGETS = {
            {"me.weishu.kernelsu", "KernelSU 管理器(官方)"},
            {"com.byyoungset.kernelsu", "KernelSU 管理器"},
            {"com.rifsxd.ksunext", "KernelSU-Next 管理器"},
            {"io.github.a13e300.ksuwebui", "KSU-WebUI"},
            {"io.github.vvb2060.magisk", "Alpha(Magisk Alpha/阿尔法面具)"},
            {"com.omarea.vtools", "Scene(骁龙工具箱)"},
            {"com.byyoung.setting", "爱玩机工具箱"},
            {"com.nenya.aiwanji", "爱玩机工具箱(助手)"}
        };

        // 证据1a：包名命中（弱证据，单条不告警）
        List<String> pkgHit = new ArrayList<>();
        for (String[] t : TARGETS) {
            if (installed.contains(t[0])) pkgHit.add(t[0] + "(" + t[1] + ")");
        }
        if (!pkgHit.isEmpty()) {
            evidence++;
            evDetail.append("包名命中[弱]:").append(String.join(",", pkgHit)).append("; ");
        }

        // 证据1b：App 标签元数据命中（弱证据；用于包名改名场景；仅精确关键词，降低误报）
        List<String> labelHit = new ArrayList<>();
        for (Map.Entry<String, String> e : labelByPkg.entrySet()) {
            if (pkgHit.contains(e.getKey())) continue; // 已按包名命中，避免同一证据重复计数
            String label = e.getValue();
            if (label == null) continue;
            String ll = label.toLowerCase(Locale.US);
            if (ll.contains("kernelsu") || ll.contains("ksu next")
                    || label.contains("爱玩机") || label.contains("阿尔法面具")) {
                labelHit.add(e.getKey() + "(标签:" + label + ")");
            }
        }
        if (!labelHit.isEmpty()) {
            evidence++;
            evDetail.append("标签元数据命中[弱]:").append(String.join(",", labelHit)).append("; ");
        }

        // ---- 证据组2：KernelSU 底层痕迹（独立于 APP 包名，佐证）----
        boolean ksuDaemonBin = exists("/data/adb/ksud");
        boolean suBin = false;
        String suBinPath = "";
        String[] suCandidates = {"/system/bin/su", "/system/xbin/su", "/sbin/su",
                "/data/adb/ksu/bin/su", "/data/adb/ap/bin/su", "/vendor/bin/su"};
        for (String p : suCandidates) {
            if (exists(p)) { suBin = true; suBinPath = p; break; }
        }
        boolean ksuKernelProp = false;
        String kProp = "";
        for (String k : new String[]{"ro.kernel.ksu", "ro.boot.ksu", "init.svc.ksud"}) {
            String v = prop(k);
            if (v != null && !v.isEmpty()) { ksuKernelProp = true; kProp += k + "=" + v + " "; }
        }
        boolean ksuDevOrDmesg = exists("/dev/ksu");
        String dmesgKsu = shExec("dmesg 2>/dev/null | grep -i ksu | head -3");
        if (dmesgKsu != null && !dmesgKsu.trim().isEmpty()) ksuDevOrDmesg = true;
        int ksuTrace = (ksuDaemonBin ? 1 : 0) + (suBin ? 1 : 0) + (ksuKernelProp ? 1 : 0) + (ksuDevOrDmesg ? 1 : 0);
        if (ksuTrace > 0) {
            evidence++;
            evDetail.append("KSU底层痕迹[佐证,").append(ksuTrace).append("]:")
                    .append(ksuDaemonBin ? "/data/adb/ksud " : "")
                    .append(suBin ? ("su二进制:" + suBinPath + " ") : "")
                    .append(ksuKernelProp ? ("内核属性:" + kProp.trim() + " ") : "")
                    .append(ksuDevOrDmesg ? "/dev/ksu或dmesg含ksu " : "")
                    .append("; ");
        }

        // ---- 证据组3：Scene/omarea 进程（独立于包名，佐证）----
        boolean sceneProc = false;
        String psOut = shExec("ps -A 2>/dev/null");
        if (psOut != null) {
            String pl = psOut.toLowerCase(Locale.US);
            if (pl.contains("omarea") || pl.contains("scene")) sceneProc = true;
        }
        if (sceneProc) {
            evidence++;
            evDetail.append("Scene/omarea进程[佐证]:存在; ");
        }

        // ---- 聚合判定 ----
        out.append(" | 独立证据数=").append(evidence);
        if (evDetail.length() > 0) out.append("(").append(evDetail.toString().trim()).append(")");
        if (evidence >= 2) {
            out.append(" | 多证据命中→SUSPECT(≥2条独立证据): ")
                    .append(evDetail.toString().trim());
        } else if (evidence == 1) {
            out.append(" | 单条弱证据(仅日志,不告警): ")
                    .append(evDetail.toString().trim());
        } else {
            out.append(" | 未检出独立风险证据");
        }
        return out.toString();
    }

    // ============ v1.2.21 新增：春秋附录 / 外挂驱动 / 扫盘·路径·UID / 认证·Keystore·内核完整性 ============

    /** 解析聚合探针返回文本的告警等级：→ABNORMAL→1；→SUSPECT→2；【能力受限】/未命中→0 */
    private int detLevel(String log) {
        if (log == null || log.startsWith("【能力受限】")) return 0;
        if (log.contains("→ABNORMAL")) return 1;
        if (log.contains("→SUSPECT")) return 2;
        return 0;
    }

    /** 为聚合探针生成人类可读判定理由（引用完整日志中的证据清单；仅 SUSPECT/ABNORMAL 返回） */
    private String aggReason(String title, String log) {
        int lv = detLevel(log);
        if (lv == 0) return null;
        String tag = lv == 1 ? "ABNORMAL(异常)" : "SUSPECT(可疑)";
        int i = log.indexOf("证据:");
        String ev = i >= 0 ? log.substring(i) : "";
        return "判定" + tag + "：「" + title + "」按≥2条来源独立证据聚合判定"
                + (ev.isEmpty() ? "" : ("，命中证据: " + ev))
                + "；命中明细/原始路径/原始值见完整日志，单条弱特征不告警。";
    }

    /** 春秋附录B：可疑/外挂类风险路径与文件全量扫描（聚合；≥2 命中→ABNORMAL，1 命中→SUSPECT，无→没问题） */
    private String chunqiuRiskPaths() {
        String[] paths = {
            "/data/A内核.ini","/data/BingHPJY/pz.cfg","/data/BingPUBG","/data/Dit驱动",
            "/data/HPX","/data/HPY","/data/encore/custom_default_cpu_gov","/data/encore/default_cpu_gov",
            "/data/gpu_freq_table.conf","/data/js","/data/js.sh","/data/local/MIO","/data/local/luckys",
            "/data/local/stryker/","/data/local/tmp/A内核公益-和平精英0215x1","/data/local/tmp/A内核公益-和平精英0215x1(1)",
            "/data/local/tmp/A内核公益-和平精英0215x1(2)","/data/local/tmp/DisabledAllGoogleServices",
            "/data/local/tmp/HyperCeiler","/data/local/tmp/Surfing_update","/data/local/tmp/android_server",
            "/data/local/tmp/android_server64","/data/local/tmp/cleaner_starter","/data/local/tmp/encore_logo.png",
            "/data/local/tmp/gdbserver","/data/local/tmp/horae_control.log","/data/local/tmp/luckys",
            "/data/local/tmp/mount_mask","/data/local/tmp/resetprop","/data/local/tmp/scriptTMP",
            "/data/local/tmp/simpleHook","/data/local/tmp/yshell","/data/local/中野三玖","/data/nh.ko",
            "/data/nh2","/data/nh3","/data/nh4","/data/nh5","/data/swap_config.conf","/data/system/AppRetention",
            "/data/system/Freezer/","/data/system/HPX","/data/system/HPY","/data/system/NoActive/",
            "/data/system/junge/","/data/system/liboxmem.so","/data/system/xydriver.ko",
            "/data/南瓜三角洲公益最新版本.sh","/data/物资.txt","/dev/Bing",
            "/my_product/etc/permissions/oplus_google_cn_gms_features.xml",
            "/sdcard/Download/com.niunaijun.blackdexa64_logcat.txt","/sdcard/Download/dexdump/","/sdcard/fart",
            "/storage/emulated/0/Android/Clash/","/storage/emulated/0/Android/HChai/",
            "/storage/emulated/0/Android/Yume-Yunyun/","/storage/emulated/0/Android/naki/",
            "/storage/emulated/0/Documents/advanced/","/storage/emulated/0/Download/advanced/",
            "/storage/emulated/0/MT2/","/storage/emulated/0/TpTestReport/screenOn/OK/0/",
            "/storage/emulated/0/rlgg/","/storage/emulated/0/弱隐.sh","/storage/emulated/0/落叶配置",
            "/storage/emulated/elgg/"
        };
        List<String> hits = new ArrayList<>();
        for (String p : paths) {
            try { if (exists(p)) hits.add(p); } catch (Exception ignored) {}
        }
        StringBuilder out = new StringBuilder();
        out.append("扫描附录B风险路径/文件 ").append(paths.length).append(" 条");
        if (hits.isEmpty()) out.append(" → 未命中,没问题");
        else {
            out.append(" → 命中 ").append(hits.size()).append(" 条:").append(String.join(",", hits));
            if (hits.size() >= 2) out.append(" | 聚合判定→ABNORMAL");
            else out.append(" | 单条命中→SUSPECT(需复核)");
        }
        return out.toString();
    }

    /** 春秋附录C：被检查系统属性基线（属性为弱特征，仅 INFO 基线，不单点告警） */
    private String chunqiuPropsCoverage() {
        String[] keys = {
            "dalvik.vm.dex2oat-flags","persist.chunqiu.path_hide",
            "persist.debug.dalvik.vm.core_platform_api_policy",
            "persist.logd.size","persist.logd.size.crash","persist.logd.size.main","persist.logd.size.system",
            "persist.sys.pihooks.disable.gms","persist.sys.pihooks_BRAND","persist.sys.pihooks_DEVICE",
            "persist.sys.pihooks_DEVICE_INIT","persist.sys.pihooks_MANUFACTURE","persist.sys.pihooks_MODEL",
            "persist.sys.pihooks_PRODUCT","persist.sys.pihooks_RELEASE","persist.sys.pihooks_SDK_INT",
            "persist.sys.pixelprops.gapps","persist.sys.pixelprops.gms","persist.sys.pixelprops.google",
            "persist.sys.pixelprops.gphotos","persist.sys.spoof.gms",
            "persist.sys.vold_app_data_isolation_enabled",
            "ro.boot.flash.locked","ro.boot.selinux","ro.boot.vbmeta.avb_version",
            "ro.boot.vbmeta.device_state","ro.boot.vbmeta.digest","ro.boot.verifiedbootstate",
            "ro.build.date.utc","ro.build.type","ro.build.version.sdk","ro.product.brand"};
        List<String> set = new ArrayList<>();
        for (String k : keys) { String v = prop(k); if (v != null && !v.isEmpty()) set.add(k + "=" + v); }
        StringBuilder out = new StringBuilder();
        out.append("附录C系统属性 ").append(keys.length).append(" 项，已设置 ").append(set.size()).append(" 项");
        if (!set.isEmpty()) out.append(": ").append(String.join(" ", set));
        out.append("（属性为弱特征，仅INFO基线，不单点告警）");
        return out.toString();
    }

    /** 外挂驱动检测：可疑 .ko 驱动/内核模块签名//dev 节点/驱动模块目录 四类独立证据，≥2 聚合→ABNORMAL */
    private String cheatDriverProbe() {
        int ev = 0; StringBuilder detail = new StringBuilder();
        // 证据1：可疑 .ko 外挂驱动文件
        String koOut = shExec("find /data/local/tmp /data /sdcard /storage/emulated/0/Download -maxdepth 3 -type f -name '*.ko' 2>/dev/null | head -60");
        List<String> koHits = new ArrayList<>();
        if (koOut != null) for (String l : koOut.split("\n")) {
            String p = l.trim(); if (p.isEmpty()) continue;
            String pl = p.toLowerCase(Locale.US);
            if (pl.contains("cheat")||pl.contains("hack")||pl.contains("ghost")||pl.contains("esp")
                ||pl.contains("aim")||pl.contains("driver")||pl.contains("nh.ko")||pl.contains("xydriver")
                ||pl.contains("外挂")||pl.contains("内核")) koHits.add(p);
        }
        if (!koHits.isEmpty()) { ev++; detail.append("可疑驱动文件[").append(koHits.size()).append("]:").append(String.join(",", koHits)).append("; "); }
        // 证据2：内核模块列表驱动签名
        String mods = read("/proc/modules");
        List<String> modHits = new ArrayList<>();
        if (mods != null) for (String l : mods.split("\n")) {
            String ll = l.toLowerCase(Locale.US);
            if (ll.contains("cheat")||ll.contains("hack")||ll.contains("esp")||ll.contains("aim")
                ||ll.contains("nh.ko")||ll.contains("xydriver")||ll.contains("外挂")) modHits.add(l.trim());
        }
        if (!modHits.isEmpty()) { ev++; detail.append("内核模块驱动签名[").append(modHits.size()).append("]:").append(String.join(",", modHits)).append("; "); }
        // 证据3：/dev 外挂驱动节点
        List<String> devHits = new ArrayList<>();
        String devLs = shExec("ls /dev 2>/dev/null");
        if (devLs != null) for (String l : devLs.split("\n")) {
            String ll = l.toLowerCase(Locale.US);
            if (ll.contains("cheat")||ll.contains("hack")||ll.contains("ghost")||ll.contains("esp")
                ||ll.contains("aim")||ll.contains("bing")||ll.contains("nh")) devHits.add(l.trim());
        }
        if (!devHits.isEmpty()) { ev++; detail.append("/dev节点[").append(devHits.size()).append("]:").append(String.join(",", devHits)).append("; "); }
        // 证据4：驱动注入模块目录
        if (exists("/data/adb/modules/nh")||exists("/data/adb/modules/ghost")||exists("/data/adb/modules/esp")
            ||exists("/data/adb/modules/cheat")||exists("/data/adb/modules/xydriver")) { ev++; detail.append("驱动模块目录:命中; "); }

        StringBuilder out = new StringBuilder();
        out.append("证据数=").append(ev);
        if (detail.length() > 0) out.append("(证据:").append(detail.toString().trim()).append(")");
        if (ev >= 2) out.append(" | 聚合判定→ABNORMAL");
        else if (ev == 1) out.append(" | 单条命中→SUSPECT(需复核)");
        else out.append(" → 未检出外挂驱动,没问题");
        return out.toString();
    }

    /** 扫盘检测：跨高风险目录扫描作弊/工具特征文件，≥2 聚合→ABNORMAL */
    private String diskScanProbe() {
        int ev = 0; StringBuilder detail = new StringBuilder();
        String[] roots = {"/data/local/tmp", "/sdcard/Download", "/data/local", "/storage/emulated/0/Android"};
        String[] pats = {"cheat","hack","payload","esp","aim","外挂","内核","android_server","luckys","ghost","driver"};
        List<String> seen = new ArrayList<>();
        for (String root : roots) {
            String out = shExec("find " + root + " -maxdepth 2 2>/dev/null | head -1200");
            if (out == null) continue;
            for (String l : out.split("\n")) {
                String p = l.trim();
                if (p.isEmpty() || p.equals(root)) continue;
                String pl = p.toLowerCase(Locale.US);
                boolean hit = false;
                for (String pat : pats) if (pl.contains(pat)) { hit = true; break; }
                if (hit && !seen.contains(p)) { seen.add(p); ev++; detail.append(p).append(' '); }
            }
        }
        StringBuilder out = new StringBuilder();
        out.append("扫描4个高风险目录,命中特征条目 ").append(ev);
        if (detail.length() > 0) out.append("(命中:").append(detail.toString().trim()).append(")");
        if (ev >= 2) out.append(" | 聚合判定→ABNORMAL");
        else if (ev == 1) out.append(" | 单条命中→SUSPECT(需复核)");
        else out.append(" → 未检出异常,没问题");
        return out.toString();
    }

    /** 路径检测：su 二进制/可疑挂载/隐藏目录//system 可写/debug_ramdisk，≥2 聚合→ABNORMAL */
    private String pathScanProbe() {
        int ev = 0; StringBuilder detail = new StringBuilder();
        List<String> suHits = new ArrayList<>();
        for (String p : new String[]{"/system/bin/su","/system/xbin/su","/sbin/su","/vendor/bin/su",
                "/data/adb/ksu/bin/su","/data/adb/ap/bin/su"}) {
            try { if (exists(p)) suHits.add(p); } catch (Exception ignored) {}
        }
        if (!suHits.isEmpty()) { ev++; detail.append("su二进制[").append(suHits.size()).append("]:").append(String.join(",", suHits)).append("; "); }
        String mi = read("/proc/self/mounts");
        if (mi != null && (mi.contains("magisk")||mi.contains("ksu")||mi.contains("apatch")||mi.contains("tricky"))) {
            ev++; detail.append("挂载含root痕迹; ");
        }
        boolean extHidden = false;
        try { extHidden = exists("/system/bin/.ext/.su")||exists("/system/.ext/.su")||exists("/system/bin/.ext")||exists("/system/xbin/.ext"); } catch (Exception ignored) {}
        if (extHidden) { ev++; detail.append("隐藏.ext目录; "); }
        boolean sysW = false;
        try { sysW = new File("/system").canWrite(); } catch (Exception ignored) {}
        if (sysW) { ev++; detail.append("/system可写; "); }
        if (exists("/debug_ramdisk")||exists("/sbin/recovery")) { ev++; detail.append("debug_ramdisk/recovery痕迹; "); }
        StringBuilder out = new StringBuilder();
        out.append("证据数=").append(ev);
        if (detail.length() > 0) out.append("(证据:").append(detail.toString().trim()).append(")");
        if (ev >= 2) out.append(" | 聚合判定→ABNORMAL");
        else if (ev == 1) out.append(" | 单条命中→SUSPECT(需复核)");
        else out.append(" → 未检出路径异常,没问题");
        return out.toString();
    }

    /** UID 检测：当前 UID/能力位/补充组/异常 UID 应用/可调试应用，≥2 聚合→ABNORMAL */
    private String uidScanProbe() {
        int ev = 0; StringBuilder detail = new StringBuilder();
        String status = read("/proc/self/status");
        String uid = statusLine(status, "Uid");
        if (uid != null && uid.trim().startsWith("0")) { ev++; detail.append("当前UID=0(root); "); }
        String capEff = statusLine(status, "CapEff");
        if (capEff != null && !capEff.trim().replace("0", "").isEmpty()) { ev++; detail.append("CapEff=" + capEff.trim() + "; "); }
        String groups = statusLine(status, "Groups");
        if (groups != null && groups.contains(" 0 ")) { ev++; detail.append("补充组含root(0); "); }
        String[] auid = abnormalUidApps();
        if (auid[1] != null && !auid[1].isEmpty()) { ev++; detail.append("异常UID应用:" + auid[1] + "; "); }
        String[] dbg = debuggableApps();
        if (dbg[1] != null && !dbg[1].isEmpty()) { ev++; detail.append("可调试应用:" + dbg[1] + "; "); }
        StringBuilder out = new StringBuilder();
        out.append("证据数=").append(ev);
        if (detail.length() > 0) out.append("(证据:").append(detail.toString().trim()).append(")");
        if (ev >= 2) out.append(" | 聚合判定→ABNORMAL");
        else if (ev == 1) out.append(" | 单条命中→SUSPECT(需复核)");
        else out.append(" → 未检出UID异常,没问题");
        return out.toString();
    }

    /** 硬件认证完整性：KeyStore 硬件安全级别 + Root-of-Trust 交叉 + 设备属性差分，≥3→ABNORMAL ≥2→SUSPECT */
    private String attestationDepthProbe() {
        int ev = 0; StringBuilder detail = new StringBuilder();
        try {
            KeyGenerator kg = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore");
            KeyGenParameterSpec spec = new KeyGenParameterSpec.Builder("dc_att_depth", KeyProperties.PURPOSE_ENCRYPT)
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM).setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE).build();
            kg.init(spec); kg.generateKey();
            KeyStore ks = KeyStore.getInstance("AndroidKeyStore"); ks.load(null);
            Key key = ks.getKey("dc_att_depth", null);
            boolean secure = key instanceof KeyInfo && ((KeyInfo) key).isInsideSecureHardware();
            if (!secure) { ev++; detail.append("KeyStore非硬件安全(软件密钥); "); }
            try { ks.deleteEntry("dc_att_depth"); } catch (Exception ignored) {}
        } catch (Exception ignored) {}
        String vb = prop("ro.boot.verifiedbootstate");
        if (vb != null && ("orange".equals(vb)||"red".equals(vb))) { ev++; detail.append("verifiedbootstate=" + vb + "; "); }
        String fl = prop("ro.boot.flash.locked");
        if (fl != null && !"1".equals(fl)) { ev++; detail.append("flash.locked=" + fl + "; "); }
        String brand = prop("ro.product.brand"), vbrand = prop("ro.product.vendor.brand");
        if (brand != null && vbrand != null && !brand.equals(vbrand)) { ev++; detail.append("brand与vendor.brand不一致; "); }
        StringBuilder out = new StringBuilder();
        out.append("证据数=").append(ev);
        if (detail.length() > 0) out.append("(证据:").append(detail.toString().trim()).append(")");
        if (ev >= 3) out.append(" | 聚合判定→ABNORMAL");
        else if (ev >= 2) out.append(" | 聚合判定→SUSPECT");
        else out.append(" → 认证维度未见异常,没问题");
        return out.toString();
    }

    /** Keystore 完整性：鉴权路径时延侧信道 + 别名隔离 + AES-GCM 篡改 tag 负例，≥2 聚合→SUSPECT/ABNORMAL */
    private String keystoreIntegrityProbe() {
        int ev = 0; StringBuilder detail = new StringBuilder();
        String timing = timingSideChannel();
        if (timing.contains("疑似 KSU/APatch 内核鉴权补丁")) { ev++; detail.append("鉴权路径时延异常; "); }
        try {
            KeyStore ks = KeyStore.getInstance("AndroidKeyStore"); ks.load(null);
            if (ks.containsAlias("dc_nonexist_keystore_probe")) { ev++; detail.append("别名隔离异常(不存在别名可读); "); }
        } catch (Exception ignored) {}
        try {
            javax.crypto.Cipher enc = javax.crypto.Cipher.getInstance("AES/GCM/NoPadding");
            javax.crypto.KeyGenerator kg = javax.crypto.KeyGenerator.getInstance("AES");
            kg.init(128);
            javax.crypto.SecretKey sk = kg.generateKey();
            enc.init(javax.crypto.Cipher.ENCRYPT_MODE, sk);
            byte[] ct = enc.doFinal("probe-data".getBytes(StandardCharsets.UTF_8));
            byte[] iv = enc.getIV();
            byte[] tampered = ct.clone();
            if (tampered.length >= 1) tampered[tampered.length - 1] ^= 0x01;
            javax.crypto.Cipher dec = javax.crypto.Cipher.getInstance("AES/GCM/NoPadding");
            javax.crypto.spec.GCMParameterSpec gspec = new javax.crypto.spec.GCMParameterSpec(128, iv);
            dec.init(javax.crypto.Cipher.DECRYPT_MODE, sk, gspec);
            byte[] pt = dec.doFinal(tampered);
            if (pt != null) { ev++; detail.append("AES-GCM篡改tag仍解密成功(完整性缺失); "); }
        } catch (Exception ignored) { /* 篡改后解密失败为正常行为，不计证据 */ }
        StringBuilder out = new StringBuilder();
        out.append("证据数=").append(ev);
        if (detail.length() > 0) out.append("(证据:").append(detail.toString().trim()).append(")");
        if (ev >= 3) out.append(" | 聚合判定→ABNORMAL");
        else if (ev >= 2) out.append(" | 聚合判定→SUSPECT");
        else out.append(" → Keystore完整性未见异常,没问题");
        return out.toString();
    }

    /** 内核身份与运行时完整性：内核版本非官方 + 运行时注入路径 + debug_ramdisk/回环，≥2 聚合→SUSPECT/ABNORMAL */
    private String kernelIdentityProbe() {
        int ev = 0; StringBuilder detail = new StringBuilder();
        String kver = kernelVersion();
        if (kver != null && (kver.contains("-Dirty")||kver.contains("-custom")||kver.contains("-ksu")
            ||kver.contains("-apatch")||kver.contains("-GKI"))) { ev++; detail.append("内核版本非官方(" + kver.trim() + "); "); }
        String maps = read("/proc/self/maps");
        List<String> inj = new ArrayList<>();
        if (maps != null) for (String l : maps.split("\n")) {
            String ll = l.toLowerCase(Locale.US);
            for (String k : new String[]{"frida","gum-js","lspd","riru","sandhook","edxposed","whale","libinject"})
                if (ll.contains(k)) { inj.add(k); break; }
        }
        if (!inj.isEmpty()) { ev++; detail.append("运行时注入痕迹[" + inj.size() + "]:" + String.join(",", inj) + "; "); }
        boolean ramdisk = false;
        try { ramdisk = exists("/debug_ramdisk")||exists("/data/adb/recovery")||exists("/dev/block/loop"); } catch (Exception ignored) {}
        if (ramdisk) { ev++; detail.append("debug_ramdisk/回环镜像痕迹; "); }
        StringBuilder out = new StringBuilder();
        out.append("证据数=").append(ev);
        if (detail.length() > 0) out.append("(证据:").append(detail.toString().trim()).append(")");
        if (ev >= 3) out.append(" | 聚合判定→ABNORMAL");
        else if (ev >= 2) out.append(" | 聚合判定→SUSPECT");
        else out.append(" → 内核/运行时维度未见异常,没问题");
        return out.toString();
    }

    // ============ v1.2.17 新增检测点（全部遵守降误报策略：单点仅日志，多点聚合才告警） ============
    /**
     * 1. 应用组件隐藏探测：
     * 只针对已知风险应用列表（高危/工具包/虚拟化/春秋黑名单）做组件隐藏交叉判定；
     * 系统应用与普通第三方应用（含厂商工具、普通 App 组件）一律不参与，避免误报。
     * 日志只列异常风险包名（短日志）：风险包已安装、但其 exported+enabled 关键组件几乎全部 resolve 失败，
     * 视为被隐藏。仅输出命中的风险包名。
     */
    private String componentHiddenProbe() {
        Set<String> riskPkgs = new HashSet<>();
        for (String p : HIGH_PKGS) riskPkgs.add(p);
        for (String p : WEAK_PKGS) riskPkgs.add(p);
        for (String p : CHUNQIU_A) riskPkgs.add(p);
        for (String p : VIRT_PKGS) riskPkgs.add(p);

        PackageManager pm = ctx.getPackageManager();
        StringBuilder susp = new StringBuilder();
        int checked = 0;
        try {
            for (String pkg : riskPkgs) {
                PackageInfo pi;
                try {
                    pi = pm.getPackageInfo(pkg, PackageManager.GET_ACTIVITIES
                            | PackageManager.GET_RECEIVERS | PackageManager.GET_SERVICES
                            | PackageManager.GET_PROVIDERS);
                } catch (PackageManager.NameNotFoundException notInstalled) {
                    continue; // 风险包未安装：正常，不报
                } catch (Exception ignored) { continue; }
                checked++;
                int total = 0, fail = 0;
                if (pi.activities != null) for (ActivityInfo a : pi.activities) {
                    if (!(a.enabled && a.exported)) continue;
                    total++;
                    try { Intent i = new Intent(); i.setClassName(pkg, a.name); if (pm.resolveActivity(i, 0) == null) fail++; }
                    catch (Exception ignored) {}
                }
                if (pi.receivers != null) for (ActivityInfo a : pi.receivers) {
                    if (!(a.enabled && a.exported)) continue;
                    total++;
                    try { Intent i = new Intent(); i.setClassName(pkg, a.name); if (pm.resolveActivity(i, 0) == null) fail++; }
                    catch (Exception ignored) {}
                }
                if (pi.services != null) for (ServiceInfo s : pi.services) {
                    if (!(s.enabled && s.exported)) continue;
                    total++;
                    try { Intent i = new Intent(); i.setClassName(pkg, s.name); if (pm.resolveService(i, 0) == null) fail++; }
                    catch (Exception ignored) {}
                }
                if (pi.providers != null) for (ProviderInfo pr : pi.providers) {
                    if (!(pr.enabled && pr.exported)) continue;
                    total++;
                    boolean resolved = false;
                    if (pr.authority != null && !pr.authority.trim().isEmpty()) {
                        for (String auth : pr.authority.split(";")) {
                            try { if (pm.resolveContentProvider(auth.trim(), 0) != null) { resolved = true; break; } }
                            catch (Exception ignored) {}
                        }
                    }
                    if (!resolved) fail++;
                }
                // 风险包已安装且关键组件几乎全部解析失败 = 疑似被 HMA 隐藏
                if (total > 0 && fail == total) susp.append(pkg).append(' ');
            }
        } catch (Exception e) { return "受限:" + e.getClass().getSimpleName(); }

        if (susp.length() == 0) return "未发现风险应用组件隐藏(已核对 " + checked + " 个已知风险包)";
        return "风险应用组件异常(疑似被隐藏): " + susp.toString().trim();
    }

    /**
     * 2. 包签名多源一致性校验：
     * 途径A：PackageManager API 获取应用签名；途径B：直接读取对应 APK 文件解析签名；
     * 同一应用两份签名摘要不一致 → 标记 SUSPECT，输出包名与两份签名摘要；
     * APK 读取失败仅日志，不告警。
     */
    private String signatureMultiSource() {
        StringBuilder sus = new StringBuilder();
        StringBuilder notes = new StringBuilder();
        int checked = 0;
        try {
            PackageManager pm = ctx.getPackageManager();
            List<ApplicationInfo> apps = pm.getInstalledApplications(0);
            for (ApplicationInfo ai : apps) {
                String pkg = ai.packageName;
                String srcDir = ai.sourceDir;
                if (srcDir == null || !new File(srcDir).exists()) continue;
                String pmSig = null, fileSig = null;
                try {
                    PackageInfo pi = pm.getPackageInfo(pkg, PackageManager.GET_SIGNATURES);
                    if (pi.signatures != null && pi.signatures.length > 0) pmSig = sigDigest(pi.signatures[0]);
                } catch (Exception ignored) {}
                try {
                    PackageInfo fpi = pm.getPackageArchiveInfo(srcDir, PackageManager.GET_SIGNATURES);
                    if (fpi != null && fpi.signatures != null && fpi.signatures.length > 0) fileSig = sigDigest(fpi.signatures[0]);
                } catch (Exception ignored) { notes.append(pkg).append("(APK签名读取失败) "); }
                if (pmSig != null && fileSig != null) {
                    checked++;
                    if (!pmSig.equals(fileSig)) {
                        sus.append(pkg).append("(PM:").append(pmSig).append(" APK:").append(fileSig).append(") ");
                    }
                }
            }
        } catch (Exception e) { return "受限:" + e.getClass().getSimpleName(); }
        if (sus.length() > 0) return "签名不一致 " + sus.toString().trim() + (notes.length() > 0 ? " | " + notes.toString().trim() : "");
        if (checked == 0) return "签名多源比对受限(无可比对样本)" + (notes.length() > 0 ? " | " + notes.toString().trim() : "");
        return "签名多源一致(" + checked + " 个应用两份签名一致)" + (notes.length() > 0 ? " | " + notes.toString().trim() : "");
    }

    /** 签名证书 SHA-256 摘要（十六进制小写） */
    private String sigDigest(Signature sig) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] d = md.digest(sig.toByteArray());
            StringBuilder sb = new StringBuilder();
            for (byte b : d) sb.append(String.format(Locale.US, "%02x", b));
            return sb.toString();
        } catch (Exception e) { return null; }
    }

    /**
     * 3. su 特征聚合汇总检测：
     * 聚合多项 su 相关探针结果：su 二进制文件存在、su 相关系统属性、su uid0 进程痕迹；
     * 单一项特征命中：仅日志记录；至少 2 项及以上独立特征同时命中才输出 SUSPECT。
     */
    private String suFeatureAggregate() {
        StringBuilder detail = new StringBuilder();
        int hits = 0;
        // 特征1：su 二进制文件存在
        boolean bin = false;
        for (String[] s : SU_PATHS) if (exists(s[0])) { bin = true; break; }
        if (bin) { hits++; detail.append("su二进制存在 "); }
        // 特征2：su 相关系统属性（弱特征）
        boolean suProp = false;
        String rootAccess = prop("persist.sys.root_access");
        boolean paHit = rootAccess != null && !"0".equals(rootAccess);
        boolean dbgProp = "1".equals(prop("ro.debuggable"));
        boolean secureProp = "0".equals(prop("ro.secure"));
        suProp = paHit || dbgProp || secureProp;
        if (suProp) {
            hits++; detail.append("su相关属性(");
            if (paHit) detail.append("persist.sys.root_access=").append(rootAccess).append(' ');
            if (dbgProp) detail.append("ro.debuggable=1 ");
            if (secureProp) detail.append("ro.secure=0 ");
            detail.append(") ");
        }
        // 特征3：su uid0 进程痕迹（root 用户下运行的 su 相关进程）
        boolean uid0 = false;
        String psOut = shExec("ps -A -o USER,NAME 2>/dev/null || ps -A 2>/dev/null");
        if (psOut != null) {
            String lower = psOut.toLowerCase();
            for (String n : new String[]{"su", "daemonsu", "magiskd", "ksud", "apd", "supolicy"}) {
                if (lower.contains("root") && lower.contains(n)) { uid0 = true; detail.append("root进程:").append(n).append(' '); break; }
            }
        }
        if (uid0) hits++;

        if (hits == 0) return "su特征聚合:无特征命中";
        if (hits >= 2) return "su特征聚合:多特征命中(" + hits + "项): " + detail.toString().trim();
        return "su特征聚合:单特征命中(仅记录): " + detail.toString().trim();
    }

    /**
     * 4. persist.* 属性篡改残留收集：
     * 遍历系统 persist.* 前缀属性，收集全部非出厂常见 persist 键值对，完整输出键、值；
     * 没有确凿证据情况下不自动输出 SUSPECT，仅做日志收集供人工研判。
     */
    private String persistPropCollection() {
        String out = shExec("getprop 2>/dev/null");
        if (out == null || out.trim().isEmpty()) return "persist 属性不可读";
        String[] common = {"persist.sys.language","persist.sys.country","persist.sys.locale","persist.sys.timezone",
                "persist.sys.usb.config","persist.sys.dalvik.vm.lib.2","persist.sys.log.main","persist.sys.log.tag",
                "persist.sys.boot.time","persist.sys.time_zone","persist.sys.miui","persist.sys.vivo",
                "persist.radio","persist.vendor.radio","persist.sys.compatibility_mode","persist.sys.display_cabc",
                "persist.sys.root_access","persist.sys.backgroundwindow","persist.sys.disable_rescue"};
        StringBuilder sb = new StringBuilder();
        int n = 0;
        for (String line : out.split("\n")) {
            line = line.trim();
            if (!line.startsWith("[persist.")) continue;
            int end = line.indexOf(']');
            if (end < 0) continue;
            String key = line.substring(1, end);
            boolean commonHit = false;
            for (String c : common) if (key.startsWith(c)) { commonHit = true; break; }
            if (commonHit) continue;
            String val = end + 2 < line.length() ? line.substring(end + 2).trim() : "";
            sb.append(key).append('=').append(val).append(' ');
            n++;
            if (n >= 40) break;
        }
        if (n == 0) return "persist 属性均属出厂常见值(无异常残留)";
        return "persist 异常键值 " + n + " 项(仅收集供人工研判): " + sb.toString().trim();
    }

    /**
     * 5. Zygisk / Shamiko 间接痕迹聚合检测：
     * 读取 /proc 下各进程 mount 信息、进程环境变量，收集 Shamiko、Zygisk 相关间接痕迹；
     * 单条痕迹仅记录日志；多条独立间接痕迹同时命中才输出 SUSPECT。
     */
    private String zygiskShamikoTrace() {
        StringBuilder detail = new StringBuilder();
        int hits = 0;
        // 痕迹1：/proc/*/mountinfo 含 zygisk/shamiko 模块挂载
        boolean mountHit = procScanContains("mountinfo", new String[]{"zygisk", "shamiko"});
        if (mountHit) { hits++; detail.append("mountinfo模块挂载 "); }
        // 痕迹2：/proc/*/maps 含 zygisk/shamiko 库
        boolean mapsHit = procScanContains("maps", new String[]{"zygisk", "shamiko"});
        if (mapsHit) { hits++; detail.append("maps库 "); }
        // 痕迹3：/proc/*/environ 进程环境变量含 zygisk/shamiko
        boolean envHit = procScanContains("environ", new String[]{"zygisk", "shamiko"});
        if (envHit) { hits++; detail.append("environ环境变量 "); }
        // 痕迹4：/data/adb/modules 下 zygisk/shamiko 模块目录
        String mods = shExec("ls /data/adb/modules 2>/dev/null");
        boolean modHit = mods != null && (mods.contains("zygisk") || mods.contains("shamiko"));
        if (modHit) { hits++; detail.append("modules目录 "); }

        if (hits == 0) return "Zygisk/Shamiko痕迹聚合:无间接痕迹";
        if (hits >= 2) return "Zygisk/Shamiko痕迹聚合:多特征命中(" + hits + "项): " + detail.toString().trim();
        return "Zygisk/Shamiko痕迹聚合:单特征命中(仅记录): " + detail.toString().trim();
    }

    /** 扫描 /proc 下各进程指定子文件是否含任一关键字（权限不足/读失败跳过，不告警） */
    private boolean procScanContains(String subFile, String[] keywords) {
        File proc = new File("/proc");
        File[] pids = proc.listFiles();
        if (pids == null) return false;
        int scanned = 0;
        for (File f : pids) {
            if (!f.getName().matches("\\d+")) continue;
            String content = read(f.getPath() + "/" + subFile);
            if (content != null) {
                String lower = content.toLowerCase();
                for (String k : keywords) if (lower.contains(k)) return true;
            }
            if (++scanned > 300) break;
        }
        return false;
    }
}
