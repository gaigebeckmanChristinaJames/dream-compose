package com.zuomeng.app;

import android.content.Context;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
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
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.UUID;
import java.util.regex.Pattern;

import javax.crypto.KeyGenerator;

/**
 * 做梦环境检测引擎 v1.2.0
 * 整合：zuomeng_check.sh 34 节 + 春秋检测(Chunqiu)全部检测项(含附录A/B/C) + DuckDetector 15 大检测域可行探针
 * 检测点总数约 250，全部在子线程执行；需要 root/native 的探针以"受限(LOW)"级别如实记录。
 */
public class DetectionEngine {

    /** 实时进度回调：每个检测点完成后触发 */
    public interface ProgressListener {
        void onProgress(DetectionResult result, int done, int total, String category, String title);
    }

    /** 检测点总数：固定 312 项 = 离线 306（第一页）+ 联网 6（第二页），与 run()/runOnline() 实际输出一致 */
    public static final int TOTAL = 313;
    /** 离线检测点（第一页，不联网） */
    public static final int TOTAL_OFFLINE = 307;
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
        String pmd = pkgMatchDiff();
        r(cat,"包管理器全量查询差异", pmd, pmd.contains("差异")?2:0);
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
        r(cat,"全盘异常目录名", susDir==null||susDir.trim().isEmpty()?"未见":susDir.replace('\n',' ').trim(), susDir!=null&&!susDir.trim().isEmpty()?2:0);
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
        if (serviceOut != null) for (String k : new String[]{"frida","lspd","xposed","magisk","ksu","apatch","shizuku","thanox","scene","tricky","zygisk","clash","proxy"})
            if (serviceOut.toLowerCase().contains(k)) svcHit.append(k).append(' ');
        r(cat,"可疑系统服务", svcHit.length()>0?svcHit.toString().trim():"未见", svcHit.length()>0?2:0);
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
        r(cat,"KeyStore 硬件安全级别(KeyInfo)", kd, kd.contains("软件")?2:0);
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
            boolean slow = r1 > 1.6;
            r(cat,"KO 时延侧信道(/data/adb)", "stat时延比="+String.format(Locale.US,"%.2f",r1)+(slow?" → 疑似内核 hook(仅记录)":""), slow?3:0);
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
        // 综合判定：多个通道交叉验证
        boolean adbOnByGlobal = "1".equals(adbGlobal);
        boolean adbOnBySvc = "running".equals(adbdSvc);
        boolean adbSusp = (adbOnByGlobal || adbOnBySvc) && !"0".equals(adbSecure);
        r(cat,"ADB多通道状态", "settings="+adbGlobal+" adbd_service="+adbdSvc+" socket="+(adbdSocket?"存在":"无")+" secure="+adbSecure, adbSusp?2:0);
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
        r(cat,"敏感路径可读性", pathHit.length()>0?pathHit.toString().trim():"全部不可读(正常)", pathHit.length()>0?2:0);
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

        // /data/app/ 包名交叉验证：文件系统存在 vs PackageManager可见
        // HMA隐藏应用后PackageManager查不到，但APK文件仍在/data/app/下
        String dataAppScan = dataAppPackageCrossCheck();
        r(cat,"/data/app包名交叉验证(HMA检测)", dataAppScan,
                dataAppScan.startsWith("风险")?1:(dataAppScan.startsWith("HMA")?2:0));

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
        StringBuilder h = new StringBuilder();
        for (String k : new String[]{"magisk","ksu","apatch","tricky","zygisk","frida","/data/adb","hide","spoof"})
            if (mountinfo.toLowerCase().contains(k)) h.append(k).append(' ');
        return h.length() > 0 ? "命中:"+h.toString().trim() : "未见异常";
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

    private boolean pkgKnown(String pkg) {
        // 高通/联发科/系统服务白名单：这些组件通常不作为独立 APK 安装，不算隐藏
        String n = pkg.toLowerCase();
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

    /** 通道6：包管理器 MATCH_UNINSTALLED 全量查询，对比被禁用/残留的包 */
    private String pkgMatchDiff() {
        try {
            int base = ctx.getPackageManager().getInstalledPackages(0).size();
            int full = ctx.getPackageManager().getInstalledPackages(
                    PackageManager.MATCH_UNINSTALLED_PACKAGES | PackageManager.MATCH_DISABLED_COMPONENTS).size();
            return "常规=" + base + " 全量=" + full + (full > base ? " · 差异 " + (full - base) + " 个(禁用/卸载残留)" : "");
        } catch (Exception e) { return "受限:" + e.getClass().getSimpleName(); }
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

    /** KeyStore 硬件安全级别：KeyInfo.isInsideSecureHardware / getSecurityLevel */
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
            if (key instanceof KeyInfo) {
                KeyInfo ki = (KeyInfo) key;
                String lvl = String.valueOf(ki.getSecurityLevel());
                return "硬件背书=" + ki.isInsideSecureHardware() + " 安全级别=" + lvl;
            }
            return "非硬件 KeyInfo(疑似软件模拟)";
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
        String[] keys = {"hook","xposed","frida","cheat","macro","lucky","deviceid","spoof","clone",
                "virtual","hidemyapp","magisk","ksu","apatch","noactive","freezer","fakelocation","autoclick"};
        try {
            List<ApplicationInfo> apps = ctx.getPackageManager().getInstalledApplications(0);
            for (ApplicationInfo ai : apps) {
                if ((ai.flags & ApplicationInfo.FLAG_SYSTEM) != 0) continue;
                if (OEM_WHITELIST.contains(ai.packageName)) continue;
                String n = ai.packageName.toLowerCase();
                for (String k : keys) if (n.contains(k)) { h.append(ai.packageName).append(' '); break; }
            }
        } catch (Exception ignored) {}
        return h.length() > 0 ? h.toString().trim() : "未发现";
    }

    /** 系统应用包名 hook/作弊关键字（强关键字全量命中；弱关键字仅对非 OEM 应用生效，避免厂商组件误报） */
    private String systemAppHookScan() {
        StringBuilder h = new StringBuilder();
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
                if (hit) h.append(ai.packageName).append(' ');
            }
        } catch (Exception ignored) {}
        return h.length() > 0 ? h.toString().trim() : "未发现";
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
}
