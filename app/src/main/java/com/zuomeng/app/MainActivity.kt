package com.zuomeng.app

import android.content.ContentValues
import android.content.Context
import android.net.Uri
import android.os.Build
import android.os.Bundle
import android.os.Environment
import android.os.Handler
import android.os.Looper
import android.provider.MediaStore
import android.widget.Toast
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.WindowInsets
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.safeDrawingPadding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Cloud
import androidx.compose.material.icons.filled.FileDownload
import androidx.compose.material.icons.filled.List
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.FloatingActionButton
import androidx.compose.material3.Icon
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.NavigationBar
import androidx.compose.material3.NavigationBarItem
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.core.view.WindowCompat
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.io.File
import java.io.FileOutputStream
import java.io.OutputStream
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

/**
 * ================= 做梦 · 环境检测（Jetpack Compose + Material 3） =================
 * 严格遵循 Google Material 3 设计指南：
 *  - 仅使用 Scaffold / NavigationBar / Card / FloatingActionButton /
 *    LinearProgressIndicator / Button 等原生 M3 组件；
 *  - 低饱和度浅紫色配色、柔和圆角卡片；
 *  - enableEdgeToEdge + WindowCompat.setDecorFitsSystemWindows(window, false)
 *    启用边缘到边缘，根布局 safeDrawingPadding() 消除顶部/底部黑边；
 *  - 底部导航仅两个标签页：在线检测（首页直达）/ 离线检测；
 *  - 整页垂直滚动（SingleColumnLayout）：向上滚动时顶部标题、进度条、
 *    测试项卡片一起上移；
 *  - 右下角 M3 圆形浮动按钮：把检测报告导出为 TXT 到下载目录；
 *  - 所有判定用客观证据表述：判断依据：通过XX检测到XX，这与预期的XX不符。
 * ==============================================================================
 */

// ================= 状态模型 =================
private data class UiState(
    val running: Boolean = false,       // 是否正在检测
    val done: Boolean = false,          // 是否检测完成
    val tab: Int = 0,                   // 0=在线检测（首页默认） 1=离线检测
    val offlineResults: List<DetectionResult> = emptyList(),  // 离线词条
    val onlineResults: List<DetectionResult> = emptyList(),   // 联网词条
    val summary: DetectionEngine.Report? = null,              // 汇总
    val status: String = "点上方按钮开始检测",                  // 当前状态
    val progress: Float = 0f,           // 总进度 0..1
    val startTime: Long = 0L,           // 检测开始时刻
    val issueCount: Int = 0,            // 异常计数
)

class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        // 1) 启用边缘到边缘全屏模式（状态栏/导航栏透明）
        enableEdgeToEdge()
        // 2) 兼容 API<30 时也关闭 decor fits system windows，让内容绘制到系统栏后面
        WindowCompat.setDecorFitsSystemWindows(window, false)
        setContent {
            MaterialTheme(colorScheme = AppColorScheme) {
                App()
            }
        }
    }
}

// ================= M3 低饱和浅紫色配色 =================
private val AppColorScheme = lightColorScheme(
    primary = Color(0xFF6750A4),
    onPrimary = Color.White,
    primaryContainer = Color(0xFFEADDFF),
    onPrimaryContainer = Color(0xFF21005D),
    secondary = Color(0xFF625B71),
    onSecondary = Color.White,
    secondaryContainer = Color(0xFFE8DEF8),
    onSecondaryContainer = Color(0xFF1D192B),
    tertiary = Color(0xFF7D5260),
    surface = Color(0xFFFEF7FF),
    surfaceVariant = Color(0xFFE7E0EC),
    background = Color(0xFFFDF8FF),
    onBackground = Color(0xFF1D1B20),
    onSurface = Color(0xFF1D1B20),
    onSurfaceVariant = Color(0xFF49454F),
    error = Color(0xFFB3261E),
    onError = Color.White,
    errorContainer = Color(0xFFF9DEDC),
    onErrorContainer = Color(0xFF410E0B),
)

// 判定状态颜色（tonal 容器风格）
private val OkColor = Color(0xFF386A20)
private val OkContainer = Color(0xFFD7F5D0)
private val WarnColor = Color(0xFF7A5900)
private val WarnContainer = Color(0xFFFFE5B3)
private val BadColor = Color(0xFFB3261E)
private val BadContainer = Color(0xFFF9DEDC)
private val LowColor = Color(0xFF625B71)
private val LowContainer = Color(0xFFE8DEF8)

// ================= 主界面 =================
@Composable
fun App() {
    var state by remember { mutableStateOf(UiState()) }
    val scope = rememberCoroutineScope()
    val context = LocalContext.current
    // 主线程 Handler，用于把后台检测回调的进度/结果切回主线程更新 Compose 状态
    val main = remember { Handler(Looper.getMainLooper()) }

    Scaffold(
        containerColor = MaterialTheme.colorScheme.background,
        // ---- 底部导航栏：仅两个标签页（离线检测在前，在线检测在后） ----
        bottomBar = {
            NavigationBar {
                // 离线检测（默认选中）
                NavigationBarItem(
                    selected = state.tab == 0,
                    onClick = { state = state.copy(tab = 0) },
                    icon = { Icon(Icons.Filled.List, contentDescription = null) },
                    label = { Text("离线检测") }
                )
                // 在线检测
                NavigationBarItem(
                    selected = state.tab == 1,
                    onClick = { state = state.copy(tab = 1) },
                    icon = { Icon(Icons.Filled.Cloud, contentDescription = null) },
                    label = { Text("在线检测") }
                )
            }
        },
        // ---- 右下角圆形浮动按钮：导出报告（完成后显示） ----
        floatingActionButton = {
            if (state.done) {
                FloatingActionButton(onClick = { export(context, state) }) {
                    Icon(Icons.Filled.FileDownload, contentDescription = "导出报告")
                }
            }
        }
    ) { innerPadding ->
        // ---- 根布局：纵向滚动页面 + 安全区内边距（消除顶部/底部黑边） ----
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(innerPadding)          // 底部导航高度
                .safeDrawingPadding()           // 状态栏/手势条安全区，消除黑边
                .verticalScroll(rememberScrollState())  // 整页垂直滚动
                .padding(horizontal = 16.dp, vertical = 10.dp)
        ) {
            // ---- 顶部页面标题（随滚动一起上移） ----
            Text(
                text = "环境检测",
                style = MaterialTheme.typography.headlineSmall,
                color = MaterialTheme.colorScheme.onSurface,
                fontWeight = FontWeight.Bold
            )
            Text(
                text = "做梦 · 1.2.11",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
            Spacer(Modifier.height(12.dp))

            // ---- 检测操作按钮 + 进度条（检测完成后隐藏"开始检测"按钮） ----
            if (!state.done) {
                Button(
                    onClick = {
                        if (!state.running) {
                            scope.launch { runDetection(context, main, onUpdate = { state = it }) }
                        }
                    },
                    enabled = !state.running,
                    shape = RoundedCornerShape(28.dp),
                    modifier = Modifier.fillMaxWidth().height(52.dp)
                ) {
                    Text(
                        if (state.running) "正在检测…" else "开始检测 · Start Scan",
                        style = MaterialTheme.typography.labelLarge
                    )
                }
            }

            // 检测中的进度条（M3 LinearProgressIndicator）
            if (state.running) {
                Spacer(Modifier.height(14.dp))
                LinearProgressIndicator(
                    progress = { state.progress },
                    modifier = Modifier.fillMaxWidth().height(6.dp)
                )
            }

            // 当前状态 + 用时
            Text(
                text = state.status,
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                modifier = Modifier.padding(top = 8.dp)
            )
            Text(
                text = timeText(state.startTime, state.running),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
            Spacer(Modifier.height(10.dp))

            // ---- 检测汇总卡片（完成后显示） ----
            if (state.done && state.summary != null) {
                SummaryRow(state.summary!!)
                Spacer(Modifier.height(10.dp))
            }

            // ---- 异常/测试结果卡片（按当前标签页显示对应的词条） ----
            // 标签顺序：离线检测(tab 0) / 在线检测(tab 1)，内容与标签一一对应
            val showOnline = state.tab == 1
            val list = if (showOnline) state.onlineResults else state.offlineResults
            if (list.isEmpty()) {
                // 空态提示
                Text(
                    text = if (showOnline) "联网检测结果将显示在这里" else "离线检测结果将显示在这里",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            } else {
                list.forEach { dr -> ResultCard(dr) }
            }
            Spacer(Modifier.height(80.dp)) // 底部留白，避免被悬浮按钮遮挡
        }
    }
}

// ================= 汇总卡片 =================
@Composable
private fun SummaryRow(report: DetectionEngine.Report) {
    Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
        // weight 在 RowScope 内通过 modifier 传入
        SummaryItem(report.total.toString(), "总检测", MaterialTheme.colorScheme.onSurfaceVariant, MaterialTheme.colorScheme.surfaceVariant, Modifier.weight(1f))
        SummaryItem(report.clean.toString(), "正常", OkColor, OkContainer, Modifier.weight(1f))
        SummaryItem(report.warn.toString(), "可疑", WarnColor, WarnContainer, Modifier.weight(1f))
        SummaryItem(report.found.toString(), "异常", BadColor, BadContainer, Modifier.weight(1f))
    }
}

@Composable
private fun SummaryItem(value: String, label: String, valueColor: Color, container: Color, modifier: Modifier = Modifier) {
    Card(
        colors = CardDefaults.cardColors(containerColor = container),
        shape = RoundedCornerShape(16.dp),
        modifier = modifier
    ) {
        Column(
            horizontalAlignment = Alignment.CenterHorizontally,
            modifier = Modifier.fillMaxWidth().padding(vertical = 12.dp)
        ) {
            Text(value, style = MaterialTheme.typography.headlineSmall, color = valueColor, fontWeight = FontWeight.Bold)
            Text(label, style = MaterialTheme.typography.labelMedium, color = valueColor)
        }
    }
}

// ================= 测试结果卡片 =================
@Composable
private fun ResultCard(dr: DetectionResult) {
    val (container, content, tag) = when (dr.level) {
        DetectionResult.Level.ABNORMAL -> Triple(BadContainer, BadColor, "异常")
        DetectionResult.Level.SUSPECT -> Triple(WarnContainer, WarnColor, "可疑")
        DetectionResult.Level.LOW -> Triple(LowContainer, LowColor, "低风险")
        else -> Triple(OkContainer, OkColor, "正常")
    }
    Card(
        colors = CardDefaults.cardColors(containerColor = container),
        shape = RoundedCornerShape(12.dp),   // 柔和圆角
        modifier = Modifier.fillMaxWidth().padding(bottom = 8.dp)
    ) {
        Column(Modifier.padding(12.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Text(
                    text = "${dr.id}. ${dr.category} · ${dr.title}",
                    style = MaterialTheme.typography.titleMedium,
                    color = MaterialTheme.colorScheme.onSurface,
                    modifier = Modifier.weight(1f)
                )
                // 状态徽章
                Text(
                    text = tag,
                    style = MaterialTheme.typography.labelSmall,
                    color = content,
                    modifier = Modifier
                        .background(MaterialTheme.colorScheme.surface, RoundedCornerShape(8.dp))
                        .padding(horizontal = 8.dp, vertical = 3.dp)
                )
            }
            // 日志
            Text(
                text = dr.log,
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                modifier = Modifier.padding(top = 5.dp)
            )
            // 非正常项：用客观证据表述判定依据
            if (dr.level != DetectionResult.Level.NORMAL) {
                Text(
                    text = evidence(dr),
                    style = MaterialTheme.typography.bodySmall,
                    color = content,
                    modifier = Modifier.padding(top = 4.dp)
                )
            }
        }
    }
}

// ================= 后台检测 =================
private suspend fun runDetection(
    context: Context,
    main: Handler,
    onUpdate: (UiState) -> Unit
) {
    var s = UiState(running = true, status = "正在初始化检测引擎…", startTime = System.currentTimeMillis())
    onUpdate(s)

    val engine = DetectionEngine(context)
    // 第一页：离线检测（288 项，不联网）
    withContext(Dispatchers.IO) {
        engine.run { dr, done, total, category, title ->
            main.post {
                s = s.copy(
                    progress = done.toFloat() / total,
                    status = "正在检测 · $category：$title",
                    offlineResults = insertSorted(s.offlineResults, dr),
                    issueCount = s.issueCount + if (dr.level == DetectionResult.Level.ABNORMAL) 1 else 0
                )
                onUpdate(s)
            }
        }
    }
    // 第二页：联网检测（6 项）
    main.post { onUpdate(s.copy(status = "正在联网检测…")) }
    val rep = withContext(Dispatchers.IO) {
        engine.runOnline { dr, done, total, category, title ->
            main.post {
                s = s.copy(
                    progress = done.toFloat() / total,
                    status = "正在检测 · $category：$title",
                    onlineResults = insertSorted(s.onlineResults, dr),
                    issueCount = s.issueCount + if (dr.level == DetectionResult.Level.ABNORMAL) 1 else 0
                )
                onUpdate(s)
            }
        }
    }
    // 完成
    main.post {
        onUpdate(
            s.copy(
                running = false,
                done = true,
                summary = rep,
                status = "检测完成"
            )
        )
    }
}

// ================= 客观判定依据 =================
private fun evidence(dr: DetectionResult): String {
    val tag = when (dr.level) {
        DetectionResult.Level.ABNORMAL -> "异常"
        DetectionResult.Level.SUSPECT -> "可疑"
        else -> "低风险"
    }
    return "判断依据：通过「${dr.title}」检测到「${dr.log}」，这与预期的正常状态不符，判定为$tag。"
}

// ================= 用时文本 =================
private fun timeText(start: Long, running: Boolean): String {
    if (start == 0L) return "检测时间：--:--:--"
    val fmt = SimpleDateFormat("HH:mm:ss", Locale.US)
    val ms = System.currentTimeMillis() - start
    val sec = ms / 1000
    val elapsed = if (sec < 60) "${sec}.${(ms % 1000) / 100}s" else "${sec / 60}m ${sec % 60}s"
    return "检测时间 ${fmt.format(Date(start))} · ${if (running) "已用时" else "耗时"} $elapsed"
}

// ================= 导出报告（TXT 到下载目录） =================
private fun export(context: Context, state: UiState) {
    val report = state.summary ?: return
    val txt = buildReportText(report, state.startTime)
    val name = "环境检测报告_" + SimpleDateFormat("yyyyMMdd_HHmmss", Locale.US).format(Date()) + ".txt"
    try {
        if (Build.VERSION.SDK_INT >= 29) {
            // Android 10+：通过 MediaStore 写入公共下载目录（无需权限）
            val cv = ContentValues().apply {
                put(MediaStore.Downloads.DISPLAY_NAME, name)
                put(MediaStore.Downloads.MIME_TYPE, "text/plain")
                put(MediaStore.Downloads.RELATIVE_PATH, Environment.DIRECTORY_DOWNLOADS)
            }
            val uri: Uri? = context.contentResolver.insert(MediaStore.Downloads.EXTERNAL_CONTENT_URI, cv)
            if (uri != null) {
                val os: OutputStream? = context.contentResolver.openOutputStream(uri)
                if (os != null) {
                    os.write(txt.toByteArray(Charsets.UTF_8))
                    os.close()
                    toast(context, "已导出到下载目录：$name")
                    return
                }
            }
            toast(context, "导出失败：无法写入下载目录")
        } else {
            // Android 9 及以下：写公共下载目录（需 WRITE_EXTERNAL_STORAGE 权限）
            val dir = Environment.getExternalStoragePublicDirectory(Environment.DIRECTORY_DOWNLOADS)
            if (dir != null && !dir.exists()) dir.mkdirs()
            val f = File(dir, name)
            val fos = FileOutputStream(f)
            fos.write(txt.toByteArray(Charsets.UTF_8))
            fos.close()
            toast(context, "已导出：${f.absolutePath}")
        }
    } catch (e: Exception) {
        toast(context, "导出失败：${e.message}")
    }
}

private fun toast(context: Context, msg: String) {
    Toast.makeText(context, msg, Toast.LENGTH_SHORT).show()
}

// ================= 拼接报告全文（异常在前 + 客观判定依据） =================
private fun buildReportText(report: DetectionEngine.Report, start: Long): String {
    val sorted = report.results.sortedWith(
        compareBy({ priority(it.level) })
    )
    val sb = StringBuilder()
    sb.append("环境检测报告 v1.2.11\n")
    sb.append("检测时间：")
        .append(SimpleDateFormat("yyyy-MM-dd HH:mm:ss", Locale.US).format(Date(start)))
        .append("（耗时 ").append(elapsedStr(System.currentTimeMillis() - start)).append("）\n")
    sb.append("总检测:").append(report.total)
        .append(" 正常:").append(report.clean)
        .append(" 可疑:").append(report.warn)
        .append(" 异常:").append(report.found)
        .append("\n离线检测 ").append(DetectionEngine.TOTAL_OFFLINE)
        .append(" 项 · 联网检测 ").append(DetectionEngine.TOTAL_ONLINE).append(" 项\n\n")
    for (dr in sorted) {
        sb.append("#").append(dr.id).append(" [").append(dr.level).append("] ")
            .append(dr.category).append(" · ").append(dr.title)
            .append("\n  日志: ").append(dr.log)
        if (dr.level != DetectionResult.Level.NORMAL) {
            sb.append("\n  判断依据: ").append(evidence(dr))
        }
        sb.append("\n")
    }
    return sb.toString()
}

private fun priority(level: DetectionResult.Level): Int = when (level) {
    DetectionResult.Level.ABNORMAL -> 0
    DetectionResult.Level.SUSPECT -> 1
    DetectionResult.Level.LOW -> 2
    else -> 3
}

/**
 * 异常项置顶排序插入：按严重级别 异常(0) > 可疑(1) > 低风险(2) > 正常(3)，
 * 把新词条插到第一个更低优先级项之前，同级保持检测到达顺序（稳定排序）。
 */
private fun insertSorted(list: List<DetectionResult>, dr: DetectionResult): List<DetectionResult> {
    val p = priority(dr.level)
    val idx = list.indexOfFirst { priority(it.level) > p }
    return if (idx >= 0) list.toMutableList().apply { add(idx, dr) } else list + dr
}

private fun elapsedStr(ms: Long): String {
    val s = ms / 1000
    return if (s < 60) "$s.${(ms % 1000) / 100}s" else "${s / 60}m ${s % 60}s"
}
