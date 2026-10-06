package com.zuomeng.app

import android.content.ActivityNotFoundException
import android.content.ContentValues
import android.content.Context
import android.content.Intent
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
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
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
import androidx.compose.material.icons.filled.Settings
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.FloatingActionButton
import androidx.compose.material3.Icon
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.ListItem
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.NavigationBar
import androidx.compose.material3.NavigationBarItem
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
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
import androidx.datastore.preferences.core.booleanPreferencesKey
import androidx.datastore.preferences.core.edit
import androidx.datastore.preferences.preferencesDataStore
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.map
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.io.File
import java.io.FileOutputStream
import java.io.OutputStream
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

/** 本项目开源仓库地址（仅此处允许出现本项目自身链接） */
private const val REPO_URL = "https://github.com/gaigebeckmanChristinaJames/dream-compose"

// DataStore：联网检测开关持久化（默认关闭）
private val Context.settingsDs by preferencesDataStore(name = "settings")
private val ONLINE_KEY = booleanPreferencesKey("online_scan_enabled")

// ================= 状态模型（本地 / 联网进度完全隔离） =================
private data class UiState(
    val running: Boolean = false,
    val done: Boolean = false,
    val tab: Int = 0,                   // 0=离线 1=在线 2=设置
    val offlineResults: List<DetectionResult> = emptyList(),
    val onlineResults: List<DetectionResult> = emptyList(),
    val summary: DetectionEngine.Report? = null,
    val status: String = "点上方按钮开始检测",
    val startTime: Long = 0L,
    val issueCount: Int = 0,
    val onlineEnabled: Boolean = false,
    // 本地进度
    val localProgress: Float = 0f,
    val localStatus: String = "",
    // 联网进度（独立）
    val onlineProgress: Float = 0f,
    val onlineStatus: String = "",
    val onlineDone: Boolean = false,
)

class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()
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

private val OkColor = Color(0xFF386A20)
private val OkContainer = Color(0xFFD7F5D0)
private val WarnColor = Color(0xFF7A5900)
private val WarnContainer = Color(0xFFFFE5B3)
private val BadColor = Color(0xFFB3261E)
private val BadContainer = Color(0xFFF9DEDC)
private val LowColor = Color(0xFF625B71)
private val LowContainer = Color(0xFFE8DEF8)

// ================= 主界面 =================
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun App() {
    var state by remember { mutableStateOf(UiState()) }
    val scope = rememberCoroutineScope()
    val context = LocalContext.current
    val main = remember { Handler(Looper.getMainLooper()) }

    // 读取 DataStore 中“联网检测开关”（默认关闭）
    LaunchedEffect(Unit) {
        context.settingsDs.data.collect { p ->
            state = state.copy(onlineEnabled = p[ONLINE_KEY] ?: false)
        }
    }

    Scaffold(
        containerColor = MaterialTheme.colorScheme.background,
        bottomBar = {
            NavigationBar {
                NavigationBarItem(
                    selected = state.tab == 0,
                    onClick = { state = state.copy(tab = 0) },
                    icon = { Icon(Icons.Filled.List, contentDescription = null) },
                    label = { Text("离线检测") }
                )
                NavigationBarItem(
                    selected = state.tab == 1,
                    onClick = { state = state.copy(tab = 1) },
                    icon = { Icon(Icons.Filled.Cloud, contentDescription = null) },
                    label = { Text("在线检测") }
                )
                NavigationBarItem(
                    selected = state.tab == 2,
                    onClick = { state = state.copy(tab = 2) },
                    icon = { Icon(Icons.Filled.Settings, contentDescription = null) },
                    label = { Text("设置") }
                )
            }
        },
        floatingActionButton = {
            if (state.done && state.tab != 2) {
                FloatingActionButton(onClick = { export(context, state) }) {
                    Icon(Icons.Filled.FileDownload, contentDescription = "导出报告")
                }
            }
        }
    ) { innerPadding ->
        if (state.tab == 2) {
            SettingsPage(
                onlineEnabled = state.onlineEnabled,
                onToggle = { v ->
                    state = state.copy(onlineEnabled = v)
                    scope.launch { context.settingsDs.edit { it[ONLINE_KEY] = v } }
                },
                modifier = Modifier.padding(innerPadding).safeDrawingPadding()
            )
            return@Scaffold
        }

        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(innerPadding)
                .safeDrawingPadding()
                .verticalScroll(rememberScrollState())
                .padding(horizontal = 16.dp, vertical = 10.dp)
        ) {
            Text(
                text = "环境检测",
                style = MaterialTheme.typography.headlineSmall,
                color = MaterialTheme.colorScheme.onSurface,
                fontWeight = FontWeight.Bold
            )
            Text(
                text = "做梦 · 1.2.19",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
            Spacer(Modifier.height(12.dp))

            if (!state.done) {
                Button(
                    onClick = {
                        if (!state.running) {
                            scope.launch { runDetection(context, main, state.onlineEnabled) { state = it } }
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

            // 本地进度（始终显示）
            if (state.running || state.localStatus.isNotEmpty()) {
                Spacer(Modifier.height(10.dp))
                LinearProgressIndicator(
                    progress = { state.localProgress },
                    modifier = Modifier.fillMaxWidth().height(6.dp)
                )
                Text(
                    text = "本地检测：${(state.localProgress * 100).toInt()}%  ${state.localStatus}",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    modifier = Modifier.padding(top = 4.dp)
                )
            }
            // 联网进度（独立，仅开关开启时才出现）
            if (state.onlineEnabled && (state.running || state.onlineStatus.isNotEmpty())) {
                Spacer(Modifier.height(6.dp))
                LinearProgressIndicator(
                    progress = { state.onlineProgress },
                    modifier = Modifier.fillMaxWidth().height(6.dp),
                    color = MaterialTheme.colorScheme.tertiary
                )
                Text(
                    text = "在线检测：${(state.onlineProgress * 100).toInt()}%  ${state.onlineStatus}",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    modifier = Modifier.padding(top = 4.dp)
                )
            }

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

            if (state.done && state.summary != null) {
                SummaryRow(state.summary!!)
                Spacer(Modifier.height(10.dp))
            }

            val showOnline = state.tab == 1
            val list = if (showOnline) state.onlineResults else state.offlineResults
            if (list.isEmpty()) {
                Text(
                    text = when {
                        showOnline && !state.onlineEnabled -> "联网检测未启用（可在「设置」页开启）"
                        showOnline -> "联网检测结果将显示在这里"
                        else -> "离线检测结果将显示在这里"
                    },
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            } else {
                list.forEach { dr -> ResultCard(dr) }
            }
            Spacer(Modifier.height(80.dp))
        }
    }
}

// ================= M3 设置页 =================
@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun SettingsPage(onlineEnabled: Boolean, onToggle: (Boolean) -> Unit, modifier: Modifier = Modifier) {
    val context = LocalContext.current
    Scaffold(
        modifier = modifier,
        containerColor = MaterialTheme.colorScheme.background,
        topBar = { TopAppBar(title = { Text("设置") }) }
    ) { pad ->
        Column(
            Modifier
                .fillMaxSize()
                .padding(pad)
                .padding(16.dp)
        ) {
            ListItem(
                headlineContent = { Text("联网检测") },
                supportingContent = { Text("开启后，本地检测完成后追加在线检测；默认关闭，关闭时不发起任何网络请求") },
                trailingContent = {
                    Switch(checked = onlineEnabled, onCheckedChange = onToggle)
                }
            )
            Spacer(Modifier.height(24.dp))
            Text(
                text = "本项目为开源环境检测工具",
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurface
            )
            Spacer(Modifier.height(6.dp))
            Text(
                text = REPO_URL,
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.primary,
                modifier = Modifier.clickable {
                    try {
                        context.startActivity(Intent(Intent.ACTION_VIEW, Uri.parse(REPO_URL)))
                    } catch (e: ActivityNotFoundException) { /* 无浏览器，忽略 */ }
                }
            )
        }
    }
}

// ================= 汇总卡片 =================
@Composable
private fun SummaryRow(report: DetectionEngine.Report) {
    Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
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

// ================= 测试结果卡片（理由默认可见，完整日志默认折叠） =================
@Composable
private fun ResultCard(dr: DetectionResult) {
    val (container, content, tag) = when (dr.level) {
        DetectionResult.Level.ABNORMAL -> Triple(BadContainer, BadColor, "异常")
        DetectionResult.Level.SUSPECT -> Triple(WarnContainer, WarnColor, "可疑")
        DetectionResult.Level.LOW -> Triple(LowContainer, LowColor, "低风险")
        else -> Triple(OkContainer, OkColor, "正常")
    }
    var expanded by remember { mutableStateOf(false) }
    Card(
        colors = CardDefaults.cardColors(containerColor = container),
        shape = RoundedCornerShape(12.dp),
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
                Text(
                    text = tag,
                    style = MaterialTheme.typography.labelSmall,
                    color = content,
                    modifier = Modifier
                        .background(MaterialTheme.colorScheme.surface, RoundedCornerShape(8.dp))
                        .padding(horizontal = 8.dp, vertical = 3.dp)
                )
            }
            // 判定理由：默认始终可见（≥80% 可视区）
            Text(
                text = reasonText(dr),
                style = MaterialTheme.typography.bodyMedium,
                color = content,
                modifier = Modifier.padding(top = 6.dp),
                lineHeight = MaterialTheme.typography.bodyMedium.fontSize * 1.5f
            )
            // 完整日志：默认折叠，点击展开
            TextButton(onClick = { expanded = !expanded }) {
                Text(if (expanded) "收起完整日志 ▲" else "展开完整日志 ▼",
                    style = MaterialTheme.typography.labelMedium)
            }
            if (expanded) {
                Text(
                    text = dr.log,
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    modifier = Modifier
                        .fillMaxWidth()
                        .background(MaterialTheme.colorScheme.surfaceVariant, RoundedCornerShape(8.dp))
                        .padding(8.dp)
                )
            }
        }
    }
}

// ================= 后台检测（本地为主，联网独立可选） =================
private suspend fun runDetection(
    context: Context,
    main: Handler,
    onlineEnabled: Boolean,
    onUpdate: (UiState) -> Unit
) {
    var s = UiState(running = true, status = "正在初始化检测引擎…", startTime = System.currentTimeMillis(), onlineEnabled = onlineEnabled)
    onUpdate(s)

    val engine = DetectionEngine(context)
    // 本地检测（始终运行）
    val rep = withContext(Dispatchers.IO) {
        engine.run { dr, done, total, category, title ->
            main.post {
                s = s.copy(
                    localProgress = (done.toFloat() / DetectionEngine.TOTAL_OFFLINE).coerceIn(0f, 1f),
                    localStatus = "$category · $title",
                    offlineResults = insertSorted(s.offlineResults, dr)
                )
                onUpdate(s)
            }
        }
    }
    // 联网检测：仅开关开启时初始化、独立进度
    if (onlineEnabled) {
        main.post { onUpdate(s.copy(onlineStatus = "正在联网检测…")) }
        withContext(Dispatchers.IO) {
            engine.runOnline { dr, done, total, category, title ->
                main.post {
                    val od = (done - DetectionEngine.TOTAL_OFFLINE).coerceAtLeast(0).toFloat() / DetectionEngine.TOTAL_ONLINE
                    s = s.copy(
                        onlineProgress = od.coerceIn(0f, 1f),
                        onlineStatus = "$category · $title",
                        onlineResults = insertSorted(s.onlineResults, dr)
                    )
                    onUpdate(s)
                }
            }
        }
        main.post { onUpdate(s.copy(onlineDone = true, onlineStatus = "联网检测完成")) }
    } else {
        main.post { onUpdate(s.copy(onlineDone = true, onlineStatus = "联网检测未启用")) }
    }

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

// ================= 判定理由（field2） =================
private fun reasonText(dr: DetectionResult): String {
    if (!dr.reason.isNullOrEmpty()) return dr.reason!!
    if (dr.level == DetectionResult.Level.NORMAL) return "通过：未命中风险特征（原始采集值见完整日志）。"
    val tag = when (dr.level) {
        DetectionResult.Level.ABNORMAL -> "异常"
        DetectionResult.Level.SUSPECT -> "可疑"
        else -> "低风险"
    }
    return "判定为$tag：「${dr.title}」检出「${dr.log.take(120)}」；" +
            "按降误报策略需多独立证据聚合，详见完整日志复核。"
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

// ================= 拼接报告全文 =================
private fun buildReportText(report: DetectionEngine.Report, start: Long): String {
    val sorted = report.results.sortedWith(compareBy({ priority(it.level) }))
    val sb = StringBuilder()
    sb.append("环境检测报告 v1.2.19\n")
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
            sb.append("\n  判定理由: ").append(reasonText(dr))
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

private fun insertSorted(list: List<DetectionResult>, dr: DetectionResult): List<DetectionResult> {
    val p = priority(dr.level)
    val idx = list.indexOfFirst { priority(it.level) > p }
    return if (idx >= 0) list.toMutableList().apply { add(idx, dr) } else list + dr
}

private fun elapsedStr(ms: Long): String {
    val s = ms / 1000
    return if (s < 60) "$s.${(ms % 1000) / 100}s" else "${s / 60}m ${s % 60}s"
}
