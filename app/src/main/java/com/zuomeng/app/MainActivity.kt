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
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.safeDrawingPadding
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

private val Context.settingsDs by preferencesDataStore(name = "settings")
private val ONLINE_KEY = booleanPreferencesKey("online_scan_enabled")

// ================= 状态模型（本地 / 联网完全隔离，互不覆盖） =================
private data class UiState(
    val tab: Int = 0,                       // 0=离线 1=在线(仅开启时存在) 2=设置
    val onlineEnabled: Boolean = false,
    // 本地
    val offlineResults: List<DetectionResult> = emptyList(),
    val localSummary: DetectionEngine.Report? = null,
    val localRunning: Boolean = false,
    val localProgress: Float = 0f,
    val localStatus: String = "",
    // 联网
    val onlineResults: List<DetectionResult> = emptyList(),
    val onlineSummary: DetectionEngine.Report? = null,
    val onlineRunning: Boolean = false,
    val onlineProgress: Float = 0f,
    val onlineStatus: String = "",
)

class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()
        WindowCompat.setDecorFitsSystemWindows(window, false)
        setContent {
            MaterialTheme(colorScheme = AppColorScheme) { App() }
        }
    }
}

private val AppColorScheme = lightColorScheme(
    primary = Color(0xFF6750A4), onPrimary = Color.White,
    primaryContainer = Color(0xFFEADDFF), onPrimaryContainer = Color(0xFF21005D),
    secondary = Color(0xFF625B71), onSecondary = Color.White,
    secondaryContainer = Color(0xFFE8DEF8), onSecondaryContainer = Color(0xFF1D192B),
    tertiary = Color(0xFF7D5260),
    surface = Color(0xFFFEF7FF), surfaceVariant = Color(0xFFE7E0EC),
    background = Color(0xFFFDF8FF), onBackground = Color(0xFF1D1B20),
    onSurface = Color(0xFF1D1B20), onSurfaceVariant = Color(0xFF49454F),
    error = Color(0xFFB3261E), onError = Color.White,
    errorContainer = Color(0xFFF9DEDC), onErrorContainer = Color(0xFF410E0B),
)

private val OkColor = Color(0xFF386A20); private val OkContainer = Color(0xFFD7F5D0)
private val WarnColor = Color(0xFF7A5900); private val WarnContainer = Color(0xFFFFE5B3)
private val BadColor = Color(0xFFB3261E); private val BadContainer = Color(0xFFF9DEDC)
private val LowColor = Color(0xFF625B71); private val LowContainer = Color(0xFFE8DEF8)

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun App() {
    var state by remember { mutableStateOf(UiState()) }
    val scope = rememberCoroutineScope()
    val context = LocalContext.current
    val main = remember { Handler(Looper.getMainLooper()) }

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
                // 在线检测标签：仅在开关开启时才显示
                if (state.onlineEnabled) {
                    NavigationBarItem(
                        selected = state.tab == 1,
                        onClick = { state = state.copy(tab = 1) },
                        icon = { Icon(Icons.Filled.Cloud, contentDescription = null) },
                        label = { Text("在线检测") }
                    )
                }
                NavigationBarItem(
                    selected = state.tab == 2,
                    onClick = { state = state.copy(tab = 2) },
                    icon = { Icon(Icons.Filled.Settings, contentDescription = null) },
                    label = { Text("设置") }
                )
            }
        },
        floatingActionButton = {
            if (state.tab != 2 && state.localSummary != null && !state.localRunning) {
                FloatingActionButton(onClick = { export(context, state) }) {
                    Icon(Icons.Filled.FileDownload, contentDescription = "导出报告")
                }
            }
        }
    ) { innerPadding ->
        when (state.tab) {
            2 -> SettingsPage(
                onlineEnabled = state.onlineEnabled,
                onToggle = { v ->
                    state = state.copy(onlineEnabled = v, tab = if (!v && state.tab == 1) 0 else state.tab)
                    scope.launch { context.settingsDs.edit { it[ONLINE_KEY] = v } }
                },
                modifier = Modifier.padding(innerPadding).safeDrawingPadding()
            )
            1 -> OnlinePanel(
                state = state,
                onStart = { scope.launch { runOnlineOnly(context, main, state) { state = it } } },
                modifier = Modifier.padding(innerPadding).safeDrawingPadding()
            )
            else -> LocalPanel(
                state = state,
                onStart = { scope.launch { runLocal(context, main, state) { state = it } } },
                modifier = Modifier.padding(innerPadding).safeDrawingPadding()
            )
        }
    }
}

// ================= 离线面板（本地检测） =================
@Composable
private fun LocalPanel(state: UiState, onStart: () -> Unit, modifier: Modifier = Modifier) {
    Column(
        modifier = modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(16.dp)
    ) {
        Text("环境检测", style = MaterialTheme.typography.headlineSmall, color = MaterialTheme.colorScheme.onSurface, fontWeight = FontWeight.Bold)
        Text("做梦 · 1.2.22", style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
        Spacer(Modifier.height(12.dp))

        Button(
            onClick = onStart,
            enabled = !state.localRunning,
            shape = RoundedCornerShape(28.dp),
            modifier = Modifier.fillMaxWidth().height(52.dp)
        ) {
            Text(if (state.localRunning) "正在本地检测…" else "开始本地检测 · Local Scan", style = MaterialTheme.typography.labelLarge)
        }

        if (state.localRunning || state.localStatus.isNotEmpty()) {
            Spacer(Modifier.height(10.dp))
            LinearProgressIndicator(progress = { state.localProgress }, modifier = Modifier.fillMaxWidth().height(6.dp))
            Text("本地检测：${(state.localProgress * 100).toInt()}%  ${state.localStatus}",
                style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant, modifier = Modifier.padding(top = 4.dp))
        }

        if (state.localSummary != null) {
            Spacer(Modifier.height(10.dp))
            SummaryRow(state.localSummary!!)
        }
        Spacer(Modifier.height(10.dp))

        if (state.offlineResults.isEmpty()) {
            Text("离线检测结果将显示在这里", style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
        } else {
            state.offlineResults.forEach { ResultCard(it) }
        }
        Spacer(Modifier.height(80.dp))
    }
}

// ================= 在线面板（仅开关开启时可达） =================
@Composable
private fun OnlinePanel(state: UiState, onStart: () -> Unit, modifier: Modifier = Modifier) {
    Column(
        modifier = modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(16.dp)
    ) {
        Text("在线检测", style = MaterialTheme.typography.headlineSmall, color = MaterialTheme.colorScheme.onSurface, fontWeight = FontWeight.Bold)
        Text("独立联网检测 · 不影响本地结果", style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
        Spacer(Modifier.height(12.dp))

        Button(
            onClick = onStart,
            enabled = !state.onlineRunning,
            shape = RoundedCornerShape(28.dp),
            modifier = Modifier.fillMaxWidth().height(52.dp)
        ) {
            Text(if (state.onlineRunning) "正在联网检测…" else "开始在线检测 · Online Scan", style = MaterialTheme.typography.labelLarge)
        }

        Spacer(Modifier.height(10.dp))
        LinearProgressIndicator(progress = { state.onlineProgress }, modifier = Modifier.fillMaxWidth().height(6.dp), color = MaterialTheme.colorScheme.tertiary)
        Text("在线检测：${(state.onlineProgress * 100).toInt()}%  ${state.onlineStatus}",
            style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant, modifier = Modifier.padding(top = 4.dp))
        Spacer(Modifier.height(10.dp))

        if (state.onlineResults.isEmpty()) {
            Text("在线检测结果将显示在这里", style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
        } else {
            state.onlineResults.forEach { ResultCard(it) }
        }
        Spacer(Modifier.height(80.dp))
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
        Column(Modifier.fillMaxSize().padding(pad).padding(16.dp)) {
            ListItem(
                headlineContent = { Text("联网检测") },
                supportingContent = { Text("开启后底部出现「在线检测」标签，可独立发起联网检测；默认关闭，关闭时不发起任何网络请求") },
                trailingContent = { Switch(checked = onlineEnabled, onCheckedChange = onToggle) }
            )
            Spacer(Modifier.height(24.dp))
            Text("本项目为开源环境检测工具", style = MaterialTheme.typography.bodyMedium, color = MaterialTheme.colorScheme.onSurface)
            Spacer(Modifier.height(6.dp))
            Text(
                text = REPO_URL,
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.primary,
                modifier = Modifier.clickable {
                    try { context.startActivity(Intent(Intent.ACTION_VIEW, Uri.parse(REPO_URL))) }
                    catch (e: ActivityNotFoundException) {}
                }
            )
        }
    }
}

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
    Card(colors = CardDefaults.cardColors(containerColor = container), shape = RoundedCornerShape(16.dp), modifier = modifier) {
        Column(horizontalAlignment = Alignment.CenterHorizontally, modifier = Modifier.fillMaxWidth().padding(vertical = 12.dp)) {
            Text(value, style = MaterialTheme.typography.headlineSmall, color = valueColor, fontWeight = FontWeight.Bold)
            Text(label, style = MaterialTheme.typography.labelMedium, color = valueColor)
        }
    }
}

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
                Text("${dr.id}. ${dr.category} · ${dr.title}", style = MaterialTheme.typography.titleMedium, color = MaterialTheme.colorScheme.onSurface, modifier = Modifier.weight(1f))
                Text(tag, style = MaterialTheme.typography.labelSmall, color = content,
                    modifier = Modifier.background(MaterialTheme.colorScheme.surface, RoundedCornerShape(8.dp)).padding(horizontal = 8.dp, vertical = 3.dp))
            }
            Text(reasonText(dr), style = MaterialTheme.typography.bodyMedium, color = content,
                modifier = Modifier.padding(top = 6.dp), lineHeight = MaterialTheme.typography.bodyMedium.fontSize * 1.5f)
            TextButton(onClick = { expanded = !expanded }) {
                Text(if (expanded) "收起完整日志 ▲" else "展开完整日志 ▼", style = MaterialTheme.typography.labelMedium)
            }
            if (expanded) {
                Text(dr.log, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant,
                    modifier = Modifier.fillMaxWidth().background(MaterialTheme.colorScheme.surfaceVariant, RoundedCornerShape(8.dp)).padding(8.dp))
            }
        }
    }
}

// ================= 后台：本地检测（独立） =================
private suspend fun runLocal(context: Context, main: Handler, current: UiState, onUpdate: (UiState) -> Unit) {
    var s = current.copy(localRunning = true, localStatus = "正在初始化本地检测…")
    onUpdate(s)
    val engine = DetectionEngine(context)
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
    main.post { onUpdate(s.copy(localRunning = false, localStatus = "本地检测完成", localSummary = rep)) }
}

// ================= 后台：联网检测（独立，仅开关开启时调用） =================
private suspend fun runOnlineOnly(context: Context, main: Handler, current: UiState, onUpdate: (UiState) -> Unit) {
    var s = current.copy(onlineRunning = true, onlineStatus = "正在初始化联网检测…")
    onUpdate(s)
    val engine = DetectionEngine(context)
    val rep = withContext(Dispatchers.IO) {
        engine.runOnline { dr, done, total, category, title ->
            main.post {
                val od = done.toFloat() / DetectionEngine.TOTAL_ONLINE
                s = s.copy(
                    onlineProgress = od.coerceIn(0f, 1f),
                    onlineStatus = "$category · $title",
                    onlineResults = insertSorted(s.onlineResults, dr)
                )
                onUpdate(s)
            }
        }
    }
    main.post { onUpdate(s.copy(onlineRunning = false, onlineStatus = "联网检测完成", onlineSummary = rep)) }
}

private fun reasonText(dr: DetectionResult): String {
    if (!dr.reason.isNullOrEmpty()) return dr.reason!!
    if (dr.level == DetectionResult.Level.NORMAL) return "通过：未命中风险特征（原始采集值见完整日志）。"
    val tag = when (dr.level) { DetectionResult.Level.ABNORMAL -> "异常"; DetectionResult.Level.SUSPECT -> "可疑"; else -> "低风险" }
    return "判定为$tag：「${dr.title}」检出「${dr.log.take(120)}」；按降误报策略需多独立证据聚合，详见完整日志复核。"
}

private fun export(context: Context, state: UiState) {
    val report = state.localSummary ?: return
    val txt = buildReportText(report)
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
                if (os != null) { os.write(txt.toByteArray(Charsets.UTF_8)); os.close(); toast(context, "已导出到下载目录：$name"); return }
            }
            toast(context, "导出失败")
        } else {
            val dir = Environment.getExternalStoragePublicDirectory(Environment.DIRECTORY_DOWNLOADS)
            if (dir != null && !dir.exists()) dir.mkdirs()
            val f = File(dir, name)
            val fos = FileOutputStream(f); fos.write(txt.toByteArray(Charsets.UTF_8)); fos.close()
            toast(context, "已导出：${f.absolutePath}")
        }
    } catch (e: Exception) { toast(context, "导出失败：${e.message}") }
}

private fun toast(context: Context, msg: String) { Toast.makeText(context, msg, Toast.LENGTH_SHORT).show() }

private fun buildReportText(report: DetectionEngine.Report): String {
    val sorted = report.results.sortedWith(compareBy({ priority(it.level) }))
    val sb = StringBuilder()
    sb.append("环境检测报告 v1.2.22\n")
    sb.append("总检测:").append(report.total)
        .append(" 正常:").append(report.clean)
        .append(" 可疑:").append(report.warn)
        .append(" 异常:").append(report.found).append("\n\n")
    for (dr in sorted) {
        sb.append("#").append(dr.id).append(" [").append(dr.level).append("] ")
            .append(dr.category).append(" · ").append(dr.title)
            .append("\n  日志: ").append(dr.log)
        if (dr.level != DetectionResult.Level.NORMAL) sb.append("\n  判定理由: ").append(reasonText(dr))
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
