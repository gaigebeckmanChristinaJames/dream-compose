package com.zuomeng.app;

public class DetectionResult {
    public enum Level { NORMAL, ABNORMAL, SUSPECT, LOW }
    public int id;
    public String title;
    public String log;          // field1: 完整日志（原始采集内容/原始值/命中特征清单）
    public Level level;
    public String category;
    public String reason;        // field2: 判定理由（人类可读，列出聚合证据；NORMAL/INFO 可空）
    public long timestamp;      // 检测时刻

    public DetectionResult(int id, String category, String title, String log, Level level) {
        this.id = id;
        this.category = category;
        this.title = title;
        this.log = log;
        this.level = level;
        this.timestamp = System.currentTimeMillis();
    }
}
