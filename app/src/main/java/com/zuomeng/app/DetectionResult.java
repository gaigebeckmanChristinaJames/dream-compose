package com.zuomeng.app;

public class DetectionResult {
    public enum Level { NORMAL, ABNORMAL, SUSPECT, LOW }
    public int id;
    public String title;
    public String log;
    public Level level;
    public String category;

    public DetectionResult(int id, String category, String title, String log, Level level) {
        this.id = id;
        this.category = category;
        this.title = title;
        this.log = log;
        this.level = level;
    }
}
