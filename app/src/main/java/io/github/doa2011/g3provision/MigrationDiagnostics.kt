package io.github.doa2011.g3provision

internal object MigrationDiagnostics {
    @Synchronized fun append(context: android.content.Context, line: String) {
        val prefs=context.getSharedPreferences("g3",0)
        val previous = prefs.getString("mqtt_diag", "").orEmpty().lines().filter { it.isNotBlank() }
        val timestamp = java.text.SimpleDateFormat("HH:mm:ss.SSS", java.util.Locale.US).format(java.util.Date())
        fun sanitize(value: String): String = value.replace(Regex("[\\r\\n\\p{Cntrl}]"), " ")
            .replace(Regex("(?i)(clientId|client_token|token|password|passwd|secret|authorization|api[_-]?key|private[_-]?key)\\s*[:=]\\s*\\S+"), "$1=[REDACTED]")
            .take(1024)
        val candidates = (previous + "$timestamp $line").takeLast(100).map { sanitize(it) }
        val retained = java.util.ArrayDeque<String>()
        var bytes = 0
        for (entry in candidates.asReversed()) {
            val size = entry.toByteArray(Charsets.UTF_8).size + if (retained.isEmpty()) 0 else 1
            if (bytes + size > 32768) break
            retained.addFirst(entry)
            bytes += size
        }
        prefs.edit().putString("mqtt_diag", retained.joinToString("\n")).apply()
    }

    @Synchronized fun clear(context: android.content.Context) {
        context.getSharedPreferences("g3",0).edit().remove("mqtt_diag").apply()
    }
}
