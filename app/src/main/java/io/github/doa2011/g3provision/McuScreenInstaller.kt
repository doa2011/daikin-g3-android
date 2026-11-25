package io.github.doa2011.g3provision

import android.content.Context
import android.os.SystemClock
import org.json.JSONObject
import org.msgpack.core.MessagePack
import org.msgpack.value.Value
import org.msgpack.value.ValueFactory
import java.io.File
import java.net.HttpURLConnection
import java.net.URL
import java.security.MessageDigest
import java.util.UUID

/** Android port of upstream BRY88BBA15G/tools/flash_screen.py --mode install. */
internal class McuScreenInstaller(private val context: Context) {
    data class Result(val sha256: String, val md5: String, val mode: String)
    private val expectedSha = "9cafaae14b47afd03c3bc0f53b63f4b7a2a99225ac0732ba39a8a6f18c3bf6c9"
    private val logFile = File(context.filesDir, "mcu-install.jsonl")

    fun install(baseUrl: String, progress: (String) -> Unit): Result {
        val uri = java.net.URI(baseUrl)
        require(uri.scheme == "http" && uri.host != null && uri.port == -1) { "G3 地址必须为 http://局域网 IPv4" }
        val host = uri.host
        require(privateIpv4(host)) { "只允许访问用户指定的局域网 G3 IPv4 地址" }
        val image = context.assets.open("g3/daikin_G3_screen.bin").use { it.readBytes() }
        validateImage(image)
        val sha = digest("SHA-256", image)
        val md5 = digest("MD5", image)
        log("image_validated", JSONObject().put("size", image.size).put("sha256", sha).put("md5", md5))
        progress("内置 MCU 固件校验通过：421888 字节，SHA-256=" + sha)

        val status = command(baseUrl, "status.get", query = true)
        require(status.str("hardware_model") == "BRY88BBA15G") { "设备型号不匹配：" + status.str("hardware_model") }
        val recovery = command(baseUrl, "screen.recovery.get", query = true)
        val factory = !recovery.bool("available")
        if (!factory && !recovery.bool("ota_activation")) error("社区 MCU 的 OTA 安装能力不可用，拒绝刷写")
        val previousSession = recovery.scalar("session")
        val installPath = if (factory) "factory-uart" else "community-maintenance"
        log("installation_path", JSONObject().put("path", installPath))
        progress("设备型号已确认，安装路径=" + installPath + "；上传 MCU 固件")

        val upload = uploadImage(baseUrl, image)
        require(upload.str("code") == "ok") { "ESP32 固件上传失败：" + upload.str("code") }
        val returnedSha = upload.obj("data").str("sha256")
        require(returnedSha.equals(sha, true)) { "ESP32 端回读 SHA-256 不匹配" }
        log("upload_verified", JSONObject().put("sha256", returnedSha).put("bytes", image.size))
        progress("ESP32 端回读 SHA-256 一致")

        val startParams = linkedMapOf("mode" to if (factory) "factory-bootstrap" else "stage")
        if (factory) startParams["sha256"] = sha
        command(baseUrl, "screen.update.start", startParams)
        log("start", JSONObject().put("mode", startParams["mode"]))
        progress(if (factory) "已触发原厂 MCU UART 首次安装，等待 MCU 重启及内部 MD5 验证" else "已触发社区 MCU 暂存，等待 staged_verified")

        val deadline = SystemClock.elapsedRealtime() + 600000L
        var last = ""
        while (SystemClock.elapsedRealtime() < deadline) {
            val snapshot = command(baseUrl, "status.get", query = true)
            val screen = snapshot.obj("screen")
            val ota = screen.obj("ota")
            val rec = screen.obj("recovery")
            val state = ota.str("state")
            val mode = rec.str("mode")
            val imageMd5 = rec.str("image_md5")
            val line = "OTA=" + state + " sent=" + ota.scalar("sent") + " MCU=" + mode + " image_md5=" + imageMd5
            if (line != last) {
                progress(line)
                log("progress", JSONObject().put("state", state).put("mode", mode).put("image_md5", imageMd5))
                last = line
            }
            if (factory && rec.bool("available") && imageMd5.equals(md5, true)) {
                if (mode == "fault_recovery") error("原厂 MCU 接收镜像后进入 fault_recovery")
                if (mode == "normal") {
                    log("verified_running", JSONObject().put("mode", mode).put("image_md5", imageMd5))
                    return Result(sha, md5, mode)
                }
            }
            if (factory && state == "artifact_ready") error("ESP32 在 MCU 传输完成前重启，安装未完成")
            if (!factory && state == "staged_verified") break
            if (state in setOf("timeout", "read_error", "write_error", "cancelled", "upload_failed")) error("MCU UART 升级失败：" + state)
            SystemClock.sleep(400)
        }
        if (factory) error("等待原厂 MCU 首次安装超过 10 分钟，未确认成功")
        val staged = command(baseUrl, "status.get", query = true).obj("screen").obj("ota").str("state")
        require(staged == "staged_verified") { "MCU 暂存未通过校验：" + staged }

        progress("MCU 暂存校验通过，发送一次 install 命令")
        val installReply = command(baseUrl, "screen.update.install", mapOf("sha256" to sha))
        val installRequest = installReply.scalar("request")
        log("install_requested", JSONObject().put("request", installRequest))
        val verifyDeadline = SystemClock.elapsedRealtime() + 90000L
        while (SystemClock.elapsedRealtime() < verifyDeadline) {
            val rec = command(baseUrl, "screen.recovery.get", query = true)
            val session = rec.scalar("session")
            val imageMd5 = rec.str("image_md5")
            val mode = rec.str("mode")
            if (rec.bool("available") && session != previousSession && imageMd5.equals(md5, true)) {
                if (mode == "fault_recovery") error("新 MCU 镜像启动失败：fault_recovery")
                if (mode == "normal") {
                    log("verified_running", JSONObject().put("mode", mode).put("image_md5", imageMd5))
                    return Result(sha, md5, mode)
                }
            }
            if (session == previousSession && rec.scalar("request") == installRequest &&
                rec.str("state") in setOf("mcu_rejected", "invalid_response", "timeout")) {
                error("MCU 拒绝安装：" + rec.str("state"))
            }
            SystemClock.sleep(400)
        }
        error("安装命令已发送，但 90 秒内未验证到新 MCU session 和匹配 MD5")
    }

    private fun uploadImage(baseUrl: String, image: ByteArray): Value {
        val c = URL(baseUrl.trimEnd('/') + "/api/v1/screen/ota/upload").openConnection() as HttpURLConnection
        c.requestMethod = "POST"
        c.connectTimeout = 8000
        c.readTimeout = 30000
        c.doOutput = true
        c.setFixedLengthStreamingMode(image.size)
        c.setRequestProperty("Content-Type", "application/octet-stream")
        c.setRequestProperty("X-IotCloud-Target", "BRY88BBA15G-screen")
        return try {
            c.outputStream.use { it.write(image) }
            val code = c.responseCode
            val stream = if (code in 200..299) c.inputStream else c.errorStream
            val bytes = stream?.use { it.readBytes() } ?: byteArrayOf()
            require(code == 200) { "MCU 固件上传 HTTP " + code }
            MessagePack.newDefaultUnpacker(bytes).use { it.unpackValue() }
        } finally { c.disconnect() }
    }

    private fun command(baseUrl: String, action: String, params: Map<String, String> = emptyMap(), query: Boolean = false): Value {
        var last: Exception? = null
        val attempts = if (query) 5 else 1
        for (attempt in 0 until attempts) {
            val c = URL(baseUrl.trimEnd('/') + "/api/v1/command").openConnection() as HttpURLConnection
            try {
                c.requestMethod = "POST"
                c.connectTimeout = 8000
                c.readTimeout = 8000
                c.doOutput = true
                c.setRequestProperty("Content-Type", "application/msgpack")
                val body = packCommand(action, params)
                c.setFixedLengthStreamingMode(body.size)
                c.outputStream.use { it.write(body) }
                val status = c.responseCode
                if (status == 503 && query && attempt < attempts - 1) {
                    SystemClock.sleep(100L * (attempt + 1))
                    continue
                }
                val stream = if (status in 200..299) c.inputStream else c.errorStream
                val bytes = stream?.use { it.readBytes() } ?: byteArrayOf()
                require(status == 200) { action + " HTTP " + status }
                val reply = MessagePack.newDefaultUnpacker(bytes).use { it.unpackValue() }
                val code = reply.str("code")
                require(code == "ok" || code == "accepted") { action + " 返回 " + code }
                return reply.obj("data")
            } catch (e: Exception) {
                last = e
                if (!query || attempt == attempts - 1) throw e
                SystemClock.sleep(100L * (attempt + 1))
            } finally { c.disconnect() }
        }
        throw last ?: IllegalStateException(action + " failed")
    }

    private fun packCommand(action: String, params: Map<String, String>): ByteArray {
        val p = MessagePack.newDefaultBufferPacker()
        p.packMapHeader(3)
        p.packString("request_id").packString(UUID.randomUUID().toString().replace("-", ""))
        p.packString("action").packString(action)
        p.packString("params").packMapHeader(params.size)
        params.forEach { (k, v) -> p.packString(k).packString(v) }
        return p.toByteArray().also { p.close() }
    }

    private fun validateImage(bytes: ByteArray) {
        require(bytes.size == 0x67000) { "MCU 固件大小错误：" + bytes.size + "，预期 421888" }
        val sp = le32(bytes, 0)
        val reset = le32(bytes, 4)
        require(sp == 0x20010000L && (reset and 1L) == 1L && reset in 0x14001L..0x7AFFF) { "MCU 应用向量校验失败" }
        val marker = "iotcloud-screen/BRY88BBA15G;application=0x14000;install=factory-uart;".toByteArray(Charsets.US_ASCII)
        require(bytes.indexOfBytes(marker) >= 0) { "MCU 型号或 factory-uart 安装标识不匹配" }
        require(digest("SHA-256", bytes).equals(expectedSha, true)) { "内置 MCU 固件 SHA-256 校验失败" }
    }

    private fun le32(b: ByteArray, i: Int): Long =
        (b[i].toLong() and 255) or ((b[i+1].toLong() and 255) shl 8) or
        ((b[i+2].toLong() and 255) shl 16) or ((b[i+3].toLong() and 255) shl 24)

    private fun ByteArray.indexOfBytes(needle: ByteArray): Int {
        if (needle.isEmpty() || needle.size > size) return -1
        for (i in 0..size-needle.size) if (needle.indices.all { this[i+it] == needle[it] }) return i
        return -1
    }

    private fun digest(algorithm: String, data: ByteArray): String =
        MessageDigest.getInstance(algorithm).digest(data).joinToString("") { "%02x".format(it.toInt() and 255) }

    private fun privateIpv4(host: String): Boolean {
        val p = host.split(".").mapNotNull { it.toIntOrNull() }
        if (p.size != 4 || p.any { it !in 0..255 }) return false
        return p[0] == 10 || (p[0] == 192 && p[1] == 168) || (p[0] == 172 && p[1] in 16..31)
    }

    private fun log(event: String, data: JSONObject) {
        synchronized(logFile) {
            logFile.parentFile?.mkdirs()
            logFile.appendText(JSONObject().put("time", System.currentTimeMillis()).put("event", event).put("data", data).toString() + "\n")
        }
    }

    private fun Value.obj(key: String): Value = asMapValue().getValue(ValueFactory.newString(key))
    private fun Value.str(key: String): String = obj(key).asStringValue().asString()
    private fun Value.bool(key: String): Boolean = try { obj(key).asBooleanValue().boolean } catch (_: Exception) { false }
    private fun Value.scalar(key: String): String = try {
        val v = obj(key)
        if (v.isStringValue) v.asStringValue().asString() else v.toString()
    } catch (_: Exception) { "" }
}
