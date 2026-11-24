package io.github.doa2011.g3provision

/** Bounded, structured migration progress. No passwords or raw protocol payloads accepted. */
internal class MigrationProgress(private val capacity: Int = 200) {
    init { require(capacity in 1..2000) }
    enum class Stage { IDLE, DISCOVERY, IDENTITY, SERVICES, ROUTER, GATEWAY, ESP32, RESTORE, MCU, COMPLETE, FAILED, CANCELLED }
    enum class Code { START, SCAN_OK, IDENTITY_OK, SERVICES_OK, ROUTER_OK, GATEWAY_OK, ESP32_VERIFIED, ROUTER_RESTORED, MCU_VERIFIED, FINISHED, ERROR, USER_CANCEL }
    data class Event(val atMs: Long, val stage: Stage, val code: Code)
    private val events = ArrayDeque<Event>()
    @Volatile var stage = Stage.IDLE
        private set
    private val sequence = listOf(Stage.IDLE,Stage.DISCOVERY,Stage.IDENTITY,Stage.SERVICES,Stage.ROUTER,
        Stage.GATEWAY,Stage.ESP32,Stage.RESTORE,Stage.MCU,Stage.COMPLETE)
    private val entryCodes = mapOf(Stage.DISCOVERY to Code.START, Stage.IDENTITY to Code.SCAN_OK,
        Stage.SERVICES to Code.IDENTITY_OK, Stage.ROUTER to Code.SERVICES_OK, Stage.GATEWAY to Code.ROUTER_OK,
        Stage.ESP32 to Code.GATEWAY_OK, Stage.RESTORE to Code.ESP32_VERIFIED, Stage.MCU to Code.ROUTER_RESTORED,
        Stage.COMPLETE to Code.MCU_VERIFIED, Stage.FAILED to Code.ERROR, Stage.CANCELLED to Code.USER_CANCEL)
    @Synchronized fun advance(next: Stage, nowMs: Long, code: Code): Boolean {
        if (nowMs < 0 || (events.lastOrNull()?.atMs ?: 0) > nowMs) return false
        if (stage in listOf(Stage.COMPLETE,Stage.FAILED,Stage.CANCELLED)) return false
        if (entryCodes[next] != code) return false
        if (next != Stage.FAILED && next != Stage.CANCELLED && sequence.getOrNull(sequence.indexOf(stage)+1) != next) return false
        stage=next
        while (events.size >= capacity) events.removeFirst()
        events.addLast(Event(nowMs,next,code))
        return true
    }
    @Synchronized fun snapshot(): List<Event> = events.toList()
}
