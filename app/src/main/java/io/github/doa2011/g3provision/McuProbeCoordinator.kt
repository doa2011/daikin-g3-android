package io.github.doa2011.g3provision

/** Transport-neutral coordinator. No device commands; adapter must verify the real protocol. */
internal class McuProbeCoordinator(private val deadlineMs: Long, private val startMs: Long) {
    init { require(startMs >= 0 && deadlineMs > startMs) }
    enum class State { WAITING, READY, REQUESTED, VERIFIED, CANCELLED, TIMED_OUT, FAILED }
    @Volatile var state = State.WAITING
        private set
    private var nextProbe = startMs
    private var counter = 0L
    private var pending: Probe? = null
    data class Probe(val id: Long, val sentAtMs: Long)
    @Synchronized fun poll(nowMs: Long): Probe? {
        if (state != State.WAITING) return null
        if (nowMs >= deadlineMs) { state = State.TIMED_OUT; pending = null; return null }
        if (nowMs < nextProbe) return null
        nextProbe = nowMs + 2000
        return Probe(++counter, nowMs).also { pending = it }
    }
    @Synchronized fun observe(probeId: Long, nowMs: Long, version: String?, imageVerifiedOnEsp: Boolean): Boolean {
        if (state != State.WAITING) return false
        if (nowMs >= deadlineMs) { state = State.TIMED_OUT; pending = null; return false }
        val probe = pending ?: return false
        if (probe.id != probeId) return false
        pending = null
        if (nowMs < probe.sentAtMs || nowMs - probe.sentAtMs >= 2000 ||
            version != "SV.04.00.01.00" || !imageVerifiedOnEsp) return false
        state = State.READY
        return true
    }
    @Synchronized fun claimUpgrade(nowMs: Long): Boolean {
        if (state != State.READY) return false
        if (nowMs >= deadlineMs || nowMs >= nextProbe) { state = State.TIMED_OUT; return false }
        if (nowMs < nextProbe - 2000) return false
        state = State.REQUESTED
        return true
    }
    @Synchronized fun verify(version: String?, expected: String, communication: Boolean, sensors: Boolean): Boolean {
        if (state != State.REQUESTED || expected.isBlank() || expected == "SV.04.00.01.00" ||
            version != expected || !communication || !sensors) return false
        state = State.VERIFIED
        return true
    }
    @Synchronized fun fail() {
        if (state in listOf(State.WAITING, State.READY, State.REQUESTED)) { pending = null; state = State.FAILED }
    }
    @Synchronized fun cancel() {
        if (state == State.WAITING || state == State.READY) { pending = null; state = State.CANCELLED }
        // Once the request is sent, do not imply a safe remote interruption.
    }
}
