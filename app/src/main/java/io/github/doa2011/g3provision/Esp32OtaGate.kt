package io.github.doa2011.g3provision

/** Authorization state only; actual OTA transport must supply verified evidence. */
internal class Esp32OtaGate(private val expectedMac: String, private val expectedSha: String) {
    init {
        require(expectedMac.matches(Regex("[0-9A-F]{12}")))
        require(expectedSha.matches(Regex("[0-9a-fA-F]{64}")))
    }
    data class Evidence(val mac: String, val model: String, val sha: String,
        val firmwareVerified: Boolean, val identityConfirmed: Boolean, val routesReady: Boolean,
        val tlsReady: Boolean, val fiveReplies: Boolean, val otaSubscribed: Boolean)
    enum class State { WAITING, AUTHORIZED, SENT, REBOOT_CONFIRMED, FAILED }
    @Volatile var state = State.WAITING
        private set
    @Synchronized fun authorize(e: Evidence): Boolean {
        if (state != State.WAITING) return false
        if (e.mac != expectedMac || e.model != "BRY88BBA15G" || !e.sha.equals(expectedSha,true) ||
            !e.firmwareVerified || !e.identityConfirmed || !e.routesReady || !e.tlsReady ||
            !e.fiveReplies || !e.otaSubscribed) return false
        state = State.AUTHORIZED
        return true
    }
    @Synchronized fun markSent(): Boolean {
        if (state != State.AUTHORIZED) return false
        state = State.SENT
        return true
    }
    @Synchronized fun confirmReboot(mac: String, model: String, communityVerified: Boolean): Boolean {
        if (state != State.SENT || mac != expectedMac || model != "BRY88BBA15G" || !communityVerified) return false
        state = State.REBOOT_CONFIRMED
        return true
    }
    @Synchronized fun fail() { if (state != State.REBOOT_CONFIRMED) state = State.FAILED }
}
