package io.github.doa2011.g3provision
import org.junit.Assert.*
import org.junit.Test

class Esp32OtaGateTest {
    private val sha = "a".repeat(64)
    private val mac = "D0EF76255DCC"
    private fun gate() = Esp32OtaGate(mac,sha)
    private val ready = Esp32OtaGate.Evidence(mac,"BRY88BBA15G",sha,true,true,true,true,true,true)
    @Test fun rejectsEveryMissingCondition() {
        for (e in listOf(ready.copy(mac="000000000001"),ready.copy(model="G2"),ready.copy(sha="b".repeat(64)),
            ready.copy(firmwareVerified=false),ready.copy(identityConfirmed=false),ready.copy(routesReady=false),
            ready.copy(tlsReady=false),ready.copy(fiveReplies=false),ready.copy(otaSubscribed=false))) {
            assertFalse(gate().authorize(e))
        }
    }
    @Test fun oneShotAndVerifiedReboot() {
        val g = gate()
        assertFalse(g.markSent()); assertTrue(g.authorize(ready)); assertFalse(g.authorize(ready))
        assertTrue(g.markSent()); assertFalse(g.markSent())
        assertFalse(g.confirmReboot(mac,"BRY88BBA15G",false))
        assertTrue(g.confirmReboot(mac,"BRY88BBA15G",true))
    }
    @Test fun failureCannotRearm() { val g=gate(); g.fail(); assertFalse(g.authorize(ready)) }
}
