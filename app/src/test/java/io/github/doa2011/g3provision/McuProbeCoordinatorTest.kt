package io.github.doa2011.g3provision
import org.junit.Assert.*
import org.junit.Test

class McuProbeCoordinatorTest {
    @Test fun probesEveryTwoSecondsAndClaimsOnlyOnce() {
        val p=McuProbeCoordinator(20000,0)
        val first=p.poll(0)!!
        assertNull(p.poll(1999))
        val second=p.poll(2000)!!
        assertFalse(p.observe(first.id,2001,"SV.04.00.01.00",true))
        assertTrue(p.observe(second.id,2050,"SV.04.00.01.00",true))
        assertTrue(p.claimUpgrade(2050)); assertFalse(p.claimUpgrade(2051))
        p.cancel()
        assertEquals(McuProbeCoordinator.State.REQUESTED,p.state)
        assertFalse(p.verify("community","community",true,false))
        assertTrue(p.verify("community","community",true,true))
    }
    @Test fun noImageNoUpgradeAndDeadline() {
        val p=McuProbeCoordinator(5000,0)
        val probe=p.poll(0)!!
        assertFalse(p.observe(probe.id,1,"SV.04.00.01.00",false))
        assertFalse(p.claimUpgrade(1)); assertNull(p.poll(5000))
        assertEquals(McuProbeCoordinator.State.TIMED_OUT,p.state)
    }
    @Test fun cancelledCannotClaim() {
        val p=McuProbeCoordinator(5000,0)
        val probe=p.poll(0)!!
        assertTrue(p.observe(probe.id,1,"SV.04.00.01.00",true))
        p.cancel(); assertFalse(p.claimUpgrade(1))
    }
    @Test fun expiredProbeCannotAuthorize() {
        val p=McuProbeCoordinator(10000,0)
        val probe=p.poll(0)!!
        assertFalse(p.observe(probe.id,2000,"SV.04.00.01.00",true))
        assertFalse(p.claimUpgrade(2000))
    }
}
