package io.github.doa2011.g3provision

import org.junit.Assert.*
import org.junit.Test

class DnsRedirectDomainScopeTest {
    @Test fun onlyTheThreeConfiguredDaikinDomainsAreIntercepted() {
        val server = DnsRedirectServer("192.168.1.1", "192.168.1.1", 0)
        assertEquals(3, DnsRedirectServer.TARGET_DOMAINS.size)
        DnsRedirectServer.TARGET_DOMAINS.forEach { assertTrue(server.isDaikinTarget(it)) }
        assertFalse(server.isDaikinTarget("example.com"))
        assertFalse(server.isDaikinTarget("daikin-china.com.cn"))
        assertFalse(server.isDaikinTarget("not-newlifemulti.daikin-china.com.cn"))
        assertFalse(server.isDaikinTarget("newlifemulti.daikin-china.com.cn.attacker.example"))
    }

    @Test fun targetMatchingIsCaseInsensitiveButExact() {
        val server = DnsRedirectServer("192.168.1.1", "192.168.1.1", 0)
        assertTrue(server.isDaikinTarget("NEWLIFEMULTI.DAIKIN-CHINA.COM.CN"))
        assertFalse(server.isDaikinTarget("x.newlifemulti.daikin-china.com.cn"))
    }
}
