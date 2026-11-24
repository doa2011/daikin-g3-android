package io.github.doa2011.g3provision

import org.junit.Assert.*
import org.junit.Test

class RouterSessionPlanTest {
    private fun plan() = RouterSessionPlan.create("192.168.1.1","192.168.1.2","192.168.1.3")
    @Test fun independentNamesAndPorts() {
        val a = plan(); val b = plan()
        assertTrue(a.rules.map { it.section }.intersect(b.rules.map { it.section }.toSet()).isEmpty())
        assertEquals(listOf(1053,1053,8443,18883),a.rules.map { it.internalPort })
        assertEquals(RouterSessionPlan.Installation.CONFLICT,a.assess(b.rules.associateBy { it.section }))
    }
    @Test fun idempotenceAndOwnership() {
        val a = plan(); val all = a.rules.associateBy { it.section }
        assertEquals(RouterSessionPlan.Installation.CREATE,a.assess(emptyMap()))
        assertEquals(RouterSessionPlan.Installation.ALREADY_INSTALLED,a.assess(all))
        val altered = all + (a.rules.first().section to a.rules.first().copy(owner="foreign"))
        assertEquals(RouterSessionPlan.Installation.CONFLICT,a.assess(altered))
        assertEquals(3,a.removable(altered).size)
        assertEquals(RouterSessionPlan.Installation.CONFLICT,a.assess(mapOf(a.rules.first().section to a.rules.first())))
    }
    @Test(expected=IllegalArgumentException::class) fun rejectsInjectedAddress() {
        RouterSessionPlan.create("192.168.1.1","192.168.1.2;echo x","192.168.1.3")
    }
}
