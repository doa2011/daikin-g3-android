package io.github.doa2011.g3provision

import org.junit.Assert.*
import org.junit.Test
import io.github.doa2011.g3provision.MigrationProgress.Stage
import io.github.doa2011.g3provision.MigrationProgress.Code

class MigrationProgressTest {
    @Test fun blocksSkippedStagesAndWrongEvidence() {
        val p=MigrationProgress()
        assertFalse(p.advance(Stage.ESP32,0,Code.GATEWAY_OK))
        assertFalse(p.advance(Stage.DISCOVERY,0,Code.IDENTITY_OK))
        assertTrue(p.advance(Stage.DISCOVERY,1,Code.START))
        assertFalse(p.advance(Stage.IDENTITY,0,Code.SCAN_OK))
        assertTrue(p.advance(Stage.IDENTITY,2,Code.SCAN_OK))
    }
    @Test fun boundedLogAndTerminalState() {
        val p=MigrationProgress(2)
        assertTrue(p.advance(Stage.DISCOVERY,1,Code.START))
        assertTrue(p.advance(Stage.IDENTITY,2,Code.SCAN_OK))
        assertTrue(p.advance(Stage.CANCELLED,3,Code.USER_CANCEL))
        assertEquals(listOf(Code.SCAN_OK,Code.USER_CANCEL),p.snapshot().map { it.code })
        assertFalse(p.advance(Stage.SERVICES,4,Code.IDENTITY_OK))
    }
    @Test fun fullSequenceRequiresRouterRestoreBeforeMcu() {
        val p=MigrationProgress()
        val steps=listOf(Stage.DISCOVERY to Code.START,Stage.IDENTITY to Code.SCAN_OK,
            Stage.SERVICES to Code.IDENTITY_OK,Stage.ROUTER to Code.SERVICES_OK,Stage.GATEWAY to Code.ROUTER_OK,
            Stage.ESP32 to Code.GATEWAY_OK,Stage.RESTORE to Code.ESP32_VERIFIED)
        steps.forEachIndexed { i,(stage,code) -> assertTrue(p.advance(stage,i.toLong(),code)) }
        assertFalse(p.advance(Stage.COMPLETE,8,Code.MCU_VERIFIED))
        assertFalse(p.advance(Stage.MCU,8,Code.ESP32_VERIFIED))
        assertTrue(p.advance(Stage.MCU,8,Code.ROUTER_RESTORED))
        assertTrue(p.advance(Stage.COMPLETE,9,Code.MCU_VERIFIED))
    }
}
