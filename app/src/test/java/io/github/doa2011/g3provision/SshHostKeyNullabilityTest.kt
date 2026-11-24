package io.github.doa2011.g3provision

import com.jcraft.jsch.HostKeyRepository
import org.junit.Assert.*
import org.junit.Test

class SshHostKeyNullabilityTest {
    @Test fun jschCanQueryWithoutHostOrKeyType() {
        for ((owner, name) in listOf(RouterBootstrap::class.java to "AcceptHostKey", RouterMigration::class.java to "PinRepository")) {
            val cls = owner.declaredClasses.single { it.simpleName == name }
            val ctor = cls.declaredConstructors.single()
            ctor.isAccessible = true
            val repo = (if (ctor.parameterCount == 0) ctor.newInstance() else ctor.newInstance("SHA256:test")) as HostKeyRepository
            assertTrue(repo.getHostKey("192.168.1.1", null).isEmpty())
            assertTrue(repo.getHostKey(null, null).isEmpty())
            repo.remove("192.168.1.1", null)
            repo.remove(null, null, null)
        }
    }
}
