package io.github.doa2011.g3provision

import java.util.UUID

/** Pure rule plan. SSH execution and transactional cleanup are deliberately separate. */
internal class RouterSessionPlan(val id: String, val routerIp: String, val phoneIp: String, val g3Ip: String) {
    init {
        require(id.matches(Regex("[a-f0-9]{32}")))
        require(listOf(routerIp, phoneIp, g3Ip).all { validIp(it) })
        require(listOf(routerIp, phoneIp, g3Ip).distinct().size == 3)
    }
    data class Rule(val section: String, val owner: String, val sourceIp: String, val destinationIp: String,
                    val protocol: String, val externalPort: Int, val internalPort: Int, val originalDestination: String?)
    val rules: List<Rule> = listOf(
        rule("du", "udp", MigrationPorts.FACTORY_DNS, MigrationPorts.DNS, null),
        rule("dt", "tcp", MigrationPorts.FACTORY_DNS, MigrationPorts.DNS, null),
        rule("hs", "tcp", MigrationPorts.FACTORY_HTTPS, MigrationPorts.HTTPS, routerIp),
        rule("mq", "tcp", MigrationPorts.FACTORY_MQTT_TLS, MigrationPorts.MQTT_TLS, routerIp)
    )
    private fun rule(suffix: String, protocol: String, external: Int, internal: Int, destination: String?) =
        Rule("g3mig_" + id + "_" + suffix, id, g3Ip, phoneIp, protocol, external, internal, destination)

    enum class Installation { CREATE, ALREADY_INSTALLED, CONFLICT }
    fun assess(existing: Map<String, Rule>): Installation {
        val found = rules.mapNotNull { existing[it.section] }
        if (found.any { it !in rules }) return Installation.CONFLICT
        // Other migration sessions for the same source must not compete for redirects.
        if (existing.values.any { it.sourceIp == g3Ip && it.owner != id }) return Installation.CONFLICT
        return when (found.size) {
            0 -> Installation.CREATE
            rules.size -> Installation.ALREADY_INSTALLED
            else -> Installation.CONFLICT
        }
    }
    fun removable(existing: Map<String, Rule>): List<String> =
        rules.filter { existing[it.section] == it }.map { it.section }

    companion object {
        fun create(router: String, phone: String, g3: String) =
            RouterSessionPlan(UUID.randomUUID().toString().replace("-", ""), router, phone, g3)
        private fun validIp(ip: String): Boolean {
            val parts = ip.split('.')
            return parts.size == 4 && parts.all { it.matches(Regex("0|[1-9][0-9]{0,2}")) && it.toInt() in 0..255 }
        }
    }
}
