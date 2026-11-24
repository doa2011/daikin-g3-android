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

    /** Generate a session-scoped UCI transaction. Caller explicitly executes it over pinned SSH. */
    fun applyScript(): String {
        val sh = '$'
        val backup = "/root/g3-migration-$id.firewall.bak"
        val sections = rules.mapIndexed { index, rule ->
            val suffix = listOf("dns_udp", "dns_tcp", "https", "mqtt")[index]
            val sourceDip = rule.originalDestination?.let { "uci set firewall.${rule.section}.src_dip='$it'" } ?: ""
            listOf("uci set firewall.${rule.section}=redirect",
                "uci set firewall.${rule.section}.name='G3 migration $suffix'",
                "uci set firewall.${rule.section}.g3mig_owner='$id'",
                "uci set firewall.${rule.section}.src=lan",
                "uci set firewall.${rule.section}.src_ip='$g3Ip'", sourceDip,
                "uci set firewall.${rule.section}.src_dport=${rule.externalPort}",
                "uci set firewall.${rule.section}.dest=lan",
                "uci set firewall.${rule.section}.dest_ip='$phoneIp'",
                "uci set firewall.${rule.section}.dest_port=${rule.internalPort}",
                "uci set firewall.${rule.section}.proto=${rule.protocol}",
                "uci set firewall.${rule.section}.target=DNAT").filter { it.isNotEmpty() }.joinToString("\n")
        }.joinToString("\n")
        val names = rules.joinToString(" ") { it.section }
        return listOf("set -eu", "backup='$backup'",
            "[ ! -e \"${sh}backup\" ] || { echo 'Session backup already exists' >&2; exit 31; }",
            "for section in $names; do if uci -q get \"firewall.${sh}section\" >/dev/null 2>&1; then echo \"Session rule exists: ${sh}section\" >&2; exit 32; fi; done",
            "[ -z \"${sh}(uci changes firewall)\" ] || { echo 'Firewall has pending changes' >&2; exit 33; }",
            "cp /etc/config/firewall \"${sh}backup\"",
            "rollback() { status=${sh}?; if [ \"${sh}status\" -ne 0 ]; then cp \"${sh}backup\" /etc/config/firewall; uci revert firewall || true; /etc/init.d/firewall reload || true; rm -f \"${sh}backup\"; fi; exit \"${sh}status\"; }",
            "trap rollback EXIT HUP INT TERM", sections, "uci commit firewall", "/etc/init.d/firewall reload",
            "trap - EXIT HUP INT TERM", "echo 'G3 migration session $id installed'").joinToString("\n") + "\n"
    }

    /** Cleanup verifies the owner marker before deleting any section. */
    fun cleanupScript(): String {
        val sh = '$'
        val names = rules.joinToString(" ") { it.section }
        val backup = "/root/g3-migration-$id.firewall.bak"
        return listOf("set -eu", "backup='$backup'",
            "[ -f \"${sh}backup\" ] || { echo 'Session backup missing' >&2; exit 41; }",
            "[ -z \"${sh}(uci changes firewall)\" ] || { echo 'Firewall has pending changes' >&2; exit 42; }",
            "for section in $names; do owner=${sh}(uci -q get \"firewall.${sh}section.g3mig_owner\" || true); if [ -n \"${sh}owner\" ] && [ \"${sh}owner\" != '$id' ]; then echo \"Foreign owner: ${sh}section\" >&2; exit 43; fi; done",
            "cp /etc/config/firewall \"${sh}backup.cleanup\"",
            "cleanup_rollback() { status=${sh}?; if [ \"${sh}status\" -ne 0 ]; then cp \"${sh}backup.cleanup\" /etc/config/firewall; uci revert firewall || true; /etc/init.d/firewall reload || true; fi; rm -f \"${sh}backup.cleanup\"; exit \"${sh}status\"; }",
            "trap cleanup_rollback EXIT HUP INT TERM",
            "for section in $names; do owner=${sh}(uci -q get \"firewall.${sh}section.g3mig_owner\" || true); if [ \"${sh}owner\" = '$id' ]; then uci -q delete \"firewall.${sh}section\"; fi; done",
            "uci commit firewall", "/etc/init.d/firewall reload", "rm -f \"${sh}backup\" \"${sh}backup.cleanup\"",
            "trap - EXIT HUP INT TERM", "echo 'G3 migration session $id cleaned'").joinToString("\n") + "\n"
    }
    companion object {
        fun create(router: String, phone: String, g3: String) =
            RouterSessionPlan(UUID.randomUUID().toString().replace("-", ""), router, phone, g3)
        private fun validIp(ip: String): Boolean {
            val parts = ip.split('.')
            return parts.size == 4 && parts.all { it.matches(Regex("0|[1-9][0-9]{0,2}")) && it.toInt() in 0..255 }
        }
    }
}
