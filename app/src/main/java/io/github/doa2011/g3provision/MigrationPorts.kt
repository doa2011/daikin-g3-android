package io.github.doa2011.g3provision

/** Shared phone listener and router destination ports; factory-facing ports stay unchanged. */
internal object MigrationPorts {
    const val DNS = 1053
    const val HTTPS = 8443
    const val MQTT_TLS = 18883
    const val FACTORY_DNS = 53
    const val FACTORY_HTTPS = 443
    const val FACTORY_MQTT_TLS = 8883
}
