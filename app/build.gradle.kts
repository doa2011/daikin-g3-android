plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
}
android {
    namespace = "io.github.doa2011.g3provision"
    compileSdk = 35
    defaultConfig {
        applicationId = "io.github.doa2011.g3provision"
        minSdk = 26
        targetSdk = 35
        versionCode = 3
        versionName = "0.3.0"
    }
    compileOptions { sourceCompatibility = JavaVersion.VERSION_17; targetCompatibility = JavaVersion.VERSION_17 }
    kotlinOptions { jvmTarget = "17" }
    packaging {
        resources {
            // JVM multi-release OSGi bundle manifests are not used by Android.
            // Keep provider classes, service descriptors and license resources intact.
            excludes += "META-INF/versions/*/OSGI-INF/MANIFEST.MF"
        }
    }
}
dependencies {
    implementation("com.github.mwiede:jsch:0.2.21")
    implementation("org.nanohttpd:nanohttpd:2.3.1")
    implementation("org.bouncycastle:bcprov-jdk18on:1.80")
    implementation("org.bouncycastle:bcpkix-jdk18on:1.80")
    testImplementation("junit:junit:4.13.2")
}
