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
        versionCode = 2
        versionName = "0.2.0"
    }
    compileOptions { sourceCompatibility = JavaVersion.VERSION_17; targetCompatibility = JavaVersion.VERSION_17 }
    kotlinOptions { jvmTarget = "17" }
    packaging { resources { excludes += "META-INF/versions/9/OSGI-INF/MANIFEST.MF" } }
}
dependencies {
    implementation("org.nanohttpd:nanohttpd:2.3.1")
    implementation("org.bouncycastle:bcprov-jdk18on:1.80")
    implementation("org.bouncycastle:bcpkix-jdk18on:1.80")
}
