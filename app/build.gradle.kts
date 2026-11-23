plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
}
dependencies { implementation("com.github.mwiede:jsch:0.2.21") }

android {
    namespace = "io.github.doa2011.g3provision"
    compileSdk = 35
    defaultConfig {
        applicationId = "io.github.doa2011.g3provision"
        minSdk = 26
        targetSdk = 35
        versionCode = 1
        versionName = "0.1.0"
    }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    kotlinOptions {
        jvmTarget = "17"
    }
}
