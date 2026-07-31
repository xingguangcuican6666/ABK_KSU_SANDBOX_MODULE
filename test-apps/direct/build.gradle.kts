plugins {
    id("com.android.application")
}

android {
    namespace = "dev.anybase.abksandbox.direct"
    compileSdk = 35

    defaultConfig {
        applicationId = "dev.anybase.abksandbox.direct"
        minSdk = 26
        targetSdk = 35
        versionCode = 2
        versionName = "0.2"
    }

    sourceSets.named("main") {
        java.srcDir("../shared/src/main/java")
        aidl.srcDir("../shared/src/main/aidl")
    }

    buildFeatures {
        aidl = true
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
}
