plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
    // Compose compiler plugin (version provided by root build script)
    id("org.jetbrains.kotlin.plugin.compose")
}

android {
    namespace = "com.example.secureime"
    compileSdk = 35

    defaultConfig {
        applicationId = "com.example.secureime"
        minSdk = 26
        targetSdk = 35
        versionCode = 1
        versionName = "1.0"
    }

    buildTypes {
        release {
            isMinifyEnabled = true
            proguardFiles(
                getDefaultProguardFile("proguard-android-optimize.txt"),
                "proguard-rules.pro"
            )
        }
        debug {
            isMinifyEnabled = false
        }
    }

    buildFeatures {
        compose = true
        buildConfig = true
    }

    // Do NOT include composeOptions { kotlinCompilerExtensionVersion = "..." } with Kotlin 2.x
    packaging {
        resources.excludes += setOf(
            "META-INF/AL2.0",
            "META-INF/LGPL2.1"
        )
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

}

kotlin {
    jvmToolchain(17)
}


// Optional: diagnostics (can be omitted)
composeCompiler {
    // Example: write reports to build/compose_compiler
    reportsDestination = layout.buildDirectory.dir("compose_compiler")
}

dependencies {
    val composeBom = platform("androidx.compose:compose-bom:2024.10.01")
    implementation(composeBom)
    androidTestImplementation(composeBom)

    implementation("androidx.activity:activity-compose:1.9.2")
    implementation("androidx.compose.material:material-icons-extended")
    implementation("androidx.compose.material3:material3")
    implementation("androidx.compose.ui:ui")
    implementation("androidx.compose.ui:ui-tooling-preview")
    debugImplementation("androidx.compose.ui:ui-tooling")
    implementation("androidx.lifecycle:lifecycle-runtime-ktx:2.8.4")
    implementation("androidx.profileinstaller:profileinstaller:1.3.1")

    implementation(project(":crypto-lib"))
}
