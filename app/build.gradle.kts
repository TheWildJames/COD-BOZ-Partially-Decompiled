import java.util.Properties

plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
    id("org.jetbrains.kotlin.plugin.compose")
}

android {
    val keystoreProperties = Properties().apply {
        val keystorePropertiesFile = rootProject.file("keystore.properties")
        if (keystorePropertiesFile.canRead()) {
            load(keystorePropertiesFile.inputStream())
        }
    }

    // Release signing is optional: keystore.properties is gitignored and absent
    // in fresh clones. Only wire up the signingConfig when it is actually present,
    // otherwise storeFile resolves to an empty path and configuration fails.
    signingConfigs {
        if (keystoreProperties.getProperty("storeFile", "").isNotBlank() &&
            rootProject.file(keystoreProperties.getProperty("storeFile")).exists()
        ) {
            create("release") {
                storeFile = rootProject.file(keystoreProperties.getProperty("storeFile"))
                storePassword = keystoreProperties.getProperty("storePassword", "")
                keyAlias = keystoreProperties.getProperty("keyAlias", "")
                keyPassword = keystoreProperties.getProperty("keyPassword", "")
            }
        }
    }

    namespace = "com.activision.boz"

    compileSdk = 36
    buildToolsVersion = "36.0.0"
    ndkVersion = "30.0.16248370"

    val versionPropsFile = file("version.properties")
    require(versionPropsFile.canRead()) { "Could not read version.properties!" }

    val versionProps = Properties().apply {
        load(versionPropsFile.inputStream())
    }

    defaultConfig {
        applicationId = "com.activision.boz"
        minSdk = 21
        // Low targetSdk restores legacy WRITE_EXTERNAL_STORAGE semantics for
        // the engine, which writes game data to /sdcard/Android/obb/<pkg>/.
        // At SDK 36 those writes are EACCES-blocked even with All files access.
        // App is private (never Play Store) so the trade-off is fine.
        targetSdk = 35
        versionCode = versionProps.getProperty("VERSION_CODE").toInt()
        versionName = "1.0.8.1"
        versionNameSuffix = "kotlin"
        multiDexEnabled = false

        // arm64-v8a only: Pixel 8 / Tensor G3 is ARMv9-A with no AArch32
        // execution unit, so armeabi-v7a payloads cannot run there at all.
        ndk {
            abiFilters += listOf("arm64-v8a")
        }
    }

    buildTypes {
        getByName("release") {
            //noinspection ChromeOsAbiSupport
            ndk {
                abiFilters += listOf("arm64-v8a")
            }
            //not worth enabling
            isMinifyEnabled = true
            proguardFiles(
                getDefaultProguardFile("proguard-android-optimize.txt"),
                "proguard-rules.pro"
            )
            signingConfig = signingConfigs.findByName("release")
        }
    }

    sourceSets {
        getByName("main") {
            java.srcDir("src/main/java")
        }
    }

    buildFeatures {
        buildConfig = true
        compose = true
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_21
        targetCompatibility = JavaVersion.VERSION_21

        tasks.withType<JavaCompile>().configureEach {
            options.compilerArgs.add("-Xlint:deprecation")
        }
    }

    kotlinOptions {
        jvmTarget = "21"
    }

    dependenciesInfo {
        includeInApk = true
        includeInBundle = true
    }

    lint {
        abortOnError = false
    }

    packaging {
        resources {
            excludes += setOf(
                "/META-INF/{AL2.0,LGPL2.1}",
                "/META-INF/LICENSE*",
                "/META-INF/NOTICE*",
            )
        }
    }
}

dependencies {
    // All native SDK sources are decompiled and inlined under src/main/java/.
    // No file-based JAR dependencies remain — see buildtools/ for the
    // decompile + Kotlin-skeleton pipeline that produced them.

    // Compose for any new Kotlin-side UI work alongside the decompiled
    // Marmalade SurfaceView.
    implementation("androidx.core:core-ktx:1.13.1")
    implementation("androidx.appcompat:appcompat:1.7.0")
    implementation("androidx.activity:activity-ktx:1.9.3")
    implementation(platform("androidx.compose:compose-bom:2024.10.01"))
    implementation("androidx.compose.ui:ui")
    implementation("androidx.compose.ui:ui-graphics")
    implementation("androidx.compose.material3:material3")
}
