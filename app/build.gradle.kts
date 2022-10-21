import java.util.Properties
import java.io.FileInputStream

val keystorePropertiesFile = rootProject.file("keystore.properties")
val useKeystoreProperties = keystorePropertiesFile.canRead()
val keystoreProperties = Properties()
if (useKeystoreProperties) {
    keystoreProperties.load(FileInputStream(keystorePropertiesFile))
}

plugins {
    id("com.android.application")
    kotlin("android")
}

android {
    if (useKeystoreProperties) {
        signingConfigs {
            create("release") {
                storeFile = rootProject.file(keystoreProperties["storeFile"]!!)
                storePassword = keystoreProperties["storePassword"] as String
                keyAlias = keystoreProperties["keyAlias"] as String
                keyPassword = keystoreProperties["keyPassword"] as String
            }

            create("play") {
                storeFile = rootProject.file(keystoreProperties["storeFile"]!!)
                storePassword = keystoreProperties["storePassword"] as String
                keyAlias = keystoreProperties["uploadKeyAlias"] as String
                keyPassword = keystoreProperties["uploadKeyPassword"] as String
            }
        }
    }

    compileSdk = 33
    buildToolsVersion = "33.0.0"

    namespace = "app.attestation.auditor"

    defaultConfig {
        applicationId = "app.attestation.auditor"
        minSdk = 26
        targetSdk = 33
        versionCode = 64
        versionName = versionCode.toString()
        resourceConfigurations.add("en")
    }

    buildTypes {
        getByName("release") {
            isShrinkResources = true
            isMinifyEnabled = true
            proguardFiles(getDefaultProguardFile("proguard-android-optimize.txt"), "proguard-rules.pro")
            if (useKeystoreProperties) {
                signingConfig = signingConfigs.getByName("release")
            }
        }

        create("play") {
            initWith(getByName("release"))
            applicationIdSuffix = ".play"
            if (useKeystoreProperties) {
                signingConfig = signingConfigs.getByName("play")
            }
        }
    }

    compileOptions {
        sourceCompatibility(JavaVersion.VERSION_11)
        targetCompatibility(JavaVersion.VERSION_11)
    }

    kotlinOptions {
        jvmTarget = JavaVersion.VERSION_11.toString()
    }

    packagingOptions {
        resources.excludes.addAll(listOf(
            "org/bouncycastle/pqc/**.properties",
            "org/bouncycastle/x509/**.properties",
        ))
    }

    aaptOptions {
       noCompress("dex")
    }
}

dependencies {
    implementation("androidx.appcompat:appcompat:1.5.1")
    implementation("androidx.biometric:biometric:1.1.0")
    implementation("androidx.preference:preference:1.2.0")
    implementation("com.google.android.material:material:1.6.1")
    implementation("com.google.guava:guava:31.1-android")
    implementation("com.google.zxing:core:3.5.0")
    implementation("org.bouncycastle:bcpkix-jdk18on:1.72")

    // work around conflict
    implementation("androidx.lifecycle:lifecycle-viewmodel-ktx:2.5.1")

    val cameraVersion = "1.2.0-beta02"
    implementation("androidx.camera:camera-core:$cameraVersion")
    implementation("androidx.camera:camera-camera2:$cameraVersion")
    implementation("androidx.camera:camera-lifecycle:$cameraVersion")
    implementation("androidx.camera:camera-view:$cameraVersion")
}
