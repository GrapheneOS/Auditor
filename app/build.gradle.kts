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
        }
    }

    compileSdk = 32
    buildToolsVersion = "32.0.0"

    defaultConfig {
        applicationId = "app.attestation.auditor"
        minSdk = 26
        targetSdk = 32
        versionCode = 49
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
    }

    compileOptions {
        sourceCompatibility(JavaVersion.VERSION_11)
        targetCompatibility(JavaVersion.VERSION_11)
    }

    kotlinOptions {
        jvmTarget = JavaVersion.VERSION_11.toString()
    }

    packagingOptions {
        dex {
            useLegacyPackaging = false
        }
    }
}

dependencies {
    implementation("androidx.appcompat:appcompat:1.4.2")
    implementation("androidx.biometric:biometric:1.1.0")
    implementation("androidx.preference:preference:1.2.0")
    implementation("com.google.android.material:material:1.6.1")
    implementation("com.google.guava:guava:31.1-android")
    implementation("com.google.zxing:core:3.5.0")
    implementation("org.bouncycastle:bcpkix-jdk15to18:1.70")

    val cameraVersion = "1.2.0-alpha01"
    implementation("androidx.camera:camera-core:$cameraVersion")
    implementation("androidx.camera:camera-camera2:$cameraVersion")
    implementation("androidx.camera:camera-lifecycle:$cameraVersion")
    implementation("androidx.camera:camera-view:$cameraVersion")
}
