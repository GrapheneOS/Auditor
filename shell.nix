{ 
  pkgs ? import (fetchTarball {
    url = "https://github.com/NixOS/nixpkgs/archive/0ca1a30c8ff3bb3d3e17f78f364da805ee05a2d5.tar.gz";
    sha256 = "1a6zv8zxf5hjd9ajyy55k528swnbgqd142jjwywcakbiwrm80y4i";
  }) {},
}:

let

  jdk = pkgs.jdk17_headless;
  
  androidStudio = pkgs.android-studio;

  androidNdkVersion = "26.1.10909125";
  androidEnv = pkgs.androidenv.composeAndroidPackages {
    platformVersions = [ "36" ];
    buildToolsVersions = [ "36.1.0" ];
    abiVersions = [ "arm64-v8a" "x86_64" ];
    includeNDK = true;
    ndkVersions = [ androidNdkVersion ];
  };
  androidSdk = androidEnv.androidsdk;

  jdkPath = "${jdk}/lib/openjdk";
  androidSdkPath = "${androidSdk}/libexec/android-sdk";
  androidNdkPath = "${androidSdkPath}/ndk/${androidNdkVersion}";

in

pkgs.mkShell {

  packages = [
    jdk
    androidStudio
    androidSdk
  ];

  shellHook = ''
    export JAVA_HOME=${jdkPath}
    export ANDROID_HOME=${androidSdkPath}
    export ANDROID_SDK_ROOT=${androidSdkPath}
    export ANDROID_NDK_HOME=${androidNdkPath}
    export PATH=$JAVA_HOME/bin:$ANDROID_HOME/platform-tools:$PATH
  '';

}
