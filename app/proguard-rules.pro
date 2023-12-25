# Needed for production builds, see https://github.com/protocolbuffers/protobuf/blob/main/java/lite.md.
-keep class * extends com.google.protobuf.GeneratedMessageLite { *; }