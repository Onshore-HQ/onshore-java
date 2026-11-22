# Onshore SDK for Java

The Onshore server SDK for Java 17+ and other JVM languages. No dependencies: the JDK's HTTP client and Ed25519, and a small built-in JSON reader.

## Install

Not on Maven Central yet. Build and install it into your local Maven repository:

```sh
git clone https://github.com/Onshore-HQ/onshore-java && cd onshore-java
mvn install
```

```xml
<dependency>
  <groupId>com.onshorevault</groupId>
  <artifactId>onshore-sdk</artifactId>
  <version>0.1.0</version>
</dependency>
```

## Documentation

Full reference, with every method, parameter, return value and error: https://docs.onshorevault.com/developers/sdks/java/

## Licence

Apache-2.0. Copyright 2026 Flowsplus Services. See [LICENSE](LICENSE) and [NOTICE](NOTICE). Contributions need the [Contributor Licence Agreement](CLA.md).
