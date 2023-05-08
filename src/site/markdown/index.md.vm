sigstore-maven-plugin
=====================

This is a Maven plugin that can be used to use the "keyless" signing paradigm supported by Sigstore.
This plugin is still in early phases, then has known limitations described below.

sign
----

```xml
      <plugin>
        <groupId>dev.sigstore</groupId>
        <artifactId>sigstore-maven-plugin</artifactId>
        <version>1.0-SNAPSHOT</version>
        <executions>
          <execution>
            <id>sign</id>
            <goals>
              <goal>sign</goal>
            </goals>
          </execution>
        </executions>
      </plugin>
```

Notes:

- GPG: Maven Central publication rules require GPG signing each files: to avoid GPG signing of `.sigstore` files, just use version 3.1.0 minimum of [maven-gpg-plugin](https://maven.apache.org/plugins/maven-gpg-plugin/).
- `.md5`/`.sha1`: to avoid unneeded checksum files for `.sigstore` files, use Maven 3.9.2 minimum or create `.mvn/maven.config` file containing `-Daether.checksums.omitChecksumsForExtensions=.asc,.sigstore`

Known limitations:

- Maven multi-module build: each module will require an OIDC authentication,
- 10 minutes siging session: if a build takes more than 10 minutes, a new OIDC authentication will be required each 10 minutes.

jarsign
-------

You can [sign JAR file](https://docs.oracle.com/javase/tutorial/deployment/jar/intro.html) with Sigstore and [`jarsigner`](https://docs.oracle.com/en/java/javase/11/tools/jarsigner.html).

Full `jarsign` goal documentation is [available here](https://sigstore.github.io/sigstore-maven-plugin/jarsign-mojo.html), but you can quickly take advantage of the plugin by adding the following configuration into your Maven `pom.xml` file:

```xml
      <plugin>
        <groupId>dev.sigstore</groupId>
        <artifactId>sigstore-maven-plugin</artifactId>
        <version>1.0-SNAPSHOT</version>
        <executions>
          <execution>
            <id>sigstore-jarsign</id>
            <goals>
              <goal>jarsign</goal>
            </goals>
            <!-- optional configuration parameters; sensible defaults are chosen
            <configuration>
              <emailAddress>YOUR-EMAIL-ADDRESS-HERE</emailAddress>
              <outputSigningCert>signingCert.pem</outputSigningCert>
              <sslVerification>false</sslVerification>
            </configuration>
            -->
          </execution>
        </executions>
      </plugin>
```
