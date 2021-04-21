# sigstore-maven-plugin

This is a Maven plugin that can be used to use the "keyless" signing paradigm supported by Sigstore. 

Javadoc can be located at:  INSERT LINK HERE, but you can quickly take advantage of the plugin by adding the following configuration into your Maven POM.XML file:

```xml
      <plugin>
        <groupId>dev.sigstore</groupId>
        <artifactId>sigstore-maven-plugin</artifactId>
        <version>1.0-SNAPSHOT</version>
        <executions>
          <execution>
            <id>sigstore-sign</id>
            <goals>
              <goal>sign</goal>
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
