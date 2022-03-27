//
// Copyright 2021 The Sigstore Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package dev.sigstore.plugin;

import org.apache.commons.io.output.TeeOutputStream;

import org.apache.maven.plugin.MojoExecutionException;
import org.apache.maven.shared.jarsigner.JarSignerUtil;

import org.apache.maven.plugins.annotations.LifecyclePhase;
import org.apache.maven.plugins.annotations.Mojo;
import org.apache.maven.plugins.annotations.Parameter;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.security.cert.CertPath;
import java.security.PrivateKey;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.function.BiConsumer;
import java.util.zip.ZipFile;

import java.io.IOException;

import jdk.security.jarsigner.JarSigner;

/**
 * Goal which:<ul>
 * <li>generates ephemeral key pair
 * <li>requests code signing certificate from sigstore Fulcio
 * <li>signs the JAR file (with {@code jarsigner})
 * <li>publishes JAR file (that contains the signature per JAR signing spec) to sigstore rekor
 * </ul>
 */
@Mojo(name = "jarsign", defaultPhase = LifecyclePhase.PACKAGE)
public class Jarsign extends AbstractSigstoreMojo {
    /**
     * Location of the {@code jarsigner}-signed JAR file; defaults to overwriting the input file with
     * the signed JAR
     */
    @Parameter(property = "output-signed-jar")
    private File outputSignedJar;

    /**
    * Signs a JAR file with {@code jarsigner} using the private key; the provided certificate chain will be included in the signed JAR file
    */
    public byte[] signFile(PrivateKey privKey, CertPath certs) throws MojoExecutionException {
        // sign JAR using keypair
        try{
            File jarToSign;
            if (inputJar != null) {
                jarToSign = inputJar;
            } else {
                jarToSign = this.project.getArtifact().getFile();
            }
            getLog().info("signing (with jarsigner) JAR file " + jarToSign.getAbsolutePath());

            File outputJarFile;
            boolean overwrite = true;
            if (outputSignedJar != null) {
                outputJarFile = outputSignedJar;
                overwrite = false;
            } else {
                outputJarFile = File.createTempFile("signingTemp", ".jar", jarToSign.getParentFile());
            }
            ByteArrayOutputStream memOut = new ByteArrayOutputStream();

            BiConsumer<String, String> progressLogger = (op, entryName) -> getLog()
                    .debug(String.format("%s %s", op, entryName));
            JarSigner.Builder jsb = new JarSigner.Builder(privKey, certs).digestAlgorithm("SHA-256")
                    .signatureAlgorithm("SHA256withECDSA").setProperty("internalsf", "true").signerName(signerName)
                    .eventHandler(progressLogger);

            if (tsaURL.toString().equals("")) {
                jsb = jsb.tsa(tsaURL.toURI());
            }

            JarSigner js = jsb.build();
            try (ZipFile in = new ZipFile(jarToSign);
                    FileOutputStream jarOut = new FileOutputStream(outputJarFile);
                    TeeOutputStream tee = new TeeOutputStream(jarOut, memOut);) {
                js.sign(in, tee);

                if (overwrite) {
                    if (!outputJarFile.renameTo(jarToSign)) {
                        throw new IOException("error overwriting unsigned JAR");
                    }
                    outputJarFile = jarToSign;
                }

                getLog().info("wrote signed JAR to " + outputJarFile.getAbsolutePath());
                if (!JarSignerUtil.isArchiveSigned(outputJarFile)) {
                    throw new VerifyError("JAR signing verification failed: archive does not contain signature");
                }
            }

            return memOut.toByteArray();
        } catch (Exception e) {
            throw new MojoExecutionException("Error signing JAR file:", e);
        }
    }

    public Map<String, Object> rekorPostContent(byte[] content) {
        String jarB64 = Base64.getEncoder().encodeToString(content);
        Map<String, Object> archiveContent = new HashMap<>();
        archiveContent.put("content", jarB64); // could be url + hash instead

        Map<String, Object> specContent = new HashMap<>();
        specContent.put("archive", archiveContent);

        Map<String, Object> rekorPostContent = new HashMap<>();
        rekorPostContent.put("kind", "jar"); // https://github.com/sigstore/rekor/blob/main/pkg/types/jar/v0.0.1/jar_v0_0_1_schema.json
        rekorPostContent.put("apiVersion", "0.0.1");
        rekorPostContent.put("spec", specContent);

        return rekorPostContent;
    }
}