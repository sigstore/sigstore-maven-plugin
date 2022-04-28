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

import org.apache.commons.codec.digest.DigestUtils;
import static org.apache.commons.codec.digest.MessageDigestAlgorithms.SHA_256;

import org.apache.maven.plugin.MojoExecutionException;
import org.apache.maven.plugins.annotations.LifecyclePhase;
import org.apache.maven.plugins.annotations.Mojo;
import org.apache.maven.plugins.annotations.Parameter;

import java.io.File;
import java.io.IOException;
import java.net.URL;
import java.nio.file.Files;
import java.security.cert.CertPath;
import java.security.KeyPair;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

/**
 * Goal which:<ul>
 * <li>generates ephemeral key pair
 * <li>requests code signing certificate from sigstore Fulcio
 * <li>signs the provided binary file
 * <li>publishes signature to sigstore rekor
 * </ul>
 */
@Mojo(name = "sign", defaultPhase = LifecyclePhase.PACKAGE)
public class Sign extends AbstractSigstoreMojo {
    /**
     * Location of the input file. defaults to default project artifact
     */
    @Parameter(property = "input-file")
    protected File inputFile;

    /**
     * Location of the signature
     */
    @Parameter(defaultValue = "${project.build.directory}/signature.sig", property = "output-signature")
    private File outputSignature;

    /**
     * Create a rekord instead of a hashedrekord
     */
    @Parameter(defaultValue = "false", property = "rekord")
    private boolean rekord;

    public URL signAndsubmitToRekor(KeyPair keypair, CertPath certs) throws MojoExecutionException {
        byte[] content;
        try {
            File fileToSign = inputFile;
            if (fileToSign == null) {
                fileToSign = this.project.getArtifact().getFile();
            }
            content = Files.readAllBytes(fileToSign.toPath());
        } catch (IOException ioe) {
            throw new MojoExecutionException("Could not read " + inputFile, ioe);
        }
        String signature = signContent(content, keypair.getPrivate());
        try {
            Files.writeString(outputSignature.toPath(), signature);
        } catch (IOException ioe) {
          throw new MojoExecutionException("Could not save signature to " + outputSignature, ioe);
        }
        return submitToRekor(content, signature, keypair);
    }

    private URL submitToRekor(byte[] content, String signature, KeyPair keypair) throws MojoExecutionException {
        // https://github.com/sigstore/rekor/blob/main/pkg/types/hashedrekord/v0.0.1/hashedrekord_v0_0_1_schema.json
        // https://github.com/sigstore/rekor/blob/main/pkg/types/rekord/v0.0.1/rekord_v0_0_1_schema.json
        Map<String, Object> hashContent = new HashMap<>();
        hashContent.put("algorithm", "sha256");
        hashContent.put("value", new DigestUtils(SHA_256).digestAsHex(content));

        Map<String, Object> dataContent = new HashMap<>();
        dataContent.put("hash", hashContent);
        if (rekord) {
            dataContent.put("content", Base64.getEncoder().encodeToString(content)); // could not avoid to send content: shouldn't sha256 be sufficient?
        }

        Map<String, Object> publicKeyContent = new HashMap<>();
        final String lineSeparator = System.getProperty("line.separator");
        Base64.Encoder encoder = Base64.getMimeEncoder(64, lineSeparator.getBytes());
        byte[] rawKeyText = keypair.getPublic().getEncoded();
        String encodedKeyText = new String(encoder.encode(rawKeyText));
        String prettifiedKey = "-----BEGIN PUBLIC KEY-----" + lineSeparator + encodedKeyText + lineSeparator
                + "-----END PUBLIC KEY-----";
        publicKeyContent.put("content", Base64.getEncoder().encodeToString(prettifiedKey.getBytes()));

        Map<String, Object> signatureContent = new HashMap<>();
        if (rekord) {
            signatureContent.put("format", "x509"); // rekord also supports "pgp", "minisign" and "ssh"
        }
        signatureContent.put("publicKey", publicKeyContent);
        signatureContent.put("content", signature);

        Map<String, Object> specContent = new HashMap<>();
        specContent.put("signature", signatureContent); // format publicKey content
        specContent.put("data", dataContent);

        return submitToRekor(rekord ? "rekord" : "hashedrekord", specContent);
    }
}