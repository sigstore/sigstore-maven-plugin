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

import org.apache.maven.plugin.MojoExecutionException;

import org.apache.maven.plugins.annotations.LifecyclePhase;
import org.apache.maven.plugins.annotations.Mojo;
import org.apache.maven.plugins.annotations.Parameter;

import java.io.File;
import java.security.cert.CertPath;
import java.security.PrivateKey;
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
     * Location of the signature
     */
    @Parameter(defaultValue = "${project.build.directory}/signature.sig", property = "output-signature", required = true)
    private File outputSignature;

    /**
     * Signature format: rekor supports {@code pgp}, {@code minisign}, {@code x509}, {@code ssh}.
     * See https://github.com/sigstore/rekor/blob/main/pkg/types/rekord/v0.0.1/rekord_v0_0_1_schema.json#L12
     * 
     */
    @Parameter(defaultValue = "pgp", property = "signature-format", required = true)
    private String format;

    public byte[] signFile(PrivateKey privKey, CertPath certs) throws MojoExecutionException {
        if ("pgp".equals(format)) {
            throw new UnsupportedOperationException("pgp signing not yet supported");
        } else if ("minisign".equals(format)) {
            throw new UnsupportedOperationException("minisign signing not yet supported");
        } else if ("x509".equals(format)) {
            throw new UnsupportedOperationException("x509 signing not yet supported");
        } else if ("ssh".equals(format)) {
            throw new UnsupportedOperationException("ssh signing not yet supported");
        } else {
            
        }
        byte[] content = null; // TODO read input file
        String sig = signContent(content, privKey);
        // TODO save to outputSignature
        return content;
    }

    public Map<String, Object> rekorPostContent(byte[] content) {
        String contentB64 = Base64.getEncoder().encodeToString(content);
        Map<String, Object> dataContent = new HashMap<>();
        dataContent.put("content", contentB64); // could be url

        Map<String, Object> signatureContent = new HashMap<>();
        signatureContent.put("format", format); // "enum": [ "pgp", "minisign", "x509", "ssh" ]
        signatureContent.put("publicKey", "TODO");
        signatureContent.put("content", "TODO"); // could be url

        Map<String, Object> specContent = new HashMap<>();
        specContent.put("signature", signatureContent); // format publicKey content
        specContent.put("data", dataContent);

        Map<String, Object> rekorPostContent = new HashMap<>();
        rekorPostContent.put("kind", "rekord"); // https://github.com/sigstore/rekor/blob/main/pkg/types/rekord/v0.0.1/rekord_v0_0_1_schema.json
        rekorPostContent.put("apiVersion", "0.0.1");
        rekorPostContent.put("spec", specContent);

        return rekorPostContent;
    }
}