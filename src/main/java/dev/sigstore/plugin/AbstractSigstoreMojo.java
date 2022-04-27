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

import org.apache.commons.validator.routines.EmailValidator;

import org.apache.http.conn.ssl.NoopHostnameVerifier;
import org.apache.http.impl.client.HttpClientBuilder;
import org.apache.maven.plugin.AbstractMojo;
import org.apache.maven.plugin.MojoExecutionException;
import org.apache.maven.project.MavenProject;

import org.apache.maven.plugins.annotations.Parameter;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileWriter;
import java.net.URL;
import java.security.cert.CertPath;
import java.security.cert.CertificateFactory;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.ECGenParameterSpec;
import java.security.cert.X509Certificate;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

import com.google.api.client.auth.oauth2.AuthorizationCodeFlow;
import com.google.api.client.auth.oauth2.BearerToken;
import com.google.api.client.auth.oauth2.ClientParametersAuthentication;
import com.google.api.client.auth.oauth2.Credential;
import com.google.api.client.auth.oauth2.TokenResponse;
import com.google.api.client.auth.openidconnect.IdToken;
import com.google.api.client.auth.openidconnect.IdTokenVerifier;
import com.google.api.client.extensions.java6.auth.oauth2.AuthorizationCodeInstalledApp;
import com.google.api.client.extensions.jetty.auth.oauth2.LocalServerReceiver;
import com.google.api.client.json.JsonFactory;
import com.google.api.client.util.PemReader;
import com.google.api.client.util.PemReader.Section;
import com.google.api.client.util.store.DataStoreFactory;
import com.google.api.client.util.store.MemoryDataStoreFactory;

import java.io.IOException;
import java.io.InputStreamReader;
import java.io.InvalidObjectException;
import java.util.List;

import com.google.api.client.http.GenericUrl;
import com.google.api.client.http.HttpRequest;
import com.google.api.client.http.HttpResponse;
import com.google.api.client.http.HttpTransport;
import com.google.api.client.http.apache.v2.ApacheHttpTransport;
import com.google.api.client.http.json.JsonHttpContent;
import com.google.api.client.json.gson.GsonFactory;

/**
 * Abstract goal which:<ul>
 * <li>generates ephemeral key pair
 * <li>requests code signing certificate from sigstore Fulcio
 * <li>let implementor do signature
 * <li>publishes result to sigstore rekor
 * </ul>
 */
public abstract class AbstractSigstoreMojo extends AbstractMojo {
    /**
     * Reference to maven project; will be used to find JAR file to be signed unless
     * specified in input-jar
     */
    @Parameter(defaultValue = "${project}", readonly = true, required = true)
    protected MavenProject project;

    /**
     * Location of the code signing certificate (including public key) used to
     * verify signature
     */
    @Parameter(defaultValue = "${project.build.directory}/signingCert.pem", property = "output-signing-cert", required = true)
    private File outputSigningCert;

    /**
     * Signing algorithm to be used; default is ECDSA
     */
    @Parameter(defaultValue = "sigstore", property = "signer-name", required = true)
    protected String signerName;

    /**
     * Signing algorithm to be used; default is ECDSA
     */
    @Parameter(defaultValue = "EC", property = "signing-algorithm", required = true)
    private String signingAlgorithm;

    /**
     * Signing algorithm specification to be used; default is secp256r1
     */
    @Parameter(defaultValue = "secp256r1", property = "signing-algorithm-spec", required = true)
    private String signingAlgorithmSpec;

    /**
     * Enable/disable SSL hostname verification
     */
    @Parameter(defaultValue = "true", property = "ssl-verification", required = true)
    private boolean sslVerfication;

    /**
     * URL of Fulcio instance
     */
    @Parameter(defaultValue = "https://fulcio.sigstore.dev", property = "fulcio-instance-url", required = true)
    private URL fulcioInstanceURL;

    /**
     * Use browser-less OAuth Device Code flow instead of opening local browser
     */
    @Parameter(defaultValue = "false", property = "oidc-device-code", required = true)
    private boolean oidcDeviceCodeFlow;

    /**
     * Client ID for OIDC Identity Provider
     */
    @Parameter(defaultValue = "sigstore", property = "oidc-client-id", required = true)
    private String oidcClientID;

    /**
     * URL of OIDC Identity Provider Authorization endpoint
     */
    @Parameter(defaultValue = "https://oauth2.sigstore.dev/auth/auth", property = "oidc-auth-url", required = true)
    private URL oidcAuthURL;

    /**
     * URL of OIDC Identity Provider Token endpoint
     */
    @Parameter(defaultValue = "https://oauth2.sigstore.dev/auth/token", property = "oidc-token-url", required = true)
    private URL oidcTokenURL;

    /**
     * URL of OIDC Identity Provider Device Code endpoint
     */
    @Parameter(defaultValue = "https://oauth2.sigstore.dev/auth/device/code", property = "oidc-device-code-url", required = true)
    private URL oidcDeviceCodeURL;

    /**
     * URL of Rekor instance
     */
    @Parameter(defaultValue = "https://rekor.sigstore.dev", property = "rekor-instance-url", required = true)
    private URL rekorInstanceURL;

    /**
     * Email address of signer; if not specified, the email address returned in the OIDC identity token will be used
     */
    @Parameter(property = "email-address")
    private String emailAddress;

    /**
     * URL of Trusted Timestamp Authority (RFC3161 compliant)
     */
    @Parameter(defaultValue = "https://rekor.sigstore.dev/api/v1/timestamp", property = "tsa-url", required = true)
    protected URL tsaURL;

    public void execute() throws MojoExecutionException {
        // generate keypair
        KeyPair keypair = generateKeyPair(signingAlgorithm, signingAlgorithmSpec);

        // do OIDC dance, get ID token
        String rawIdToken = getIDToken(emailAddress);

        // sign email address with private key
        String signedEmail = signEmailAddress(emailAddress, keypair.getPrivate());

        // push to fulcio, get signing cert chain
        CertPath certs = getSigningCert(signedEmail, keypair.getPublic(), rawIdToken);

        // write signing certificate to file
        writeSigningCertToFile(certs, outputSigningCert);

        // sign file then submit to rekor
        signAndsubmitToRekor(keypair, certs);
    }

    public abstract URL signAndsubmitToRekor(KeyPair keypair, CertPath certs) throws MojoExecutionException;

    /**
    * Returns a new ephemeral keypair according to the plugin parameters
    *
    * @param  signingAlgorithm     an absolute URL giving the base location of the image
    * @param  signingAlgorithmSpec the location of the image, relative to the url argument
    * @return      the public and private keypair
    * @throws MojoExecutionException If any exception happened during the key generation process
    */
    public KeyPair generateKeyPair(String signingAlgorithm, String signingAlgorithmSpec) throws MojoExecutionException {
        getLog().info(String.format("generating keypair using %s with %s parameters", signingAlgorithm,
                signingAlgorithmSpec));
        try {
            KeyPairGenerator kpg = KeyPairGenerator.getInstance(signingAlgorithm);
            AlgorithmParameterSpec aps = null;
            switch (signingAlgorithm) {
            case "EC":
                aps = new ECGenParameterSpec(signingAlgorithmSpec);
                break;
            default:
                throw new IllegalArgumentException(String
                        .format("unable to create signing algorithm spec for signing algorithm %s", signingAlgorithm));
            }
            kpg.initialize(aps, new SecureRandom());
            return kpg.generateKeyPair();
        } catch (Exception e) {
            throw new MojoExecutionException("Error creating keypair:", e);
        }
    }

    /**
    * Signs the provided content using the provided private key
    *
    * @param  content  The binary content to sign
    * @param  privKey  The private key used to sign the email address
    * @return      base64 encoded String containing the signature for the provided content
    * @throws MojoExecutionException If any exception happened during the signing process
    */
    public String signContent(byte[] content, PrivateKey privKey) throws MojoExecutionException {
        try {
            if (privKey == null) {
                throw new IllegalArgumentException("private key must be specified");
            }
            if (content == null) {
                throw new IllegalArgumentException("content must not be null");
            }

            Signature sig = null;
            switch (privKey.getAlgorithm()) {
            case "EC":
                sig = Signature.getInstance("SHA256withECDSA");
                break;
            default:
                throw new NoSuchAlgorithmException(
                        String.format("unable to generate signature for signing algorithm %s", signingAlgorithm));
            }
            sig.initSign(privKey);
            sig.update(content);
            return Base64.getEncoder().encodeToString(sig.sign());
        } catch (Exception e) {
            throw new MojoExecutionException(String.format("Error signing content: %s", e.getMessage()), e);
        }
    }

    /**
    * Signs the provided email address using the provided private key
    *
    * @param  emailAddress The email address to sign; this should match the email address in the OIDC token
    * @param  privKey      The private key used to sign the email address
    * @return      base64 encoded String containing the signature for the provided email address
    * @throws MojoExecutionException If any exception happened during the signing process
    */
    public String signEmailAddress(String emailAddress, PrivateKey privKey) throws MojoExecutionException {
        try {
            if (emailAddress == null) {
                throw new IllegalArgumentException("email address must not be null");
            } else {
                EmailValidator ev = EmailValidator.getInstance();
                if (!ev.isValid(emailAddress)) {
                    throw new IllegalArgumentException(String.format("email address specified '%s' is invalid", emailAddress));
                }
            }

            getLog().info(String.format("signing email address '%s' as proof of possession of private key", emailAddress));
            return signContent(emailAddress.getBytes(), privKey);
        } catch (Exception e) {
            throw new MojoExecutionException(String.format("Error signing '%s': %s", emailAddress, e.getMessage()), e);
        }
    }

    /**
    * Generates an HTTP Transport according to the requested SSL verification settings
    *
    * @return transport object with SSL verification enabled/disabled per the plugin parameter <code>sslVerification</code>
    */
    public HttpTransport getHttpTransport() {
        HttpClientBuilder hcb = ApacheHttpTransport.newDefaultHttpClientBuilder();
        if (!sslVerfication) {
            hcb = hcb.setSSLHostnameVerifier(NoopHostnameVerifier.INSTANCE);
        }
        return new ApacheHttpTransport(hcb.build());
    }

    /**
    * Obtains an OpenID Connect Identity Token from the OIDC provider specified in <code>oidcAuthURL</code>
    *
    * @param  expectedEmailAddress The email address we expected to see in the identity token
    * @return      the ID token String (in JWS format)
    * @throws MojoExecutionException If any exception happened during the OIDC authentication flow
    */
    public String getIDToken(String expectedEmailAddress) throws MojoExecutionException {
        try {
            JsonFactory jsonFactory = new GsonFactory();
            HttpTransport httpTransport = getHttpTransport();
            DataStoreFactory memStoreFactory = new MemoryDataStoreFactory();

            final String idTokenKey = "id_token";

            if (!oidcDeviceCodeFlow) {
                AuthorizationCodeFlow.Builder flowBuilder = new AuthorizationCodeFlow.Builder(
                        BearerToken.authorizationHeaderAccessMethod(), httpTransport, jsonFactory,
                        new GenericUrl(oidcTokenURL.toString()), new ClientParametersAuthentication(oidcClientID, null),
                        oidcClientID, oidcAuthURL.toString())
                        .enablePKCE()
                        .setScopes(List.of("openid", "email"))
                        .setCredentialCreatedListener(new AuthorizationCodeFlow.CredentialCreatedListener() {
                            @Override
                            public void onCredentialCreated(Credential credential, TokenResponse tokenResponse)
                                throws IOException {
                                memStoreFactory.getDataStore("user").set(idTokenKey,
                                tokenResponse.get(idTokenKey).toString());
                            }
                        });
                AuthorizationCodeInstalledApp app = new AuthorizationCodeInstalledApp(flowBuilder.build(),
                        new LocalServerReceiver());
                app.authorize("user");
            }
            // TODO: add device code flow support

            String idTokenString = (String) memStoreFactory.getDataStore("user").get(idTokenKey);

            IdTokenVerifier idTokenVerifier = new IdTokenVerifier();
            IdToken parsedIdToken = IdToken.parse(jsonFactory, idTokenString);
            if (!idTokenVerifier.verify(parsedIdToken)) {
                throw new InvalidObjectException("id token could not be verified");
            }

            String emailFromIDToken = (String) parsedIdToken.getPayload().get("email");
            Boolean emailVerified = (Boolean) parsedIdToken.getPayload().get("email_verified");
            if (expectedEmailAddress != null && !emailFromIDToken.equals(expectedEmailAddress)) {
                throw new InvalidObjectException(
                        String.format("email in ID token '%s' does not match address specified to plugin '%s'",
                                emailFromIDToken, emailAddress));
            } else if (Boolean.FALSE.equals(emailVerified)) {
                throw new InvalidObjectException(
                        String.format("identity provider '%s' reports email address '%s' has not been verified",
                                parsedIdToken.getPayload().getIssuer(), emailAddress));
            }
            this.emailAddress = emailFromIDToken;

            return idTokenString;
        } catch (Exception e) {
            throw new MojoExecutionException("Error signing email address:", e);
        }
    }

    /**
    * Obtains a X509 code signing certificate signed by the Fulcio instance specified in <code>fulcioInstanceURL</code>.
    *
    * @param  signedEmail a base64 encoded String containing the signed email address to associate with the requested certificate
    * @param  pubKey      the public key used to verify the signed email address; this key will be included in the final certificate
    * @param  idToken     a raw OIDC Identity token specified in JWS format
    * @return      The certificate chain including the code signing certificate
    * @throws MojoExecutionException If any exception happened during the request for the code signing certificate
    */
    public CertPath getSigningCert(String signedEmail, PublicKey pubKey, String idToken) throws MojoExecutionException {
        try {
            HttpTransport httpTransport = getHttpTransport();

            String publicKeyB64 = Base64.getEncoder().encodeToString(pubKey.getEncoded());
            Map<String, Object> fulcioPostContent = new HashMap<>();
            Map<String, Object> publicKeyContent = new HashMap<>();
            publicKeyContent.put("content", publicKeyB64);
            // TODO: look at signingAlgorithm and set accordingly
            if (pubKey.getAlgorithm().equals("EC")) {
                publicKeyContent.put("algorithm", "ecdsa");
            }

            fulcioPostContent.put("signedEmailAddress", signedEmail);
            fulcioPostContent.put("publicKey", publicKeyContent);
            JsonHttpContent jsonContent = new JsonHttpContent(new GsonFactory(), fulcioPostContent);
            ByteArrayOutputStream stream = new ByteArrayOutputStream();
            jsonContent.writeTo(stream);

            GenericUrl fulcioPostUrl = new GenericUrl(fulcioInstanceURL + "/api/v1/signingCert");
            HttpRequest req = httpTransport.createRequestFactory().buildPostRequest(fulcioPostUrl, jsonContent);

            req.getHeaders().set("Accept", "application/pem-certificate-chain");
            req.getHeaders().set("Authorization", "Bearer " + idToken);

            getLog().info("requesting signing certificate");
            HttpResponse resp = req.execute();
            if (resp.getStatusCode() != 201) {
                throw new IOException(
                        String.format("bad response from fulcio @ '%s' : %s", fulcioPostUrl, resp.parseAsString()));
            }

            getLog().info("parsing signing certificate");
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            ArrayList<X509Certificate> certList = new ArrayList<>();
            PemReader pemReader = new PemReader(new InputStreamReader(resp.getContent()));
            while (true) {
                Section section = pemReader.readNextSection();
                if (section == null) {
                    break;
                }

                byte[] certBytes = section.getBase64DecodedBytes();
                certList.add((X509Certificate) cf.generateCertificate(new ByteArrayInputStream(certBytes)));
            }
            if (certList.isEmpty()) {
                throw new IOException("no certificates were found in response from Fulcio instance");
            }
            return cf.generateCertPath(certList);
        } catch (Exception e) {
            throw new MojoExecutionException(String.format("Error obtaining signing certificate from Fulcio @%s:", fulcioInstanceURL), e);
        }
    }

    /**
    * Writes the code signing certificate to a file
    *
    * @param  certs             The certificate chain including the code signing certificate which can be used to verify the signature
    * @param  outputSigningCert The file where the code signing cert should be written to
    * @throws MojoExecutionException If any exception happened during writing the certificate to the specified file
    */
    public void writeSigningCertToFile(CertPath certs, File outputSigningCert) throws MojoExecutionException {
        getLog().info("writing signing certificate to " + outputSigningCert.getAbsolutePath());
        try {
            final String lineSeparator = System.getProperty("line.separator");
            Base64.Encoder encoder = Base64.getMimeEncoder(64, lineSeparator.getBytes());
            // we only write the first one, not the entire chain
            byte[] rawCrtText = certs.getCertificates().get(0).getEncoded();
            String encodedCertText = new String(encoder.encode(rawCrtText));
            String prettifiedCert = "-----BEGIN CERTIFICATE-----" + lineSeparator + encodedCertText + lineSeparator
                    + "-----END CERTIFICATE-----";

            if (!outputSigningCert.createNewFile()) {
                throw new IOException(String.format("file at %s already exists; will not overwrite",
                        outputSigningCert.getAbsolutePath()));
            }
            try (FileWriter fw = new FileWriter(outputSigningCert)) {
                fw.write(prettifiedCert);
            }
        } catch (Exception e) {
            throw new MojoExecutionException(String.format("Error writing signing certificate to file '%s':",
                    outputSigningCert.getAbsolutePath()), e);
        }
    }

    /**
    * Submits the content spec to a Rekor transparency log using defined
    * <a href="https://github.com/sigstore/rekor/blob/main/pkg/types">rekor-supported type</a>.
    *
    * @param  kind The kind of rekor entry
    * @param  spec The rekor entry spec
    * @return       The URL where the entry in the transparency log can be seen for this signature/key combination
    * @throws MojoExecutionException If any exception happened during interaction with the Rekor instance
    */
    protected URL submitToRekor(String kind, Map<String, Object> spec) throws MojoExecutionException {
        try {
            HttpTransport httpTransport = getHttpTransport();

            Map<String, Object> rekorPostContent = new HashMap<>();
            rekorPostContent.put("kind", kind); 
            rekorPostContent.put("apiVersion", "0.0.1");
            rekorPostContent.put("spec", spec);

            JsonHttpContent rekorJsonContent = new JsonHttpContent(new GsonFactory(), rekorPostContent);

            if (getLog().isDebugEnabled()) {
                ByteArrayOutputStream rekorStream = new ByteArrayOutputStream();
                rekorJsonContent.writeTo(rekorStream);
                getLog().debug("submitting to rekor: " + rekorStream.toString());
            }

            GenericUrl rekorPostUrl = new GenericUrl(rekorInstanceURL + "/api/v1/log/entries");
            HttpRequest rekorReq = httpTransport.createRequestFactory().buildPostRequest(rekorPostUrl, rekorJsonContent);

            rekorReq.getHeaders().set("Accept", "application/json");
            rekorReq.getHeaders().set("Content-Type", "application/json");

            HttpResponse rekorResp = rekorReq.execute();
            if (rekorResp.getStatusCode() != 201) {
                throw new IOException("bad response from rekor: " + rekorResp.parseAsString());
            }

            URL rekorEntryUrl = new URL(rekorInstanceURL, rekorResp.getHeaders().getLocation());
            getLog().info(String.format("Created %s entry in transparency log @ '%s'", kind, rekorEntryUrl));
            return rekorEntryUrl;
        } catch (Exception e) {
            throw new MojoExecutionException(
                    String.format("Error in submitting entry to Rekor @ %s:", rekorInstanceURL), e);
        }
    }
}