/*
Copyright The sigstore Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
package sigstore.plugin;

import org.apache.commons.io.output.TeeOutputStream;

import org.apache.http.conn.ssl.NoopHostnameVerifier;
import org.apache.http.impl.client.HttpClientBuilder;
import org.apache.maven.plugin.AbstractMojo;
import org.apache.maven.plugin.MojoExecutionException;

import org.apache.maven.plugins.annotations.LifecyclePhase;
import org.apache.maven.plugins.annotations.Mojo;
import org.apache.maven.plugins.annotations.Parameter;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.FileWriter;
import java.net.URL;
import java.security.cert.CertPath;
import java.security.cert.CertificateFactory;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.ECGenParameterSpec;
import java.security.cert.X509Certificate;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.function.BiConsumer;
import java.util.zip.ZipFile;

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
import java.util.List;

import com.google.api.client.http.GenericUrl;
import com.google.api.client.http.HttpRequest;
import com.google.api.client.http.HttpResponse;
import com.google.api.client.http.HttpTransport;
import com.google.api.client.http.apache.v2.ApacheHttpTransport;
import com.google.api.client.http.json.JsonHttpContent;
import com.google.api.client.json.gson.GsonFactory;

import jdk.security.jarsigner.JarSigner;

/**
 * Goal which:
 * - generates ephemeral key pair
 * - requests code signing certificate from sigstore Fulcio
 * - signs the JAR file
 * - publishes signature to sigstore rekor
 * - verifies the signed JAR
 */
@Mojo( name = "sign", defaultPhase = LifecyclePhase.PACKAGE )
public class Sign extends AbstractMojo {
    /**
     * Location of the input JAR file.
     */
    @Parameter( property = "input-jar", required = true )
    private File inputJar;

    /**
     * Location of the signed JAR file; defaults to overwriting the input file with the signed JAR
     */
    @Parameter( property = "output-signed-jar" )
    private File outputSignedJar;

    /**
     * Location of the code signing certificate (including public key) used to verify signature
     */
    @Parameter( property = "output-signing-cert", required = true )
    private File outputSigningCert;

    /**
     * Signing algorithm to be used; default is ECDSA
     */
    @Parameter( defaultValue = "sigstore", property = "signer-name", required = true )
    private String signerName;

    /**
     * Signing algorithm to be used; default is ECDSA
     */
    @Parameter( defaultValue = "EC", property = "signing-algorithm", required = true )
    private String signingAlgorithm;

    /**
     * Signing algorithm specification to be used; default is secp256r1
     */
    @Parameter( defaultValue = "secp256r1", property = "signing-algorithm-spec", required = true )
    private String signingAlgorithmSpec;

    /**
     * Enable/disable SSL hostname verification
     */
    @Parameter( defaultValue = "true", property = "ssl-verification", required = true )
    private boolean sslVerfication;

    /**
     * URL of Fulcio instance
     */
    @Parameter( defaultValue = "https://fulcio.sigstore.dev", property = "fulcio-instance-url", required = true )
    private URL fulcioInstanceURL;

    /**
     * Use browser-less OAuth Device Code flow instead of opening local browser
     */
    @Parameter( defaultValue = "false", property = "oidc-device-code", required = true )
    private boolean oidcDeviceCodeFlow;

    /**
     * Client ID for OIDC Identity Provider
     */
    @Parameter( defaultValue = "sigstore", property = "oidc-client-id", required = true )
    private String oidcClientID;

    /**
     * URL of OIDC Identity Provider Authorization endpoint
     */
    @Parameter( defaultValue = "https://oauth2.sigstore.dev/auth/auth", property = "oidc-auth-url", required = true )
    private URL oidcAuthURL;

    /**
     * URL of OIDC Identity Provider Token endpoint
     */
    @Parameter( defaultValue = "https://oauth2.sigstore.dev/auth/token", property = "oidc-token-url", required = true )
    private URL oidcTokenURL;

    /**
     * URL of OIDC Identity Provider Device Code endpoint
     */
    @Parameter( defaultValue = "https://oauth2.sigstore.dev/auth/device/code", property = "oidc-device-code-url", required = true )
    private URL oidcDeviceCodeURL;

    /**
     * URL of Rekor instance
     */
    @Parameter( defaultValue = "https://rekor.sigstore.dev", property = "rekor-instance-url", required = true )
    private URL rekorInstanceURL;

    /**
     * Email address of signer
     */
    @Parameter( property = "email-address", required = true )
    private String emailAddress;

    /**
     * URL of Trusted Timestamp Authority (RFC3161 compliant)
     */
    @Parameter( defaultValue = "http://timestamp.digicert.com", property = "tsa-url", required = true )
    private URL tsaURL;

    public void execute() throws MojoExecutionException {
        //generate keypair
        KeyPair keypair;
        try {
            keypair = generateKeyPair();
        } catch (Exception e) {
            getLog().error(e);
            throw new MojoExecutionException("Error creating keypair:", e);
        }

        // do OIDC dance, get ID token
        String rawIdToken = "";
        try {
            rawIdToken = getIDToken(emailAddress);
        } catch (Exception e) {
            getLog().error(e);
            throw new MojoExecutionException(String.format("Error authenticating for %s:", emailAddress), e);
        }

        // sign email address with private key
        String signedEmail = "";
        try {
            signedEmail = signEmailAddress(emailAddress, keypair.getPrivate());
        } catch (Exception e) {
            getLog().error(e);
            throw new MojoExecutionException("Error signing email address:", e);
        }

        // push to fulcio, get signing cert chain
        CertPath certs = null;
        try {
            certs = getSigningCert(signedEmail, keypair.getPublic(), rawIdToken);
        } catch (Exception e) {
            getLog().error(e);
            throw new MojoExecutionException(String.format("Error obtaining signing certificate from Fulcio @%s:",
                                             fulcioInstanceURL), e);
        }

        // sign JAR file here
        byte[] jarBytes = null;
        try {
            jarBytes = signJarFile(keypair.getPrivate(), certs);
        } catch (Exception e) {
            getLog().error(e);
            throw new MojoExecutionException(String.format("Error signing JAR file '%s':", inputJar.getAbsolutePath()), e);
        }

        // write signing certificate to file
        try {
            writeSigningCertToFile(certs);
        } catch (Exception e) {
            getLog().error(e);
            throw new MojoExecutionException(String.format("Error writing signing certificate to file '%s':", outputSigningCert.getAbsolutePath()), e);
        }

        // submit jar to rekor
        URL rekorEntryUrl = null;
        try {
            rekorEntryUrl = submitToRekor(jarBytes);
        } catch (Exception e) {
            getLog().error(e);
            throw new MojoExecutionException(String.format("Error in submitting entry to Rekor @ %s:", rekorInstanceURL), e);
        }
        getLog().info(String.format("Created entry in transparency log for JAR @ '%s'", rekorEntryUrl));

        // verify JAR
    }

    // generateKeyPair creates a keypair according to the plugin parameters specified
    private KeyPair generateKeyPair() throws Exception {
        getLog().info(String.format("generating keypair using %s with %s parameters", signingAlgorithm, signingAlgorithmSpec));
        KeyPairGenerator kpg = KeyPairGenerator.getInstance(signingAlgorithm);
        AlgorithmParameterSpec aps = null;
        switch(signingAlgorithm) {
            case "EC":
                aps = new ECGenParameterSpec(signingAlgorithmSpec);
                break;
            default:
                throw new Exception(String.format("unable to create signing algorithm spec for signing algorithm %s", signingAlgorithm));
        }
        kpg.initialize(aps, new SecureRandom());
        return kpg.generateKeyPair();
    }

    // signEmailAddress returns a base64 encoded String representing the signature of the specified email address using the provided keypair
    private String signEmailAddress(String emailAddress, PrivateKey privKey) throws Exception {
        getLog().info(String.format("signing email address '%s' as proof of possession of private key", emailAddress));
        Signature sig = null;
        switch(signingAlgorithm) {
            case "EC":
                sig = Signature.getInstance("SHA256withECDSA");
                break;
            default:
                throw new Exception(String.format("unable to generate signature for signing algorithm %s", signingAlgorithm));
        }
        sig.initSign(privKey);
        sig.update(emailAddress.getBytes());
        return Base64.getEncoder().encodeToString(sig.sign());
    }

    private HttpTransport getHttpTransport() {
        HttpClientBuilder hcb = ApacheHttpTransport.newDefaultHttpClientBuilder();
        if (!sslVerfication) {
            hcb = hcb.setSSLHostnameVerifier(NoopHostnameVerifier.INSTANCE);
        }
        return new ApacheHttpTransport(hcb.build());
    }

    // getIDToken returns the raw OIDC Identity token if successfully obtained for the expected email address
    private String getIDToken(String expectedEmailAddress) throws Exception {
        JsonFactory jsonFactory = new GsonFactory();

        HttpTransport httpTransport = getHttpTransport();

        DataStoreFactory MEMORY_STORE_FACTORY = new MemoryDataStoreFactory();

        if (!oidcDeviceCodeFlow) {
            AuthorizationCodeFlow.Builder flowBuilder = new AuthorizationCodeFlow.Builder(
                BearerToken.authorizationHeaderAccessMethod(),
                httpTransport, jsonFactory, new GenericUrl(oidcTokenURL.toString()),
                new ClientParametersAuthentication(oidcClientID, null), oidcClientID,
                oidcAuthURL.toString())
                    .enablePKCE()
                    .setScopes(List.of("openid","email"))
                    .setCredentialCreatedListener(new AuthorizationCodeFlow.CredentialCreatedListener() {
                        @Override
                        public void onCredentialCreated(Credential credential, TokenResponse tokenResponse) throws IOException {
                        MEMORY_STORE_FACTORY.getDataStore("user").set("id_token", tokenResponse.get("id_token").toString());
                    }});
            AuthorizationCodeInstalledApp app = new AuthorizationCodeInstalledApp(flowBuilder.build(), new LocalServerReceiver());
            app.authorize("user");
        }
        //TODO: add device code flow support

        String idTokenString = (String) MEMORY_STORE_FACTORY.getDataStore("user").get("id_token");
        
        IdTokenVerifier idTokenVerifier = new IdTokenVerifier();
        IdToken parsedIdToken = IdToken.parse(jsonFactory, idTokenString);
        if (!idTokenVerifier.verify(parsedIdToken)){
            throw new Exception("id token could not be verified");
        }
        
        String emailFromIDToken = (String)parsedIdToken.getPayload().get("email");
        Boolean emailVerified = (Boolean)parsedIdToken.getPayload().get("email_verified");
        if (!emailFromIDToken.equals(expectedEmailAddress)) {
            throw new Exception(String.format("email in ID token '%s' does not match address specified to plugin '%s'",
                                              emailFromIDToken, emailAddress));
        } else if (!emailVerified) {
            throw new Exception(String.format("identity provider '%s' reports email address '%s' has not been verified",
                                parsedIdToken.getPayload().getIssuer(), emailAddress));
        }

        return idTokenString;
    }

    private CertPath getSigningCert(String signedEmail, PublicKey pubKey, String idToken) throws Exception {
        HttpTransport httpTransport = getHttpTransport();

        String publicKeyB64 = Base64.getEncoder().encodeToString(pubKey.getEncoded());
        Map<String, Object> fulcioPostContent = new HashMap<>();
        Map<String, Object> publicKeyContent = new HashMap<>();
        publicKeyContent.put("content", publicKeyB64);
        //TODO: look at signingAlgorithm and set accordingly
        if (pubKey.getAlgorithm() == "EC") {
            publicKeyContent.put("algorithm","ecdsa");
        }

        fulcioPostContent.put("signedEmailAddress",signedEmail);
        fulcioPostContent.put("publicKey",publicKeyContent);
        JsonHttpContent jsonContent = new JsonHttpContent(new GsonFactory(), fulcioPostContent);
        ByteArrayOutputStream stream = new ByteArrayOutputStream();
        jsonContent.writeTo(stream);
        
        GenericUrl fulcioPostUrl = new GenericUrl(fulcioInstanceURL+"/api/v1/signingCert");
        HttpRequest req = httpTransport.createRequestFactory().buildPostRequest(fulcioPostUrl, jsonContent);

        req.getHeaders().set("Accept", "application/pem-certificate-chain");
        req.getHeaders().set("Authorization", "Bearer "+idToken);

        getLog().info("requesting signing certificate");
        HttpResponse resp = req.execute();
        getLog().debug(resp.toString());
        if (resp.getStatusCode() != 201) {
            throw new Exception(String.format("bad response from fulcio @ '%s' : %s", fulcioPostUrl, resp.parseAsString()));
        }

        getLog().info("parsing signing certificate");
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        ArrayList<X509Certificate> certList = new ArrayList<X509Certificate>();
        PemReader pemReader = new PemReader(new InputStreamReader(resp.getContent()));
        while (true) {
            Section section = pemReader.readNextSection();
            if (section == null) {
                break;
            }

            byte[] certBytes = section.getBase64DecodedBytes();
            certList.add((X509Certificate)cf.generateCertificate(new ByteArrayInputStream(certBytes)));
        }
        if (certList.size() == 0) {
            throw new Exception("no certificates were found in response from Fulcio instance");
        }
        return cf.generateCertPath(certList);
    }

    // signJarFile signs the JAR file with the specified private key, and embeds the cert chain 
    // Returns: the signed JAR in a byte array
    private byte[] signJarFile(PrivateKey privKey, CertPath certs) throws Exception {
        // sign JAR using keypair
        getLog().info("signing JAR file, writing to " + outputSignedJar.getAbsolutePath());
        ByteArrayOutputStream memOut = new ByteArrayOutputStream();

        BiConsumer<String, String> progressLogger = (op, entryName) -> getLog().debug(String.format("%s %s", op, entryName));
        JarSigner.Builder jsb = new JarSigner.Builder(privKey, certs)
                                    .digestAlgorithm("SHA-256")
                                    .signatureAlgorithm("SHA256withECDSA")
                                    .setProperty("internalsf", "true")
                                    .signerName(signerName)
                                    .eventHandler(progressLogger);
                                        
        if (tsaURL.toString() != "") {
            jsb = jsb.tsa(tsaURL.toURI());
        }
        JarSigner js = jsb.build();
        ZipFile in = new ZipFile(inputJar);
        FileOutputStream jarOut = new FileOutputStream(outputSignedJar);
        TeeOutputStream tee = new TeeOutputStream(jarOut, memOut);
        js.sign(in, tee);

        getLog().info("finished signing JAR");
        return memOut.toByteArray();
    }

    private void writeSigningCertToFile(CertPath certs) throws Exception {
        getLog().info("writing signing certificate to " + outputSigningCert.getAbsolutePath());
        Base64.Encoder encoder = Base64.getMimeEncoder(64, System.getProperty("line.separator").getBytes());
        // we only write the first one, not the entire chain
        byte[] rawCrtText = certs.getCertificates().get(0).getEncoded();
        String encodedCertText = new String(encoder.encode(rawCrtText));
        String prettified_cert = 
            "-----BEGIN CERTIFICATE-----" + 
            System.getProperty("line.separator") +
            encodedCertText + 
            System.getProperty("line.separator") + 
            "-----END CERTIFICATE-----";

        if (!outputSigningCert.createNewFile()) {
            throw new Exception(String.format("file at %s already exists; will not overwrite", outputSigningCert.getAbsolutePath()));
        }
        FileWriter fw = new FileWriter(outputSigningCert);
        fw.write(prettified_cert);
        fw.close();
    }

    private URL submitToRekor(byte[] jarBytes) throws Exception {
        HttpTransport httpTransport = getHttpTransport();

        String jarB64 = Base64.getEncoder().encodeToString(jarBytes);
        Map<String, Object> rekorPostContent = new HashMap<>();
        Map<String, Object> specContent = new HashMap<>();
        Map<String, Object> archiveContent = new HashMap<>();
        archiveContent.put("content", jarB64);
        specContent.put("archive", archiveContent);

        rekorPostContent.put("kind","jar");
        rekorPostContent.put("apiVersion","0.0.1");
        rekorPostContent.put("spec",specContent);
        JsonHttpContent rekorJsonContent = new JsonHttpContent(new GsonFactory(), rekorPostContent);
        ByteArrayOutputStream rekorStream = new ByteArrayOutputStream();
        rekorJsonContent.writeTo(rekorStream);
        
        GenericUrl rekorPostUrl = new GenericUrl(rekorInstanceURL+"/api/v1/log/entries");
        HttpRequest rekorReq = httpTransport.createRequestFactory().buildPostRequest(rekorPostUrl, rekorJsonContent);

        rekorReq.getHeaders().set("Accept", "application/json");
        rekorReq.getHeaders().set("Content-Type", "application/json");

        HttpResponse rekorResp = rekorReq.execute();
        if (rekorResp.getStatusCode() != 201) {
            throw new Exception("bad response from rekor: "+rekorResp.parseAsString());
        }

        return new URL(rekorInstanceURL,rekorResp.getHeaders().getLocation());
    }
}