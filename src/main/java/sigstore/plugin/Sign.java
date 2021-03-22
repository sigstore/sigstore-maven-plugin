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


import org.apache.http.conn.ssl.AllowAllHostnameVerifier;
import org.apache.http.conn.ssl.NoopHostnameVerifier;
import org.apache.maven.plugin.AbstractMojo;
import org.apache.maven.plugin.MojoExecutionException;

import org.apache.maven.plugins.annotations.LifecyclePhase;
import org.apache.maven.plugins.annotations.Mojo;
import org.apache.maven.plugins.annotations.Parameter;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.net.URL;
import java.security.cert.CertPath;
import java.security.cert.CertificateFactory;
import java.security.spec.ECGenParameterSpec;
import java.security.cert.X509Certificate;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.Signature;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.zip.ZipFile;

import com.google.api.client.auth.oauth2.AuthorizationCodeFlow;
import com.google.api.client.auth.oauth2.BearerToken;
import com.google.api.client.auth.oauth2.ClientParametersAuthentication;
import com.google.api.client.auth.oauth2.Credential;
import com.google.api.client.auth.oauth2.CredentialRefreshListener;
import com.google.api.client.auth.oauth2.TokenErrorResponse;
import com.google.api.client.auth.oauth2.TokenResponse;
import com.google.api.client.auth.openidconnect.IdToken;
import com.google.api.client.auth.openidconnect.IdTokenVerifier;
import com.google.api.client.extensions.java6.auth.oauth2.AuthorizationCodeInstalledApp;
import com.google.api.client.extensions.jetty.auth.oauth2.LocalServerReceiver;
import com.google.api.client.googleapis.auth.oauth2.GoogleAuthorizationCodeFlow;
import com.google.api.client.googleapis.auth.oauth2.GoogleClientSecrets;
import com.google.api.client.json.JsonFactory;
import com.google.api.client.util.PemReader;
import com.google.api.client.util.PemReader.Section;
import com.google.api.client.util.store.DataStoreFactory;
import com.google.api.client.util.store.MemoryDataStoreFactory;

import java.io.IOException;
import java.io.InputStreamReader;
import java.util.List;

import com.google.api.client.googleapis.javanet.GoogleNetHttpTransport;
import com.google.api.client.http.GenericUrl;
import com.google.api.client.http.HttpHeaders;
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
    @Parameter( property = "jarToSign", required = true )
    private File jarToSign;

    /**
     * Location of the signed JAR file.
     */
    @Parameter( property = "outputFile", required = true )
    private File outputFile;

    /**
     * URL of Fulcio instance
     */
    @Parameter( defaultValue = "https://fulcio.rekor.dev", property = "fulcioInstanceURL", required = true )
    private URL fulcioInstanceURL;

    /**
     * Client ID for OIDC Identity Provider
     */
    @Parameter( defaultValue = "fulcio", property = "fulcioClientID", required = true )
    private String fulcioClientID;

    /**
     * URL of OIDC Identity Provider Authorization endpoint
     */
    @Parameter( defaultValue = "https://fulcio.rekor.dev/auth/auth", property = "fulcioAuthURL", required = true )
    private URL fulcioAuthURL;

    /**
     * URL of OIDC Identity Provider Token endpoint
     */
    @Parameter( defaultValue = "https://fulcio.rekor.dev/auth/token", property = "fulcioTokenURL", required = true )
    private URL fulcioTokenURL;

    /**
     * URL of Rekor instance
     */
    @Parameter( defaultValue = "https://rekor.sigstore.dev", property = "rekorInstanceURL", required = true )
    private URL rekorInstanceURL;

    /**
     * Email address of signer
     */
    @Parameter( property = "emailAddress", required = true )
    private String emailAddress;

    public void execute() throws MojoExecutionException {
        //generate keypair
        KeyPair keypair;
        try {
            keypair = this.generateKeyPair();
        } catch (Exception e) {
            throw new MojoExecutionException("Error creating keypair:", e);
        }

        // get email address, sign with private key
        String signedEmail;
        try {
            signedEmail = this.signEmailAddress(emailAddress, keypair);
        } catch (Exception e) {
            throw new MojoExecutionException("Error signing email address: ", e);
        }

        // do OIDC dance, get ID token
        try {
            JsonFactory jsonFactory = new GsonFactory();
            HttpTransport apacheTransport = new ApacheHttpTransport(ApacheHttpTransport.newDefaultHttpClientBuilder()
                .setSSLHostnameVerifier(NoopHostnameVerifier.INSTANCE).build());

            DataStoreFactory MEMORY_STORE_FACTORY = new MemoryDataStoreFactory();

            AuthorizationCodeFlow.Builder flowBuilder = new AuthorizationCodeFlow.Builder(
                BearerToken.authorizationHeaderAccessMethod(), apacheTransport, jsonFactory,
                new GenericUrl(fulcioTokenURL.toString()), new ClientParametersAuthentication(fulcioClientID, null),
                fulcioClientID, fulcioAuthURL.toString())
                    .enablePKCE()
                    .setScopes(List.of("openid","email"))
                    .setCredentialCreatedListener(new AuthorizationCodeFlow.CredentialCreatedListener() {
                        @Override
                        public void onCredentialCreated(Credential credential, TokenResponse tokenResponse) throws IOException {
                        MEMORY_STORE_FACTORY.getDataStore("user").set("id_token", tokenResponse.get("id_token").toString());
                    }});
            AuthorizationCodeInstalledApp app = new AuthorizationCodeInstalledApp(flowBuilder.build(), new LocalServerReceiver());

            app.authorize("user");

            String idTokenString = (String) MEMORY_STORE_FACTORY.getDataStore("user").get("id_token");
            //verify idToken
            IdTokenVerifier idTokenVerifier = new IdTokenVerifier();
            if (idTokenVerifier.verify(IdToken.parse(jsonFactory, idTokenString)) == false ){
                throw new MojoExecutionException("id token invalid");
            }

            // push to fulcio, get cert chain
            String publicKeyB64 = Base64.getEncoder().encodeToString(keypair.getPublic().getEncoded());
            Map<String, Object> fulcioPostContent = new HashMap<>();
            Map<String, Object> publicKeyContent = new HashMap<>();
            publicKeyContent.put("content", publicKeyB64);
            publicKeyContent.put("algorithm","ecdsa");

            fulcioPostContent.put("signedEmailAddress",signedEmail);
            fulcioPostContent.put("publicKey",publicKeyContent);
            JsonHttpContent jsonContent = new JsonHttpContent(new GsonFactory(), fulcioPostContent);
            ByteArrayOutputStream stream = new ByteArrayOutputStream();
            jsonContent.writeTo(stream);
            
            HttpTransport httpTransport = GoogleNetHttpTransport.newTrustedTransport();
            GenericUrl fulcioPostUrl = new GenericUrl("http://localhost:5555/api/v1/signingCert");
            HttpRequest req = httpTransport.createRequestFactory().buildPostRequest(fulcioPostUrl, jsonContent);

            req.getHeaders().set("Accept", "application/pem-certificate-chain");
            req.getHeaders().set("Authorization", "Bearer "+idTokenString);

            HttpResponse resp = req.execute();
            if (resp.getStatusCode() != 201) {
                throw new Exception("bad response from fulcio: "+resp.parseAsString());
            }

            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            ArrayList<X509Certificate> certList = new ArrayList<X509Certificate>();
            PemReader pemReader = new PemReader(new InputStreamReader(resp.getContent()));
            while (true) {
                Section section = pemReader.readNextSection();
                if (section == null) {
                    break;
                }
                certList.add((X509Certificate)cf.generateCertificate(new ByteArrayInputStream(section.getBase64DecodedBytes())));
            }

            CertPath cert = cf.generateCertPath(certList);

            // sign JAR using keypair
            JarSigner js = new JarSigner.Builder(keypair.getPrivate(), cert)
                .digestAlgorithm("SHA-256")
                .signatureAlgorithm("SHA256withECDSA")
                .build();
            try (ZipFile in = new ZipFile(jarToSign);
                FileOutputStream out = new FileOutputStream(outputFile)) {
                    js.sign(in, out);
                }
            // extract signature, submit to rekor
        } catch (Exception e){
            getLog().error(e);
            throw new MojoExecutionException("Error posting to fulcio:", e);
        }
    }

    private KeyPair generateKeyPair() throws Exception {
        ECGenParameterSpec ecSpec = new ECGenParameterSpec("secp384r1");
        KeyPairGenerator g = KeyPairGenerator.getInstance("EC");
        g.initialize(ecSpec, new SecureRandom());
        return g.generateKeyPair();
    }

    private String signEmailAddress(String emailAddress, KeyPair keypair) throws Exception {
        Signature sig = Signature.getInstance("SHA256withECDSA");
        sig.initSign(keypair.getPrivate());
        sig.update(emailAddress.getBytes());
        return Base64.getEncoder().encodeToString(sig.sign());
    }
}
