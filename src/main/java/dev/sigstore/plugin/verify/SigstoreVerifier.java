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
package dev.sigstore.plugin.verify;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.IOException;
import java.io.StringReader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.Signature;
import java.security.cert.CertPath;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

import javax.inject.Inject;
import javax.inject.Named;
import javax.inject.Singleton;

import com.google.api.client.util.PemReader;
import com.google.api.client.util.PemReader.Section;
import dev.sigstore.plugin.client.SigstoreClient;
import dev.sigstore.plugin.model.HashedRekordWrapper;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.codec.digest.DigestUtils;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import static java.nio.charset.StandardCharsets.UTF_8;
import static org.apache.commons.codec.digest.MessageDigestAlgorithms.SHA_256;

@Singleton
@Named
public class SigstoreVerifier
{
  private static final Logger LOG = LoggerFactory.getLogger(SigstoreVerifier.class);

  @Inject
  private SigstoreClient sigstoreClient;

  public void verifySignature(final File binaryFile) {
    try {
      LOG.info("checking binary file {}", binaryFile);
      String sha256 = new DigestUtils(SHA_256).digestAsHex(binaryFile);
      LOG.info("sha256 = {}", sha256);

      List<HashedRekordWrapper> rekords = sigstoreClient.getHashedRekordWrappersFromChecksum("sha256", sha256);

      LOG.info("Found rekords {}", rekords);

      processRekords(binaryFile, sha256, rekords);
    }
    catch (IOException e) {
      throw new RuntimeException("Failed to verify signature", e);
    }
  }

  private void processRekords(
      final File binaryFile,
      final String sha256,
      final List<HashedRekordWrapper> rekords)
  {
    rekords.forEach(rekord -> processRekord(binaryFile, sha256, rekord));
  }

  private void processRekord(
      final File binaryFile,
      final String sha256,
      final HashedRekordWrapper rekord)
  {
    CertPath publicSigningCert = getSigningCert(rekord.decodedX509PublicSigningCertificate);

    publicSigningCert.getCertificates()
        .forEach(certificate -> processCert(binaryFile, sha256, rekord, certificate));
  }

  private void processCert(
      final File binaryFile,
      final String sha256,
      final HashedRekordWrapper rekord,
      final Certificate certificate)
  {
    try {
      File sigFile = new File(binaryFile.getAbsolutePath() + ".EC");

      String sig = new String(Base64.decodeBase64(Files.readAllBytes(sigFile.toPath())), UTF_8);

      LOG.info("Processing verification with cert {} and sig {}", certificate, sig);

      Signature signature = Signature.getInstance("SHA384withECDSA", new BouncyCastleProvider());
      signature.initVerify(certificate.getPublicKey());
      signature.verify(rekord.decodedSignature.getBytes(UTF_8));
    }
    catch (Exception e) {
      throw new RuntimeException("Failed to process the signature with cert", e);
    }
  }

  private CertPath getSigningCert(final String publicSigningCert) {
    try {
      CertificateFactory cf = CertificateFactory.getInstance("X.509");
      ArrayList<X509Certificate> certList = new ArrayList<>();
      PemReader pemReader = new PemReader(new StringReader(publicSigningCert));
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
    }
    catch (Exception e) {
      throw new RuntimeException("Failed to get signing certificate");
    }
  }
}
