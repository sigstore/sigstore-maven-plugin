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

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.cert.CertPath;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.util.List;

import javax.inject.Inject;
import javax.inject.Named;
import javax.inject.Singleton;

import dev.sigstore.rekor.RekorClient;
import dev.sigstore.rekor.model.HashedRekordWrapper;
import dev.sigstore.rekor.model.RekorLogEntry;

import org.apache.commons.codec.digest.DigestUtils;
import org.apache.commons.io.IOUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import static dev.sigstore.plugin.Utils.getCertPath;
import static java.nio.charset.StandardCharsets.UTF_8;
import static java.util.stream.Collectors.toList;
import static org.apache.commons.codec.digest.MessageDigestAlgorithms.SHA_256;

@Singleton
@Named
public class SigstoreVerifier
{
  private static final String NL = System.lineSeparator();

  private static final Logger LOG = LoggerFactory.getLogger(SigstoreVerifier.class);

  @Inject
  private RekorClient rekorClient;

  //Solely used for generating a file in /target containing all the logging statements for IT validation as of now
  private final StringBuilder contentBuilder = new StringBuilder();

  public void verifySignature(final File binaryFile) {
    try {
      contentBuilder.setLength(0);

      String sha256 = new DigestUtils(SHA_256).digestAsHex(binaryFile);

      printInit(binaryFile, sha256);

      List<String> rekorUuids = rekorClient.getRekorUuidsFromChecksum("sha256", sha256);

      List<RekorLogEntry> rekorLogEntries = rekorUuids.stream().map(rekorClient::getRekordLogEntryFromUuid).collect(toList());

      printRekords(binaryFile, sha256, rekorLogEntries);
      rekorLogEntries.forEach(rekorLogEntry -> processRekord(binaryFile, sha256, rekorLogEntry));

      writeContent();
    }
    catch (IOException e) {
      throw new RuntimeException("Failed to verify signature", e);
    }
  }

  private void processRekord(
      final File binaryFile,
      final String sha256,
      final RekorLogEntry rekorLogEntry)
  {
    HashedRekordWrapper rekord = rekorClient.getRekordWrapper(rekorLogEntry);
    try {
      printRekord(rekord);
      CertPath publicSigningCert =
          getCertPath(IOUtils.toInputStream(rekord.decodedX509PublicSigningCertificate, UTF_8));
      publicSigningCert.getCertificates().forEach(certificate -> processCert(binaryFile, sha256, rekord, certificate));
    }
    catch (CertificateException | IOException e) {
      LOG.error("Failed to retrieve certificates", e);
    }
  }

  private void processCert(
      final File binaryFile,
      final String sha256,
      final HashedRekordWrapper rekord,
      final Certificate certificate)
  {
    printCert(certificate);

    //TODO: the actual signature verification
    String todo = "implementMe";
  }

  private void printInit(final File binaryFile, final String sha256) {
    logAndAppend(
        String.format("Query sigstore for published signatures using sha256 %s of the provided file %s", sha256,
            binaryFile.getAbsolutePath()));
  }

  private void printRekords(final File binaryFile, final String sha256, final List<RekorLogEntry> rekords) {
    logAndAppend(String.format("Found %d rekord(s) matching sha256 %s of the provided file %s", rekords.size(), sha256,
        binaryFile.getAbsolutePath()));
  }

  private void printRekord(final HashedRekordWrapper rekord)
  {
    logAndAppend(String.format("Rekord kind='%s' retrieved from sigstore with integratedTime %d", rekord.hashedRekord.kind, rekord.integratedTime));
    logAndAppend(String.format("Decoded public signing cert:%n%s", rekord.decodedX509PublicSigningCertificate));
    logAndAppend(String.format("Decoded signature:%n%s", rekord.decodedSignature));
  }

  private void printCert(final Certificate certificate)
  {
    logAndAppend(String.format("Certificate pulled from public signing certificate:%n%s", certificate));
  }

  private void logAndAppend(final String msg) {
    LOG.info(msg);
    contentBuilder.append(msg).append(System.lineSeparator());
  }

  private void writeContent() {
    Path path = Path.of("target", "verify-receipt.txt");
    try {
      if (Files.exists(path)) {
        LOG.debug("Deleting existing content file and rewriting {}", path.toAbsolutePath().toString());
        Files.delete(path);
      }
      Files.write(path, contentBuilder.toString().getBytes(UTF_8));
    }
    catch (IOException e) {
      LOG.error("Failed to write content to {}", path.toAbsolutePath().toString());
    }
  }
}
