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

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.StringReader;
import java.security.cert.CertPath;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;

import com.google.api.client.util.PemReader;
import com.google.api.client.util.PemReader.Section;

public class Utils
{
  public static CertPath getCertPath(final InputStream publicSigningCert)
      throws CertificateException, IOException
  {
    CertificateFactory cf = CertificateFactory.getInstance("X.509");
    ArrayList<X509Certificate> certList = new ArrayList<>();
    PemReader pemReader = new PemReader(new InputStreamReader(publicSigningCert));
    while (true) {
      Section section = pemReader.readNextSection();
      if (section == null) {
        break;
      }

      byte[] certBytes = section.getBase64DecodedBytes();
      certList.add((X509Certificate) cf.generateCertificate(new ByteArrayInputStream(certBytes)));
    }
    if (certList.isEmpty()) {
      throw new IOException("no certificates were found in publicSigningCert");
    }
    return cf.generateCertPath(certList);
  }
}
