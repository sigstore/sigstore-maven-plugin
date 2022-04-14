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
package dev.sigstore.rekor.model;

public class HashedRekordWrapper
{
  public Long integratedTime;

  public RekorLogEntryBody hashedRekord;

  public String decodedX509PublicSigningCertificate;

  public String decodedSignature;

  public HashedRekordWrapper(
      final Long integratedTime,
      final RekorLogEntryBody hashedRekord,
      final String decodedX509PublicSigningCertificate,
      final String decodedSignature)
  {
    this.integratedTime = integratedTime;
    this.hashedRekord = hashedRekord;
    this.decodedX509PublicSigningCertificate = decodedX509PublicSigningCertificate;
    this.decodedSignature = decodedSignature;
  }

  @Override
  public String toString() {
    return "HashedRekordWrapper{" +
        "integratedTime=" + integratedTime +
        ", hashedRekord=" + hashedRekord +
        ", decodedX509PublicSigningCertificate='" + decodedX509PublicSigningCertificate + '\'' +
        ", decodedSignature='" + decodedSignature + '\'' +
        '}';
  }
}
