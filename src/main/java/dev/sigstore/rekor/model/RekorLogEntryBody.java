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

public class RekorLogEntryBody
{
  public String apiVersion;

  public String kind;

  // TODO based on kind value, spec may be different:
  // hashedrekord: https://github.com/sigstore/rekor/blob/main/pkg/types/hashedrekord/v0.0.1/hashedrekord_v0_0_1_schema.json
  // jar: https://github.com/sigstore/rekor/blob/main/pkg/types/jar/v0.0.1/jar_v0_0_1_schema.json
  public HashedRekordSpec spec;

  @Override
  public String toString() {
    return "RekorLogEntryBody{" +
        "apiVersion='" + apiVersion + '\'' +
        ", kind='" + kind + '\'' +
        ", spec=" + spec +
        '}';
  }
}
