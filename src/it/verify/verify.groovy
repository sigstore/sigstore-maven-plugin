// Copyright 2021 The Sigstore Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

File contentResult = new File( basedir, "target/verify-receipt.txt" )

//As the plugin isn't doing actual signature validation yet, just data retrieval, just do some assertions against
//the data
assert contentResult.isFile()
assert contentResult.text.contains("sha256 536d91853bf1d29af438e5e2478f1a9113c081e03367fb2f82e2ddb711291e6d")
assert contentResult.text.contains("-----BEGIN CERTIFICATE-----")
assert contentResult.text.contains("-----END CERTIFICATE-----")
assert contentResult.text.contains("-----BEGIN PKCS7-----")
assert contentResult.text.contains("-----END PKCS7-----")

println "Assertions succeeded!"
