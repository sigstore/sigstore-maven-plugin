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

import java.io.File;

import javax.inject.Inject;

import dev.sigstore.plugin.verify.SigstoreVerifier;
import org.apache.maven.plugin.AbstractMojo;
import org.apache.maven.plugin.MojoExecutionException;
import org.apache.maven.plugins.annotations.LifecyclePhase;
import org.apache.maven.plugins.annotations.Mojo;
import org.apache.maven.plugins.annotations.Parameter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Goal which:<ul>
 * <li>verifies dependency signatures against Rekor
 * </ul>
 */
@Mojo(name = "verify", defaultPhase = LifecyclePhase.VERIFY)
public class Verify
    extends AbstractMojo
{
  private static final Logger LOG = LoggerFactory.getLogger(Verify.class);

  @Parameter(property = "binary-file")
  private File binaryFile;

  @Inject
  private SigstoreVerifier sigstoreVerifier;

  @Override
  public final void execute() throws MojoExecutionException {
    sigstoreVerifier.verifySignature(binaryFile);
  }
}
