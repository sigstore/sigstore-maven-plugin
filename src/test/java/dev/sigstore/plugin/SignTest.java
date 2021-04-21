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

import org.apache.maven.plugin.testing.MojoRule;
import org.apache.maven.plugin.testing.WithoutMojo;
import org.junit.Rule;
import static org.junit.Assert.*;

import java.security.KeyPair;
import java.security.PrivateKey;
import java.util.Arrays;

import org.junit.Test;
import org.junit.experimental.runners.Enclosed;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.junit.runners.Parameterized.Parameters;

@RunWith(Enclosed.class)
public class SignTest
{
    /*
    @Rule
    public MojoRule rule = new MojoRule() {
        @Override
        protected void before() throws Throwable {
        }

        @Override
        protected void after() {
        }
    };
    */

    @RunWith(Parameterized.class)
    public static class TestGenerateKeypair {

        @Parameters(name = "{index}: {0} {1})")
        public static Iterable<Object[]> keypairsToTest() {
            return Arrays.asList(new Object[][] {
                {"EC", "secp256r1", true},
                {"EC", "secp384r1", true},
                {"EC", "secp256z1", false},
                {"unknown", "secp384r1", false},
                {"EC", null, false},
                {null, "secp384r1", false},
            });
        }

        @Parameterized.Parameter(0)
        public String signAlg;

        @Parameterized.Parameter(1)
        public String signAlgParams;

        @Parameterized.Parameter(2)
        public Boolean expectedSuccess;

        @WithoutMojo
        @Test
        public void testGenerateKeypair() {
            Sign signToTest = new Sign();
            try {
                signToTest.generateKeyPair(signAlg, signAlgParams);
            } catch (Exception e) {
                if (Boolean.TRUE.equals(expectedSuccess)) {
                    fail(e.getMessage());
                }
                return;
            }
            if (Boolean.FALSE.equals(expectedSuccess)) {
                fail("expected failure but method returned without exception");
            }
            assertTrue(true);
        }
    }

    @RunWith(Parameterized.class)
    public static class TestSignEmailAddress {

        @Parameters(name = "{index}: {0} {1})")
        public static Iterable<Object[]> emailAndKeysToTest() {
            Sign sign = new Sign();
            KeyPair kp;
            try {
                kp = sign.generateKeyPair("EC", "secp256r1");
            } catch (Exception e) {
                fail("should not get here");
                return null;
            }

            return Arrays.asList(new Object[][] {
                {"someone@yahoo.com", kp.getPrivate(), true},
                {"", kp.getPrivate(), false},
                {null, kp.getPrivate(), false},
                {"not_an_email", kp.getPrivate(), false},
                {"someone@yahoo.com", null, false},
            });
        }

        @Parameterized.Parameter(0)
        public String emailAddress;

        @Parameterized.Parameter(1)
        public PrivateKey privateKey;

        @Parameterized.Parameter(2)
        public Boolean expectedSuccess;

        @WithoutMojo
        @Test
        public void testSignEmailAddress() {
            Sign signToTest = new Sign();
            try {
                signToTest.signEmailAddress(emailAddress, privateKey);
            } catch (Exception e) {
                if (Boolean.TRUE.equals(expectedSuccess)) {
                    fail(e.getMessage());
                }
                return;
            }
            if (Boolean.FALSE.equals(expectedSuccess)) {
                fail("expected failure but method returned without exception");
            }
            assertTrue(true);
        }
    }
}

