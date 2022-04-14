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
package dev.sigstore.rekor;

import java.io.IOException;
import java.net.URI;
import java.util.List;
import java.util.Map;

import javax.inject.Named;
import javax.inject.Singleton;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;

import dev.sigstore.rekor.model.RekorLogEntryBody;
import dev.sigstore.rekor.model.RekorEntriesRequest;
import dev.sigstore.rekor.model.RekorIndexRequest;
import dev.sigstore.rekor.model.HashedRekordWrapper;
import dev.sigstore.rekor.model.RekorLogEntry;

import org.apache.commons.codec.binary.Base64;
import org.apache.http.HttpStatus;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.util.EntityUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import static java.nio.charset.StandardCharsets.UTF_8;
import static java.util.Collections.singletonList;
import static org.apache.http.entity.ContentType.APPLICATION_JSON;

/**
 * Sigstore Rekor transparency log client,
 * see <a href="https://github.com/sigstore/rekor/blob/main/openapi.yaml">Rekor OpenAPI definition</a>
 */
@Named
@Singleton
public class RekorClient
{
  private static final Logger LOG = LoggerFactory.getLogger(RekorClient.class);

  private static final String TRANSPARENCY_LOG_INDEX_URL = "https://rekor.sigstore.dev/api/v1/index/retrieve";

  private static final String TRANSPARENCY_LOG_ENTRY_URL = "https://rekor.sigstore.dev/api/v1/log/entries/retrieve";

  private final ObjectMapper objectMapper = new ObjectMapper();

  public RekorClient() {
    objectMapper.configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);
  }

  /*
   * Send request off to rekor to find any transparency logs for checksum
   * example:
   *
   * POST https://rekor.sigstore.dev/api/v1/index/retrieve
   * {
   *   hash: "sha256:342024b59f3b8fe1a37efce6167023bc368f71ca01779ae81e78b2f4aca376be"
   * }
   */
  public List<String> getRekorUuidsFromChecksum(
      final String checksumType,
      final String checksum)
  {
    try {
      LOG.debug("Requesting rekor entry UUIDs from {} for checksum {}:{}", TRANSPARENCY_LOG_INDEX_URL,
          checksumType, checksum);

      List<String> transparencyLogUuids = objectMapper.readValue(getJsonFromPOST(TRANSPARENCY_LOG_INDEX_URL,
              objectMapper.writeValueAsString(new RekorIndexRequest(String.format("%s:%s", checksumType, checksum)))),
          new TypeReference<>() { });

      LOG.debug("Found {} rekor entry UUIDs: {}",transparencyLogUuids.size(), transparencyLogUuids);

      return transparencyLogUuids;
    }
    catch (Exception e) {
      throw new RuntimeException(e);
    }
  }

  /*
   * Send request off to rekor to grab the Rekord associated with a single uuid
   * example:
   *
   * POST https://rekor.sigstore.dev/api/v1/log/entries/retrieve
   * {
   *   entryUUIDs: ["a9bd97ee5453ce44525069e8ff8703555bc28d9f1553b9745bd6cdff3732bb87"]
   * }
   */
  public RekorLogEntry getRekordLogEntryFromUuid(final String uuid) {
    try {
      LOG.debug("Requesting rekor log entry from {} for uuid {}", TRANSPARENCY_LOG_ENTRY_URL, uuid);

      List<Map<String, Object>> rekorLogEntries = objectMapper.readValue(
          getJsonFromPOST(TRANSPARENCY_LOG_ENTRY_URL,
              objectMapper.writeValueAsString(new RekorEntriesRequest(singletonList(uuid)))),
          new TypeReference<>() { });

      if (rekorLogEntries.size() != 1) {
        throw new RuntimeException(
            String.format("Received %s results for uuid %s query, expected 1.", rekorLogEntries.size(), uuid));
      }

      return
          objectMapper.readValue(objectMapper.writeValueAsString(rekorLogEntries.get(0).get(uuid)),
              RekorLogEntry.class);
    }
    catch (Exception e) {
      throw new RuntimeException(e);
    }
  }

  public HashedRekordWrapper getRekordWrapper(final RekorLogEntry rekorLogEntry) {
    try {
      String decodedBody = new String(Base64.decodeBase64(rekorLogEntry.body), UTF_8);
      LOG.debug("Rekor log entry decoded body: {}", objectMapper.writerWithDefaultPrettyPrinter()
          .writeValueAsString(objectMapper.readValue(decodedBody, Object.class)));

      RekorLogEntryBody record = objectMapper.readValue(decodedBody, RekorLogEntryBody.class);
 
      return new HashedRekordWrapper(rekorLogEntry.integratedTime, record,
          new String(Base64.decodeBase64(record.spec.signature.publicKey.content), UTF_8),
          new String(Base64.decodeBase64(record.spec.signature.content), UTF_8));
    }
    catch (Exception e) {
      throw new RuntimeException(e);
    }
  }

  private String getJsonFromPOST(final String url, final String json) throws IOException {
    try (final CloseableHttpClient httpClient = HttpClients.createDefault()) {
      HttpPost post = new HttpPost(URI.create(url));
      post.setEntity(new StringEntity(json, APPLICATION_JSON));

      try (final CloseableHttpResponse httpResponse = httpClient.execute(post)) {
        if (httpResponse.getStatusLine().getStatusCode() != HttpStatus.SC_OK) {
          throw new RuntimeException(String.format("Failed to send POST request to %s status %d response %s", url,
              httpResponse.getStatusLine().getStatusCode(), EntityUtils.toString(httpResponse.getEntity())));
        }

        String responseJson = EntityUtils.toString(httpResponse.getEntity());
        LOG.debug("Received JSON\n{}", objectMapper.writerWithDefaultPrettyPrinter()
            .writeValueAsString(objectMapper.readValue(responseJson, Object.class)));
        return responseJson;
      }
    }
  }
}
