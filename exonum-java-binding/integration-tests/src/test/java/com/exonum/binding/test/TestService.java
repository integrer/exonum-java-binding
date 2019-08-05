/*
 * Copyright 2019 The Exonum Team
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.exonum.binding.test;

import static com.exonum.binding.test.TestTransaction.BODY_CHARSET;

import com.exonum.binding.common.hash.HashCode;
import com.exonum.binding.common.hash.Hashing;
import com.exonum.binding.core.service.AbstractService;
import com.exonum.binding.core.service.BlockCommittedEvent;
import com.exonum.binding.core.service.Node;
import com.exonum.binding.core.storage.database.Fork;
import com.exonum.binding.core.storage.database.View;
import com.exonum.binding.core.storage.indices.ProofMapIndexProxy;
import com.exonum.binding.core.transaction.RawTransaction;
import io.vertx.ext.web.Router;
import java.nio.charset.StandardCharsets;
import java.util.Properties;

public final class TestService extends AbstractService {

  static final HashCode INITIAL_ENTRY_KEY = Hashing.defaultHashFunction()
      .hashString("initial key", StandardCharsets.UTF_8);
  static final String INITIAL_ENTRY_VALUE = "initial value";
  static final String INITIAL_CONFIGURATION = "{ \"version\": \"0.2.0\" }";

  private Node node;

  public TestService() {
    // todo: Shall we remove the converter:
    //  TestTransaction::from);
  }

  public Node getNode() {
    return node;
  }

  @Override
  protected TestSchema createDataSchema(View view) {
    return new TestSchema(view);
  }

  @Override
  public void configure(Fork fork, Properties properties) {
    TestSchema schema = createDataSchema(fork);
    ProofMapIndexProxy<HashCode, String> testMap = schema.testMap();
    testMap.put(INITIAL_ENTRY_KEY, INITIAL_ENTRY_VALUE);
  }

  @Override
  public void afterCommit(BlockCommittedEvent event) {
    long height = event.getHeight();
    RawTransaction rawTransaction = constructAfterCommitTransaction(height);
    node.submitTransaction(rawTransaction);
  }

  static RawTransaction constructAfterCommitTransaction(long height) {
    String payload = "Test message on height " + height;
    return RawTransaction.newBuilder()
        // todo: Or keep getId() in the interface, and implement it in the AbstractService
        //   for cases like this one (submitting a transaction to self)?
        .serviceId(SERVICE_ID)
        .transactionId(TestTransaction.ID)
        .payload(payload.getBytes(BODY_CHARSET))
        .build();
  }

  @Override
  public void createPublicApiHandlers(Node node, Router router) {
    this.node = node;
  }
}
