/*
 * Copyright 2018 The Exonum Team
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

package com.exonum.binding.common.proofs.map;

import com.exonum.binding.common.collect.MapEntry;
import com.exonum.binding.common.proofs.CheckedProof;
import com.google.protobuf.ByteString;
import java.util.Set;

/**
 * A checked map proof.
 * In case of incorrect proof all methods (except for getProofStatus)
 * throw IllegalStateException.
 * Example usage:
 * <pre>{@code
 * ByteString key = "The key for which I want a proved value".getBytes();
 * HashCode expectedIndexHash = // get a known index hash from block proof //
 * UncheckedMapProof proof = requestProofForKey(key);
 * // Convert to checked
 * CheckedMapProof checkedProof = proof.check();
 * // Check the index hash
 * if (checkedProof.isValid() && checkedProof.getIndexHash().equals(expectedIndexHash)) {
 *   // Get and use the value(s)
 *   ByteString value = checked.get(key);
 * }
 * }</pre>
 */
public interface CheckedMapProof extends CheckedProof {
  /**
   * Get all leaf entries of this proof.
   * @throws IllegalStateException if the proof is not valid
   */
  Set<MapEntry<ByteString, ByteString>> getEntries();

  /**
   * Get all keys that were requested, but did not appear in this proof.
   * @throws IllegalStateException if the proof is not valid
   */
  Set<ByteString> getMissingKeys();

  /**
   * If this proof is valid, returns true if there is a given key in the proof;
   * false — if there is no such key.
   * @throws IllegalStateException if the proof is not valid
   */
  boolean containsKey(ByteString key);

  /**
   * If this proof is valid, returns the value corresponding to the specified key
   * or null if there is no such key in the proof.
   * @throws IllegalStateException if the proof is not valid
   */
  ByteString get(ByteString key);

  /**
   * Returns the status of this proof: whether it is structurally valid.
   */
  @Override
  MapProofStatus getProofStatus();
}
