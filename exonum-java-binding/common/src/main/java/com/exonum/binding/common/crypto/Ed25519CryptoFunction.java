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

package com.exonum.binding.common.crypto;

import static com.exonum.binding.common.crypto.CryptoFunctions.Ed25519.PRIVATE_KEY_BYTES;
import static com.exonum.binding.common.crypto.CryptoFunctions.Ed25519.PUBLIC_KEY_BYTES;
import static com.exonum.binding.common.crypto.CryptoFunctions.Ed25519.SEED_BYTES;
import static com.exonum.binding.common.crypto.CryptoFunctions.Ed25519.SIGNATURE_BYTES;
import static com.exonum.binding.common.crypto.CryptoUtils.hasLength;
import static com.google.common.base.Preconditions.checkArgument;

import com.goterl.lazycode.lazysodium.LazySodium;
import com.goterl.lazycode.lazysodium.LazySodiumJava;
import com.goterl.lazycode.lazysodium.SodiumJava;
import com.goterl.lazycode.lazysodium.utils.LibraryLoader;

/**
 * A ED25519 public-key signature system crypto function.
 */
final class Ed25519CryptoFunction extends AbstractEd25519CryptoFunction {

  private final LazySodiumJava lazySodium;

  @Override
  protected LazySodium getLazySodium() {
    return lazySodium;
  }

  /**
   * Creates a new Ed25519 crypto function that will attempt to load the sodium library
   * using the specified mode. If the sodium library is already loaded, the mode will
   * have <em>no</em> effect.
   */
  Ed25519CryptoFunction(LibraryLoader.Mode mode) {
    lazySodium = new LazySodiumJava(new SodiumJava(mode));
  }

}
