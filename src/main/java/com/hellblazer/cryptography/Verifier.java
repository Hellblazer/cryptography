/*
 * Copyright (c) 2021, salesforce.com, inc.
 * All rights reserved.
 * SPDX-License-Identifier: BSD-3-Clause
 * For full license text, see the LICENSE file in the repo root or https://opensource.org/licenses/BSD-3-Clause
 */
package com.hellblazer.cryptography;

import com.google.protobuf.ByteString;

import java.io.InputStream;
import java.nio.ByteBuffer;
import java.security.PublicKey;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Verifies a signature using a given key
 *
 * @author hal.hildebrand
 */
public interface Verifier {

    default boolean verify(JohnHancock signature, byte[]... message) {
        return verify(signature, BbBackedInputStream.aggregate(message));
    }

    default boolean verify(JohnHancock signature, ByteBuffer... message) {
        return verify(signature, BbBackedInputStream.aggregate(message));
    }

    default boolean verify(JohnHancock signature, ByteString... message) {
        return verify(signature, BbBackedInputStream.aggregate(message));
    }

    boolean verify(JohnHancock signature, InputStream message);

    default boolean verify(JohnHancock signature, List<ByteBuffer> forSigning) {
        return verify(signature, BbBackedInputStream.aggregate(forSigning));
    }

    default boolean verify(JohnHancock signature, String message) {
        return verify(signature, BbBackedInputStream.aggregate(message.getBytes()));
    }

    class DefaultVerifier implements Verifier {
        private final PublicKey key;

        public DefaultVerifier(PublicKey key) {
            this.key = key;
        }

        @Override
        public String toString() {
            return "V[" + key.getEncoded() + "]";
        }

        @Override
        public boolean verify(JohnHancock signature, InputStream message) {
            return signature.verify(key, message);
        }
    }

    class MockVerifier implements Verifier {

        @Override
        public boolean verify(JohnHancock signature, InputStream message) {
            return true;
        }

    }
}
