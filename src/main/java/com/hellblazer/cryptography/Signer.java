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
import java.security.PrivateKey;
import java.util.List;

import static java.util.Objects.requireNonNull;

/**
 * Produces signatures using a given key
 *
 * @author hal.hildebrand
 */
public interface Signer {

    SignatureAlgorithm algorithm();

    default JohnHancock sign(byte[]... bytes) {
        return sign(BbBackedInputStream.aggregate(bytes));
    }

    default JohnHancock sign(ByteBuffer... buffs) {
        return sign(BbBackedInputStream.aggregate(buffs));
    }

    default JohnHancock sign(ByteString... message) {
        return sign(BbBackedInputStream.aggregate(message));
    }

    JohnHancock sign(InputStream message);

    default JohnHancock sign(List<ByteBuffer> buffers) {
        return sign(BbBackedInputStream.aggregate(buffers));
    }

    default JohnHancock sign(String msg) {
        return sign(BbBackedInputStream.aggregate(msg.getBytes()));
    }

    class MockSigner implements Signer {
        private final SignatureAlgorithm algorithm;

        public MockSigner(SignatureAlgorithm algorithm) {
            this.algorithm = algorithm;
        }

        @Override
        public SignatureAlgorithm algorithm() {
            return algorithm;
        }

        @Override
        public JohnHancock sign(byte[]... bytes) {
            return new JohnHancock(algorithm(), new byte[algorithm().signatureLength()]);
        }

        @Override
        public JohnHancock sign(ByteBuffer... buffs) {
            return new JohnHancock(algorithm(), new byte[algorithm().signatureLength()]);
        }

        @Override
        public JohnHancock sign(ByteString... message) {
            return new JohnHancock(algorithm(), new byte[algorithm().signatureLength()]);
        }

        @Override
        public JohnHancock sign(InputStream message) {
            return new JohnHancock(algorithm(), new byte[algorithm().signatureLength()]);
        }

        @Override
        public JohnHancock sign(List<ByteBuffer> buffers) {
            return new JohnHancock(algorithm(), new byte[algorithm().signatureLength()]);
        }
    }

    class SignerImpl implements Signer {
        private final SignatureAlgorithm algorithm;
        private final PrivateKey         privateKey;

        public SignerImpl(PrivateKey privateKey) {
            assert privateKey != null;
            this.privateKey = requireNonNull(privateKey);
            algorithm = SignatureAlgorithm.lookup(privateKey);
        }

        @Override
        public SignatureAlgorithm algorithm() {
            return algorithm;
        }

        @Override
        public JohnHancock sign(InputStream message) {
            return algorithm.sign(privateKey, message);
        }
    }

}
