/*
 * Copyright (c) 2021, salesforce.com, inc.
 * All rights reserved.
 * SPDX-License-Identifier: BSD-3-Clause
 * For full license text, see the LICENSE file in the repo root or https://opensource.org/licenses/BSD-3-Clause
 *
 * Copyright (C) 2023 Hal Hildebrand. All rights reserved.
 */
package com.hellblazer.cryptography;

import com.google.protobuf.ByteString;
import com.hellblazer.cryptography.hash.Digest;
import com.hellblazer.cryptography.hash.DigestAlgorithm;
import com.hellblazer.cryptography.proto.Signature_;
import org.slf4j.LoggerFactory;

import java.io.BufferedInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.PublicKey;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.Objects;

/**
 * A signature
 *
 * @author hal.hildebrand
 */
public class JohnHancock {

    private final SignatureAlgorithm algorithm;
    private final byte[]             signature;

    public JohnHancock(Signature_ sig) {
        this(SignatureAlgorithm.fromSignatureCode(sig.getType()), sig.toByteArray());
    }

    public JohnHancock(SignatureAlgorithm algorithm, byte[] signature) {
        this.algorithm = algorithm;
        this.signature = signature;
    }

    public static JohnHancock from(Signature_ signature) {
        return new JohnHancock(signature);
    }

    public static JohnHancock of(Signature_ signature) {
        return new JohnHancock(signature);
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof JohnHancock)) {
            return false;
        }
        JohnHancock other = (JohnHancock) obj;
        return algorithm == other.algorithm && Arrays.equals(signature, other.signature);
    }

    public SignatureAlgorithm getAlgorithm() {
        return algorithm;
    }

    public byte[] getSignature() {
        return signature;
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;
        result = prime * result + Arrays.hashCode(signature);
        result = prime * result + Objects.hash(algorithm);
        return result;
    }

    public int signatureCount() {
        return signature.length;
    }

    public Digest toDigest(DigestAlgorithm digestAlgorithm) {
        if (digestAlgorithm.digestLength() * 2 != algorithm.signatureLength()) {
            throw new IllegalArgumentException(
            "Cannot convert to a hash, as digest and signature length are not compatible");
        }
        Digest combined = digestAlgorithm.getOrigin();
        combined = combined.xor(new Digest(digestAlgorithm, Arrays.copyOf(signature, digestAlgorithm.digestLength())));
        combined = combined.xor(
        new Digest(digestAlgorithm, Arrays.copyOfRange(signature, digestAlgorithm.digestLength(), signature.length)));
        return combined;
    }

    public Signature_ toSig() {
        return Signature_.newBuilder()
                         .setType(algorithm.signatureCode())
                         .setSignature(ByteString.copyFrom(signature))
                         .build();
    }

    @Override
    public String toString() {
        String hexString = HexFormat.of().formatHex(getSignature());
        return "Sig[" + hexString.substring(0, Math.min(hexString.length(), 12)) + ":" + algorithm.signatureCode()
        + "]";
    }

    public boolean verify(PublicKey publicKey, InputStream input) {
        assert publicKey != null;
        assert input != null;
        var message = new BufferedInputStream(input);
        message.mark(Integer.MAX_VALUE);
        var verifiedSignatures = new ArrayList<Integer>();
        try {
            message.reset();
        } catch (IOException e) {
            LoggerFactory.getLogger(JohnHancock.class).error("Cannot reset message input", e);
            return false;
        }
        return algorithm.verify(publicKey, signature, message);
    }
}
