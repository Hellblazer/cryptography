/*
 * Copyright (c) 2021, salesforce.com, inc.
 * All rights reserved.
 * SPDX-License-Identifier: BSD-3-Clause
 * For full license text, see the LICENSE file in the repo root or https://opensource.org/licenses/BSD-3-Clause
 */
package com.hellblazer.cryptography.bloomFilters;

import com.hellblazer.cryptography.Entropy;
import com.hellblazer.cryptography.hash.Digest;
import com.hellblazer.cryptography.hash.DigestAlgorithm;
import org.junit.jupiter.api.Test;

import java.text.DecimalFormat;
import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * @author hal.hildebrand
 */
public class BloomFilterTest {

    @Test
    public void smoke() throws Exception {
        int max = 1_000_000;
        double target = 0.000125;
        BloomFilter<Digest> biff = new BloomFilter.DigestBloomFilter(Entropy.nextBitsStreamLong(), max, target);

        List<Digest> added = new ArrayList<>();
        for (int i = 0; i < max; i++) {
            byte[] hash = new byte[DigestAlgorithm.DEFAULT.digestLength()];
            Entropy.nextSecureBytes(hash);
            Digest d = new Digest(DigestAlgorithm.DEFAULT, hash);
            added.add(d);
            biff.add(d);
        }

        for (Digest d : added) {
            assertTrue(biff.contains(d));
        }

        List<Digest> failed = new ArrayList<>();
        int unknownSample = max * 4;

        for (int i = 0; i < unknownSample; i++) {
            byte[] hash = new byte[DigestAlgorithm.DEFAULT.digestLength()];
            Entropy.nextSecureBytes(hash);
            //            if (i % 80_000 == 0) {
            //                System.out.println();
            //            }
            //            if (i % 1000 == 0) {
            //                System.out.print('.');
            //            }
            Digest d = new Digest(DigestAlgorithm.DEFAULT, hash);
            if (biff.contains(d)) {
                failed.add(d);
            }
        }
        System.out.println();
        double failureRate = (double) failed.size() / (double) unknownSample;
        DecimalFormat format = new DecimalFormat("#.#############");
        System.out.print(
        "Target failure rate: " + format.format(target) + " measured: " + format.format(failureRate) + "; failed: "
        + failed.size() + " out of " + unknownSample + " random probes");
    }
}
