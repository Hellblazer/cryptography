/*
 * Copyright (c) 2021, salesforce.com, inc.
 * All rights reserved.
 * SPDX-License-Identifier: BSD-3-Clause
 * For full license text, see the LICENSE file in the repo root or https://opensource.org/licenses/BSD-3-Clause
 */
package com.hellblazer.cryptography;

import org.apache.commons.math3.fraction.Fraction;

import java.util.Arrays;
import java.util.Objects;
import java.util.Optional;
import java.util.stream.IntStream;
import java.util.stream.Stream;

import static java.util.Objects.requireNonNull;

/**
 * @author hal.hildebrand
 */
public interface SigningThreshold {

    static int countWeights(Weighted.Weight[][] weights) {
        return Arrays.stream(weights).mapToInt(w -> w.length).sum();
    }

    static Weighted.Weight[] group(String... weights) {
        return Stream.of(weights).map(SigningThreshold::weight).toArray(Weighted.Weight[]::new);
    }

    static Weighted.Weight[] group(Weighted.Weight... weights) {
        return weights;
    }

    static boolean thresholdMet(SigningThreshold threshold, int[] indexes) {
        if (threshold instanceof Unweighted) {
            return thresholdMet((Unweighted) threshold, indexes);
        } else if (threshold instanceof Weighted) {
            return thresholdMet((Weighted) threshold, indexes);
        } else {
            throw new IllegalArgumentException("Unknown threshold type: " + threshold.getClass().getCanonicalName());
        }
    }

    static boolean thresholdMet(Unweighted threshold, int[] indexes) {
        requireNonNull(indexes, "indexes");
        return indexes.length >= threshold.getThreshold();
    }

    static boolean thresholdMet(Weighted threshold, int[] indexes) {
        requireNonNull(indexes);

        if (indexes.length == 0) {
            return false;
        }

        var maxIndex = IntStream.of(indexes).max().getAsInt();
        var countWeights = countWeights(threshold.getWeights());

        var sats = prefillSats(Integer.max(maxIndex + 1, countWeights));
        for (var i : indexes) {
            sats[i] = true;
        }

        var index = 0;
        for (var clause : threshold.getWeights()) {
            var accumulator = Fraction.ZERO;
            for (var weight : clause) {
                if (sats[index]) {
                    accumulator = accumulator.add(fraction(weight));
                }
                index++;
            }

            if (accumulator.compareTo(Fraction.ONE) < 0) {
                return false;
            }
        }

        return true;
    }

    static Unweighted unweighted(int threshold) {
        if (threshold < 0) {
            throw new IllegalArgumentException("threshold must be >= 0");
        }

        return new Unweighted() {
            @Override
            public int getThreshold() {
                return threshold;
            }
        };
    }

    static Weighted.Weight weight(int value) {
        return weight(value, null);
    }

    static Weighted.Weight weight(int numerator, Integer denominator) {
        if (denominator != null && denominator <= 0) {
            throw new IllegalArgumentException("denominator must be > 0");
        }

        if (numerator <= 0) {
            throw new IllegalArgumentException("numerator must be > 0");
        }

        return new Weighted.Weight.WeightImpl(numerator, denominator);
    }

    static Weighted.Weight weight(String value) {
        var parts = value.split("/");
        if (parts.length == 1) {
            return weight(Integer.parseInt(parts[0]));
        } else if (parts.length == 2) {
            return weight(Integer.parseInt(parts[0]), Integer.parseInt(parts[1]));
        } else {
            throw new IllegalArgumentException("invalid weight: " + value);
        }
    }

    static Weighted weighted(String... weightsAsStrings) {
        var weights = Stream.of(weightsAsStrings).map(SigningThreshold::weight).toArray(Weighted.Weight[]::new);

        return weighted(weights);
    }

    static Weighted weighted(Weighted.Weight... weights) {
        return weighted(new Weighted.Weight[][] { weights });
    }

    static Weighted weighted(Weighted.Weight[]... weightGroups) {
        for (var group : weightGroups) {
            if (!sumGreaterThanOrEqualToOne(group)) {
                throw new IllegalArgumentException("group sum is less than 1: " + Arrays.deepToString(group));
            }
        }
        return new Weighted.WeightedImpl(weightGroups);
    }

    private static Fraction fraction(Weighted.Weight weight) {
        if (weight.denominator().isEmpty()) {
            return new Fraction(weight.numerator());
        }

        return new Fraction(weight.numerator(), weight.denominator().get());
    }

    private static boolean[] prefillSats(int count) {
        var sats = new boolean[count];
        Arrays.fill(sats, false);
        return sats;
    }

    private static boolean sumGreaterThanOrEqualToOne(Weighted.Weight[] weights) {
        var sum = Fraction.ZERO;
        for (var w : weights) {
            // noinspection ObjectAllocationInLoop
            sum = sum.add(fraction(w));
        }

        return sum.compareTo(Fraction.ONE) >= 0;
    }

    interface Unweighted extends SigningThreshold {

        int getThreshold();

    }

    interface Weighted extends SigningThreshold {

        Weight[][] getWeights();

        interface Weight {
            Optional<Integer> denominator();

            int numerator();

            class WeightImpl implements Weight {
                private final Integer denominator;
                private final Integer numerator;

                public WeightImpl(Integer numerator, Integer denominator) {
                    this.numerator = numerator;
                    this.denominator = denominator;
                }

                @Override
                public Optional<Integer> denominator() {
                    return Optional.ofNullable(denominator);
                }

                @Override
                public int numerator() {
                    return numerator;
                }

                @Override
                public int hashCode() {
                    return Objects.hash(denominator, numerator);
                }

                @Override
                public boolean equals(Object obj) {
                    if (this == obj) {
                        return true;
                    }
                    if (!(obj instanceof WeightImpl other)) {
                        return false;
                    }
                    return Objects.equals(denominator, other.denominator) && Objects.equals(numerator, other.numerator);
                }

            }
        }

        class WeightedImpl implements Weighted {
            private final Weight[][] weights;

            public WeightedImpl(Weight[][] weightGroups) {
                this.weights = weightGroups;
            }

            @Override
            public boolean equals(Object obj) {
                if (this == obj) {
                    return true;
                }
                if (!(obj instanceof WeightedImpl other)) {
                    return false;
                }
                return Arrays.deepEquals(weights, other.weights);
            }

            @Override
            public int hashCode() {
                final int prime = 31;
                int result = 1;
                result = prime * result + Arrays.deepHashCode(weights);
                return result;
            }

            @Override
            public Weight[][] getWeights() {
                return weights;
            }
        }
    }
}
