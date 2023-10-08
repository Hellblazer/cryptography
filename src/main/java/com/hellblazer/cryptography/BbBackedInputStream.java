/*
 * Copyright (c) 2020, salesforce.com, inc.
 * All rights reserved.
 * SPDX-License-Identifier: BSD-3-Clause
 * For full license text, see the LICENSE file in the repo root or https://opensource.org/licenses/BSD-3-Clause
 */
package com.hellblazer.cryptography;

import com.google.protobuf.ByteString;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.SequenceInputStream;
import java.nio.ByteBuffer;
import java.util.*;
import java.util.stream.Collectors;

/**
 * @author hal.hildebrand
 */
public class BbBackedInputStream extends InputStream {

    private final ByteBuffer buf;

    public BbBackedInputStream(ByteBuffer buf) {
        this.buf = buf;
    }

    public static InputStream aggregate(byte[]... buffers) {
        return aggregateStreams(
        Arrays.asList(buffers).stream().map(e -> new ByteArrayInputStream(e)).collect(Collectors.toList()));
    }

    public static InputStream aggregate(ByteBuffer... buffers) {
        return aggregate(Arrays.asList(buffers));
    }

    public static InputStream aggregate(ByteString... byteStrings) {
        return aggregate(
        Arrays.asList(byteStrings).stream().map(e -> e.asReadOnlyByteBuffer()).collect(Collectors.toList()));

    }

    public static InputStream aggregate(ByteString byteString) {
        return aggregate(new ByteString[] { byteString });
    }

    @SafeVarargs
    public static InputStream aggregate(List<ByteBuffer>... buffers) {
        return new SequenceInputStream(new Enumeration<InputStream>() {
            private volatile List<ByteBuffer> aggregate = Arrays.asList(buffers)
                                                                .stream()
                                                                .flatMap(bl -> bl.stream())
                                                                .collect(Collectors.toList());

            @Override
            public boolean hasMoreElements() {
                List<ByteBuffer> current = aggregate;
                return !current.isEmpty();
            }

            @Override
            public InputStream nextElement() {
                List<ByteBuffer> current = aggregate;
                if (current.isEmpty()) {
                    throw new NoSuchElementException();
                }
                BbBackedInputStream is = new BbBackedInputStream(current.get(0));
                if (current.size() == 1) {
                    aggregate = Collections.emptyList();
                } else {
                    aggregate = current.subList(1, current.size());
                }
                return is;
            }
        });
    }

    public static InputStream aggregate(List<ByteString> buffers) {
        return aggregate(buffers.stream().map(e -> e.asReadOnlyByteBuffer()).collect(Collectors.toList()));

    }

    public static InputStream aggregateStreams(final List<InputStream> a) {
        return new SequenceInputStream(new Enumeration<InputStream>() {
            List<InputStream> current = a;

            @Override
            public boolean hasMoreElements() {
                return !current.isEmpty();
            }

            @Override
            public InputStream nextElement() {
                if (current.isEmpty()) {
                    throw new NoSuchElementException();
                }
                InputStream is = current.get(0);
                if (current.size() == 1) {
                    current = Collections.emptyList();
                } else {
                    current = current.subList(1, current.size());
                }
                return is;
            }
        });
    }

    @Override
    public int available() throws IOException {
        return buf.remaining();
    }

    @Override
    public int read() throws IOException {
        if (!buf.hasRemaining()) {
            return -1;
        }
        return buf.get() & 0xFF;
    }

    @Override
    public int read(byte[] bytes, int off, int len) throws IOException {
        if (!buf.hasRemaining()) {
            return -1;
        }

        len = Math.min(len, buf.remaining());
        buf.get(bytes, off, len);
        return len;
    }
}
