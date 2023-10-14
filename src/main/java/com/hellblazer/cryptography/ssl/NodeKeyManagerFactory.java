/*
 * Copyright (c) 2021, salesforce.com, inc.
 * All rights reserved.
 * SPDX-License-Identifier: BSD-3-Clause
 * For full license text, see the LICENSE file in the repo root or https://opensource.org/licenses/BSD-3-Clause
 */
package com.hellblazer.cryptography.ssl;

import javax.net.ssl.KeyManagerFactory;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.cert.X509Certificate;

public class NodeKeyManagerFactory extends KeyManagerFactory {

    public NodeKeyManagerFactory(String alias, X509Certificate certificate, PrivateKey privateKey, Provider provider) {
        super(new NodeKeyManagerFactorySpi(alias, certificate, privateKey), provider, "Keys");
    }

}