/*
 * Copyright (c) 2021, salesforce.com, inc.
 * All rights reserved.
 * SPDX-License-Identifier: BSD-3-Clause
 * For full license text, see the LICENSE file in the repo root or https://opensource.org/licenses/BSD-3-Clause
 */
package com.hellblazer.cryptography.ssl;

import javax.net.ssl.TrustManagerFactory;
import java.security.Provider;

public class NodeTrustManagerFactory extends TrustManagerFactory {

    public NodeTrustManagerFactory(CertificateValidator validator, Provider provider) {
        super(new NodeTrustManagerFactorySpi(validator), provider, "Trust");
    }

}
