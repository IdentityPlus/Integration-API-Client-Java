/*
 * (C) Copyright 2016 Identity+ (https://identity.plus) and others.
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
 *
 * This code is part of the identity+ API Wrapper suite and it is meant to facilitate
 * access to the identity + ReST Service. While the ReST service is not dependent 
 * upon this code, this code shortens implementation time because it wraps regular
 * ReST calls into a more developer friendly package.
 * 
 * You are free to make changes to this code to better suite your particular
 * implementation and keep it closed source, however, if you consider the changes are relevant to the
 * the identity + community, please consider donating your changes back to the community.
 * 
 * You are permitted to use the identity.plus package names in your fork as long as the 
 * code can be used exclusively to connect to the Identity + ReST API services.
 * 
 * Please submit bugs or improvement requests at https://identity.plus/
 *
 * Contributors:
 *     Stefan Harsan Farr
 */
package identity.plus.api.communication;

import java.util.Map;

import javax.json.JsonObject;

import identity.plus.api.Identity_Plus_Utils;
import identity.plus.api.json.API_Object;
import identity.plus.api.json.API_Request;
import identity.plus.api.json.Json_Codec;
import identity.plus.api.json.Secrets;

/**
 * The Certificate Renewal request is used to issue certificates for API Clients. This can happen
 * in two ways: either the request is made with a valid previous certificate, in which case a
 * renewal procedure is executed, or it is made with an initial secret, in which case a new
 * certificate is issued.
 *
 * The secret is a credential. {@link #toString()} redacts it.
 *
 * @param secret  the initial secret used to authorize issuing
 * @param custom  additional fields, sent as-is
 *
 * @author Stefan Harsan Farr
 */
public record Certificate_Renewal(
        String secret,
        Map<String, String> custom
) implements API_Request {

    /**
     * The JSON Name of this request object as sent to the ReST API
     */
    public static final String JSON_NAME = Identity_Plus_Utils.json_name(Certificate_Renewal.class);

    public Certificate_Renewal {
        custom = API_Object.custom_of(custom);
    }

    public Certificate_Renewal(String secret) {
        this(require(secret), null);
    }

    public static Certificate_Renewal from_json(JsonObject object) {
        return Json_Codec.decode(Certificate_Renewal.class, object);
    }

    @Override
    public String toString() {
        return "Certificate_Renewal[secret=" + Secrets.redacted(secret) + "]";
    }

    private static String require(String secret) {
        if (secret == null) throw new NullPointerException("The secret must be specified");
        return secret;
    }
}