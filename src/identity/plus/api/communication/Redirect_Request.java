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
import java.util.Objects;

import javax.json.JsonObject;

import identity.plus.api.Identity_Plus_Utils;
import identity.plus.api.json.API_Object;
import identity.plus.api.json.API_Request;
import identity.plus.api.json.Json_Codec;

/**
 * The Redirect_Request is part of the Legacy HTTP call assembly.
 * This request is sent URL encoded as part of the redirect when the identity + service
 * is used to read the client certificate from the user's browser.
 *
 * This object is only needed by implementations that use the identity + service over
 * http, or that cannot read the SSL client certificate for other reasons.
 *
 * This request object must always be encrypted with the API Client's private key.
 *
 * @param return_url  the URL to return to after the certificate has been extracted (or not);
 *                    the response comes encrypted in the URL query
 * @param salt        random text with no meaning in the identity + process; it only exists so
 *                    that requests with the same values encrypt to different outputs
 * @param custom      additional fields, sent as-is
 *
 * @author Stefan Harsan Farr
 */
public record Redirect_Request(
        String return_url,
        String salt,
        Map<String, String> custom
) implements API_Request {

    /**
     * The JSON Name of this request object as sent to the ReST API
     */
    public static final String JSON_NAME = Identity_Plus_Utils.json_name(Redirect_Request.class);

    public Redirect_Request {
        custom = API_Object.custom_of(custom);
    }

    /**
     * Creates a new Redirect_Request with a freshly generated 16 character salt.
     */
    public Redirect_Request(String return_url) {
        this(Objects.requireNonNull(return_url, "return_url cannot be null"),
             Identity_Plus_Utils.random_text(16),
             null);
    }

    public static Redirect_Request from_json(JsonObject object) {
        return Json_Codec.decode(Redirect_Request.class, object);
    }
}