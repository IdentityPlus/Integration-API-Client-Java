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

/**
 * The Identity_Inquiry wraps the request for the identity profile of a visitor whose
 * identity + certificate has been read.
 *
 * If the certificate cannot be read the SSL way, the legacy redirect must be used.
 *
 * At least one of {@code serial_number} or {@code anonymous_id} must be given.
 *
 * @param service        explicitly inquire for a specific service; the role-based relationship
 *                       between this service and the inquiring service applies. May be null.
 * @param serial_number  the certificate serial number, a string-encoded positive integer.
 *                       As of version 2, this is the primary way clients are identified.
 * @param anonymous_id   the anonymous id extracted from the visitor's identity + certificate.
 *                       As of version 1.1, not required if the serial number is given.
 * @param ip_address     the IP address of the visitor
 * @param custom         additional fields, sent as-is
 *
 * @author Stefan Harsan Farr
 */
public record Identity_Inquiry(
        String service,
        String serial_number,
        String anonymous_id,
        String ip_address,
        Map<String, String> custom
) implements API_Request {

    /**
     * The JSON Name of this request object as sent to the ReST API
     */
    public static final String JSON_NAME = Identity_Plus_Utils.json_name(Identity_Inquiry.class);

    public Identity_Inquiry {
        custom = API_Object.custom_of(custom);
    }

    public Identity_Inquiry(String serial_number, String anonymous_id, String ip_address) {
        this(null, serial_number, anonymous_id, ip_address);
    }

    public Identity_Inquiry(String service, String serial_number, String anonymous_id, String ip_address) {
        this(require(service, serial_number, anonymous_id), serial_number, anonymous_id, ip_address, null);
    }

    public static Identity_Inquiry from_json(JsonObject object) {
        return Json_Codec.decode(Identity_Inquiry.class, object);
    }

    private static String require(String service, String serial_number, String anonymous_id) {
        if (serial_number == null && anonymous_id == null)
            throw new NullPointerException("Either serial_number or anonymous_id must be specified");
        return service;
    }
}