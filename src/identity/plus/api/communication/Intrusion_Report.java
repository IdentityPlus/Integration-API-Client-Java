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

import java.util.List;
import java.util.Map;

import javax.json.JsonObject;

import identity.plus.api.Identity_Plus_Utils;
import identity.plus.api.Object_Of_Intrusion;
import identity.plus.api.json.API_Object;
import identity.plus.api.json.API_Request;
import identity.plus.api.json.Json_Codec;

/**
 * The Intrusion_Report deposits an intrusion event against an identity + certificate.
 * The local user name is not needed for this operation: an intrusion can be reported on any
 * incoming offending certificate.
 *
 * @param intruding_certificate_uid  the identifier of the offending identity + certificate
 * @param severity                   the severity of the intrusion; see {@link Object_Of_Intrusion}
 * @param message                    a message delivered to the owner of the identity associated
 *                                   with the offending certificate
 * @param intruder_ip_address        the IP address the request was made from
 * @param intruded_url               the URL accessed during the intrusion
 * @param intruding_request_headers  HTTP headers of the intruding request; never null
 * @param additional_information     free-form additional information
 * @param custom                     additional fields, sent as-is
 *
 * @author Stefan Harsan Farr
 */
public record Intrusion_Report(
        String intruding_certificate_uid,
        Object_Of_Intrusion severity,
        String message,
        String intruder_ip_address,
        String intruded_url,
        List<String> intruding_request_headers,
        String additional_information,
        Map<String, String> custom
) implements API_Request {

    /**
     * The JSON Name of this request object as sent to the ReST API
     */
    public static final String JSON_NAME = Identity_Plus_Utils.json_name(Intrusion_Report.class);

    public Intrusion_Report {
        intruding_request_headers = intruding_request_headers == null ? List.of() : List.copyOf(intruding_request_headers);
        custom = API_Object.custom_of(custom);
    }

    public Intrusion_Report(String offending_certificate_uid, Object_Of_Intrusion severity, String message,
                            String request_ip_address, String visited_uri, List<String> request_headers,
                            String additional_information) {
        this(require(offending_certificate_uid, request_ip_address), severity, message, request_ip_address,
             visited_uri, request_headers, additional_information, null);
    }

    public static Intrusion_Report from_json(JsonObject object) {
        return Json_Codec.decode(Intrusion_Report.class, object);
    }

    @Override
    public String toString() {
        return "Intrusion_Report[certificate=" + intruding_certificate_uid
             + ", severity=" + severity
             + ", ip=" + intruder_ip_address
             + ", url=" + intruded_url
             + ", headers=" + intruding_request_headers.size() + "]";
    }

    private static String require(String certificate_uid, String ip_address) {
        if (certificate_uid == null || ip_address == null)
            throw new NullPointerException("Offending certificate and the IP address must be included in the report");
        return certificate_uid;
    }
}