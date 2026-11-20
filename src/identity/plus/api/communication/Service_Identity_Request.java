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
 * The Service Identity request issues or renews the identity of a service.
 *
 * @param service_domain  domain name of the service the identity should be issued for. If null, the identity
 *                        is created or renewed for the service the calling agent belongs to. If given, the
 *                        calling service must have administrative rights in the target service, otherwise
 *                        the operation fails.
 * @param force_renewal   request renewal even if it is not necessary
 * @param custom          additional fields, sent as-is
 *
 * @author Stefan Harsan Farr
 */
public record Service_Identity_Request(
        String service_domain,
        Boolean force_renewal,
        Map<String, String> custom
) implements API_Request {

    /**
     * The JSON Name of this request object as sent to the ReST API
     */
    public static final String JSON_NAME = Identity_Plus_Utils.json_name(Service_Identity_Request.class);

    public Service_Identity_Request {
        custom = API_Object.custom_of(custom);
    }

    public Service_Identity_Request(String service_domain, Boolean force_renewal) {
        this(service_domain, force_renewal, null);
    }

    public static Service_Identity_Request from_json(JsonObject object) {
        return Json_Codec.decode(Service_Identity_Request.class, object);
    }
}