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
 * The Service Agent Identity request is used to issue certificates for Service Agents (Clients).
 * This can happen in two ways: either the request is made with a valid previous certificate,
 * in which case a renewal procedure is executed, or it is made with an authorization token,
 * in which case a new certificate is issued.
 *
 * A service agent can renew its own certificate this way, but care must be taken: the previous
 * certificate is revoked when the new one is issued.
 *
 * The authorization token is a credential. {@link #toString()} redacts it.
 *
 * @param service_domain  domain name of the service where the agent should be issued. If null, the agent is
 *                        created or renewed within the service the calling agent belongs to. If given, the
 *                        calling service must have administrative rights in the target service, otherwise
 *                        the operation fails.
 * @param agent_name      name of the agent to issue the certificate for. If the agent exists it is renewed,
 *                        otherwise a new agent is created.
 * @param authorization   authorization token; only needed if the agent is not authenticating with a
 *                        previously issued certificate
 * @param custom          additional fields, sent as-is
 *
 * @author Stefan Harsan Farr
 */
public record Service_Agent_Identity_Request(
        String service_domain,
        String agent_name,
        String authorization,
        Map<String, String> custom
) implements API_Request {

    /**
     * The JSON Name of this request object as sent to the ReST API
     */
    public static final String JSON_NAME = Identity_Plus_Utils.json_name(Service_Agent_Identity_Request.class);

    public Service_Agent_Identity_Request {
        custom = API_Object.custom_of(custom);
    }

    public Service_Agent_Identity_Request(String service_domain, String agent_name, String authorization) {
        this(service_domain, agent_name, authorization, null);
    }

    public Service_Agent_Identity_Request(String service_domain, String agent_name) {
        this(service_domain, agent_name, null, null);
    }

    public static Service_Agent_Identity_Request from_json(JsonObject object) {
        return Json_Codec.decode(Service_Agent_Identity_Request.class, object);
    }

    @Override
    public String toString() {
        return "Service_Agent_Identity_Request[service_domain=" + service_domain
             + ", agent_name=" + agent_name
             + ", authorization=" + Secrets.redacted(authorization) + "]";
    }
}