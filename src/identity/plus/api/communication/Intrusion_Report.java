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

import javax.json.JsonObject;

import identity.plus.api.Identity_Plus_Utils;
import identity.plus.api.Object_Of_Intrusion;

/**
 * The Trust Intrusion_Report deposits a certain intrusion event with an identity + certificate
 * The local user name is not necessary for this operation, an intrusion can be reported on any
 * incoming offending certificate. 
 * 
 * @author Stefan Harsan Farr
 */
public class Intrusion_Report extends API_Request{
    private static final long serialVersionUID = 1L;
    
    /**
     * The JSON Name of this request object as returned by the ReST API
     */
    public static final String JSON_NAME = Identity_Plus_Utils.json_name(Intrusion_Report.class);

    /**
     * The anonymous id extracted from the identity + certificate of the visitor.
     */
    public final String intruding_certificate_uid;

    /**
     * The severity of the intrusion, see severity for details
     */
    public final Object_Of_Intrusion severity;

    /**
     * A message which will be delivered to the person who owns the identity associated with the
     * offending certificate
     */
    public final String message;
    
    /**
     * IP address where the request was made from
     */
    public final String intruder_ip_address;
    
    /**
     * The url that was accessed during the intrusion
     */
    public final String intruded_url;
    
    /**
     * HTTP headers from the intrusion requests
     */
    public final List<String> intruding_request_headers;
    
    /**
     * Additional information.
     */
    public final String additional_information;
    
    public Intrusion_Report(String offending_certificate_uid, Object_Of_Intrusion severity, String message, String request_ip_address, String visited_uri, List<String> request_headers, String additional_information) {
        if(offending_certificate_uid == null || request_ip_address == null) throw new NullPointerException("Offending certificate and the IP address must be included in the report");

        this.intruding_certificate_uid = offending_certificate_uid;
        this.severity = severity;
        this.message = message;
        this.intruder_ip_address = request_ip_address;
        this.intruded_url = visited_uri;
        this.intruding_request_headers = request_headers;
        this.additional_information = additional_information;
    }

    /**
     * Empty initializer, it is necessary to initialize to null the public final fields.
     * The deserializer will override the final modifier and re-initialize the fields
     * with the proper values  
     */
    public Intrusion_Report(JsonObject object){
        this.intruding_certificate_uid = null;
        this.severity = null;
        this.message = null;
        this.intruder_ip_address = null;
        this.intruded_url = null;
        this.intruding_request_headers = null;
        this.additional_information = null;
        
        restore_object(object);
    }
}
