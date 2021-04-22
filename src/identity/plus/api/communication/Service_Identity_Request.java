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

import javax.json.JsonObject;

import identity.plus.api.Identity_Plus_Utils;

/**
 * The Certificate Renewal request is used to issue certificates for API Clients. This can happen in two ways, 
 * either the request is made with a valid previous certificate, in which a renewal procedure is executed,
 * or it needs to be performed with an initial secret and then an issuing is performed
 * 
 * @author Stefan Harsan Farr
 */
public class Service_Identity_Request extends API_Request{
    private static final long serialVersionUID = 1L;
    
    /**
     * The JSON Name of this request object as returned by the ReST API
     */
    public static final String JSON_NAME = Identity_Plus_Utils.json_name(Service_Identity_Request.class);

    /**
     * Request renewal even if it is not necessary
     */
    public final Boolean force_renewal;
    
    /**
     * Domain Name of the service for which identity should be issued.
     * 
     * By default (if the domain is not specified), the identity will be created/renewed for the service
     * to which the calling agent (the one whose certificate is used to make this call) belongs to.
     * 
     * If the target service is specified, then the calling service (the service to which the calling agent belongs to)
     * must have administrative rights in target service. Otherwise this operation will fail 
     */
    public final String service_domain;
    
    public Service_Identity_Request(String service_domain, Boolean force_renewal){
            this.force_renewal = force_renewal;
            this.service_domain = service_domain;
    }

    /**
     * Empty initializer, it is necessary to initialize to null the public final fields.
     * The deserializer will override the final modifier and re-initialize the fields
     * with the proper values  
     */
    public Service_Identity_Request(JsonObject object){
            this.force_renewal = null;
            this.service_domain = null;
            restore_object(object);
    }
}
