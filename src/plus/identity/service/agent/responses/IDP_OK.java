package plus.identity.service.agent.responses;

import javax.json.JsonObject;

public class IDP_OK extends IDP_Response{
    public final JsonObject body;
    
    public IDP_OK(int code, JsonObject body){
            super(code);
            this.body = body;
    }
}
