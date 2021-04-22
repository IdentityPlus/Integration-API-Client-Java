package plus.identity.service.agent.responses;

public class IDP_Impossible extends IDP_Response{
    public final String message;
    
    public IDP_Impossible(int code, String message){
            super(code);
            this.message = message;
    }
}
