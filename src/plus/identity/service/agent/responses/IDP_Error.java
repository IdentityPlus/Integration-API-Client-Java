package plus.identity.service.agent.responses;

public class IDP_Error extends IDP_Response{
    public final String message;
    
    public IDP_Error(int code, String message){
            super(code);
            this.message = message;
    }
}
