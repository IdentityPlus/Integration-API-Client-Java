package plus.identity.service.agent.responses;

public class IDP_Response {
    public final int code;
    
    public IDP_Response(int code){
            this.code = code;
    }
    
    public static boolean is_ok(int code){
            return code/100 == 2;
    }

    public static boolean is_error(int code){
            return code/100 == 5;
    }

    public static boolean is_block(int code){
            return code == 423;
    }

    public static boolean is_impossible(int code){
            return code/100 == 4;
    }

    public static boolean is_redirect(int code){
            return code/100 == 3;
    }
}
