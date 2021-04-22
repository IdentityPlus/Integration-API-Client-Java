package identity.plus.api.util;

import java.io.InputStream;

public interface HTTP_Response_Handler {
        public void handle(int code, InputStream body);
}
