package es.shehub.auth_service.config;

public class ApiPaths {
    public static final String FRONTEND_URL = "http://localhost:5173";

    public static final String API_VERSION = "v1";
    public static final String BASE_API = "/api/" + API_VERSION;

    public static final String REGISTER_URL = BASE_API + "/auth/register";
    public static final String LOGIN_URL = BASE_API + "/auth/login";
    public static final String LOGOUT_URL = BASE_API + "/auth/logout";
}
