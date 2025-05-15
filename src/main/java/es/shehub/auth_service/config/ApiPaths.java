package es.shehub.auth_service.config;

/**
 * Holds constants for API endpoint paths and frontend URLs.
 */

public class ApiPaths {
    public static final String FRONTEND_URL = "http://localhost:5173";

    public static final String API_VERSION = "v1";
    public static final String BASE_API = "/api/" + API_VERSION;

    public static final String REGISTER_PATH = BASE_API + "/auth/register";
    public static final String LOGIN_PATH = BASE_API + "/auth/login";
    public static final String LOGOUT_PATH = BASE_API + "/auth/logout";
    public static final String ACCESS_TOKEN_COOKIE_PATH = "/";
    public static final String REFRESH_TOKEN_COOKIE_PATH = "/api/auth/refresh-token";
}
