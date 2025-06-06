package es.shehub.auth_service.config;

/**
 * Holds constants for API endpoint paths and frontend URLs.
 */

public class ApiPaths {
    public static final String FRONTEND_URL = "http://localhost:5173";

    public static final String API_VERSION = "v1";
    public static final String BASE_API = "/api/" + API_VERSION;

    public static final String REGISTER_PATH = BASE_API + "/auth/register";
    public static final String GOOGLE_REGISTER_PATH = BASE_API + "/auth/google/register";
    public static final String CREATE_ADMIN_PATH = BASE_API + "/admin/create";

    public static final String LOGIN_PATH = BASE_API + "/auth/login";
    public static final String LOGOUT_PATH = BASE_API + "/auth/logout";

    public static final String ACCESS_TOKEN_COOKIE_PATH = "/";
    public static final String REFRESH_TOKEN_COOKIE_PATH = BASE_API + "/auth/refresh-token";

    public static final String REQUEST_PASSWORD_RESET_PATH = BASE_API + "/auth/request-password-reset";
    public static final String RESET_PASSWORD_PATH = BASE_API + "/auth/reset-password";

    public static final String UPDATE_USER_STATUS_PATH = BASE_API + "/admin/users/{userId}/status";
    public static final String UPDATE_USER_ROLE_PATH = BASE_API + "/admin/users/{userId}/role";

    public static final String DELETE_USER_PATH = BASE_API + "/users/{userId}/delete";
}
