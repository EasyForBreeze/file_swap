using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Tokens;
using new_assistant.Configuration;
using new_assistant.Core.Constants;
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Text.Json;
using System.Threading.Tasks;

namespace new_assistant.Infrastructure.Extensions;

/// <summary>
/// Extension методы для настройки аутентификации (Cookie + OpenID Connect)
/// </summary>
public static class AuthenticationExtensions
{
    /// <summary>
    /// Добавление аутентификации с Cookie схемой и OpenID Connect
    /// </summary>
    public static IServiceCollection AddAuthenticationConfiguration(
        this IServiceCollection services,
        IConfiguration configuration,
        IWebHostEnvironment environment)
    {
        var keycloakAuthSettings = configuration
            .GetSection("Authentication:Keycloak")
            .Get<KeycloakAuthenticationSettings>()
            ?? throw new InvalidOperationException("Keycloak configuration is missing. Check the Authentication:Keycloak section in appsettings.json.");

        var tokenValidationSettings = configuration
            .GetSection("TokenValidation")
            .Get<EnhancedTokenValidationSettings>()
            ?? new EnhancedTokenValidationSettings();

        // Валидация обязательных полей конфигурации
        if (string.IsNullOrWhiteSpace(keycloakAuthSettings.Authority))
        {
            throw new InvalidOperationException(
                "Authentication:Keycloak:Authority is required but is missing or empty.");
        }

        // Проверка валидности Authority URL
        if (!Uri.TryCreate(keycloakAuthSettings.Authority, UriKind.Absolute, out var authorityUri))
        {
            throw new InvalidOperationException(
                $"Authentication:Keycloak:Authority must be a valid absolute URI. Current value: {keycloakAuthSettings.Authority}");
        }

        // HTTP разрешен везде - проверка на HTTPS удалена

        if (string.IsNullOrWhiteSpace(keycloakAuthSettings.ClientId))
        {
            throw new InvalidOperationException(
                "Authentication:Keycloak:ClientId is required but is missing or empty.");
        }

        if (string.IsNullOrWhiteSpace(keycloakAuthSettings.ClientSecret))
        {
            throw new InvalidOperationException(
                "Authentication:Keycloak:ClientSecret is required but is missing or empty.");
        }

        if (keycloakAuthSettings.Scopes == null || !keycloakAuthSettings.Scopes.Any())
        {
            throw new InvalidOperationException(
                "Authentication:Keycloak:Scopes is required and must contain at least one scope.");
        }

        // Валидация RoleClaim
        if (string.IsNullOrWhiteSpace(keycloakAuthSettings.RoleClaim))
        {
            throw new InvalidOperationException(
                "RoleClaim не может быть пустым. Проверьте конфигурацию Authentication:Keycloak:RoleClaim");
        }

        // Валидация путей
        if (string.IsNullOrWhiteSpace(keycloakAuthSettings.LoginPath) || !keycloakAuthSettings.LoginPath.StartsWith("/"))
        {
            throw new InvalidOperationException(
                $"Authentication:Keycloak:LoginPath must be a valid path starting with '/'. Current value: {keycloakAuthSettings.LoginPath}");
        }

        if (string.IsNullOrWhiteSpace(keycloakAuthSettings.AccessDeniedPath) || !keycloakAuthSettings.AccessDeniedPath.StartsWith("/"))
        {
            throw new InvalidOperationException(
                $"Authentication:Keycloak:AccessDeniedPath must be a valid path starting with '/'. Current value: {keycloakAuthSettings.AccessDeniedPath}");
        }

        if (string.IsNullOrWhiteSpace(keycloakAuthSettings.LogoutPath) || !keycloakAuthSettings.LogoutPath.StartsWith("/"))
        {
            throw new InvalidOperationException(
                $"Authentication:Keycloak:LogoutPath must be a valid path starting with '/'. Current value: {keycloakAuthSettings.LogoutPath}");
        }

        if (string.IsNullOrWhiteSpace(keycloakAuthSettings.ErrorPath) || !keycloakAuthSettings.ErrorPath.StartsWith("/"))
        {
            throw new InvalidOperationException(
                $"Authentication:Keycloak:ErrorPath must be a valid path starting with '/'. Current value: {keycloakAuthSettings.ErrorPath}");
        }

        if (string.IsNullOrWhiteSpace(keycloakAuthSettings.CallbackPath) || !keycloakAuthSettings.CallbackPath.StartsWith("/"))
        {
            throw new InvalidOperationException(
                $"Authentication:Keycloak:CallbackPath must be a valid path starting with '/'. Current value: {keycloakAuthSettings.CallbackPath}");
        }

        if (string.IsNullOrWhiteSpace(keycloakAuthSettings.SignedOutCallbackPath) || !keycloakAuthSettings.SignedOutCallbackPath.StartsWith("/"))
        {
            throw new InvalidOperationException(
                $"Authentication:Keycloak:SignedOutCallbackPath must be a valid path starting with '/'. Current value: {keycloakAuthSettings.SignedOutCallbackPath}");
        }

        // Сохраняем необходимые значения в локальные переменные для избежания замыкания
        var accessDeniedPath = keycloakAuthSettings.AccessDeniedPath;
        var errorPath = keycloakAuthSettings.ErrorPath;
        var roleClaim = keycloakAuthSettings.RoleClaim;

        // Добавляем куки-схему и OpenID Connect с PKCE: куки хранят локальную сессию, а OIDC отвечает за challenge/выход.
        services
            .AddAuthentication(options =>
            {
                options.DefaultScheme = CookieAuthenticationDefaults.AuthenticationScheme;
                options.DefaultChallengeScheme = OpenIdConnectDefaults.AuthenticationScheme;
                options.DefaultSignOutScheme = OpenIdConnectDefaults.AuthenticationScheme;
            })
            .AddCookie(CookieAuthenticationDefaults.AuthenticationScheme, options =>
            {
                // HttpOnly и Secure обеспечиваются через CookiePolicy, здесь дополнительно ограничиваем время жизни и включаем sliding expiration.
                options.Cookie.SameSite = Microsoft.AspNetCore.Http.SameSiteMode.Lax;
                options.ExpireTimeSpan = TimeSpan.FromMinutes(60);
                options.SlidingExpiration = true;
                options.LogoutPath = keycloakAuthSettings.LogoutPath;
                options.LoginPath = keycloakAuthSettings.LoginPath;
                options.AccessDeniedPath = keycloakAuthSettings.AccessDeniedPath;
                options.ReturnUrlParameter = "returnUrl";
                options.Cookie.Name = ".AspNetCore.Cookies";
                options.Cookie.HttpOnly = true;
                // Разрешаем HTTP для cookies везде
                options.Cookie.SecurePolicy = Microsoft.AspNetCore.Http.CookieSecurePolicy.None;
                options.Cookie.IsEssential = true;
                options.Cookie.Path = "/";
                options.Cookie.Domain = null;
            })
            .AddOpenIdConnect(OpenIdConnectDefaults.AuthenticationScheme, options =>
            {
                // Основные параметры OIDC берём из настроек, чтобы не хардкодить значения в коде.
                options.Authority = keycloakAuthSettings.Authority;
                options.ClientId = keycloakAuthSettings.ClientId;
                options.ClientSecret = keycloakAuthSettings.ClientSecret;
                // Используем настройку из конфигурации - HTTP разрешен везде
                options.RequireHttpsMetadata = keycloakAuthSettings.RequireHttpsMetadata;
                options.ResponseType = keycloakAuthSettings.ResponseType;
                options.UsePkce = keycloakAuthSettings.UsePkce;
                options.CallbackPath = keycloakAuthSettings.CallbackPath;
                options.SignedOutCallbackPath = keycloakAuthSettings.SignedOutCallbackPath;
                options.SignedOutRedirectUri = keycloakAuthSettings.PostLogoutRedirectUri;
                options.SaveTokens = true; // сохраняем токены в AuthenticationProperties, чтобы позже можно было обращаться к Keycloak.
                options.GetClaimsFromUserInfoEndpoint = true; // userinfo помогает получить расширенные claim'ы, если они настроены в Keycloak.

                // Настройка автоматического обновления токенов
                options.RefreshOnIssuerKeyNotFound = true; // Автоматически обновлять токены при 401/403
                options.UseTokenLifetime = keycloakAuthSettings.UseTokenLifetime; // Использовать lifetime токена или настройки cookie

                // Настройка перенаправлений после авторизации
                options.Events.OnTicketReceived = context =>
                {
                    // После успешной авторизации перенаправляем на главную страницу
                    context.ReturnUri = "/";
                    return Task.CompletedTask;
                };

                // Обработка ошибок при обновлении токена
                options.Events.OnRemoteFailure = context =>
                {
                    var loggerFactory = context.HttpContext.RequestServices.GetRequiredService<ILoggerFactory>();
                    var logger = loggerFactory.CreateLogger("AuthenticationExtensions");
                    
                    // В .NET 9 RemoteFailureContext и OpenIdConnectProtocolException не имеют свойства ProtocolMessage
                    // Используем информацию из context.Failure и других доступных свойств
                    var errorDescription = string.Empty;
                    var protocolError = string.Empty;
                    
                    if (context.Failure is OpenIdConnectProtocolException oidcProtocolEx)
                    {
                        // В .NET 9 OpenIdConnectProtocolException не имеет свойства ProtocolMessage
                        // Используем информацию из самого исключения для более детального логирования
                        errorDescription = oidcProtocolEx.Message ?? string.Empty;
                        protocolError = oidcProtocolEx.GetType().Name;
                        
                        // Дополнительная информация из исключения, если доступна
                        if (!string.IsNullOrEmpty(oidcProtocolEx.Data?.ToString()))
                        {
                            errorDescription += $" | Data: {oidcProtocolEx.Data}";
                        }
                    }
                    else if (context.Failure != null)
                    {
                        // Для других типов исключений используем общую информацию
                        errorDescription = context.Failure.Message ?? string.Empty;
                        protocolError = context.Failure.GetType().Name;
                    }
                    
                    logger.LogError(context.Failure, 
                        "Ошибка при аутентификации. Error: {Error}, ErrorDescription: {ErrorDescription}, ProtocolError: {ProtocolError}", 
                        context.Failure?.Message, 
                        errorDescription,
                        protocolError);
                    
                    // Обработка специфичных ошибок
                    if (context.Failure is OpenIdConnectProtocolException oidcEx)
                    {
                        if (oidcEx.Message.Contains("access_denied"))
                        {
                            if (!context.Response.HasStarted)
                            {
                                context.Response.Redirect(accessDeniedPath);
                                context.HandleResponse();
                            }
                            return Task.CompletedTask;
                        }
                    }
                    
                    // Общая обработка ошибок
                    if (!context.Response.HasStarted)
                    {
                        context.Response.Redirect($"{errorPath}?error=auth_failed");
                        context.HandleResponse();
                    }
                    return Task.CompletedTask;
                };

                // Перезаписываем список scope, чтобы использовать только то, что задано в конфигурации.
                options.Scope.Clear();
                foreach (var scope in keycloakAuthSettings.Scopes)
                {
                    options.Scope.Add(scope);
                }

                // Задаём claim для имени пользователя и ролей, чтобы ASP.NET автоматически выставил User.Identity.Name и User.IsInRole.
                options.TokenValidationParameters = new TokenValidationParameters
                {
                    NameClaimType = keycloakAuthSettings.NameClaim,
                    RoleClaimType = ClaimTypes.Role,
                    ValidateIssuer = true,
                    ValidIssuer = keycloakAuthSettings.Authority,
                    ValidateAudience = tokenValidationSettings.RequireAudience,
                    ValidAudience = keycloakAuthSettings.ClientId,
                    ValidateLifetime = tokenValidationSettings.ValidateLifetime,
                    ValidateIssuerSigningKey = tokenValidationSettings.ValidateIssuerSigningKey,
                    RequireSignedTokens = tokenValidationSettings.RequireSignedTokens,
                    RequireAudience = tokenValidationSettings.RequireAudience,
                    ClockSkew = TimeSpan.FromSeconds(tokenValidationSettings.ClockSkewSeconds),
                    RequireExpirationTime = true,
                    ValidateTokenReplay = tokenValidationSettings.ValidateTokenReplay ?? false
                };

                options.Events.OnTokenResponseReceived = context =>
                {
                    var loggerFactory = context.HttpContext.RequestServices.GetRequiredService<ILoggerFactory>();
                    var logger = loggerFactory.CreateLogger("AuthenticationExtensions");

                    if (context.TokenEndpointResponse?.AccessToken != null)
                    {
                        try
                        {
                            // Проверка на максимальный размер токена
                            const int MaxTokenLength = 32768; // 32KB - разумный лимит для JWT
                            if (context.TokenEndpointResponse.AccessToken.Length > MaxTokenLength)
                            {
                                logger.LogWarning("Access токен превышает максимальный размер: {Length} байт", 
                                    context.TokenEndpointResponse.AccessToken.Length);
                                context.Fail(new InvalidOperationException("Access token is too large"));
                                return Task.FromException(new InvalidOperationException("Access token is too large"));
                            }

                            var accessToken = new JwtSecurityToken(context.TokenEndpointResponse.AccessToken);
                            logger.LogDebug("Access токен получен, извлекаем роли");

                            using var payloadDocument = JsonDocument.Parse(accessToken.Payload.SerializeToJson());

                            // Проверяем все возможные места, где могут быть роли
                            // Используем приоритетный порядок: сначала конфигурируемый путь, затем стандартные
                            // Используем HashSet для автоматического исключения дубликатов
                            var rolePathsToCheck = new HashSet<string>(StringComparer.Ordinal);
                            if (!string.IsNullOrWhiteSpace(roleClaim))
                            {
                                rolePathsToCheck.Add(roleClaim);
                            }
                            // Добавляем стандартные пути (HashSet автоматически исключит дубликаты)
                            rolePathsToCheck.Add("realm_access.roles");
                            rolePathsToCheck.Add("resource_access.app-assistant-auth.roles");
                            rolePathsToCheck.Add("roles");

                            // Кэшируем разбитые пути для оптимизации
                            var rolePathsSegments = rolePathsToCheck
                                .Select(path => new { Path = path, Segments = path.Split('.') })
                                .ToList();

                            var foundRoles = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

                            // Оптимизация: прерываем поиск после первого найденного пути с ролями
                            foreach (var pathInfo in rolePathsSegments)
                            {
                                if (TryResolveJsonElement(payloadDocument.RootElement, pathInfo.Segments, out var element))
                                {
                                    if (element.ValueKind == JsonValueKind.Array)
                                    {
                                        foreach (var role in element.EnumerateArray())
                                        {
                                            var roleName = role.GetString();
                                            if (!string.IsNullOrWhiteSpace(roleName))
                                            {
                                                foundRoles.Add(roleName);
                                            }
                                        }
                                        // Нашли роли, прерываем поиск
                                        break;
                                    }
                                }
                            }

                            // Сохраняем роли в контексте для последующего использования
                            // Преобразуем HashSet в List для совместимости
                            if (foundRoles.Any())
                            {
                                context.HttpContext.Items["UserRoles"] = foundRoles.ToList();
                            }

                            // Извлекаем custom claims availableRealmRolesRW и availableClientRolesRW
                            // Эти claims содержат массивы строк с доступными ролями для добавления
                            var realmRoles = ExtractRolesFromClaim(
                                payloadDocument.RootElement, 
                                Claims.AvailableRealmRolesRW, 
                                logger);
                            if (realmRoles.Any())
                            {
                                context.HttpContext.Items["AvailableRealmRolesRW"] = realmRoles;
                                logger.LogDebug("Найдено {Count} доступных realm ролей для добавления", realmRoles.Count);
                            }

                            var clientRoles = ExtractRolesFromClaim(
                                payloadDocument.RootElement, 
                                Claims.AvailableClientRolesRW, 
                                logger);
                            if (clientRoles.Any())
                            {
                                context.HttpContext.Items["AvailableClientRolesRW"] = clientRoles;
                                logger.LogDebug("Найдено {Count} доступных client ролей для добавления", clientRoles.Count);
                            }
                        }
                        catch (Exception ex)
                        {
                            logger.LogError(ex, "Критическая ошибка при обработке Access токена");
                            // Прерываем процесс аутентификации
                            context.Fail(ex);
                            return Task.FromException(ex);
                        }
                    }

                    return Task.CompletedTask;
                };

                // Добавляем роли из Access токена в claims пользователя и логируем обновление токена
                options.Events.OnTokenValidated = context =>
                {
                    var loggerFactory = context.HttpContext.RequestServices.GetRequiredService<ILoggerFactory>();
                    var logger = loggerFactory.CreateLogger("AuthenticationExtensions");

                    // Логируем успешную валидацию/обновление токена
                    logger.LogDebug("Токен валидирован для пользователя {Username}", context.Principal?.Identity?.Name);

                    if (context.Principal?.Identity is ClaimsIdentity identity)
                    {
                        // Получаем роли из контекста (сохраненные из Access токена)
                        if (context.HttpContext.Items["UserRoles"] is List<string> roles && roles.Any())
                        {
                            foreach (var role in roles)
                            {
                                if (!identity.HasClaim(ClaimTypes.Role, role))
                                {
                                    identity.AddClaim(new Claim(ClaimTypes.Role, role));
                                }
                            }
                            
                            // Логируем успешную аутентификацию для аудита
                            logger.LogInformation("Пользователь {Username} успешно аутентифицирован. Ролей: {RoleCount}", 
                                context.Principal?.Identity?.Name,
                                roles.Count);
                        }
                        else
                        {
                            logger.LogDebug("Роли не найдены в контексте для пользователя {UserName}. Это может быть нормально для пользователей без ролей.", identity.Name);
                        }

                        // Добавляем custom claims availableRealmRolesRW и availableClientRolesRW
                        // Эти claims нужны для функционала добавления ролей пользователям
                        if (context.HttpContext.Items["AvailableRealmRolesRW"] is List<string> availableRealmRoles && availableRealmRoles.Any())
                        {
                            foreach (var role in availableRealmRoles)
                            {
                                if (!identity.HasClaim(Claims.AvailableRealmRolesRW, role))
                                {
                                    identity.AddClaim(new Claim(Claims.AvailableRealmRolesRW, role));
                                }
                            }
                            logger.LogDebug("Добавлено {Count} claims типа availableRealmRolesRW", availableRealmRoles.Count);
                        }

                        if (context.HttpContext.Items["AvailableClientRolesRW"] is List<string> availableClientRoles && availableClientRoles.Any())
                        {
                            foreach (var role in availableClientRoles)
                            {
                                if (!identity.HasClaim(Claims.AvailableClientRolesRW, role))
                                {
                                    identity.AddClaim(new Claim(Claims.AvailableClientRolesRW, role));
                                }
                            }
                            logger.LogDebug("Добавлено {Count} claims типа availableClientRolesRW", availableClientRoles.Count);
                        }
                    }
                    else
                    {
                        logger.LogWarning("Не удалось обработать токен: Principal={HasPrincipal}", context.Principal != null);
                    }

                    return Task.CompletedTask;
                };
            });

        return services;
    }

    private static bool TryResolveJsonElement(JsonElement root, IReadOnlyList<string> pathSegments, out JsonElement result)
    {
        var current = root;
        foreach (var segment in pathSegments)
        {
            if (current.ValueKind != JsonValueKind.Object || !current.TryGetProperty(segment, out var next))
            {
                result = default;
                return false;
            }

            current = next;
        }

        result = current;
        return true;
    }

    /// <summary>
    /// Извлекает роли из claim в токене
    /// </summary>
    private static List<string> ExtractRolesFromClaim(
        JsonElement rootElement, 
        string claimName, 
        ILogger logger)
    {
        if (!rootElement.TryGetProperty(claimName, out var claimElement))
        {
            return new List<string>();
        }

        const int MaxRoleNameLength = 255; // Стандартное ограничение для имен ролей
        var roles = new List<string>();
        
        if (claimElement.ValueKind == JsonValueKind.Array)
        {
            foreach (var roleElement in claimElement.EnumerateArray())
            {
                var roleValue = roleElement.GetString();
                if (!string.IsNullOrWhiteSpace(roleValue))
                {
                    if (roleValue.Length <= MaxRoleNameLength)
                    {
                        roles.Add(roleValue);
                    }
                    else
                    {
                        logger.LogWarning("Имя роли превышает максимальную длину: {RoleName} ({Length} символов)", 
                            roleValue, roleValue.Length);
                    }
                }
            }
        }
        else if (claimElement.ValueKind == JsonValueKind.String)
        {
            try
            {
                var parsed = JsonSerializer.Deserialize<string[]>(claimElement.GetString() ?? "[]");
                if (parsed != null)
                {
                    foreach (var roleValue in parsed.Where(r => !string.IsNullOrWhiteSpace(r)))
                    {
                        if (roleValue.Length <= MaxRoleNameLength)
                        {
                            roles.Add(roleValue);
                        }
                        else
                        {
                            logger.LogWarning("Имя роли превышает максимальную длину: {RoleName} ({Length} символов)", 
                                roleValue, roleValue.Length);
                        }
                    }
                }
            }
            catch (JsonException jsonEx)
            {
                logger.LogWarning(jsonEx, 
                    "Не удалось распарсить {ClaimName} как JSON массив, используем как строку", 
                    claimName);
                var roleValue = claimElement.GetString();
                if (!string.IsNullOrWhiteSpace(roleValue))
                {
                    if (roleValue.Length <= MaxRoleNameLength)
                    {
                        roles.Add(roleValue);
                    }
                    else
                    {
                        logger.LogWarning("Имя роли превышает максимальную длину: {RoleName} ({Length} символов)", 
                            roleValue, roleValue.Length);
                    }
                }
            }
            catch (ArgumentNullException)
            {
                // Игнорируем, если значение null
                logger.LogDebug("Claim {ClaimName} имеет null значение", claimName);
            }
            catch (Exception ex)
            {
                logger.LogError(ex, "Неожиданная ошибка при обработке {ClaimName}", claimName);
                // Не добавляем некорректные данные
            }
        }
        
        return roles;
    }
}

