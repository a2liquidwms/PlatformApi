using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.DependencyInjection;
using PlatformApi.Data;
using PlatformApi.Models;

namespace PlatformApi;

public static class AuthServerExtensions
{
    public static void ConfigureIdentity(this IServiceCollection services)
    {
        services.AddIdentity<AuthUser, IdentityRole<Guid>>(options =>
        {
            // Password settings
            options.Password.RequiredLength = 6;
            options.Password.RequireLowercase = true;
            options.Password.RequireUppercase = false;
            options.Password.RequireNonAlphanumeric = false;
            options.Password.RequireDigit = true;

            // Email settings
            options.SignIn.RequireConfirmedEmail = true;
            options.User.RequireUniqueEmail = true;

            // Token settings
            options.Tokens.EmailConfirmationTokenProvider = TokenOptions.DefaultEmailProvider;
            options.Tokens.PasswordResetTokenProvider = TokenOptions.DefaultEmailProvider;
        })
        .AddEntityFrameworkStores<PlatformDbContext>()
        .AddDefaultTokenProviders();

        // Configure token lifespans
        services.Configure<DataProtectionTokenProviderOptions>(options =>
        {
            options.TokenLifespan = TimeSpan.FromHours(24); // Email confirmation tokens expire in 24 hours
        });

        // Disable cookie authentication and ensure JWT is used
        services.ConfigureApplicationCookie(options =>
        {
            options.LoginPath = null;  // Ensure no redirect happens
            options.AccessDeniedPath = null;
            options.Events.OnRedirectToLogin = context =>
            {
                context.Response.StatusCode = StatusCodes.Status401Unauthorized;
                return Task.CompletedTask;
            };
            options.Events.OnRedirectToAccessDenied = context =>
            {
                context.Response.StatusCode = StatusCodes.Status403Forbidden;
                return Task.CompletedTask;
            };
        });
    }
    
    public static void AddGoogleAuthentication(this IServiceCollection services, IConfiguration configuration,
        ILogger logger)
    {
        services.AddAuthentication()
            .AddGoogle(googleOptions =>
            {
                googleOptions.ClientId = configuration["AUTH_GOOGLE_CLIENT_ID"]
                                         ?? throw new InvalidOperationException("Missing Google Client ID");
                googleOptions.ClientSecret = configuration["AUTH_GOOGLE_CLIENT_SECRET"]
                                             ?? throw new InvalidOperationException("Missing Google Client Secret");
                googleOptions.SaveTokens = true;

                googleOptions.CorrelationCookie.SameSite = SameSiteMode.None;
                googleOptions.CorrelationCookie.SecurePolicy = CookieSecurePolicy.Always;
                
                googleOptions.Events.OnTicketReceived = context =>
                {
                    logger.LogInformation($"Successfully authenticated user: {context.Principal?.Identity?.Name}");
                    return Task.CompletedTask;
                };
                googleOptions.Events.OnRemoteFailure = context =>
                {
                    logger.LogError($"Failed to authenticate user: {context.Failure?.Message}");
                    return Task.CompletedTask;
                };
            });
    }
    
    public static WebApplication ConfigureAuthCookies(this WebApplication app)
    {
        app.UseCookiePolicy(new CookiePolicyOptions
        {
            MinimumSameSitePolicy = SameSiteMode.Unspecified,
            Secure = CookieSecurePolicy.None // Use .Always in production
        });
        return app;
    }
}