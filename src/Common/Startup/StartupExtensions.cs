using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc.Authorization;
using Microsoft.OpenApi.Models;

namespace PlatformApi.Common.Startup;

public static class StartupExtensions
{
    public static void AddSwaggerDocExtensions(this IServiceCollection services, IConfiguration configuration)
    {
        var appName = configuration["APP_NAME"];

        services.AddSwaggerGen(c =>
        {
            c.AddSecurityDefinition("Bearer", new OpenApiSecurityScheme
            {
                Description = "JWT Authorization Scheme Enter 'Bearer [space]' ",
                Name = "Authorization",
                In = ParameterLocation.Header,
                Type = SecuritySchemeType.ApiKey,
                Scheme = "Bearer"
            });

            c.AddSecurityRequirement(new OpenApiSecurityRequirement
            {
                {
                    new OpenApiSecurityScheme
                    {
                        Reference = new OpenApiReference
                        {
                            Type = ReferenceType.SecurityScheme,
                            Id = "Bearer"
                        },
                        Scheme = "0auth2",
                        Name = "Bearer",
                        In = ParameterLocation.Header
                    },
                    new List<string>()
                }
            });

            c.SwaggerDoc("v1", new OpenApiInfo { Title = appName, Version = "v1" });
        });

        services.AddEndpointsApiExplorer();
        services.AddRouting(options => options.LowercaseUrls = true);
    }

    public static void AddCorsCustom(this IServiceCollection services, IConfiguration configuration)
    {
        var allowedHosts = configuration["CORS_ALLOWEDHOSTS"] ?? throw new InvalidOperationException();
        services.AddCors(p =>
            p.AddPolicy("corsPolicy", b => { b.WithOrigins(allowedHosts).AllowAnyMethod().AllowAnyHeader(); }));
    }

    public static void AddCommonStartupServices(this IServiceCollection services, IConfiguration configuration)
    {
        services.AddHttpContextAccessor();
        services.AddHttpClient("PermissionApiClient", client =>
        {
            var permissionBaseUrl = configuration["PERMISSION_BASEURL"] ?? throw new InvalidOperationException();
            client.BaseAddress = new Uri(permissionBaseUrl);
        });

        services.AddControllers(options =>
        {
            //Add a global AuthorizeFilter
            var policy = new AuthorizationPolicyBuilder()
                .RequireAuthenticatedUser()
                .Build();
            options.Filters.Add(new AuthorizeFilter(policy));

            options.Filters.Add<InputValidationFilter>(); //change modelStateInvalid output
        }).AddJsonOptions(options => { options.JsonSerializerOptions.Converters.Add(new NullableGuidConverter()); });
    }

    public static WebApplication ConfigureCors(this WebApplication app)
    {
        app.UseCors("corsPolicy");
        return app;
    }
}