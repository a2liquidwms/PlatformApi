using System.Text;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.IdentityModel.Tokens;

namespace PlatformApi;

public static class AuthStartupExtensions
{
    public static void ConfigureAuthWithJwt(this IServiceCollection services, IConfiguration configuration)
    {
        var jwtIssuer = configuration["JWT_ISSUER"]
                        ?? throw new InvalidOperationException("JWT_ISSUER is missing from configuration.");

        var jwtAudience = configuration["JWT_AUDIENCE"]
                          ?? throw new InvalidOperationException("JWT_AUDIENCE is missing from configuration.");

        var jwtSecret = configuration["JWT_SECRET"];
        if (string.IsNullOrEmpty(jwtSecret) || jwtSecret.Length < 32)
        {
            throw new InvalidOperationException("JWT_SECRET is missing or too weak! Must be at least 32 characters.");
        }
        
        services.AddAuthentication(options =>
            {
                options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
                options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
                options.DefaultScheme = JwtBearerDefaults.AuthenticationScheme;
            })
            .AddJwtBearer(options =>
            {
                options.RequireHttpsMetadata = false; // For development only
                options.SaveToken = true;
    
                // Enable detailed errors for debugging
                options.IncludeErrorDetails = true;
    
                // Don't challenge for anonymous endpoints
                options.Events = new JwtBearerEvents
                {
                    OnChallenge = context =>
                    {
                        // Check if the endpoint allows anonymous access
                        var endpoint = context.HttpContext.GetEndpoint();
                        if (endpoint?.Metadata?.GetMetadata<IAllowAnonymous>() != null)
                        {
                            // Skip the challenge for anonymous endpoints
                            context.HandleResponse();
                            return Task.CompletedTask;
                        }
                    
                        return Task.CompletedTask;
                    }
                };
                
                options.TokenValidationParameters = new TokenValidationParameters
                {
                    ValidateIssuerSigningKey = true,
                    IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwtSecret)),
                    ValidateIssuer = true,
                    ValidIssuer = jwtIssuer,
                    ValidateAudience = true,
                    ValidAudience = jwtAudience,
                    ValidateLifetime = true,
                    RequireExpirationTime = true,
                    ClockSkew = TimeSpan.Zero
                };
            });
    }
}