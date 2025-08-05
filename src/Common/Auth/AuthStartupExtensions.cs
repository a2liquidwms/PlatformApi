using System.Text;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;

namespace PlatformApi.Common.Auth;

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
        
        services.AddAuthentication(o =>
            {
                o.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
                o.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
                o.DefaultScheme = JwtBearerDefaults.AuthenticationScheme;
            })
            .AddJwtBearer(options =>
            {
                options.MapInboundClaims = false;
                options.TokenValidationParameters = new TokenValidationParameters
                {
                    ValidateIssuerSigningKey = true,
                    IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwtSecret)),
                    ValidateIssuer = true,
                    ValidIssuer = jwtIssuer,
                    ValidateAudience = true,
                    ValidAudience = jwtAudience,
                    ValidateLifetime = true,
                   ClockSkew = TimeSpan.Zero,
                   RequireExpirationTime = true
                };
            });
    }

}