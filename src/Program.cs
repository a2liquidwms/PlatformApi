using Amazon.SimpleEmail;
using Amazon.SimpleNotificationService;
using DotNetEnv;
using Microsoft.AspNetCore.Authorization;
using Microsoft.EntityFrameworkCore;
using PlatformApi;
using PlatformApi.Common.Auth;
using PlatformApi.Common.Permissions;
using PlatformApi.Common.Services;
using PlatformApi.Common.Startup;
using PlatformApi.Common.Tenant;
using PlatformApi.Data;
using PlatformApi.Services;
using AuthStartupExtensions = PlatformApi.AuthStartupExtensions;

Console.WriteLine("🚀 PlatformApi Starting Up");

Env.Load();

var builder = WebApplication.CreateBuilder(args);
builder.Configuration.AddEnvironmentVariables();

// Add services to the container.
var connectionString = builder.Configuration["DBCONNECTION_AUTH"];
builder.Services.AddDbContext<PlatformDbContext>(options =>
    {
        options.UseNpgsql(connectionString);
        options.UseSnakeCaseNamingConvention();
    }
);

builder.Services.AddSingleton<IAmazonSimpleEmailService>(provider =>
{
    var configuration = provider.GetRequiredService<IConfiguration>();
    
    var accessKey = configuration["AWS_ACCESS_KEY_ID"] ?? 
                    throw new InvalidOperationException("AWS_ACCESS_KEY_ID not found");
    var secretKey = configuration["AWS_SECRET_ACCESS_KEY"] ?? 
                    throw new InvalidOperationException("AWS_SECRET_ACCESS_KEY not found");
    var region = configuration["AWS_REGION"] ?? "us-east-1";

    var config = new AmazonSimpleEmailServiceConfig
    {
        RegionEndpoint = Amazon.RegionEndpoint.GetBySystemName(region)
    };

    return new AmazonSimpleEmailServiceClient(accessKey, secretKey, config);
});

builder.Services.AddSingleton<IAmazonSimpleNotificationService>(provider =>
{
    var configuration = provider.GetRequiredService<IConfiguration>();
    
    var accessKey = configuration["AWS_ACCESS_KEY_ID"] ?? 
                    throw new InvalidOperationException("AWS_ACCESS_KEY_ID not found");
    var secretKey = configuration["AWS_SECRET_ACCESS_KEY"] ?? 
                    throw new InvalidOperationException("AWS_SECRET_ACCESS_KEY not found");
    var region = configuration["AWS_REGION"] ?? "us-east-1";
    // var topicArn = configuration["AWS_SNS_TOPIC_ARN"] ?? 
    //                throw new InvalidOperationException("AWS_SNS_TOPIC_ARN not found");

    var config = new AmazonSimpleNotificationServiceConfig
    {
        RegionEndpoint = Amazon.RegionEndpoint.GetBySystemName(region)
    };

    return new AmazonSimpleNotificationServiceClient(accessKey, secretKey, config);
});

//Identity 
builder.Services.ConfigureIdentity();

builder.Services.AddCommonStartupServices(builder.Configuration);  // from Common
AuthStartupExtensions.ConfigureAuthWithJwt(builder.Services, builder.Configuration);
builder.Services.AddCorsCustom(builder.Configuration);
builder.Services.AddSwaggerDocExtensions(builder.Configuration);
builder.Services.TenantCheckServices(builder.Configuration);
builder.Services.PermissionCheckServices(builder.Configuration);
builder.Services.AddHealthChecks();
builder.Services.AddAutoMapper(typeof(Program));
builder.Services.AddMemoryCache();

builder.Services.AddScoped<IUnitOfWork<PlatformDbContext>, UnitOfWork<PlatformDbContext>>();
builder.Services.AddScoped<IAuthService, AuthService>();
builder.Services.AddScoped<ITenantService, TenantService>();
builder.Services.AddScoped<IPermissionService, PermissionService>();
builder.Services.AddScoped<IBrandingService, BrandingService>();
builder.Services.AddScoped<IUserService, UserService>();
builder.Services.AddScoped<IEmailService, EmailAwsSesService>();
builder.Services.AddScoped<ISnsService, SnsService>();
builder.Services.AddScoped<UserHelper>();


// Add this before adding authentication in Program.cs
builder.Services.Configure<CookiePolicyOptions>(options =>
{
    options.MinimumSameSitePolicy = SameSiteMode.None;
    options.Secure = CookieSecurePolicy.Always;
});


// Add Google Authentication Separately
var logger = LoggerFactory.Create(logging =>
{
    logging.AddConsole(); // Add console logging
}).CreateLogger<StartupBase>();
builder.Services.AddGoogleAuthentication(builder.Configuration, logger);

builder.Services
    .AddSingleton<IAuthorizationMiddlewareResultHandler, AuthResponseHandler>();

var app = builder.Build();

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment() || app.Environment.IsStaging())
{
    // foreach (var envVar in Environment.GetEnvironmentVariables())
    // {
    //     Console.WriteLine($"{envVar.ToString()} ");
    // }
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.MapHealthChecks("/health");

app.ConfigureCors();  // common services

//if using auth
app.UseCookiePolicy();
app.UseAuthentication();
app.UseMiddleware<PermissionsAuthServerMiddleware>();
app.ConfigureTenantMiddleware(); //must come before permissions

app.UseAuthorization();
app.MapControllers();

app.Run();