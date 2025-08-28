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

Console.WriteLine("🚀 PlatformApi Starting Up");

Env.Load();

var builder = WebApplication.CreateBuilder(args);
builder.Configuration.AddEnvironmentVariables();

SetLogging(builder);

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

// Cache configuration
builder.Services.AddMemoryCache();
// Default to memory cache
//builder.Services.AddSingleton<ICacheService, DistributedCacheService>();
builder.Services.AddSingleton<ICacheService, MemoryCacheService>();

builder.Services.AddScoped<IUnitOfWork<PlatformDbContext>, UnitOfWork<PlatformDbContext>>();
builder.Services.AddScoped<IAuthService, AuthService>();
builder.Services.AddScoped<ITenantService, TenantService>();
builder.Services.AddScoped<IPermissionService, PermissionService>();
builder.Services.AddScoped<IBrandingService, BrandingService>();
builder.Services.AddScoped<IUserService, UserService>();
builder.Services.AddScoped<IEmailContentService, EmailContentService>();
builder.Services.AddScoped<IEmailService, EmailAwsSesService>();
// Register SNS service conditionally based on configuration
var snsEnabled = builder.Configuration.GetValue<bool>("AWS_SNS_ENABLED", true);
if (snsEnabled)
{
    builder.Services.AddScoped<ISnsService, SnsService>();
}
else
{
    builder.Services.AddScoped<ISnsService, NoOpSnsService>();
}
builder.Services.AddScoped<UserHelper>();
builder.Services.AddScoped<PermissionHelper>();


// Add Google Authentication Separately
// var logger = LoggerFactory.Create(logging =>
// {
//     logging.AddConsole(); // Add console logging
// }).CreateLogger<StartupBase>();
// builder.Services.AddGoogleAuthentication(builder.Configuration, logger);

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

app.UseStaticFiles(); // Enable serving static files (CSS, etc.)

app.ConfigureCors();  // common services

//if using auth
app.UseAuthentication();
app.UseMiddleware<PermissionsAuthServerMiddleware>();
app.ConfigureTenantMiddleware(); //must come before permissions

app.UseAuthorization();
app.MapControllers();

app.Run();

void SetLogging(WebApplicationBuilder webApplicationBuilder)
{
    // Configure logging levels to reduce EF Core SQL query noise
    webApplicationBuilder.Logging.ClearProviders();
    webApplicationBuilder.Logging.AddConsole();

    var efVerboseLogging = webApplicationBuilder.Configuration.GetValue<bool>("LOGGING_EF_VERBOSE", false);
    if (!efVerboseLogging)
    {
        webApplicationBuilder.Logging.AddFilter("Microsoft.EntityFrameworkCore.Database.Command", LogLevel.Warning);
        webApplicationBuilder.Logging.AddFilter("Microsoft.EntityFrameworkCore.Query", LogLevel.Warning);
    }
    var logLevel = webApplicationBuilder.Configuration.GetValue<string>("LOGGING_LEVEL", "Information");
    if (Enum.TryParse<LogLevel>(logLevel, out var parsedLogLevel))
    {
        webApplicationBuilder.Logging.SetMinimumLevel(parsedLogLevel);
    }
    
    // Reduce Microsoft framework noise - filter out HTTP request lifecycle chatter
    builder.Logging.AddFilter("Microsoft.AspNetCore.Hosting.Diagnostics", LogLevel.Warning); // Request starting/finished
    builder.Logging.AddFilter("Microsoft.AspNetCore.Mvc.Infrastructure.ControllerActionInvoker", LogLevel.Warning); // Route matched, executing action details
    builder.Logging.AddFilter("Microsoft.AspNetCore.Mvc.Infrastructure.ObjectResultExecutor", LogLevel.Warning); // Executing ObjectResult
    builder.Logging.AddFilter("Microsoft.AspNetCore.Cors", LogLevel.Warning); // CORS policy execution successful

// Keep endpoint execution - useful to see which APIs are being called
    builder.Logging.AddFilter("Microsoft.AspNetCore.Routing.EndpointMiddleware", LogLevel.Information);

// Keep security-related logs at Information for monitoring
    builder.Logging.AddFilter("Microsoft.AspNetCore.Authentication", LogLevel.Information);
    builder.Logging.AddFilter("Microsoft.AspNetCore.Authorization", LogLevel.Information);

}