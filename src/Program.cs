using System.Security.Claims;
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
using Serilog;
using Serilog.Events;
using Serilog.Formatting.Json;

Console.WriteLine("🚀 PlatformApi Starting Up");

Env.Load();

var builder = WebApplication.CreateBuilder(args);
builder.Configuration.AddEnvironmentVariables();

ConfigureLogging(builder);

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

// Add correlation ID middleware (must be early in pipeline)
app.UseMiddleware<CorrelationIdMiddleware>();

// Add Serilog request logging
ConfigureLoggingHTTP(app);

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

void ConfigureLogging(WebApplicationBuilder webApplicationBuilder)
{
    // Get configuration values
    var logLevel = webApplicationBuilder.Configuration.GetValue<string>("LOGGING_LEVEL", "Information");
    var jsonFormat = webApplicationBuilder.Configuration.GetValue<bool>("LOGGING_JSON_FORMAT", false);
    var efVerboseLogging = webApplicationBuilder.Configuration.GetValue<bool>("LOGGING_EF_VERBOSE", false);
    
    // Parse log level
    if (!Enum.TryParse<LogEventLevel>(logLevel, out var serilogLevel))
    {
        serilogLevel = LogEventLevel.Information;
    }

    // Determine formatter based on environment and configuration
    var isDevelopment = webApplicationBuilder.Environment.IsDevelopment();
    var useJsonFormat = jsonFormat || !isDevelopment;
    
    // Configure Serilog
    var loggerConfig = new LoggerConfiguration()
        .MinimumLevel.Is(serilogLevel)
        .Enrich.FromLogContext();
        
    // Add enrichment based on format - full enrichment for JSON, minimal for development
    if (useJsonFormat)
    {
        loggerConfig
            .Enrich.WithEnvironmentName()
            .Enrich.WithProcessId()
            .Enrich.WithThreadId();
    }

    // Add console sink with appropriate formatter
    if (useJsonFormat)
    {
        loggerConfig.WriteTo.Console(new JsonFormatter());
    }
    else
    {
        // Development: clean, readable format with correlation ID and user ID
        loggerConfig.WriteTo.Console(
            outputTemplate: "[{Timestamp:HH:mm:ss} {Level:u3}] {SourceContext:l} {Message:lj} {CorrelationId} {UserId}{NewLine}{Exception}");
    }

    // Framework noise filtering - same as your existing logic
    loggerConfig.MinimumLevel.Override("Microsoft", LogEventLevel.Warning);
    
    // Override specific Microsoft loggers we want to see
    loggerConfig.MinimumLevel.Override("Microsoft.AspNetCore.Authentication", LogEventLevel.Information);
    loggerConfig.MinimumLevel.Override("Microsoft.AspNetCore.Authorization", LogEventLevel.Information);
    loggerConfig.MinimumLevel.Override("Microsoft.Hosting.Lifetime", LogEventLevel.Information);

    // EF Core noise filtering
    if (!efVerboseLogging)
    {
        loggerConfig.MinimumLevel.Override("Microsoft.EntityFrameworkCore.Database.Command", LogEventLevel.Warning);
        loggerConfig.MinimumLevel.Override("Microsoft.EntityFrameworkCore.Query", LogEventLevel.Warning);
        loggerConfig.MinimumLevel.Override("Microsoft.EntityFrameworkCore.Database.Connection", LogEventLevel.Warning);
        loggerConfig.MinimumLevel.Override("Microsoft.EntityFrameworkCore.Infrastructure", LogEventLevel.Warning);
        loggerConfig.MinimumLevel.Override("Microsoft.EntityFrameworkCore.ChangeTracking", LogEventLevel.Warning);
        loggerConfig.MinimumLevel.Override("Microsoft.EntityFrameworkCore.Update", LogEventLevel.Warning);
    }

    // Create the logger
    Log.Logger = loggerConfig.CreateLogger();
    
    // Log the configuration on startup
    Console.WriteLine($"🚀 Logging configured - Level: {serilogLevel}, Format: {(useJsonFormat ? "JSON" : "Console")}, EF Verbose: {efVerboseLogging}");
    
    // Replace built-in logging with Serilog
    webApplicationBuilder.Host.UseSerilog();
}

void ConfigureLoggingHTTP(WebApplication webApplication)
{
    webApplication.UseSerilogRequestLogging(options =>
    {
        options.MessageTemplate = "HTTP {RequestMethod} {RequestPath} responded {StatusCode} in {Elapsed:0.0000} ms";
        options.EnrichDiagnosticContext = (diagnosticContext, httpContext) =>
        {
            diagnosticContext.Set("RequestHost", httpContext.Request.Host.Value);
            diagnosticContext.Set("UserAgent", httpContext.Request.Headers["User-Agent"].ToString());
            if (httpContext.User?.Identity?.IsAuthenticated == true)
            {
                var userIdClaim = httpContext.User.FindFirstValue("userid");
                if (!string.IsNullOrEmpty(userIdClaim))
                {
                    diagnosticContext.Set("UserId", userIdClaim);
                }
            }
            // Add correlation ID from context
            if (httpContext.Items.TryGetValue("CorrelationId", out var correlationId))
            {
                diagnosticContext.Set("CorrelationId", correlationId);
            }
        };
    });
}