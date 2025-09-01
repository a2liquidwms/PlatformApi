
using Amazon.SimpleEmail;
using Amazon.SimpleNotificationService;
using DotNetEnv;
using Microsoft.EntityFrameworkCore;
using PlatformApi;
using PlatformApi.Data;
using PlatformApi.Data.SeedData;
using PlatformApi.Middleware;
using PlatformApi.Services;
using PlatformStarterCommon.Core.Common.Auth;
using PlatformStarterCommon.Core.Common.Permissions;
using PlatformStarterCommon.Core.Common.Services;
using PlatformStarterCommon.Core.Common.Startup;
using PlatformStarterCommon.Core.Common.Tenant;


Console.WriteLine("🚀 PlatformApi Starting Up");

Env.Load();

var builder = WebApplication.CreateBuilder(args);
builder.Configuration.AddEnvironmentVariables();

builder.ConfigureLogging();

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
builder.Services.ConfigureAuthWithJwt(builder.Configuration);
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
builder.Services.AddScoped<IInitialDataService, InitialDataService>();
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

// Add Google Authentication Separately
// var logger = LoggerFactory.Create(logging =>
// {
//     logging.AddConsole(); // Add console logging
// }).CreateLogger<StartupBase>();
// builder.Services.AddGoogleAuthentication(builder.Configuration, logger);


var app = builder.Build();

// Ensure initial data is created
using (var scope = app.Services.CreateScope())
{
    var initialDataService = scope.ServiceProvider.GetRequiredService<IInitialDataService>();
    await initialDataService.EnsureInitialAdminUserAsync();
}

// Add correlation ID middleware (must be early in pipeline)
app.UseMiddleware<CorrelationIdMiddleware>();

// Add Serilog request logging
app.ConfigureLoggingHttp();

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

app.UseAuthorization();
app.MapControllers();

app.Run();