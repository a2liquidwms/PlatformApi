using Serilog.Context;

namespace PlatformApi.Common.Startup;

public class CorrelationIdMiddleware
{
    private readonly RequestDelegate _next;
    private readonly ILogger<CorrelationIdMiddleware> _logger;

    public CorrelationIdMiddleware(RequestDelegate next, ILogger<CorrelationIdMiddleware> logger)
    {
        _next = next;
        _logger = logger;
    }

    public async Task InvokeAsync(HttpContext context)
    {
        // Get correlation ID from header or generate new one
        var correlationId = context.Request.Headers["X-Correlation-ID"].FirstOrDefault()
                           ?? Guid.NewGuid().ToString("D");
        
        // Store correlation ID in context for other middleware/controllers to access
        context.Items["CorrelationId"] = correlationId;
        
        // Add correlation ID to response headers
        context.Response.Headers.TryAdd("X-Correlation-ID", correlationId);
        
        // Push correlation ID to Serilog context so it appears in all log messages
        using (LogContext.PushProperty("CorrelationId", correlationId))
        {
            await _next(context);
        }
    }
}