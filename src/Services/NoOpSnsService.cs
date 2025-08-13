using PlatformApi.Models.Messages;

namespace PlatformApi.Services;

public class NoOpSnsService : ISnsService
{
    private readonly ILogger<NoOpSnsService> _logger;

    public NoOpSnsService(ILogger<NoOpSnsService> logger)
    {
        _logger = logger;
    }

    public Task PublishUserCreatedAsync(UserCreatedMessage message)
    {
        _logger.LogInformation("SNS disabled - skipping user-created message for user {UserId}", message.UserId);
        return Task.CompletedTask;
    }

    public Task PublishUserModifiedAsync(UserModifiedMessage message)
    {
        _logger.LogInformation("SNS disabled - skipping user-modified message for user {UserId}", message.UserId);
        return Task.CompletedTask;
    }

    public Task PublishTenantCreatedAsync(TenantCreatedMessage message)
    {
        _logger.LogInformation("SNS disabled - skipping tenant-created message for tenant {TenantId}", message.TenantId);
        return Task.CompletedTask;
    }
}