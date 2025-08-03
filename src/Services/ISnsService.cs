using PlatformApi.Models.Messages;

namespace PlatformApi.Services;

public interface ISnsService
{
    Task PublishUserCreatedAsync(UserCreatedMessage message);
    Task PublishUserModifiedAsync(UserModifiedMessage message);
    Task PublishTenantCreatedAsync(TenantCreatedMessage message);
}