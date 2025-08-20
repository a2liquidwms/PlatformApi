namespace PlatformApi.Models.DTOs;

public class SwitchTenantRequest
{
    public required Guid TenantId { get; set; }
}