namespace PlatformApi.Models.DTOs;

public class AddUserToTenantDto
{
    public required string Email { get; set; }

    public required Guid TenantId { get; set; }
    
}