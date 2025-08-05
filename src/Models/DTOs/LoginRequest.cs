namespace PlatformApi.Models.DTOs;

public class LoginRequest
{
    public required string Email { get; set; }

    public required string Password { get; set; }
    
    public Guid? TenantId { get; set; }
    public Guid? SiteId { get; set; }
}