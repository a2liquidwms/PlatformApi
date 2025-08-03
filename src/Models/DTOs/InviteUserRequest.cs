namespace PlatformApi.Models.DTOs;

public class InviteUserRequest
{
    public required string Email { get; set; }
    
    public required Guid TenantId { get; set; }
    
    public List<string>? RoleIds { get; set; }
}