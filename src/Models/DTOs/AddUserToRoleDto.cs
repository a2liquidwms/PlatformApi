namespace PlatformApi.Models.DTOs;

public class AddUserToRoleDto
{
    public required string UserId { get; set; }

    public required Guid TenantId { get; set; }

    public required string RoleId { get; set; }
}