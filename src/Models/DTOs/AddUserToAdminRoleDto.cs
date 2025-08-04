namespace PlatformApi.Models.DTOs;

public class AddUserToAdminRoleDto
{
    public required Guid UserId { get; set; }
    
    public required Guid RoleId { get; set; }
}