namespace PlatformApi.Models.DTOs;

public class AddUserToAdminRoleDto
{
    public required string UserId { get; set; }
    
    public required string RoleId { get; set; }
}