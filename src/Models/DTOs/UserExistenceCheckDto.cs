namespace PlatformApi.Models.DTOs;

public class UserExistenceCheckDto
{
    public required string Email { get; set; }
    
    public List<RoleNoPermissionDto> Roles { get; set; } = new();
}