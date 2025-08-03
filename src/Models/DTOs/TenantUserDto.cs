using System.ComponentModel.DataAnnotations;

namespace PlatformApi.Models.DTOs;

public class TenantUserDto
{
    public required string Email { get; set; }
    public List<RoleDto>? Roles { get; set; }
}

public class TenantUserWithRolesDto
{
    public required string UserId { get; set; }
    public required string Email { get; set; }
    public required List<RoleNoPermissionDto> Roles { get; set; } = new();
}

public class AddUserToRoleRequest
{
    [Required]
    [EmailAddress]
    public required string Email { get; set; }
    
    [Required]
    public required string RoleId { get; set; }
}

public class RemoveUserFromRoleRequest
{
    [Required]
    [EmailAddress]
    public required string Email { get; set; }
    
    [Required]
    public required string RoleId { get; set; }
}

public class UserEmailDto
{
    public required string Id { get; set; }
    public required string Email { get; set; }
}