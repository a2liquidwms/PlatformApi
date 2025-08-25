using System.ComponentModel.DataAnnotations;

namespace PlatformApi.Models.DTOs;

public class TenantUserDto
{
    public required string Email { get; set; }
    public List<RoleDto>? Roles { get; set; }
}

public class TenantUserWithRolesDto
{
    public required Guid UserId { get; set; }
    public required string Email { get; set; }
    public required List<RoleNoPermissionDto> Roles { get; set; } = new();
}

public class AddUserToRoleRequest
{
    [Required]
    [EmailAddress]
    public required string Email { get; set; }
    
    [Required]
    public required Guid RoleId { get; set; }
}

public class RemoveUserFromRoleDto
{
    [Required]
    [EmailAddress]
    public required string Email { get; set; }
    
    public Guid? TenantId { get; set; }
    
    public Guid? SiteId { get; set; }
    
    [Required]
    public required Guid RoleId { get; set; }
    
    public RoleScope Scope { get; set; }
}

public class RemoveUserFromTenantRoleDto
{
    [Required]
    [EmailAddress]
    public required string Email { get; set; }
    
    [Required]
    public required Guid RoleId { get; set; }
}

public class RemoveUserFromSiteRoleDto
{
    [Required]
    [EmailAddress]
    public required string Email { get; set; }
    
    [Required]
    public required Guid SiteId { get; set; }
    
    [Required]
    public required Guid RoleId { get; set; }
}

public class RemoveUserFromInternalRoleDto
{
    [Required]
    [EmailAddress]
    public required string Email { get; set; }
    
    [Required]
    public required Guid RoleId { get; set; }
}

public class InternalUserWithRolesDto
{
    public required Guid UserId { get; set; }
    public required string Email { get; set; }
    public required List<RoleNoPermissionDto> Roles { get; set; } = new();
}

public class UserEmailDto
{
    public required string Id { get; set; }
    public required string Email { get; set; }
}