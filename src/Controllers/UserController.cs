using AutoMapper;
using Microsoft.AspNetCore.Mvc;
using NetStarterCommon.Core.Common.Permissions;
using NetStarterCommon.Core.Common.Tenant;
using PlatformApi.Models.DTOs;
using PlatformApi.Services;

namespace PlatformApi.Controllers;

[Route("api/v1/user")]
[ApiController]
public class UserController : ControllerBase
{
    private readonly ILogger<UserController> _logger;
    private readonly IMapper _mapper;
    private readonly IUserService _userService;
    private readonly TenantHelper _tenantHelper;

    public UserController(
        ILogger<UserController> logger,
        IMapper mapper,
        IUserService userService,
        TenantHelper tenantHelper)
    {
        _logger = logger;
        _mapper = mapper;
        _userService = userService;
        _tenantHelper = tenantHelper;
    }

    // Get all tenant users
    [RequirePermission("tenant.admin.manage.users")]
    [HttpGet("tenant/{tenantId:guid}/users")]
    public async Task<ActionResult<IEnumerable<TenantUserWithRolesDto>>> GetTenantUsers([FromRoute] Guid tenantId)
    {
        try
        {
            var users = await _userService.GetTenantUsers(tenantId);
            return Ok(users);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error getting tenant users for tenant {TenantId}", tenantId);
            return StatusCode(500, "Internal server error");
        }
    }

    // Get all site users
    [RequirePermission("tenant.manage.beacon.config")]
    [HttpGet("site/{siteId:guid}/users")]
    public async Task<ActionResult<IEnumerable<SiteUserWithRolesDto>>> GetSiteUsers([FromRoute] Guid siteId)
    {
        try
        {
            var users = await _userService.GetSiteUsers(siteId);
            return Ok(users);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error getting site users for site {SiteId}", siteId);
            return StatusCode(500, "Internal server error");
        }
    }

    // Add user to tenant (tenant role optional)
    [RequirePermission("tenant.admin.manage.users")]
    [HttpPost("tenant/add")]
    public async Task<ActionResult> AddUserToTenant([FromBody] AddUserToTenantDto dto)
    {
        try
        {
            var result = await _userService.AddUserToTenant(dto);
            if (!result)
            {
                return BadRequest("Failed to add user to tenant. User may not exist.");
            }
            
            return Ok(new { Message = "User added to tenant successfully" });
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error adding user to tenant");
            return StatusCode(500, "Internal server error");
        }
    }

    // Add user to site (with site role required)
    [RequirePermission("tenant.manage.beacon.config")]
    [HttpPost("site/add")]
    public async Task<ActionResult> AddUserToSite([FromBody] AddUserToSiteDto dto)
    {
        try
        {
            var result = await _userService.AddUserToSite(dto);
            if (!result)
            {
                return BadRequest("Failed to add user to site. User or site may not exist, or role is invalid.");
            }
            
            return Ok(new { Message = "User added to site successfully" });
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error adding user to site");
            return StatusCode(500, "Internal server error");
        }
    }

    // Add user to role (scope-aware)
    [RequirePermission("tenant.admin.manage.users")]
    [HttpPost("role/add")]
    public async Task<ActionResult> AddUserToRole([FromBody] AddUserToRoleDto dto)
    {
        try
        {
            var result = await _userService.AddUserToRole(dto);
            if (!result)
            {
                return BadRequest("Failed to add user to role. User may not exist, role may be invalid, or scope mismatch.");
            }
            
            return Ok(new { Message = "User added to role successfully" });
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error adding user to role");
            return StatusCode(500, "Internal server error");
        }
    }

    // Remove user from role (scope-aware)
    [RequirePermission("tenant.admin.manage.users")]
    [HttpPost("role/remove")]
    public async Task<ActionResult> RemoveUserFromRole([FromBody] RemoveUserFromRoleDto dto)
    {
        try
        {
            var result = await _userService.RemoveUserFromRole(dto);
            if (!result)
            {
                return BadRequest("Failed to remove user from role. Assignment may not exist.");
            }
            
            return Ok(new { Message = "User removed from role successfully" });
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error removing user from role");
            return StatusCode(500, "Internal server error");
        }
    }

    // Add internal role to user (system-wide)
    [RequirePermission("systemadmin.manage.users")]
    [HttpPost("internal-role/add")]
    public async Task<ActionResult> AddInternalRole([FromBody] AddInternalRoleDto dto)
    {
        try
        {
            var result = await _userService.AddInternalRole(dto.Email, Guid.Parse(dto.RoleId));
            if (!result)
            {
                return BadRequest("Failed to add internal role. User may not exist or role is not an internal role.");
            }
            
            return Ok(new { Message = "Internal role added successfully" });
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error adding internal role");
            return StatusCode(500, "Internal server error");
        }
    }

    // Remove internal role from user (system-wide)
    [RequirePermission("systemadmin.manage.users")]
    [HttpPost("internal-role/remove")]
    public async Task<ActionResult> RemoveInternalRole([FromBody] RemoveInternalRoleDto dto)
    {
        try
        {
            var result = await _userService.RemoveInternalRole(dto.Email, Guid.Parse(dto.RoleId));
            if (!result)
            {
                return BadRequest("Failed to remove internal role. Assignment may not exist.");
            }
            
            return Ok(new { Message = "Internal role removed successfully" });
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error removing internal role");
            return StatusCode(500, "Internal server error");
        }
    }
}

// Additional DTOs for internal role management
public class AddInternalRoleDto
{
    public required string Email { get; set; }
    public required string RoleId { get; set; }
}

public class RemoveInternalRoleDto
{
    public required string Email { get; set; }
    public required string RoleId { get; set; }
}