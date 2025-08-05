using AutoMapper;
using Microsoft.AspNetCore.Mvc;
using PlatformApi.Common.Constants;
using PlatformApi.Common.Permissions;
using PlatformApi.Common.Tenant;
using PlatformApi.Data;
using PlatformApi.Models;
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
    [RequirePermission(RolePermissionConstants.TenantManageUsers)]
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
    [RequirePermission(RolePermissionConstants.SiteManagerUsers)]
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
    [RequirePermission(RolePermissionConstants.TenantManageUsers)]
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
    [RequirePermission(RolePermissionConstants.SiteManagerUsers)]
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

    // Add user to site role
    [RequirePermission(RolePermissionConstants.SiteManagerUsers)]
    [HttpPost("role/site/add")]
    public async Task<ActionResult> AddUserToRoleSite([FromBody] AddUserToRoleDto dto)
    {
        try
        {
            await _userService.AddUserToRole(dto, RoleScope.Site);
            return Ok(new { Message = "User added to site role successfully" });
        }
        catch (NotFoundException ex)
        {
            return NotFound(ex.Message);
        }
        catch (InvalidDataException ex)
        {
            return BadRequest(ex.Message);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error adding user to site role");
            return StatusCode(500, "Internal server error");
        }
    }

    // Add user to tenant role
    [RequirePermission(RolePermissionConstants.TenantManageUsers)]
    [HttpPost("role/tenant/add")]
    public async Task<ActionResult> AddUserToRoleTenant([FromBody] AddUserToRoleDto dto)
    {
        try
        {
            await _userService.AddUserToRole(dto, RoleScope.Tenant);
            return Ok(new { Message = "User added to tenant role successfully" });
        }
        catch (NotFoundException ex)
        {
            return NotFound(ex.Message);
        }
        catch (InvalidDataException ex)
        {
            return BadRequest(ex.Message);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error adding user to tenant role");
            return StatusCode(500, "Internal server error");
        }
    }

    // Add user to internal role
  //  [RequirePermission(RolePermissionConstants.SysAdminManageUsers)]
    [HttpPost("role/internal/add")]
    public async Task<ActionResult> AddUserToRoleInternal([FromBody] AddUserToRoleDto dto)
    {
        try
        {
            await _userService.AddUserToRole(dto, RoleScope.Internal);
            return Ok(new { Message = "User added to internal role successfully" });
        }
        catch (NotFoundException ex)
        {
            return NotFound(ex.Message);
        }
        catch (InvalidDataException ex)
        {
            return BadRequest(ex.Message);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error adding user to internal role");
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

}