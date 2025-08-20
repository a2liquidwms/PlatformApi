using AutoMapper;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using PlatformApi.Common.Auth;
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
    private readonly ITenantService _tenantService;
    private readonly TenantHelper _tenantHelper;
    private readonly UserHelper _userHelper;
    private readonly PermissionHelper _permissionHelper;

    public UserController(
        ILogger<UserController> logger,
        IMapper mapper,
        IUserService userService,
        ITenantService tenantService,
        TenantHelper tenantHelper,
        UserHelper userHelper,
        PermissionHelper permissionHelper)
    {
        _logger = logger;
        _mapper = mapper;
        _userService = userService;
        _tenantService = tenantService;
        _tenantHelper = tenantHelper;
        _userHelper = userHelper;
        _permissionHelper = permissionHelper;
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

    // Get all internal users
    [RequirePermission(RolePermissionConstants.SysAdminManageUsers)]
    [HttpGet("internal")]
    public async Task<ActionResult<IEnumerable<InternalUserWithRolesDto>>> GetInternalUsers()
    {
        try
        {
            var users = await _userService.GetInternalUsers();
            return Ok(users);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error getting internal users");
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
            _logger.LogError(ex, "Error adding user to tenant");
            return StatusCode(500, "Internal server error");
        }
    }

    // Add user to site (role is optional)
    [RequirePermission(RolePermissionConstants.SiteManagerUsers)]
    [HttpPost("site/add")]
    public async Task<ActionResult> AddUserToSite([FromBody] AddUserToSiteDto dto)
    {
        try
        {
            var result = await _userService.AddUserToSite(dto);
            if (!result)
            {
                return BadRequest("Failed to add user to site. User or site may not exist.");
            }
            
            return Ok(new { Message = "User added to site successfully" });
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
            _logger.LogError(ex, "Error adding user to site");
            return StatusCode(500, "Internal server error");
        }
    }

    // Add user to site role
    [RequirePermission(RolePermissionConstants.SiteManagerUsers)]
    [HttpPost("role/site/add")]
    public async Task<ActionResult> AddUserToRoleSite([FromBody] AddUserToSiteRoleDto dto)
    {
        try
        {
            // Map to the existing DTO format for service call
            var addUserToRoleDto = new AddUserToRoleDto
            {
                Email = dto.Email,
                SiteId = dto.SiteId,
                RoleId = dto.RoleId,
                Scope = RoleScope.Site
            };
            
            await _userService.AddUserToRole(addUserToRoleDto, RoleScope.Site);
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
    public async Task<ActionResult> AddUserToRoleTenant([FromBody] AddUserToTenantRoleDto dto)
    {
        try
        {
            // Map to the existing DTO format for service call
            var addUserToRoleDto = new AddUserToRoleDto
            {
                Email = dto.Email,
                TenantId = dto.TenantId,
                RoleId = dto.RoleId,
                Scope = RoleScope.Tenant
            };
            
            await _userService.AddUserToRole(addUserToRoleDto, RoleScope.Tenant);
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
    [RequirePermission(RolePermissionConstants.SysAdminManageUsers)]
    [HttpPost("role/internal/add")]
    public async Task<ActionResult> AddUserToRoleInternal([FromBody] AddUserToInternalRoleDto dto)
    {
        try
        {
            // Map to the existing DTO format for service call
            var addUserToRoleDto = new AddUserToRoleDto
            {
                Email = dto.Email,
                RoleId = dto.RoleId,
                Scope = RoleScope.Internal
            };
            
            await _userService.AddUserToRole(addUserToRoleDto, RoleScope.Internal);
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

    // Remove user from tenant role
    [RequirePermission(RolePermissionConstants.TenantManageUsers)]
    [HttpPost("role/tenant/remove")]
    public async Task<ActionResult> RemoveUserFromTenantRole([FromBody] RemoveUserFromTenantRoleDto dto)
    {
        try
        {
            // Map to the existing DTO format for service call
            var removeUserFromRoleDto = new RemoveUserFromRoleDto
            {
                Email = dto.Email,
                TenantId = dto.TenantId,
                SiteId = null,
                RoleId = dto.RoleId,
                Scope = RoleScope.Tenant
            };
            
            await _userService.RemoveUserFromRole(removeUserFromRoleDto, RoleScope.Tenant);
            return Ok(new { Message = "User removed from tenant role successfully" });
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
            _logger.LogError(ex, "Error removing user from tenant role");
            return StatusCode(500, "Internal server error");
        }
    }

    // Remove user from site role
    [RequirePermission(RolePermissionConstants.SiteManagerUsers)]
    [HttpPost("role/site/remove")]
    public async Task<ActionResult> RemoveUserFromSiteRole([FromBody] RemoveUserFromSiteRoleDto dto)
    {
        try
        {
            // Map to the existing DTO format for service call
            var removeUserFromRoleDto = new RemoveUserFromRoleDto
            {
                Email = dto.Email,
                TenantId = null,
                SiteId = dto.SiteId,
                RoleId = dto.RoleId,
                Scope = RoleScope.Site
            };
            
            await _userService.RemoveUserFromRole(removeUserFromRoleDto, RoleScope.Site);
            return Ok(new { Message = "User removed from site role successfully" });
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
            _logger.LogError(ex, "Error removing user from site role");
            return StatusCode(500, "Internal server error");
        }
    }

    // Remove user from internal role
    [RequirePermission(RolePermissionConstants.SysAdminManageUsers)]
    [HttpPost("role/internal/remove")]
    public async Task<ActionResult> RemoveUserFromInternalRole([FromBody] RemoveUserFromInternalRoleDto dto)
    {
        try
        {
            // Map to the existing DTO format for service call
            var removeUserFromRoleDto = new RemoveUserFromRoleDto
            {
                Email = dto.Email,
                TenantId = null,
                SiteId = null,
                RoleId = dto.RoleId,
                Scope = RoleScope.Internal
            };
            
            await _userService.RemoveUserFromRole(removeUserFromRoleDto, RoleScope.Internal);
            return Ok(new { Message = "User removed from internal role successfully" });
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
            _logger.LogError(ex, "Error removing user from internal role");
            return StatusCode(500, "Internal server error");
        }
    }


    // Get current user's tenants
    [Authorize]
    [HttpGet("my/tenants")]
    public async Task<ActionResult<IEnumerable<TenantDto>>> GetMyTenants()
    {
        try
        {
            var userId = _userHelper.GetCurrentUserId();
            var tenants = await _userService.GetUserTenants(userId);
            return Ok(tenants);
        }
        catch (UnauthorizedAccessException ex)
        {
            return Unauthorized(ex.Message);
        }
        catch (InvalidDataException ex)
        {
            return BadRequest(ex.Message);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error getting current user's tenants");
            return StatusCode(500, "Internal server error");
        }
    }

    // Get current user's sites
    [RequireTenantAccess]
    [HttpGet("my/sites")]
    public async Task<ActionResult<IEnumerable<SiteDto>>> GetMySites()
    {
        try
        {
            var userId = _userHelper.GetCurrentUserId();
            var tenantId = _tenantHelper.GetTenantId();
            var sites = await _userService.GetUserSites(userId, tenantId);
            return Ok(sites);
        }
        catch (UnauthorizedAccessException ex)
        {
            return Unauthorized(ex.Message);
        }
        catch (InvalidDataException ex)
        {
            return BadRequest(ex.Message);
        }
        catch (Exception ex)
        {
            var tenantId = _tenantHelper.GetTenantId();
            _logger.LogError(ex, "Error getting current user's sites for tenant {TenantId}", tenantId);
            return StatusCode(500, "Internal server error");
        }
    }

}