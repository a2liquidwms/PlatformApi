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



    // Add user to site role
    [RequireTenantAccess]
    [RequirePermission(RolePermissionConstants.SiteManagerUsers)]
    [HttpPost("role/site")]
    public async Task<ActionResult> AddUserToRoleSite([FromBody] AddUserToSiteRoleDto dto)
    {
        try
        {
            var tenantId = _tenantHelper.GetTenantId();
            // Map to the existing DTO format for service call
            var addUserToRoleDto = new AddUserToRoleDto
            {
                Email = dto.Email,
                SiteId = dto.SiteId,
                RoleId = dto.RoleId,
                TenantId = tenantId,
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
    
    [RequireTenantAccess]
    [RequirePermission(RolePermissionConstants.TenantManageUsers)]
    [HttpPost("role/tenant")]
    public async Task<ActionResult> AddUserToRoleTenant([FromBody] AddUserToTenantRoleDto dto)
    {
        try
        {
            var tenantId = _tenantHelper.GetTenantId();
            // Map to the existing DTO format for service call
            var addUserToRoleDto = new AddUserToRoleDto
            {
                Email = dto.Email,
                TenantId = tenantId,
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
    
    [RequirePermission(RolePermissionConstants.SysAdminManageUsers)]
    [HttpPost("role/internal")]
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
    [RequireTenantAccess]
    [RequirePermission(RolePermissionConstants.TenantManageUsers)]
    [HttpDelete("role/tenant")]
    public async Task<ActionResult> RemoveUserFromTenantRole([FromBody] RemoveUserFromTenantRoleDto dto)
    {
        try
        {
            var tenantId = _tenantHelper.GetTenantId();
            // Map to the existing DTO format for service call
            var removeUserFromRoleDto = new RemoveUserFromRoleDto
            {
                Email = dto.Email,
                TenantId = tenantId,
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
    [RequireTenantAccess]
    [RequirePermission(RolePermissionConstants.SiteManagerUsers)]
    [HttpDelete("role/site")]
    public async Task<ActionResult> RemoveUserFromSiteRole([FromBody] RemoveUserFromSiteRoleDto dto)
    {
        try
        {
            var tenantId = _tenantHelper.GetTenantId();
            // Map to the existing DTO format for service call
            var removeUserFromRoleDto = new RemoveUserFromRoleDto
            {
                Email = dto.Email,
                TenantId = tenantId,
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
    [HttpDelete("role/internal")]
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



    // Check if user exists by username
    [RequirePermission(RolePermissionConstants.AdminsLookupUsers)]
    [HttpGet("lookup/{userName}")]
    public async Task<ActionResult<UserLookupDto>> LookupUserByUserName([FromRoute] string userName)
    {
        try
        {
            var user = await _userService.GetUserByUserName(userName);
            if (user == null)
            {
                return NotFound("User not found");
            }
            
            return Ok(user);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error checking user existence for userName {UserName}", userName);
            return StatusCode(500, "Internal server error");
        }
    }

    // Invite user to tenant
    [RequireTenantAccess]
    [RequirePermission(RolePermissionConstants.TenantManageUsers)]
    [HttpPost("invite/tenant")]
    public async Task<ActionResult<InvitationResponse>> InviteTenantUser([FromBody] InviteTenantUserRequest request)
    {
        try
        {
            var tenantId = _tenantHelper.GetTenantId();
            var currentUserId = _userHelper.GetCurrentUserId();
            
            // Map to the generic DTO for service call
            var inviteRequest = new InviteUserRequest
            {
                Email = request.Email,
                TenantId = tenantId,
                SiteId = null,
                RoleId = request.RoleId,
                Scope = RoleScope.Tenant
            };
            
            var response = await _userService.InviteUserAsync(inviteRequest, RoleScope.Tenant, currentUserId.ToString());
            
            if (response.Success)
            {
                return Ok(response);
            }
            else
            {
                return BadRequest(response);
            }
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
            _logger.LogError(ex, "Error inviting user {Email} to tenant", request.Email);
            return StatusCode(500, "Internal server error");
        }
    }

    // Invite user to site
    [RequireTenantAccess]
    [RequirePermission(RolePermissionConstants.SiteManagerUsers)]
    [HttpPost("invite/site")]
    public async Task<ActionResult<InvitationResponse>> InviteSiteUser([FromBody] InviteSiteUserRequest request)
    {
        try
        {
            var tenantId = _tenantHelper.GetTenantId();
            var currentUserId = _userHelper.GetCurrentUserId();
            
            // Map to the generic DTO for service call
            var inviteRequest = new InviteUserRequest
            {
                Email = request.Email,
                TenantId = tenantId,
                SiteId = request.SiteId,
                RoleId = request.RoleId,
                Scope = RoleScope.Site
            };
            
            var response = await _userService.InviteUserAsync(inviteRequest, RoleScope.Site, currentUserId.ToString());
            
            if (response.Success)
            {
                return Ok(response);
            }
            else
            {
                return BadRequest(response);
            }
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
            _logger.LogError(ex, "Error inviting user {Email} to site", request.Email);
            return StatusCode(500, "Internal server error");
        }
    }

    // Invite user to internal role
    [RequirePermission(RolePermissionConstants.SysAdminManageUsers)]
    [HttpPost("invite/internal")]
    public async Task<ActionResult<InvitationResponse>> InviteInternalUser([FromBody] InviteInternalUserRequest request)
    {
        try
        {
            var currentUserId = _userHelper.GetCurrentUserId();
            
            // Map to the generic DTO for service call
            var inviteRequest = new InviteUserRequest
            {
                Email = request.Email,
                TenantId = null,
                SiteId = null,
                RoleId = request.RoleId,
                Scope = RoleScope.Internal
            };
            
            var response = await _userService.InviteUserAsync(inviteRequest, RoleScope.Internal, currentUserId.ToString());
            
            if (response.Success)
            {
                return Ok(response);
            }
            else
            {
                return BadRequest(response);
            }
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
            _logger.LogError(ex, "Error inviting user {Email} to internal role", request.Email);
            return StatusCode(500, "Internal server error");
        }
    }


    // Get pending tenant invitations
    [RequireTenantAccess]
    [RequirePermission(RolePermissionConstants.TenantManageUsers)]
    [HttpGet("invitations/tenant")]
    public async Task<ActionResult<IEnumerable<UserInvitation>>> GetPendingTenantInvitations()
    {
        try
        {
            var tenantId = _tenantHelper.GetTenantId();
            var invitations = await _userService.GetPendingInvitationsAsync(RoleScope.Tenant, tenantId);
            
            return Ok(invitations);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error getting pending tenant invitations");
            return StatusCode(500, "Internal server error");
        }
    }

    // Get pending site invitations
    [RequireTenantAccess]
    [RequirePermission(RolePermissionConstants.SiteManagerUsers)]
    [HttpGet("invitations/site/{siteId:guid}")]
    public async Task<ActionResult<IEnumerable<UserInvitation>>> GetPendingSiteInvitations([FromRoute] Guid siteId)
    {
        try
        {
            var tenantId = _tenantHelper.GetTenantId();
            var invitations = await _userService.GetPendingInvitationsAsync(RoleScope.Site, tenantId, siteId);
            
            return Ok(invitations);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error getting pending site invitations for site {SiteId}", siteId);
            return StatusCode(500, "Internal server error");
        }
    }

    // Get pending internal invitations
    [RequirePermission(RolePermissionConstants.SysAdminManageUsers)]
    [HttpGet("invitations/internal")]
    public async Task<ActionResult<IEnumerable<UserInvitation>>> GetPendingInternalInvitations()
    {
        try
        {
            var invitations = await _userService.GetPendingInvitationsAsync(RoleScope.Internal);
            
            return Ok(invitations);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error getting pending internal invitations");
            return StatusCode(500, "Internal server error");
        }
    }

    // Delete invitation by email
    [RequirePermission(RolePermissionConstants.TenantManageUsers)]
    [HttpDelete("invitation/{email}")]
    public async Task<ActionResult> DeleteInvitation([FromRoute] string email)
    {
        try
        {
            await _userService.DeleteInvitationAsync(email);
            return Ok(new { Message = "Invitation deleted successfully" });
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
            _logger.LogError(ex, "Error deleting invitation for email {Email}", email);
            return StatusCode(500, "Internal server error");
        }
    }

}