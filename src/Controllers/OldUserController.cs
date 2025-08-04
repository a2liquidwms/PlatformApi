// using AutoMapper;
// using Microsoft.AspNetCore.Mvc;
// using Microsoft.IdentityModel.JsonWebTokens;
// using NetStarterCommon.Core.Common.Constants;
// using NetStarterCommon.Core.Common.Permissions;
// using NetStarterCommon.Core.Common.Tenant;
// using PlatformApi.Data;
// using PlatformApi.Models.DTOs;
// using PlatformApi.Services;
//
// namespace PlatformApi.Controllers;
//
// [Route("api/v1/olduser")]
// public class OldUserController : ControllerBase
// {
//     private readonly ILogger<OldUserController> _logger;
//     private readonly IMapper _mapper;
//     private readonly IOldUserService _oldUserService;
//     private readonly TenantHelper _tenantHelper;
//
//     public OldUserController(ILogger<OldUserController> logger, IMapper mapper, IOldUserService oldUserService,
//         TenantHelper tenantHelper)
//     {
//         _logger = logger;
//         _mapper = mapper;
//         _oldUserService = oldUserService;
//         _tenantHelper = tenantHelper;
//     }
//
//     //must be open to all for Permission Checks
//     [RequirePermission("default:all")]
//     [HttpGet("my/roles/{tenantId:Guid?}")]
//     public async Task<ActionResult<IEnumerable<PermissionDto>>> GetMyRoles([FromRoute] Guid? tenantId)
//     {
//         var userId = HttpContext.User.Claims.FirstOrDefault(x => x.Type == CommonConstants.ClaimUserId)?.Value ??
//                      throw new InvalidOperationException("No User Set");
//
//         var roles = await _oldUserService.GetUserRoles(userId, tenantId);
//
//         return Ok(_mapper.Map<IEnumerable<RoleDto>>(roles));
//     }
//
//     [RequireTenantAccess]
//     [RequirePermission("default:all")]
//     [HttpGet("my/tenants")]
//     public async Task<ActionResult<IEnumerable<TenantDto>>> GetMyTenants()
//     {
//         var userId = HttpContext.User.Claims.FirstOrDefault(x => x.Type == CommonConstants.ClaimUserId)?.Value ??
//                      throw new InvalidOperationException("No User Set");
//
//         var tenants = await _oldUserService.GetUserTenants(userId);
//
//         return Ok(_mapper.Map<IEnumerable<TenantDto>>(tenants));
//     }
//
//     //must be open to all for Permission Checks
//     [HttpGet("my/permissions/{tenantId:Guid?}")]
//     public async Task<ActionResult<IEnumerable<PermissionDto>>> GetMyPermissions([FromRoute] Guid? tenantId)
//     {
//         var userId = HttpContext.User.Claims.FirstOrDefault(x => x.Type == CommonConstants.ClaimUserId)?.Value ??
//                      throw new InvalidOperationException("No User Set");
//
//         var perms = await _oldUserService.GetUserPermissions(userId, tenantId);
//
//         return Ok(_mapper.Map<IEnumerable<PermissionDto>>(perms));
//     }
//
//     //must be open to all for Permission Checks
//     [RequirePermission("default:all")]
//     [HttpGet("check/permission/{tenantId:Guid?}")]
//     public async Task<ActionResult<bool>> CheckPermissions([FromRoute] Guid? tenantId,
//         [FromQuery] string permissionCode)
//     {
//         var userId = HttpContext.User.Claims.FirstOrDefault(x => x.Type == JwtRegisteredClaimNames.Sub)?.Value ??
//                      throw new InvalidOperationException("No User Set");
//
//         var hasPermission = await _oldUserService.DoesUserHavePermission(userId, permissionCode, tenantId);
//
//         return Ok(hasPermission);
//     }
//     
//     [RequireTenantAccess]
//     [RequirePermission(RolePermissionConstants.TenantAdminManageUsers)]
//     [HttpGet("users")]
//     public async Task<ActionResult<IEnumerable<TenantUserWithRolesDto>>> GetTenantUsers()
//     {
//         try
//         {
//             var tenantId = _tenantHelper.GetTenantId();
//
//             var usersWithRoles = await _oldUserService.GetTenantUsersWithNonGuestRoles(tenantId);
//
//             return Ok(usersWithRoles);
//         }
//         catch (Exception ex)
//         {
//             _logger.LogError(ex, "Error getting tenant users");
//             return BadRequest(ex.Message);
//         }
//     }
//
//     [RequireTenantAccess]
//     [RequirePermission(RolePermissionConstants.TenantManageBeaconConfig)]
//     [HttpGet("users/departmentLeads")]
//     public async Task<ActionResult<IEnumerable<UserEmailDto>>> GetDepartmentLeads()
//     {
//         try
//         {
//             var tenantId = _tenantHelper.GetTenantId();
//
//             var users = await _oldUserService.GetTenantUsersByRoleName(tenantId, "Department Lead");
//
//             var userEmailDtos = _mapper.Map<IEnumerable<UserEmailDto>>(users);
//
//             return Ok(userEmailDtos);
//         }
//         catch (Exception ex)
//         {
//             _logger.LogError(ex, "Error getting tenant users by role name");
//             return BadRequest(ex.Message);
//         }
//     }
//
//     [RequireTenantAccess]
//     [RequirePermission(RolePermissionConstants.TenantManageBeaconConfig)]
//     [HttpGet("users/departmentEmployees")]
//     public async Task<ActionResult<IEnumerable<UserEmailDto>>> GetDepartmentEmployees()
//     {
//         try
//         {
//             var tenantId = _tenantHelper.GetTenantId();
//
//             var users = await _oldUserService.GetTenantUsersByRoleName(tenantId, "Department Employee");
//
//             var userEmailDtos = _mapper.Map<IEnumerable<UserEmailDto>>(users);
//
//             return Ok(userEmailDtos);
//         }
//         catch (Exception ex)
//         {
//             _logger.LogError(ex, "Error getting tenant users by role name");
//             return BadRequest(ex.Message);
//         }
//     }
//
//     [RequireTenantAccess]
//     [RequirePermission(RolePermissionConstants.TenantAdminManageUsers)]
//     [HttpPost("user/add/role")]
//     public async Task<ActionResult> AddUserToTenant([FromBody] AddUserToRoleRequest request)
//     {
//         try
//         {
//             var tenantId = _tenantHelper.GetTenantId();
//
//             // Find user by email
//             var user = await _oldUserService.GetUserByEmail(request.Email);
//             if (user == null)
//                 return BadRequest("User not found");
//
//             var result = await _oldUserService.AddUserToRole(user.Id.ToString(), tenantId, request.RoleId.ToString());
//
//             if (result)
//             {
//                 _logger.LogInformation($"Added user {request.Email} to tenant {tenantId} with role {request.RoleId}");
//                 return Ok(new { Message = "User added to tenant successfully" });
//             }
//
//             return BadRequest("Failed to add user to tenant");
//         }
//         catch (Exception ex)
//         {
//             _logger.LogError(ex, "Error adding user to tenant");
//             return BadRequest(ex.Message);
//         }
//     }
//
//     [RequireTenantAccess]
//     [RequirePermission(RolePermissionConstants.TenantAdminManageUsers)]
//     [HttpPost("user/delete/role")]
//     public async Task<ActionResult> RemoveUserFromRole([FromBody] AddUserToRoleRequest request)
//     {
//         try
//         {
//             var tenantId = _tenantHelper.GetTenantId();
//
//             // Find user by email
//             var user = await _oldUserService.GetUserByEmail(request.Email);
//             if (user == null)
//                 return BadRequest("User not found");
//
//             var result = await _oldUserService.RemoveUserFromRole(user.Id.ToString(), tenantId, request.RoleId.ToString());
//
//             if (result)
//             {
//                 _logger.LogInformation($"Removed user {request.Email} from role {request.RoleId} in tenant {tenantId}");
//                 return Ok(new { Message = "User removed from role successfully" });
//             }
//
//             return BadRequest("Failed to remove user from role");
//         }
//         catch (Exception ex)
//         {
//             _logger.LogError(ex, "Error removing user from role");
//             return BadRequest(ex.Message);
//         }
//     }
//     
//     [RequireTenantAccess]
//     [RequirePermission(RolePermissionConstants.TenantAdminManageUsers)]
//     [HttpPost("invite")]
//     public async Task<ActionResult<InvitationResponse>> InviteUser([FromBody] InviteUserRequest request)
//     {
//         try
//         {
//             var userId = HttpContext.User.Claims.FirstOrDefault(x => x.Type == CommonConstants.ClaimUserId)?.Value 
//                 ?? throw new InvalidOperationException("No User Set");
//             
//             var tenantId = _tenantHelper.GetTenantId();
//             
//             // Override the tenant ID from the helper to ensure consistency
//             request.TenantId = tenantId;
//             
//             var result = await _oldUserService.InviteUserAsync(request, userId);
//             
//             if (result.Success)
//             {
//                 _logger.LogInformation("User invitation sent successfully for {Email} in tenant {TenantId}", 
//                     request.Email, tenantId);
//                 return Ok(result);
//             }
//             
//             return BadRequest(result);
//         }
//         catch (Exception ex)
//         {
//             _logger.LogError(ex, "Error sending user invitation for {Email}", request.Email);
//             return BadRequest(new InvitationResponse
//             {
//                 Success = false,
//                 Message = "Failed to send invitation"
//             });
//         }
//     }
//     
//     [RequireTenantAccess]
//     [RequirePermission(RolePermissionConstants.TenantAdminManageUsers)]
//     [HttpPost("exists")]
//     public async Task<ActionResult<UserExistenceCheckDto>> CheckUserExists([FromBody] CheckUserExistsRequest request)
//     {
//         try
//         {
//             var tenantId = _tenantHelper.GetTenantId();
//             
//             var result = await _oldUserService.CheckUserExistenceAsync(request.Email, tenantId);
//             
//             _logger.LogInformation("User existence check for {Email} in tenant {TenantId} - Found", request.Email, tenantId);
//             return Ok(result);
//         }
//         catch (NotFoundException ex)
//         {
//             _logger.LogInformation("User existence check for {Email} - Not found: {Message}", request.Email, ex.Message);
//             return NotFound(new { Message = ex.Message });
//         }
//         catch (Exception ex)
//         {
//             _logger.LogError(ex, "Error checking user existence for {Email}", request.Email);
//             return BadRequest(new { Message = "Failed to check user existence" });
//         }
//     }
//     
//     [RequireTenantAccess]
//     [RequirePermission(RolePermissionConstants.TenantAdminManageUsers)]
//     [HttpGet("invitations")]
//     public async Task<ActionResult<IEnumerable<UserInvitationDto>>> GetPendingInvitations()
//     {
//         try
//         {
//             var tenantId = _tenantHelper.GetTenantId();
//             
//             var pendingInvitations = await _oldUserService.GetPendingInvitationsAsync(tenantId);
//             
//             return Ok(_mapper.Map<IEnumerable<UserInvitationDto>>(pendingInvitations));
//         }
//         catch (Exception ex)
//         {
//             _logger.LogError(ex, "Error retrieving pending invitations");
//             return BadRequest(new { Message = "Failed to retrieve pending invitations" });
//         }
//     }
// }