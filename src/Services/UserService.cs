using System.Security.Cryptography;
using System.Text.Json;
using System.Web;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Caching.Memory;
using NetStarterCommon.Core.Common.Constants;
using NetStarterCommon.Core.Common.Services;
using PlatformApi.Data;
using PlatformApi.Models;
using PlatformApi.Models.DTOs;
using PlatformApi.Models.Messages;

namespace PlatformApi.Services;

public class UserService : IUserService
{
    private readonly ILogger<UserService> _logger;
    private readonly PlatformDbContext _context;
    private readonly IUnitOfWork<PlatformDbContext> _uow;
    private readonly ITenantService _tenantService;
    private readonly IPermissionService _permissionService;
    private readonly IMemoryCache _cache;
    private readonly ISnsService _snsService;
    private readonly IEmailService _emailService;
    private readonly IConfiguration _configuration;
    private readonly IBrandingService _brandingService;

    public UserService(ILogger<UserService> logger, PlatformDbContext context, IUnitOfWork<PlatformDbContext> uow,
        ITenantService tenantService, IPermissionService permissionService, IMemoryCache cache, ISnsService snsService, 
        IEmailService emailService, IConfiguration configuration, IBrandingService brandingService)
    {
        _logger = logger;
        _context = context;
        _uow = uow;
        _tenantService = tenantService;
        _permissionService = permissionService;
        _cache = cache;
        _snsService = snsService;
        _emailService = emailService;
        _configuration = configuration;
        _brandingService = brandingService;
    }

    public async Task<IEnumerable<AuthRole>> GetUserRoles(string userId, Guid? tenantId)
    {
        var roles = new List<AuthRole>();

        var defaultRole = _context.Roles.FirstOrDefault(x => x.Name == "Default");

        if (defaultRole != null)
        {
            roles.Add(defaultRole);
        }

        if (tenantId.HasValue)
        {
            var tenantRoles = await
                (from userTenantRole in _context.UserTenantRoles
                    join role in _context.Roles on userTenantRole.UserRoleId equals role.Id
                    where userTenantRole.UserId == userId
                    where userTenantRole.TenantId == tenantId
                    select new AuthRole
                    {
                        Id = role.Id,
                        Name = role.Name,
                        IsAdmin = role.IsAdmin
                    }).Distinct().ToListAsync();

            roles.AddRange(tenantRoles);
        }
        
        var adminRoles = await GetUserAdminRoles(userId);
        roles.AddRange(adminRoles);

        return roles;
    }

    public async Task<IEnumerable<Permission>?> GetUserPermissions(string userId, Guid? tenantId)
    {
        var cacheKey = GetCacheKey(userId, tenantId);

        if (!_cache.TryGetValue(cacheKey, out List<Permission>? userPermissions))
        {
            _logger.LogInformation($"Fetching new user permissions - {cacheKey}");

            userPermissions = await FetchUserPermissions(userId, tenantId);

            var cacheOptions = new MemoryCacheEntryOptions()
                .SetSlidingExpiration(TimeSpan.FromMinutes(10)) // Adjust expiration as needed
                .SetAbsoluteExpiration(TimeSpan.FromMinutes(45));

            _cache.Set(cacheKey, userPermissions, cacheOptions);
        }

        return userPermissions;
    }

    private string GetCacheKey(string userId, Guid? tenantId)
    {
        string cacheKey = $"Perms-{userId}";
        if (tenantId.HasValue)
        {
            cacheKey += $"-{tenantId}";
        }
        return cacheKey;
    }
    
    public bool InvalidateUserPermissions(string userId, Guid? tenantId = null)
    {
        _logger.LogInformation($"Invalidating Cache Perms for - {userId}");
        //remove non tenant cache too
        if (tenantId.HasValue)
        {
            var cacheUserKey = GetCacheKey(userId, null);
            _cache.Remove(cacheUserKey);
        }
        var cacheKey = GetCacheKey(userId, tenantId);
        _cache.Remove(cacheKey);
        return true;
    }
    
    
    public async Task<IEnumerable<Tenant?>> GetUserTenants(string userId)
    {
        var tenants = await _context.UserTenants
            .Where(utr => utr.UserId == userId)
            .Include(utr => utr.Tenant)
            .Select(utr => utr.Tenant)
            .Distinct()
            .ToListAsync();

        return tenants;
    }

    private async Task<List<Permission>> FetchUserPermissions(string userId, Guid? tenantId)
    {
        var perms = new List<Permission>();
        var defaultPermissions = await (
            from permission in _context.Permissions
            where permission.IsDefaultFlg == true
            select new Permission
            {
                Code = permission.Code
            }).ToListAsync();

        perms.AddRange(defaultPermissions);

        if (tenantId.HasValue)
        {
            var tenantPermissions = await
                (from userTenantRole in _context.UserTenantRoles
                    join role in _context.Roles on userTenantRole.UserRoleId equals role.Id
                    join rolePermission in _context.RolePermissions on role.Id equals rolePermission.UserRoleId
                    join permission in _context.Permissions on rolePermission.PermissionCode equals permission.Code
                    where userTenantRole.UserId == userId
                    where userTenantRole.TenantId == tenantId
                    select new Permission
                    {
                        Code = permission.Code
                    }).Distinct().ToListAsync();

            perms.AddRange(tenantPermissions);
        }

        var adminPermissions = await
            (from userRole in _context.UserRoles
                join role in _context.Roles on userRole.RoleId equals role.Id
                join rolePermission in _context.RolePermissions on role.Id equals rolePermission.UserRoleId
                join permission in _context.Permissions on rolePermission.PermissionCode equals permission.Code
                where userRole.UserId == userId
                where role.IsAdmin == true
                select new Permission
                {
                    Code = permission.Code
                }).Distinct().ToListAsync();
        
        perms.AddRange(adminPermissions);


        return perms;
    }

    public async Task<bool> DoesUserHavePermission(string userId, string checkPermission, Guid? tenantId)
    {
        var perms = await GetUserPermissions(userId, tenantId);

        return perms?.Any(p => p.Code.Equals(checkPermission, StringComparison.OrdinalIgnoreCase)) ?? false;
    }

    public async Task<bool> AddUserToRole(string userId, Guid tenantId, string roleId)
    {
        // Ensure tenant exists
        var tenant = await _tenantService.GetById(tenantId);
        if (tenant == null)
            throw new NotFoundException("Tenant not Found");

        // Ensure user exists
        var user = await _context.Users.FindAsync(userId);
        if (user == null)
            throw new NotFoundException("User not found");

        // Ensure role exists and is not admin
        var role = await _permissionService.GetRoleById(roleId, true);
        if (role == null)
            throw new NotFoundException($"Role with ID {roleId} does not exist");
        if (role.IsAdmin)
            throw new Exception("Cannot add user to AdminRole");

        // Auto-create UserTenant if it doesn't exist
        var userTenant = await _context.UserTenants
            .FirstOrDefaultAsync(ut => ut.UserId == userId && ut.TenantId == tenantId);

        if (userTenant == null)
        {
            userTenant = new UserTenant
            {
                UserId = userId,
                TenantId = tenantId
            };
            _context.UserTenants.Add(userTenant);
            await _uow.CompleteAsync(); // Save to get the UserTenant created
        }

        // Check if user already has this role
        var existingRole = await _context.UserTenantRoles
            .FirstOrDefaultAsync(utr => utr.UserId == userId &&
                                        utr.TenantId == tenantId &&
                                        utr.UserRoleId == roleId);

        if (existingRole != null)
            throw new ArgumentException("User already has this role");

        // Add the role
        var newUserRole = new UserTenantRole
        {
            TenantId = tenantId,
            UserRoleId = roleId,
            UserId = userId
        };

        _context.UserTenantRoles.Add(newUserRole);
        await _uow.CompleteAsync();

        //invalidate cached permissions
        InvalidateUserPermissions(userId, tenantId);
        
        return true;
    }

    public async Task<bool> AddUserToTenant(string userId, Guid tenantId)
    {
        // Ensure tenant
        var tenant = await _tenantService.GetById(tenantId);

        if (tenant == null)
        {
            throw new NotFoundException($"Tenant not Found");
        }

        // Retrieve the role by its ID
        var user = await _context.Users.Where(u => u.Id == userId).FirstOrDefaultAsync();

        if (user == null)
        {
            throw new NotFoundException($"User with ID {userId} does not exist.");
        }

        var alreadyExists = await _context.UserTenants.Where(u => u.UserId == userId && u.TenantId == tenantId)
            .FirstOrDefaultAsync();

        if (alreadyExists != null)
        {
            throw new ArgumentException($"User already exists on tenant.");
        }

        //add user to role
        var newUserTenant = new UserTenant()
        {
            TenantId = tenantId,
            UserId = userId
        };

        _context.UserTenants.Add(newUserTenant);
        await _uow.CompleteAsync();
        _logger.LogInformation($"Added user:{userId} to tenant - {tenantId}");
        return true;
    }

    public async Task<bool> AddUserToAdminRole(string userId, string roleId)
    {
        // Retrieve the role by its ID
        var role = await _permissionService.GetRoleById(roleId, true);

        if (role == null)
        {
            throw new NotFoundException($"Role with ID {roleId} does not exist.");
        }

        if (!role.IsAdmin)
        {
            throw new Exception($"Wrong role");
        }

        // Retrieve the role by its ID
        var user = await _context.Users.Where(u => u.Id == userId).FirstOrDefaultAsync();

        if (user == null)
        {
            throw new NotFoundException($"User with ID {userId} does not exist.");
        }

        //might want to send email on this.  toDo 

        //add user to role
        var newUserRole = new IdentityUserRole<string>()
        {
            UserId = userId,
            RoleId = roleId
        };

        _context.UserRoles.Add(newUserRole);
        await _uow.CompleteAsync();

        return true;
    }

    private async Task<IEnumerable<AuthRole>> GetUserAdminRoles(string userId)
    {
        var adminRoles = await
            (from role in _context.Roles
                join userRole in _context.UserRoles on role.Id equals userRole.RoleId
                where userRole.UserId == userId
                where role.IsAdmin == true
                select new AuthRole
                {
                    Id = role.Id,
                    Name = role.Name,
                    IsAdmin = role.IsAdmin
                }).Distinct().ToListAsync();

        return adminRoles;
    }

    public async Task<IEnumerable<AuthUser>> GetTenantUsers(Guid tenantId, bool includeRoles = false)
    {
        var query = from userTenant in _context.UserTenants
            join user in _context.Users on userTenant.UserId equals user.Id
            where userTenant.TenantId == tenantId
            select user;

        var users = await query.Distinct().ToListAsync();

        // if (includeRoles)
        // {
        //     // Load roles for each user
        //     foreach (var user in users)
        //     {
        //         var userRoles = await GetUserRoles(user.Id, tenantId);
        //         // Note: You might want to create a UserWithRolesDto to include roles in the response
        //         // For now, this method just returns users, roles will be handled in the controller
        //     }
        // }

        return users;
    }
    
    public async Task<IEnumerable<TenantUserWithRolesDto>> GetTenantUsersWithNonGuestRoles(Guid tenantId)
    {
        // Query to get users who have non-guest roles in the tenant
        var usersWithRoles = await (
            from userTenantRole in _context.UserTenantRoles
            join user in _context.Users on userTenantRole.UserId equals user.Id
            join role in _context.Roles on userTenantRole.UserRoleId equals role.Id
            where userTenantRole.TenantId == tenantId
            where role.Id != AuthApiConstants.GUEST_ROLE // Exclude guest roles
            select new
            {
                UserId = user.Id,
                UserEmail = user.Email,
                RoleId = role.Id,
                RoleName = role.Name,
                RoleIsAdmin = role.IsAdmin
            }).ToListAsync();

        // Group by user and create the result DTOs
        var result = usersWithRoles
            .GroupBy(x => new { x.UserId, x.UserEmail })
            .Select(group => new TenantUserWithRolesDto
            {
                UserId = group.Key.UserId,
                Email = group.Key.UserEmail!,
                Roles = group.Select(r => new RoleNoPermissionDto()
                {
                    Id = r.RoleId,
                    Name = r.RoleName!
                }).ToList()
            })
            .ToList();

        return result;
    }

    public async Task<bool> RemoveUserFromRole(string userId, Guid tenantId, string roleId)
    {
        // Ensure tenant exists
        var tenant = await _tenantService.GetById(tenantId);
        if (tenant == null)
            throw new NotFoundException("Tenant not Found");

        // Ensure user exists
        var user = await _context.Users.FindAsync(userId);
        if (user == null)
            throw new NotFoundException("User not found");

        // Ensure role exists
        var role = await _permissionService.GetRoleById(roleId, true);
        if (role == null)
            throw new NotFoundException($"Role with ID {roleId} does not exist");

        // Find the user tenant role record
        var userTenantRole = await _context.UserTenantRoles
            .FirstOrDefaultAsync(utr => utr.UserId == userId &&
                                        utr.TenantId == tenantId &&
                                        utr.UserRoleId == roleId);

        if (userTenantRole == null)
            throw new ArgumentException("User does not have this role");

        // Remove the role
        _context.UserTenantRoles.Remove(userTenantRole);
        await _uow.CompleteAsync();

        //invalidate cached permissions
        InvalidateUserPermissions(userId, tenantId);
        
        _logger.LogInformation($"Removed user:{userId} from role:{roleId} in tenant:{tenantId}");
        return true;
    }

    public async Task<AuthUser?> GetUserByEmail(string email)
    {
        return await _context.Users.FirstOrDefaultAsync(u => u.Email == email);
    }
    
    public async Task<IEnumerable<AuthRole>> GetUserRolesExcludingGuest(string userId, Guid? tenantId)
    {
        var roles = new List<AuthRole>();

        // Get non-guest roles only
        if (tenantId.HasValue)
        {
            var tenantRoles = await
                (from userTenantRole in _context.UserTenantRoles
                    join role in _context.Roles on userTenantRole.UserRoleId equals role.Id
                    where userTenantRole.UserId == userId
                    where userTenantRole.TenantId == tenantId
                    where role.Id != AuthApiConstants.GUEST_ROLE // Exclude Guest role
                    select new AuthRole
                    {
                        Id = role.Id,
                        Name = role.Name,
                        IsAdmin = role.IsAdmin
                    }).Distinct().ToListAsync();

            roles.AddRange(tenantRoles);
        }

        // Still include admin roles (these are not tenant-specific guest roles)
        var adminRoles = await GetUserAdminRoles(userId);
        roles.AddRange(adminRoles);
    
        return roles;
    }

    public async Task<IEnumerable<AuthUser>> GetTenantUsersByRoleName(Guid tenantId, string roleName)
    {
        // Query to get users who have the specified role in the tenant
        var users = await (
            from userTenantRole in _context.UserTenantRoles
            join user in _context.Users on userTenantRole.UserId equals user.Id
            join role in _context.Roles on userTenantRole.UserRoleId equals role.Id
            where userTenantRole.TenantId == tenantId
            where EF.Functions.Like(role.Name, roleName)
            select user
            ).Distinct().ToListAsync();

        return users;
    }

    public async Task PublishUserModifiedAsync(string userId, string email)
    {
        var userModifiedMessage = new UserModifiedMessage
        {
            UserId = userId,
            Email = email
        };
        await _snsService.PublishUserModifiedAsync(userModifiedMessage);
    }
    
    public async Task<InvitationResponse> InviteUserAsync(InviteUserRequest request, string invitedByUserId)
    {
        try
        {
            // Check if user already exists
            var existingUser = await GetUserByEmail(request.Email);
            if (existingUser != null)
            {
                return new InvitationResponse
                {
                    Success = false,
                    Message = "User with this email already exists"
                };
            }
            
            // Check if there's already a pending invitation for this email/tenant
            var existingInvitation = await _context.UserInvitations
                .FirstOrDefaultAsync(ui => ui.Email == request.Email 
                                    && ui.TenantId == request.TenantId 
                                    && !ui.IsUsed 
                                    && ui.ExpiresAt > DateTime.UtcNow);
            
            if (existingInvitation != null)
            {
                return new InvitationResponse
                {
                    Success = false,
                    Message = "Pending invitation already exists for this user"
                };
            }
            
            // Generate secure invitation token
            var invitationToken = GenerateSecureToken();
            
            // Serialize roles to JSON if provided
            string? rolesJson = null;
            if (request.RoleIds != null && request.RoleIds.Any())
            {
                rolesJson = JsonSerializer.Serialize(request.RoleIds);
            }
            
            // Create invitation record
            var invitation = new UserInvitation
            {
                Email = request.Email,
                TenantId = request.TenantId,
                InvitationToken = invitationToken,
                InvitedRoles = rolesJson,
                ExpiresAt = DateTime.UtcNow.AddDays(7), // 7 day expiration
                IsUsed = false
            };
            
            _context.UserInvitations.Add(invitation);
            await _uow.CompleteAsync();
            
            // Get branding context for tenant-specific URL
            var branding = await _brandingService.GetBrandingContextAsync(null, request.TenantId);
            
            // Build invitation URL (similar to password reset pattern)
            var encodedToken = HttpUtility.UrlEncode(invitationToken);
            var encodedEmail = HttpUtility.UrlEncode(request.Email);
            var invitationUrl = $"{branding.BaseUrl}/register-invitation?token={encodedToken}&email={encodedEmail}";
            
            // Send invitation email
            await _emailService.SendTenantInvitationEmailAsync(request.Email, invitationUrl, request.Email, branding);
            
            _logger.LogInformation("User invitation created for {Email} by {InvitedBy}", request.Email, invitedByUserId);
            
            return new InvitationResponse
            {
                Success = true,
                Message = "Invitation sent successfully",
                InvitationId = invitation.Id
            };
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error creating invitation for {Email}", request.Email);
            return new InvitationResponse
            {
                Success = false,
                Message = "Failed to send invitation"
            };
        }
    }
    
    public async Task<UserInvitation?> ValidateInvitationTokenAsync(string token)
    {
        var invitation = await _context.UserInvitations
            .FirstOrDefaultAsync(ui => ui.InvitationToken == token 
                                && !ui.IsUsed 
                                && ui.ExpiresAt > DateTime.UtcNow);
        
        return invitation;
    }
    
    public async Task<UserExistenceCheckDto> CheckUserExistenceAsync(string email, Guid tenantId)
    {
        // Check if user exists
        var user = await GetUserByEmail(email);
        if (user == null)
        {
            throw new NotFoundException($"User with email '{email}' not found");
        }
        
        // Get user roles for this tenant (even if user is not in tenant, will return empty roles)
        var roles = await GetUserRoles(user.Id, tenantId);
        
        return new UserExistenceCheckDto
        {
            Email = user.Email!,
            Roles = roles.Select(r => new RoleNoPermissionDto
            {
                Id = r.Id,
                Name = r.Name!,
            }).ToList()
        };
    }
    
    public async Task<IEnumerable<UserInvitation>> GetPendingInvitationsAsync(Guid tenantId)
    {
        return await _context.UserInvitations
            .Where(ui => ui.TenantId == tenantId 
                      && !ui.IsUsed 
                      && ui.ExpiresAt > DateTime.UtcNow)
            .OrderByDescending(ui => ui.CreateDate)
            .ToListAsync();
    }
    
    private static string GenerateSecureToken()
    {
        using var rng = RandomNumberGenerator.Create();
        var tokenBytes = new byte[32];
        rng.GetBytes(tokenBytes);
        return Convert.ToBase64String(tokenBytes).Replace("+", "-").Replace("/", "_").Replace("=", "");
    }
    
}