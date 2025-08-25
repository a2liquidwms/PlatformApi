using AutoMapper;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using PlatformApi.Common.Constants;
using PlatformApi.Common.Permissions;
using PlatformApi.Common.Services;
using PlatformApi.Data;
using PlatformApi.Models;
using PlatformApi.Models.DTOs;
using System.Security.Cryptography;
using System.Text;

namespace PlatformApi.Services;

public class UserService : IUserService
{
    private readonly PlatformDbContext _context;
    private readonly UserManager<AuthUser> _userManager;
    private readonly IMapper _mapper;
    private readonly ILogger<UserService> _logger;
    private readonly IUnitOfWork<PlatformDbContext> _uow;
    private readonly PermissionHelper _permissionHelper;
    private readonly ICacheService _cache;

    public UserService(
        PlatformDbContext context,
        UserManager<AuthUser> userManager,
        IMapper mapper,
        ILogger<UserService> logger,
        IUnitOfWork<PlatformDbContext> uow,
        PermissionHelper permissionHelper,
        ICacheService cache)
    {
        _context = context;
        _userManager = userManager;
        _mapper = mapper;
        _logger = logger;
        _uow = uow;
        _permissionHelper = permissionHelper;
        _cache = cache;
    }

    public async Task<IEnumerable<TenantUserWithRolesDto>> GetTenantUsers(Guid tenantId)
    {
        // Get all users with tenant-scoped roles for this tenant
        var usersWithRoles = await _context.UserRoles
            .Where(ur => ur.TenantId == tenantId && ur.Scope == RoleScope.Tenant)
            .Include(ur => ur.User)
            .GroupBy(ur => ur.User)
            .ToListAsync();

        var result = new List<TenantUserWithRolesDto>();
        
        foreach (var userGroup in usersWithRoles)
        {
            var user = userGroup.Key!;
            var roles = await GetUserRoles(user.Id, RoleScope.Tenant, tenantId);
            var roleNoPerm = _mapper.Map<List<RoleNoPermissionDto>>(roles);
            
            result.Add(new TenantUserWithRolesDto
            {
                UserId = user.Id,
                Email = user.Email!,
                Roles = roleNoPerm
            });
        }

        return result;
    }

    public async Task<IEnumerable<SiteUserWithRolesDto>> GetSiteUsers(Guid siteId)
    {
        // Get all users with site-scoped roles for this site
        var usersWithRoles = await _context.UserRoles
            .Where(ur => ur.SiteId == siteId && ur.Scope == RoleScope.Site)
            .Include(ur => ur.User)
            .GroupBy(ur => ur.User)
            .ToListAsync();

        var result = new List<SiteUserWithRolesDto>();
        
        foreach (var userGroup in usersWithRoles)
        {
            var user = userGroup.Key!;
            var roles = await GetUserRoles(user.Id, RoleScope.Site, siteId: siteId);
            var roleNoPerm = _mapper.Map<List<RoleNoPermissionDto>>(roles);
            
            result.Add(new SiteUserWithRolesDto
            {
                UserId = user.Id,
                Email = user.Email!,
                SiteId = siteId,
                Roles = roleNoPerm
            });
        }

        return result;
    }

    public async Task<IEnumerable<InternalUserWithRolesDto>> GetInternalUsers()
    {
        var usersWithRoles = await _context.UserRoles
            .Where(ur => ur.Scope == RoleScope.Internal)
            .Include(ur => ur.User)
            .Include(ur => ur.Role)
            .Where(ur => ur.User != null && ur.User.Email != null)
            .GroupBy(ur => new { ur.UserId, ur.User!.Email })
            .Select(g => new InternalUserWithRolesDto
            {
                UserId = g.Key.UserId,
                Email = g.Key.Email!,
                Roles = g.Select(ur => new RoleNoPermissionDto
                {
                    Id = ur.Role!.Id.ToString(),
                    Name = ur.Role.Name
                }).ToList()
            })
            .ToListAsync();

        return usersWithRoles;
    }

    public async Task<bool> AddUserToTenant(AddUserToTenantDto dto)
    {
        var user = await GetUserByEmail(dto.Email);
        if (user == null) return false;

        // Add role if specified, otherwise add default tenant role
        string roleId = dto.RoleId;
        if (string.IsNullOrEmpty(roleId))
        {
            // Get default tenant role
            var defaultRole = await _context.Roles
                .FirstOrDefaultAsync(r => r.Scope == RoleScope.Tenant && r.IsSystemRole);
            if (defaultRole == null) throw new NotFoundException("No default tenant role found");
            roleId = defaultRole.Id.ToString();
        }

        var roleDto = new AddUserToRoleDto
        {
            Email = dto.Email,
            TenantId = dto.TenantId,
            RoleId = roleId,
            Scope = RoleScope.Tenant
        };
        
        await AddUserToRole(roleDto);
        await _uow.CompleteAsync();
        return true;
    }

    public async Task<bool> AddUserToSite(AddUserToSiteDto dto)
    {
        var user = await GetUserByEmail(dto.Email);
        if (user == null) return false;

        // Get site to ensure it exists and get tenant info
        var site = await _context.Sites
            .FirstOrDefaultAsync(s => s.Id == dto.SiteId);
        if (site == null) return false;

        // Add role if specified, otherwise add default site role
        string roleId;
        if (dto.RoleId.HasValue)
        {
            roleId = dto.RoleId.Value.ToString();
        }
        else
        {
            // Get default site role
            var defaultRole = await _context.Roles
                .FirstOrDefaultAsync(r => r.Scope == RoleScope.Site && r.IsSystemRole);
            if (defaultRole == null) throw new NotFoundException("No default site role found");
            roleId = defaultRole.Id.ToString();
        }

        var roleDto = new AddUserToRoleDto
        {
            Email = dto.Email,
            TenantId = site.TenantId,
            SiteId = dto.SiteId,
            RoleId = roleId,
            Scope = RoleScope.Site
        };
        
        await AddUserToRole(roleDto);
        await _uow.CompleteAsync();
        return true;
    }

    public async Task<bool> AddUserToRole(AddUserToRoleDto dto)
    {
        var user = await GetUserByEmail(dto.Email);
        if (user == null) throw new NotFoundException("User not found");

        // Validate role exists and matches scope
        var role = await _context.Roles.FirstOrDefaultAsync(r => r.Id == Guid.Parse(dto.RoleId));
        if (role == null) throw new NotFoundException("Role not found");
        if (role.Scope != dto.Scope) throw new InvalidDataException("Role scope mismatch");


        // Check if assignment already exists
        var existingAssignment = await _context.UserRoles
            .FirstOrDefaultAsync(ura => ura.UserId == user.Id && 
                                       ura.RoleId == Guid.Parse(dto.RoleId) &&
                                       ura.TenantId == dto.TenantId &&
                                       ura.SiteId == dto.SiteId &&
                                       ura.Scope == dto.Scope);

        if (existingAssignment != null) throw new InvalidDataException("User is already assigned to this role");

        var roleAssignment = new UserRoles
        {
            UserId = user.Id,
            RoleId = Guid.Parse(dto.RoleId),
            TenantId = dto.TenantId,
            SiteId = dto.SiteId,
            Scope = dto.Scope
        };

        await _context.UserRoles.AddAsync(roleAssignment);
        await _uow.CompleteAsync();
        return true;
    }

    public async Task<bool> AddUserToRole(AddUserToRoleDto dto, RoleScope expectedScope)
    {
        var user = await GetUserByEmail(dto.Email);
        if (user == null) throw new NotFoundException("User not found");

        // Validate role exists and matches expected scope
        var role = await _context.Roles.FirstOrDefaultAsync(r => r.Id == Guid.Parse(dto.RoleId));
        if (role == null) throw new NotFoundException("Role not found");
        if (role.Scope != expectedScope) throw new InvalidDataException($"Role is not a {expectedScope} scope role");

        // Ensure the DTO scope matches expected scope
        if (dto.Scope != expectedScope) throw new InvalidDataException($"DTO scope must be {expectedScope}");


        // Check if assignment already exists
        var existingAssignment = await _context.UserRoles
            .FirstOrDefaultAsync(ura => ura.UserId == user.Id && 
                                       ura.RoleId == Guid.Parse(dto.RoleId) &&
                                       ura.TenantId == dto.TenantId &&
                                       ura.SiteId == dto.SiteId &&
                                       ura.Scope == dto.Scope);

        if (existingAssignment != null) throw new InvalidDataException("User is already assigned to this role");

        var roleAssignment = new UserRoles
        {
            UserId = user.Id,
            RoleId = Guid.Parse(dto.RoleId),
            TenantId = dto.TenantId,
            SiteId = dto.SiteId,
            Scope = dto.Scope
        };

        await _context.UserRoles.AddAsync(roleAssignment);
        await _uow.CompleteAsync();
        return true;
    }


    public async Task RemoveUserFromRole(RemoveUserFromRoleDto dto, RoleScope expectedScope)
    {
        var user = await GetUserByEmail(dto.Email);
        if (user == null)
            throw new NotFoundException($"User with email {dto.Email} not found");

        // First verify the role exists and matches the expected scope
        var role = await _context.Roles.FirstOrDefaultAsync(r => r.Id == dto.RoleId);
        if (role == null)
            throw new NotFoundException($"Role with ID {dto.RoleId} not found");

        if (role.Scope != expectedScope)
            throw new InvalidDataException($"Role {role.Name} is not a {expectedScope.ToString().ToLower()} role");

        // Validate that the DTO scope matches the expected scope
        if (dto.Scope != expectedScope)
            throw new InvalidDataException($"Request scope {dto.Scope} does not match expected scope {expectedScope}");

        var assignment = await _context.UserRoles
            .FirstOrDefaultAsync(ura => ura.UserId == user.Id && 
                                       ura.RoleId == dto.RoleId &&
                                       ura.TenantId == dto.TenantId &&
                                       ura.SiteId == dto.SiteId &&
                                       ura.Scope == expectedScope);

        if (assignment == null)
            throw new NotFoundException("User role assignment not found");

        _context.UserRoles.Remove(assignment);
        await _uow.CompleteAsync();
    }

    public async Task<AuthUser?> GetUserByEmail(string email)
    {
        return await _userManager.FindByEmailAsync(email);
    }

    public async Task<IEnumerable<Role>> GetUserRoles(Guid userId, RoleScope scope, Guid? tenantId = null, Guid? siteId = null)
    {
        var query = _context.UserRoles
            .Where(ura => ura.UserId == userId && ura.Scope == scope);

        if (tenantId.HasValue)
            query = query.Where(ura => ura.TenantId == tenantId);
            
        if (siteId.HasValue)
            query = query.Where(ura => ura.SiteId == siteId);

        var roleIds = await query.Select(ura => ura.RoleId).ToListAsync();
        
        return await _context.Roles
            .Where(r => roleIds.Contains(r.Id))
            .ToListAsync();
    }

    public async Task<IEnumerable<Permission>?> GetUserPermissions(Guid userId, Guid? tenantId = null, Guid? siteId = null)
    {
        // Get all role assignments for user with hierarchical priority
        var assignments = await _context.UserRoles
            .Where(ura => ura.UserId == userId)
            .Include(ura => ura.Role)
            .ThenInclude(r => r!.RolePermissions)!
            .ThenInclude(rp => rp.Permission)
            .ToListAsync();

        // Filter based on context and apply hierarchy (Internal > Tenant > Site)
        var contextualAssignments = assignments.Where(a => 
            a.Scope == RoleScope.Internal ||
            (a.Scope == RoleScope.Tenant && a.TenantId == tenantId) ||
            (a.Scope == RoleScope.Site && a.SiteId == siteId && a.TenantId == tenantId)
        ).ToList();

        var allPermissions = contextualAssignments
            .SelectMany(a => a.Role?.RolePermissions?.Select(rp => rp.Permission) ?? Enumerable.Empty<Permission>())
            .Where(p => p != null)
            .Distinct()
            .ToList();

        return allPermissions!;
    }

    public async Task<IEnumerable<TenantDto>> GetUserTenants(Guid userId, bool forLogin = false)
    {
        // Check if user is system admin - use appropriate method based on context
        bool isSystemAdmin = forLogin 
            ? await IsSystemAdminByRoles(userId)
            : _permissionHelper.HasPermission(RolePermissionConstants.SysAdminManageTenants);

        if (isSystemAdmin)
        {
            var logContext = forLogin ? "login" : "normal";
            _logger.LogDebug("System admin access ({Context}) - returning fresh data for all tenants, user {UserId}", logContext, userId);
            var allTenants = await _context.Tenants
                .Select(t => new TenantDto 
                { 
                    Id = t.Id, 
                    Name = t.Name, 
                    Code = t.Code, 
                    SubDomain = t.SubDomain 
                })
                .ToListAsync();
            return allTenants;
        }
        
        // For login, skip caching and return fresh data
        if (forLogin)
        {
            var tenants = await _context.UserRoles
                .Where(ur => ur.UserId == userId && ur.TenantId != null && ur.Scope == RoleScope.Tenant)
                .Include(ur => ur.Tenant)
                .Select(ur => new TenantDto 
                { 
                    Id = ur.Tenant!.Id, 
                    Name = ur.Tenant!.Name, 
                    Code = ur.Tenant!.Code, 
                    SubDomain = ur.Tenant!.SubDomain 
                })
                .Distinct()
                .ToListAsync();
            return tenants;
        }

        // Regular users get cached results for performance (post-authentication)
        var cachedTenants = await _cache.GetCachedUserTenantsAsync(userId);
        if (cachedTenants != null)
        {
            _logger.LogDebug("Cache hit for user tenants: {UserId}", userId);
            return cachedTenants;
        }

        _logger.LogDebug("Cache miss for user tenants, querying database: {UserId}", userId);
        
        // Get all tenants where user has tenant-scoped roles
        var userTenants = await _context.UserRoles
            .Where(ur => ur.UserId == userId && ur.TenantId != null && ur.Scope == RoleScope.Tenant)
            .Include(ur => ur.Tenant)
            .Select(ur => new TenantDto 
            { 
                Id = ur.Tenant!.Id, 
                Name = ur.Tenant!.Name, 
                Code = ur.Tenant!.Code, 
                SubDomain = ur.Tenant!.SubDomain 
            })
            .Distinct()
            .ToListAsync();

        // Cache the results for regular users
        await _cache.SetCachedUserTenantsAsync(userId, userTenants);
        _logger.LogDebug("Cached {TenantCount} tenants for user {UserId}", userTenants.Count(), userId);
            
        return userTenants;
    }

    public async Task<IEnumerable<SiteDto>> GetUserSites(Guid userId, Guid tenantId, bool forLogin = false)
    {
        // Check if user has access to all sites in this tenant
        bool hasAllSitesAccess = await IsTenantAccessAllSites(userId, tenantId);

        if (hasAllSitesAccess)
        {
            var logContext = forLogin ? "login" : "normal";
            _logger.LogDebug("All-sites access ({Context}) - returning all sites for tenant {TenantId}, user {UserId}", logContext, tenantId, userId);
            var allSites = await _context.Sites
                .Where(s => s.IsActive && s.TenantId == tenantId)
                .Select(s => new SiteDto 
                { 
                    Id = s.Id, 
                    Code = s.Code,
                    Name = s.Name, 
                    TenantId = s.TenantId,
                    IsActive = s.IsActive 
                }).ToListAsync();
            
            return allSites;
        }

        // For login, skip caching and return fresh data
        if (forLogin)
        {
            _logger.LogDebug("Regular user login - querying assigned sites for tenant {TenantId}, user {UserId}", tenantId, userId);
            var loginSites = await _context.UserRoles
                .Where(ur => ur.UserId == userId && ur.TenantId == tenantId && ur.SiteId != null && ur.Scope == RoleScope.Site)
                .Include(ur => ur.Site)
                .Where(ur => ur.Site!.IsActive)
                .Select(ur => new SiteDto 
                { 
                    Id = ur.Site!.Id, 
                    Code = ur.Site!.Code,
                    Name = ur.Site!.Name, 
                    TenantId = ur.Site!.TenantId,
                    IsActive = ur.Site!.IsActive 
                })
                .Distinct()
                .ToListAsync();
            
            return loginSites;
        }

        // Regular users get cached results for performance (post-authentication)
        var cachedSites = await _cache.GetCachedUserSitesAsync(userId, tenantId);
        if (cachedSites != null)
        {
            _logger.LogDebug("Cache hit for user sites: {UserId}, tenant {TenantId}", userId, tenantId);
            return cachedSites;
        }

        _logger.LogDebug("Cache miss for user sites, querying database: {UserId}, tenant {TenantId}", userId, tenantId);
        
        // Get all sites where user has site-scoped roles within the specified tenant (site must be active)
        var siteDtos = await _context.UserRoles
            .Where(ur => ur.UserId == userId && ur.TenantId == tenantId && ur.SiteId != null && ur.Scope == RoleScope.Site)
            .Include(ur => ur.Site)
            .Where(ur => ur.Site!.IsActive)
            .Select(ur => new SiteDto 
            { 
                Id = ur.Site!.Id, 
                Code = ur.Site!.Code,
                Name = ur.Site!.Name, 
                TenantId = ur.Site!.TenantId,
                IsActive = ur.Site!.IsActive 
            })
            .Distinct()
            .ToListAsync();

        // Cache the results for regular users
        await _cache.SetCachedUserSitesAsync(userId, tenantId, siteDtos);
        _logger.LogDebug("Cached {SiteCount} sites for user {UserId}, tenant {TenantId}", siteDtos.Count, userId, tenantId);
            
        return siteDtos;
    }

    public async Task<int> GetUserTenantCount(Guid userId)
    {
        // Always use forLogin=true behavior for system admin check
        bool isSystemAdmin = await IsSystemAdminByRoles(userId);

        if (isSystemAdmin)
        {
            // System admin has access to all tenants
            return await _context.Tenants.CountAsync();
        }

        // Regular user - count tenants they have roles in
        return await _context.UserRoles
            .Where(ur => ur.UserId == userId && ur.TenantId != null && ur.Scope == RoleScope.Tenant)
            .Select(ur => ur.TenantId)
            .Distinct()
            .CountAsync();
    }

    public async Task<int> GetUserSiteCount(Guid userId, Guid tenantId)
    {
        // Check if user has access to all sites in this tenant (system admin or tenant-level all-sites access)
        bool hasAllSitesAccess = await IsTenantAccessAllSites(userId, tenantId);

        if (hasAllSitesAccess)
        {
            // User has access to all sites in the specified tenant
            return await _context.Sites
                .Where(s => s.TenantId == tenantId)
                .CountAsync();
        }

        // Regular user - count sites they have roles in within the specified tenant
        return await _context.UserRoles
            .Where(ur => ur.UserId == userId && ur.TenantId == tenantId && ur.SiteId != null && ur.Scope == RoleScope.Site)
            .Select(ur => ur.SiteId)
            .Distinct()
            .CountAsync();
    }

    public async Task<bool> HasTenantAccess(Guid userId, Guid tenantId, bool forLogin = false)
    {
        // Leverage GetUserTenants which already handles system admin permissions and caching
        var tenantDtos = await GetUserTenants(userId, forLogin);
        var tenantIds = tenantDtos.Where(t => t.Id.HasValue).Select(t => t.Id!.Value);
        return tenantIds.Contains(tenantId);
    }

    public async Task<bool> HasSiteAccess(Guid userId, Guid siteId, Guid tenantId, bool forLogin = false)
    {
        // Leverage GetUserSites which already handles system admin permissions  
        var siteDtos = await GetUserSites(userId, tenantId, forLogin);
        return siteDtos.Any(s => s.Id == siteId);
    }

    // Cache invalidation methods
    public void InvalidateUserTenantCache(Guid userId)
    {
        _ = Task.Run(async () => await _cache.InvalidateCachedUserTenantsAsync(userId));
        
        _logger.LogDebug("Invalidated tenant cache for user {UserId}", userId);
    }

    public void InvalidateAllUserTenantCaches()
    {
        _ = Task.Run(async () => await _cache.InvalidateAllCachedUserTenantsAsync());
        
        _logger.LogDebug("Invalidated all user tenant caches by incrementing generation");
    }

    public void InvalidateUserSiteCache(Guid userId, Guid tenantId)
    {
        _ = Task.Run(async () => await _cache.InvalidateCachedUserSitesAsync(userId, tenantId));
        
        _logger.LogDebug("Invalidated site cache for user {UserId}, tenant {TenantId}", userId, tenantId);
    }

    public void InvalidateAllUserSiteCaches()
    {
        _ = Task.Run(async () => await _cache.InvalidateAllCachedUserSitesAsync());
        
        _logger.LogDebug("Invalidated all user site caches by incrementing generation");
    }

    // User invitation methods
    public async Task<InvitationResponse> InviteUserAsync(InviteUserRequest request, string invitedByUserId)
    {
        // Check if user already exists
        var existingUser = await GetUserByEmail(request.Email);
        if (existingUser != null)
        {
            // Check if user is already in tenant
            var hasAccess = await HasTenantAccess(existingUser.Id, request.TenantId);
            if (hasAccess)
            {
                return new InvitationResponse
                {
                    Success = false,
                    Message = "User is already a member of this tenant"
                };
            }
        }

        // Check if there's already a pending invitation
        var existingInvitation = await _context.UserInvitations
            .FirstOrDefaultAsync(ui => ui.Email == request.Email && 
                                      ui.TenantId == request.TenantId && 
                                      !ui.IsUsed && 
                                      ui.ExpiresAt > DateTime.UtcNow);

        if (existingInvitation != null)
        {
            return new InvitationResponse
            {
                Success = false,
                Message = "User already has a pending invitation for this tenant"
            };
        }

        // Generate invitation token
        var tokenBytes = RandomNumberGenerator.GetBytes(32);
        var invitationToken = Convert.ToBase64String(tokenBytes)
            .Replace('+', '-')
            .Replace('/', '_')
            .Replace("=", "");

        // Create invitation
        var invitation = new UserInvitation
        {
            Email = request.Email,
            TenantId = request.TenantId,
            InvitationToken = invitationToken,
            InvitedRoles = request.RoleIds != null && request.RoleIds.Any() 
                ? System.Text.Json.JsonSerializer.Serialize(request.RoleIds) 
                : null,
            ExpiresAt = DateTime.UtcNow.AddDays(7), // 7 days expiration
            CreatedBy = invitedByUserId
        };

        _context.UserInvitations.Add(invitation);
        await _uow.CompleteAsync();

        return new InvitationResponse
        {
            Success = true,
            Message = "Invitation sent successfully",
            InvitationId = invitation.Id
        };
    }

    public async Task<UserInvitation?> ValidateInvitationTokenAsync(string token)
    {
        return await _context.UserInvitations
            .FirstOrDefaultAsync(ui => ui.InvitationToken == token && 
                                      !ui.IsUsed && 
                                      ui.ExpiresAt > DateTime.UtcNow);
    }

    public async Task<UserExistenceCheckDto> CheckUserExistenceAsync(string email, Guid tenantId)
    {
        var user = await GetUserByEmail(email);
        var result = new UserExistenceCheckDto { Email = email };

        if (user != null)
        {
            // Get user's roles in this tenant
            var roles = await GetUserRoles(user.Id, RoleScope.Tenant, tenantId);
            result.Roles = _mapper.Map<List<RoleNoPermissionDto>>(roles);
        }

        return result;
    }

    public async Task<IEnumerable<UserInvitation>> GetPendingInvitationsAsync(Guid tenantId)
    {
        return await _context.UserInvitations
            .Where(ui => ui.TenantId == tenantId && 
                        !ui.IsUsed && 
                        ui.ExpiresAt > DateTime.UtcNow)
            .OrderByDescending(ui => ui.CreateDate)
            .ToListAsync();
    }



    private async Task<bool> IsSystemAdminByRoles(Guid userId)
    {
        // Query database directly to check if user has system admin permission
        // This bypasses the permission middleware that isn't available during login
        var hasSystemAdminPermission = await _context.UserRoles
            .Where(ur => ur.UserId == userId)
            .Include(ur => ur.Role)
            .ThenInclude(r => r!.RolePermissions!)
            .ThenInclude(rp => rp.Permission)
            .AnyAsync(ur => ur.Role!.RolePermissions!.Any(rp => 
                               rp.Permission!.Code == RolePermissionConstants.SysAdminManageTenants));

        _logger.LogDebug("Direct role check for system admin permission: {HasPermission} for user {UserId}", hasSystemAdminPermission, userId);
        return hasSystemAdminPermission;
    }
    
    private async Task<bool> IsTenantAccessAllSites(Guid userId, Guid tenantId)
    {
        // Check for system admin permission (global access)
        bool isSystemAdmin = await IsSystemAdminByRoles(userId);
        if (isSystemAdmin)
        {
            _logger.LogDebug("User {UserId} has system admin permission for all sites", userId);
            return true;
        }

        // Check for tenant-specific all-sites permission
        var hasTenantAllSitesPermission = await _context.UserRoles
            .Where(ur => ur.UserId == userId && ur.TenantId == tenantId)
            .Include(ur => ur.Role)
            .ThenInclude(r => r!.RolePermissions!)
            .ThenInclude(rp => rp.Permission)
            .AnyAsync(ur => ur.Role!.RolePermissions!.Any(rp => 
                rp.Permission!.Code == RolePermissionConstants.TenantAccessAllSites));

        _logger.LogDebug("User {UserId} tenant {TenantId} all-sites permission: {HasPermission}", userId, tenantId, hasTenantAllSitesPermission);
        return hasTenantAllSitesPermission;
    }

    public async Task RemoveUserFromTenant(Guid userId, Guid tenantId)
    {
        // Validate user exists
        var user = await _userManager.FindByIdAsync(userId.ToString());
        if (user == null)
            throw new NotFoundException($"User with ID {userId} not found");

        // Remove all tenant-scoped roles for this user in this tenant
        var tenantRoles = await _context.UserRoles
            .Where(ur => ur.UserId == userId && 
                        ur.Scope == RoleScope.Tenant && 
                        ur.TenantId == tenantId)
            .ToListAsync();
        
        _context.UserRoles.RemoveRange(tenantRoles);

        // Remove all site-scoped roles for this user in all sites within this tenant
        var siteRoles = await _context.UserRoles
            .Where(ur => ur.UserId == userId && 
                        ur.Scope == RoleScope.Site && 
                        ur.TenantId == tenantId)
            .ToListAsync();
        
        _context.UserRoles.RemoveRange(siteRoles);


        // Revoke all refresh tokens for this user in this tenant context
        var refreshTokens = await _context.RefreshTokens
            .Where(rt => rt.UserId == userId && rt.TenantId == tenantId && !rt.IsRevoked)
            .ToListAsync();
        
        foreach (var token in refreshTokens)
        {
            token.IsRevoked = true;
        }

        await _uow.CompleteAsync();

        // Invalidate caches
        InvalidateUserTenantCache(userId);
        InvalidateUserSiteCache(userId, tenantId);

        _logger.LogInformation("Removed user {UserId} from tenant {TenantId} including all roles, associations, and refresh tokens", userId, tenantId);
    }

    public async Task RemoveUserFromSite(Guid userId, Guid siteId)
    {
        // Validate user exists
        var user = await _userManager.FindByIdAsync(userId.ToString());
        if (user == null)
            throw new NotFoundException($"User with ID {userId} not found");

        // Get site info to validate tenant
        var site = await _context.Sites
            .FirstOrDefaultAsync(s => s.Id == siteId);
        
        if (site == null)
            throw new NotFoundException($"Site with ID {siteId} not found");

        // Remove all site-scoped roles for this user in this specific site
        var siteRoles = await _context.UserRoles
            .Where(ur => ur.UserId == userId && 
                        ur.Scope == RoleScope.Site && 
                        ur.SiteId == siteId)
            .ToListAsync();
        
        _context.UserRoles.RemoveRange(siteRoles);


        // Revoke all refresh tokens for this user in this site context
        var refreshTokens = await _context.RefreshTokens
            .Where(rt => rt.UserId == userId && rt.SiteId == siteId && !rt.IsRevoked)
            .ToListAsync();
        
        foreach (var token in refreshTokens)
        {
            token.IsRevoked = true;
        }

        await _uow.CompleteAsync();

        // Invalidate caches
        InvalidateUserSiteCache(userId, site.TenantId);

        _logger.LogInformation("Removed user {UserId} from site {SiteId} including all roles, associations, and refresh tokens", userId, siteId);
    }
}