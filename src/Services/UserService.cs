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
        var userTenants = await _context.UserTenants
            .Where(ut => ut.TenantId == tenantId)
            .Include(ut => ut.User)
            .Select(ut => ut.User!)
            .ToListAsync();

        var result = new List<TenantUserWithRolesDto>();
        
        foreach (var user in userTenants)
        {
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
        var userSites = await _context.UserSites
            .Where(us => us.SiteId == siteId)
            .Include(us => us.User)
            .Select(us => us.User!)
            .ToListAsync();

        var result = new List<SiteUserWithRolesDto>();
        
        foreach (var user in userSites)
        {
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

        // Validate role exists and has correct scope BEFORE making any changes
        if (!string.IsNullOrEmpty(dto.RoleId))
        {
            var role = await _context.Roles.FirstOrDefaultAsync(r => r.Id == Guid.Parse(dto.RoleId));
            if (role == null) throw new NotFoundException($"Role with ID {dto.RoleId} does not exist.");
            if (role.Scope != RoleScope.Tenant) throw new InvalidDataException($"Role {role.Name} is not a Tenant scope role.");
        }

        // Check if user is already in tenant
        var existingUserTenant = await _context.UserTenants
            .FirstOrDefaultAsync(ut => ut.UserId == user.Id && ut.TenantId == dto.TenantId);

        if (existingUserTenant == null)
        {
            // Add user to tenant
            var userTenant = new UserTenant
            {
                UserId = user.Id,
                TenantId = dto.TenantId
            };
            
            await _context.UserTenants.AddAsync(userTenant);
        }

        // Add role if specified
        if (!string.IsNullOrEmpty(dto.RoleId))
        {
            var roleDto = new AddUserToRoleDto
            {
                Email = dto.Email,
                TenantId = dto.TenantId,
                RoleId = dto.RoleId,
                Scope = RoleScope.Tenant
            };
            
            await AddUserToRole(roleDto);
        }

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

        // Validate role exists and has correct scope BEFORE making any changes
        if (dto.RoleId.HasValue)
        {
            var role = await _context.Roles.FirstOrDefaultAsync(r => r.Id == dto.RoleId.Value);
            if (role == null) throw new NotFoundException($"Role with ID {dto.RoleId.Value} does not exist.");
            if (role.Scope != RoleScope.Site) throw new InvalidDataException($"Role {role.Name} is not a Site scope role.");
        }

        // Ensure user is in the tenant first
        var userTenant = await _context.UserTenants
            .FirstOrDefaultAsync(ut => ut.UserId == user.Id && ut.TenantId == site.TenantId);

        if (userTenant == null)
        {
            // Add user to tenant first
            userTenant = new UserTenant
            {
                UserId = user.Id,
                TenantId = site.TenantId
            };
            await _context.UserTenants.AddAsync(userTenant);
        }

        // Check if user is already in site
        var existingUserSite = await _context.UserSites
            .FirstOrDefaultAsync(us => us.UserId == user.Id && us.SiteId == dto.SiteId);

        if (existingUserSite == null)
        {
            // Add user to site
            var userSite = new UserSite
            {
                UserId = user.Id,
                SiteId = dto.SiteId,
                TenantId = site.TenantId
            };
            
            await _context.UserSites.AddAsync(userSite);
        }

        // Add role if specified
        if (dto.RoleId.HasValue)
        {
            var roleDto = new AddUserToRoleDto
            {
                Email = dto.Email,
                TenantId = site.TenantId,
                SiteId = dto.SiteId,
                RoleId = dto.RoleId.Value.ToString(),
                Scope = RoleScope.Site
            };
            
            await AddUserToRole(roleDto);
        }

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

        // Ensure user has proper tenant/site associations based on role scope
        await EnsureUserAssociations(dto.Email, dto.Scope, dto.TenantId, dto.SiteId);

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

        // Ensure user has proper tenant/site associations based on role scope
        await EnsureUserAssociations(dto.Email, expectedScope, dto.TenantId, dto.SiteId);

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
            var tenants = await _context.UserTenants
                .Where(ut => ut.UserId == userId)
                .Include(ut => ut.Tenant)
                .Select(ut => new TenantDto 
                { 
                    Id = ut.Tenant!.Id, 
                    Name = ut.Tenant!.Name, 
                    Code = ut.Tenant!.Code, 
                    SubDomain = ut.Tenant!.SubDomain 
                })
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
        
        // Get all tenants where user is explicitly assigned via UserTenant table
        var userTenants = await _context.UserTenants
            .Where(ut => ut.UserId == userId)
            .Include(ut => ut.Tenant)
            .Select(ut => new TenantDto 
            { 
                Id = ut.Tenant!.Id, 
                Name = ut.Tenant!.Name, 
                Code = ut.Tenant!.Code, 
                SubDomain = ut.Tenant!.SubDomain 
            })
            .ToListAsync();

        // Cache the results for regular users
        await _cache.SetCachedUserTenantsAsync(userId, userTenants);
        _logger.LogDebug("Cached {TenantCount} tenants for user {UserId}", userTenants.Count(), userId);
            
        return userTenants;
    }

    public async Task<IEnumerable<SiteDto>> GetUserSites(Guid userId, Guid tenantId, bool forLogin = false)
    {
        // Check if user is system admin - use appropriate method based on context
        bool isSystemAdmin = forLogin 
            ? await IsSystemAdminByRoles(userId)
            : _permissionHelper.HasPermission(RolePermissionConstants.SysAdminManageTenants);

        if (isSystemAdmin)
        {
            var logContext = forLogin ? "login" : "normal";
            _logger.LogDebug("System admin access ({Context}) - returning all sites for tenant {TenantId}, user {UserId}", logContext, tenantId, userId);
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
            var loginSites = await _context.UserSites
                .Where(us => us.UserId == userId && us.TenantId == tenantId && us.Site!.IsActive)
                .Include(us => us.Site)
                .ToListAsync();
            
            return loginSites.Where(us => us.Site != null).Select(us => new SiteDto 
            { 
                Id = us.Site!.Id, 
                Code = us.Site!.Code,
                Name = us.Site!.Name, 
                TenantId = us.Site!.TenantId,
                IsActive = us.Site!.IsActive 
            });
        }

        // Regular users get cached results for performance (post-authentication)
        var cachedSites = await _cache.GetCachedUserSitesAsync(userId, tenantId);
        if (cachedSites != null)
        {
            _logger.LogDebug("Cache hit for user sites: {UserId}, tenant {TenantId}", userId, tenantId);
            return cachedSites;
        }

        _logger.LogDebug("Cache miss for user sites, querying database: {UserId}, tenant {TenantId}", userId, tenantId);
        
        // Get all sites where user is explicitly assigned within the specified tenant (site must be active)
        var userSites = await _context.UserSites
            .Where(us => us.UserId == userId && us.TenantId == tenantId && us.Site!.IsActive)
            .Include(us => us.Site)
            .ToListAsync();
        
        var siteDtos = userSites.Where(us => us.Site != null).Select(us => new SiteDto 
        { 
            Id = us.Site!.Id, 
            Code = us.Site!.Code,
            Name = us.Site!.Name, 
            TenantId = us.Site!.TenantId,
            IsActive = us.Site!.IsActive 
        }).ToList();

        // Cache the results for regular users
        await _cache.SetCachedUserSitesAsync(userId, tenantId, siteDtos);
        _logger.LogDebug("Cached {SiteCount} sites for user {UserId}, tenant {TenantId}", siteDtos.Count, userId, tenantId);
            
        return siteDtos;
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

    private async Task EnsureUserAssociations(string email, RoleScope scope, Guid? tenantId, Guid? siteId)
    {
        var user = await GetUserByEmail(email);
        if (user == null) return;

        switch (scope)
        {
            case RoleScope.Tenant:
                if (tenantId.HasValue)
                    await EnsureUserTenantAssociation(user.Id, tenantId.Value);
                break;

            case RoleScope.Site:
                if (tenantId.HasValue && siteId.HasValue)
                {
                    await EnsureUserTenantAssociation(user.Id, tenantId.Value);
                    await EnsureUserSiteAssociation(user.Id, siteId.Value, tenantId.Value);
                }
                break;

            default:
                // Internal and Default roles don't require tenant/site associations
                break;
        }
    }

    private async Task EnsureUserTenantAssociation(Guid userId, Guid tenantId)
    {
        var existingUserTenant = await _context.UserTenants
            .FirstOrDefaultAsync(ut => ut.UserId == userId && ut.TenantId == tenantId);

        if (existingUserTenant == null)
        {
            var userTenant = new UserTenant
            {
                UserId = userId,
                TenantId = tenantId
            };
            await _context.UserTenants.AddAsync(userTenant);
        }
    }

    private async Task EnsureUserSiteAssociation(Guid userId, Guid siteId, Guid tenantId)
    {
        var existingUserSite = await _context.UserSites
            .FirstOrDefaultAsync(us => us.UserId == userId && us.SiteId == siteId);

        if (existingUserSite == null)
        {
            var userSite = new UserSite
            {
                UserId = userId,
                SiteId = siteId,
                TenantId = tenantId
            };
            await _context.UserSites.AddAsync(userSite);
        }
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
}