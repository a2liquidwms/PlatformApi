using AutoMapper;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using PlatformStarterCommon.Core.Common.Constants;
using PlatformStarterCommon.Core.Common.Permissions;
using PlatformStarterCommon.Core.Common.Services;
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
    private readonly IEmailContentService _emailContentService;
    private readonly IEmailService _emailService;

    public UserService(
        PlatformDbContext context,
        UserManager<AuthUser> userManager,
        IMapper mapper,
        ILogger<UserService> logger,
        IUnitOfWork<PlatformDbContext> uow,
        PermissionHelper permissionHelper,
        ICacheService cache,
        IEmailContentService emailContentService,
        IEmailService emailService)
    {
        _context = context;
        _userManager = userManager;
        _mapper = mapper;
        _logger = logger;
        _uow = uow;
        _permissionHelper = permissionHelper;
        _cache = cache;
        _emailContentService = emailContentService;
        _emailService = emailService;
    }

    public async Task<IEnumerable<TenantUserWithRolesDto>> GetTenantUsers(Guid tenantId)
    {
        _logger.LogDebug("Getting tenant users for tenant {TenantId}", tenantId);
        
        // Get all users with tenant-scoped roles for this tenant in a single optimized query
        var usersWithRoles = await _context.UserRoles
            .Where(ur => ur.TenantId == tenantId && ur.Scope == RoleScope.Tenant)
            .Include(ur => ur.User)
            .Include(ur => ur.Role)
            .Where(ur => ur.User != null && ur.User.Email != null)
            .GroupBy(ur => ur.UserId)
            .Select(g => new TenantUserWithRolesDto
            {
                UserId = g.Key,
                Email = g.First().User!.Email!,
                Roles = g.Select(ur => new RoleNoPermissionDto
                {
                    Id = ur.Role!.Id.ToString(),
                    Name = ur.Role.Name
                }).ToList()
            })
            .ToListAsync();

        _logger.LogDebug("Found {UserCount} users with tenant roles for tenant {TenantId}", usersWithRoles.Count, tenantId);
        return usersWithRoles;
    }

    public async Task<IEnumerable<SiteUserWithRolesDto>> GetSiteUsers(Guid siteId)
    {
        _logger.LogDebug("Getting site users for site {SiteId}", siteId);
        
        // Get all users with site-scoped roles for this site in a single optimized query
        var usersWithRoles = await _context.UserRoles
            .Where(ur => ur.SiteId == siteId && ur.Scope == RoleScope.Site)
            .Include(ur => ur.User)
            .Include(ur => ur.Role)
            .Where(ur => ur.User != null && ur.User.Email != null)
            .GroupBy(ur => ur.UserId)
            .Select(g => new SiteUserWithRolesDto
            {
                UserId = g.Key,
                Email = g.First().User!.Email!,
                SiteId = siteId,
                Roles = g.Select(ur => new RoleNoPermissionDto
                {
                    Id = ur.Role!.Id.ToString(),
                    Name = ur.Role.Name
                }).ToList()
            })
            .ToListAsync();

        _logger.LogDebug("Found {UserCount} users with site roles for site {SiteId}", usersWithRoles.Count, siteId);
        return usersWithRoles;
    }

    public async Task<IEnumerable<InternalUserWithRolesDto>> GetInternalUsers()
    {
        _logger.LogDebug("Getting internal users");
        
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

        _logger.LogDebug("Found {UserCount} internal users", usersWithRoles.Count);
        return usersWithRoles;
    }




    public async Task<bool> AddUserToRole(AddUserToRoleDto dto, RoleScope expectedScope)
    {
        _logger.LogDebug("Adding user {Email} to {Scope} role {RoleId} with context tenant {TenantId}, site {SiteId}", 
            dto.Email, expectedScope, dto.RoleId, dto.TenantId, dto.SiteId);
            
        var user = await GetUserByEmail(dto.Email);
        
        // If user doesn't exist, create a placeholder user
        if (user == null)
        {
            _logger.LogDebug("User {Email} not found, creating placeholder user", dto.Email);
            user = await CreatePlaceholderUserAsync(dto.Email);
        }

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
        
        // Invalidate appropriate caches based on scope
        if (expectedScope == RoleScope.Tenant)
        {
            await _cache.InvalidateCachedUserTenantsAsync(user.Id);
            _logger.LogInformation("Invalidated cached user tenants for user {UserId} after adding tenant role", user.Id);
        }
        else if (expectedScope == RoleScope.Site && dto.TenantId.HasValue)
        {
            await _cache.InvalidateCachedUserSitesAsync(user.Id, dto.TenantId.Value);
            _logger.LogInformation("Invalidated cached user sites for user {UserId} in tenant {TenantId} after adding site role", 
                user.Id, dto.TenantId.Value);
        }
        
        _logger.LogInformation("Successfully added user {UserId} ({Email}) to {Scope} role {RoleName} with context tenant {TenantId}, site {SiteId}", 
            user.Id, dto.Email, expectedScope, role.Name, dto.TenantId, dto.SiteId);
        return true;
    }


    public async Task RemoveUserFromRole(RemoveUserFromRoleDto dto, RoleScope expectedScope)
    {
        _logger.LogDebug("Removing user {Email} from {Scope} role {RoleId} with context tenant {TenantId}, site {SiteId}", 
            dto.Email, expectedScope, dto.RoleId, dto.TenantId, dto.SiteId);
            
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
        
        // Invalidate appropriate caches based on scope
        if (expectedScope == RoleScope.Tenant)
        {
            await _cache.InvalidateCachedUserTenantsAsync(user.Id);
            _logger.LogInformation("Invalidated cached user tenants for user {UserId} after removing tenant role", user.Id);
        }
        else if (expectedScope == RoleScope.Site && dto.TenantId.HasValue)
        {
            await _cache.InvalidateCachedUserSitesAsync(user.Id, dto.TenantId.Value);
            _logger.LogInformation("Invalidated cached user sites for user {UserId} in tenant {TenantId} after removing site role", 
                user.Id, dto.TenantId.Value);
        }
        
        _logger.LogInformation("Successfully removed user {UserId} ({Email}) from {Scope} role {RoleName} with context tenant {TenantId}, site {SiteId}", 
            user.Id, dto.Email, expectedScope, role.Name, dto.TenantId, dto.SiteId);
    }

    private async Task<AuthUser?> GetUserByEmail(string email)
    {
        return await _userManager.FindByEmailAsync(email);
    }

    private async Task<AuthUser> CreatePlaceholderUserAsync(string email)
    {
        var placeholderUser = new AuthUser
        {
            Email = email,
            UserName = email,
            EmailConfirmed = false,
            NormalizedEmail = email.ToUpper(),
            NormalizedUserName = email.ToUpper()
        };

        var result = await _userManager.CreateAsync(placeholderUser);
        if (!result.Succeeded)
        {
            var errors = string.Join(", ", result.Errors.Select(e => e.Description));
            throw new InvalidDataException($"Failed to create placeholder user: {errors}");
        }
        
        _logger.LogInformation("Created placeholder user for email {Email}", email);
        return placeholderUser;
    }

    public async Task<UserLookupDto?> GetUserByUserName(string userName)
    {
        _logger.LogDebug("Looking up user by username: {UserName}", userName);
        
        var user = await _userManager.FindByNameAsync(userName);
        if (user == null)
        {
            _logger.LogDebug("User not found for username: {UserName}", userName);
            return null;
        }

        _logger.LogDebug("Found user {Email} for username: {UserName}", user.Email, userName);
        return new UserLookupDto
        {
            UserName = user.UserName!,
            Email = user.Email!
        };
    }

    private async Task<IEnumerable<Role>> GetUserRoles(Guid userId, RoleScope scope, Guid? tenantId = null, Guid? siteId = null)
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
            _logger.LogInformation("Cache hit for user tenants: {UserId}", userId);
            return cachedTenants;
        }

        _logger.LogInformation("Cache miss for user tenants, querying database: {UserId}", userId);
        
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
        _logger.LogDebug("Cached tenants for user {UserId}", userId);
            
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
            _logger.LogInformation("Cache hit for user sites: {UserId}, tenant {TenantId}", userId, tenantId);
            return cachedSites;
        }

        _logger.LogInformation("Cache miss for user sites, querying database: {UserId}, tenant {TenantId}", userId, tenantId);
        
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
        _logger.LogInformation("Cached {SiteCount} sites for user {UserId}, tenant {TenantId}", siteDtos.Count, userId, tenantId);
            
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


    // User invitation methods
    public async Task<InvitationResponse> InviteUserAsync(InviteUserRequest request, RoleScope expectedScope, string invitedByUserId)
    {
        _logger.LogDebug("Inviting user {Email} to {Scope} role {RoleId} with context tenant {TenantId}, site {SiteId} by user {InvitedByUserId}", 
            request.Email, expectedScope, request.RoleId, request.TenantId, request.SiteId, invitedByUserId);
            
        // Validate request scope matches expected scope
        if (request.Scope != expectedScope)
        {
            throw new InvalidDataException($"Request scope must be {expectedScope}");
        }

        // First, create placeholder user and assign role (this validates everything)
        var addRoleDto = new AddUserToRoleDto
        {
            Email = request.Email,
            TenantId = request.TenantId,
            SiteId = request.SiteId,
            RoleId = request.RoleId,
            Scope = request.Scope
        };

        try
        {
            await AddUserToRole(addRoleDto, expectedScope);
        }
        catch (InvalidDataException ex) when (ex.Message.Contains("already assigned"))
        {
            return new InvitationResponse
            {
                Success = false,
                Message = "User already has this role assigned"
            };
        }

        // Check if user has completed registration (has password)
        var user = await GetUserByEmail(request.Email);
        if (user != null && !string.IsNullOrEmpty(user.PasswordHash))
        {
            // User already exists and has password - role was just added, no invitation needed
            _logger.LogInformation("User {Email} already exists and has password - role assigned directly for {Scope} role {RoleId}", 
                request.Email, expectedScope, request.RoleId);
            return new InvitationResponse
            {
                Success = true,
                Message = "User already exists - role assigned directly",
                InvitationId = null // No invitation created
            };
        }

        // Check if there's already a pending invitation for this scope/context
        var existingInvitation = await _context.UserInvitations
            .FirstOrDefaultAsync(ui => ui.Email == request.Email && 
                                      ui.TenantId == request.TenantId &&
                                      ui.SiteId == request.SiteId &&
                                      ui.Scope == request.Scope &&
                                      !ui.IsUsed && 
                                      ui.ExpiresAt > DateTime.UtcNow);

        if (existingInvitation != null)
        {
            _logger.LogWarning("User {Email} already has a pending invitation for {Scope} scope with context tenant {TenantId}, site {SiteId}", 
                request.Email, request.Scope, request.TenantId, request.SiteId);
            return new InvitationResponse
            {
                Success = false,
                Message = "User already has a pending invitation for this scope"
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
            SiteId = request.SiteId,
            InvitationToken = invitationToken,
            Scope = request.Scope,
            ExpiresAt = DateTime.UtcNow.AddDays(7), // 7 days expiration
            CreatedBy = invitedByUserId
        };

        _context.UserInvitations.Add(invitation);
        await _uow.CompleteAsync();
        
        _logger.LogInformation("Created invitation {InvitationId} for user {Email} to {Scope} role {RoleId} with context tenant {TenantId}, site {SiteId}", 
            invitation.Id, request.Email, request.Scope, request.RoleId, request.TenantId, request.SiteId);
        
        // Send invitation email
        try
        {
            var emailContent = await _emailContentService.PrepareInvitationEmailAsync(
                request.Email, 
                invitationToken, 
                request.Email, // Using email as userName for now, will be updated when user registers
                request.Scope, 
                request.TenantId);
            
            var emailSent = await _emailService.SendEmailAsync(emailContent);
            
            if (!emailSent)
            {
                _logger.LogWarning("Failed to send invitation email to {Email} for scope {Scope} with invitation {InvitationId}", 
                    request.Email, request.Scope, invitation.Id);
            }
            else
            {
                _logger.LogInformation("Successfully sent invitation email to {Email} for invitation {InvitationId}", 
                    request.Email, invitation.Id);
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error sending invitation email to {Email} for scope {Scope} with invitation {InvitationId}", 
                request.Email, request.Scope, invitation.Id);
        }

        _logger.LogInformation("Invitation process completed successfully for user {Email} with invitation {InvitationId}", 
            request.Email, invitation.Id);
        
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


    public async Task<IEnumerable<UserInvitation>> GetPendingInvitationsAsync(RoleScope scope, Guid? tenantId = null, Guid? siteId = null)
    {
        _logger.LogDebug("Getting pending {Scope} invitations with context tenant {TenantId}, site {SiteId}", 
            scope, tenantId, siteId);
            
        var query = _context.UserInvitations
            .Where(ui => !ui.IsUsed && ui.ExpiresAt > DateTime.UtcNow);

        query = scope switch
        {
            RoleScope.Internal => query.Where(ui => ui.Scope == RoleScope.Internal),
            RoleScope.Tenant => query.Where(ui => ui.TenantId == tenantId && ui.Scope == RoleScope.Tenant),
            RoleScope.Site => query.Where(ui => ui.SiteId == siteId && ui.Scope == RoleScope.Site),
            _ => throw new InvalidDataException($"Invalid scope: {scope}")
        };

        var invitations = await query
            .OrderByDescending(ui => ui.CreateDate)
            .ToListAsync();
            
        _logger.LogDebug("Found {InvitationCount} pending {Scope} invitations", invitations.Count, scope);
        return invitations;
    }

    public async Task DeleteInvitationAsync(string email)
    {
        _logger.LogDebug("Attempting to delete invitation for email {Email}", email);
        
        // Find unused invitation by email
        var invitation = await _context.UserInvitations
            .FirstOrDefaultAsync(ui => ui.Email == email && 
                                      !ui.IsUsed && 
                                      ui.ExpiresAt > DateTime.UtcNow);

        if (invitation == null)
        {
            _logger.LogWarning("No open invitation found for email {Email}", email);
            throw new NotFoundException("Open invitation does not exist");
        }

        // Find user by email
        var user = await _userManager.FindByEmailAsync(email);
        
        if (user != null)
        {
            // Check if user email is confirmed
            if (user.EmailConfirmed)
            {
                _logger.LogWarning("Cannot delete invitation for email {Email} - user already accepted invite", email);
                throw new InvalidDataException("User already accepted invite");
            }

            // User exists but email not confirmed - remove all user roles and delete user
            _logger.LogInformation("Removing unconfirmed user {UserId} and their roles for email {Email}", user.Id, email);
            var userRoles = await _context.UserRoles
                .Where(ur => ur.UserId == user.Id)
                .ToListAsync();

            _context.UserRoles.RemoveRange(userRoles);
            _logger.LogDebug("Removed {RoleCount} role assignments for user {UserId}", userRoles.Count, user.Id);

            await _userManager.DeleteAsync(user);
            _logger.LogInformation("Deleted unconfirmed user account {UserId} for email {Email}", user.Id, email);
        }

        // Remove the invitation
        _context.UserInvitations.Remove(invitation);
        _logger.LogInformation("Deleted invitation {InvitationId} for email {Email}", invitation.Id, email);
        
        await _uow.CompleteAsync();
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

}