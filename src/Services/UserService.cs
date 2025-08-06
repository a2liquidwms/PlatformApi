using AutoMapper;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using PlatformApi.Common.Constants;
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

    public UserService(
        PlatformDbContext context,
        UserManager<AuthUser> userManager,
        IMapper mapper,
        ILogger<UserService> logger,
        IUnitOfWork<PlatformDbContext> uow)
    {
        _context = context;
        _userManager = userManager;
        _mapper = mapper;
        _logger = logger;
        _uow = uow;
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

    public async Task<bool> AddUserToTenant(AddUserToTenantDto dto)
    {
        var user = await GetUserByEmail(dto.Email);
        if (user == null) return false;

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

        // Add required role
        var roleDto = new AddUserToRoleDto
        {
            Email = dto.Email,
            TenantId = site.TenantId,
            SiteId = dto.SiteId,
            RoleId = dto.RoleId.ToString(),
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

    public async Task<bool> RemoveUserFromRole(RemoveUserFromRoleDto dto)
    {
        var user = await GetUserByEmail(dto.Email);
        if (user == null) return false;

        var assignment = await _context.UserRoles
            .FirstOrDefaultAsync(ura => ura.UserId == user.Id && 
                                       ura.RoleId == dto.RoleId &&
                                       ura.TenantId == dto.TenantId &&
                                       ura.SiteId == dto.SiteId &&
                                       ura.Scope == dto.Scope);

        if (assignment == null) return false;

        _context.UserRoles.Remove(assignment);
        await _uow.CompleteAsync();
        return true;
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

    public async Task<IEnumerable<TenantDto>> GetUserTenants(Guid userId)
    {
        // Get all tenants where user is explicitly assigned via UserTenant table
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

    public async Task<IEnumerable<SiteDto>> GetUserSites(Guid userId, Guid? tenantId = null)
    {
        IQueryable<UserSite> query = _context.UserSites
            .Where(us => us.UserId == userId && us.IsActive);

        if (tenantId.HasValue)
        {
            query = query.Where(us => us.TenantId == tenantId.Value);
        }

        var userSites = await query.Include(us => us.Site).ToListAsync();
        
        return userSites.Where(us => us.Site != null).Select(us => new SiteDto 
        { 
            Id = us.Site!.Id, 
            Name = us.Site!.Name, 
            TenantId = us.Site!.TenantId,
            IsActive = us.Site!.IsActive 
        });
    }

    public async Task<bool> HasTenantAccess(Guid userId, Guid tenantId)
    {
        return await _context.UserTenants
            .AnyAsync(ut => ut.UserId == userId && ut.TenantId == tenantId);
    }

    public async Task<bool> HasSiteAccess(Guid userId, Guid siteId, Guid tenantId)
    {
        return await _context.UserSites
            .AnyAsync(us => us.UserId == userId && us.SiteId == siteId && us.TenantId == tenantId && us.IsActive);
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
}