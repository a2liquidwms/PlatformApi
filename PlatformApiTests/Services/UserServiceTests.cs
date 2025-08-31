using AutoMapper;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using Moq;
using PlatformStarterCommon.Core.Common.Constants;
using PlatformStarterCommon.Core.Common.Permissions;
using PlatformStarterCommon.Core.Common.Services;
using PlatformApi.Data;
using PlatformApi.Models;
using PlatformApi.Models.DTOs;
using PlatformApi.Services;
using Xunit;

namespace PlatformApiTests.Services;

public class UserServiceTests : IDisposable
{
    private readonly PlatformDbContext _context;
    private readonly Mock<UserManager<AuthUser>> _mockUserManager;
    private readonly Mock<IMapper> _mockMapper;
    private readonly Mock<ILogger<UserService>> _mockLogger;
    private readonly Mock<IUnitOfWork<PlatformDbContext>> _mockUow;
    private readonly Mock<PermissionHelper> _mockPermissionHelper;
    private readonly Mock<ICacheService> _mockCache;
    private readonly Mock<IEmailContentService> _mockEmailContentService;
    private readonly Mock<IEmailService> _mockEmailService;
    private readonly UserService _userService;

    public UserServiceTests()
    {
        var options = new DbContextOptionsBuilder<PlatformDbContext>()
            .UseInMemoryDatabase(databaseName: Guid.NewGuid().ToString())
            .Options;
        _context = new PlatformDbContext(options);

        var userStore = new Mock<IUserStore<AuthUser>>();
        _mockUserManager = new Mock<UserManager<AuthUser>>(
            userStore.Object, null!, null!, null!, null!, null!, null!, null!, null!);

        _mockMapper = new Mock<IMapper>();
        _mockLogger = new Mock<ILogger<UserService>>();
        _mockUow = new Mock<IUnitOfWork<PlatformDbContext>>();
        _mockUow.Setup(x => x.CompleteAsync()).Returns(async () => await _context.SaveChangesAsync());
        var mockHttpContextAccessor = new Mock<Microsoft.AspNetCore.Http.IHttpContextAccessor>();
        var mockLogger = new Mock<ILogger<PermissionHelper>>();
        _mockPermissionHelper = new Mock<PermissionHelper>(mockHttpContextAccessor.Object, mockLogger.Object);
        _mockCache = new Mock<ICacheService>();
        _mockEmailContentService = new Mock<IEmailContentService>();
        _mockEmailService = new Mock<IEmailService>();

        _userService = new UserService(
            _context,
            _mockUserManager.Object,
            _mockMapper.Object,
            _mockLogger.Object,
            _mockUow.Object,
            _mockPermissionHelper.Object,
            _mockCache.Object,
            _mockEmailContentService.Object,
            _mockEmailService.Object
        );
    }

    public void Dispose()
    {
        _context.Dispose();
    }

    private async Task SeedTestData()
    {
        var tenant1 = new Tenant { Id = Guid.NewGuid(), Name = "Tenant 1", Code = "T1", SubDomain = "t1" };
        var tenant2 = new Tenant { Id = Guid.NewGuid(), Name = "Tenant 2", Code = "T2", SubDomain = "t2" };
        
        _context.Tenants.AddRange(tenant1, tenant2);
        await _context.SaveChangesAsync();
        
        var site1 = new Site { Id = Guid.NewGuid(), TenantId = tenant1.Id, Name = "Site 1", Code = "S1", IsActive = true };
        var site2 = new Site { Id = Guid.NewGuid(), TenantId = tenant1.Id, Name = "Site 2", Code = "S2", IsActive = true };

        _context.Sites.AddRange(site1, site2);
        await _context.SaveChangesAsync();

        var user1 = new AuthUser { Id = Guid.NewGuid(), Email = "user1@test.com", UserName = "user1@test.com" };
        var user2 = new AuthUser { Id = Guid.NewGuid(), Email = "user2@test.com", UserName = "user2@test.com" };

        _context.Users.AddRange(user1, user2);
        await _context.SaveChangesAsync();

        var tenantRole = new Role { Id = Guid.NewGuid(), Name = "TenantAdmin", Scope = RoleScope.Tenant, TenantId = tenant1.Id };
        var siteRole = new Role { Id = Guid.NewGuid(), Name = "SiteUser", Scope = RoleScope.Site, TenantId = tenant1.Id, SiteId = site1.Id };
        var internalRole = new Role { Id = Guid.NewGuid(), Name = "SystemAdmin", Scope = RoleScope.Internal };

        _context.Roles.AddRange(tenantRole, siteRole, internalRole);
        await _context.SaveChangesAsync();

        var permission1 = new Permission { Code = RolePermissionConstants.SysAdminManageTenants };
        var permission2 = new Permission { Code = RolePermissionConstants.TenantAccessAllSites };

        _context.Permissions.AddRange(permission1, permission2);
        await _context.SaveChangesAsync();
    }

    #region GetTenantUsers Tests

    [Fact]
    public async Task GetTenantUsers_ReturnsUsersWithRoles_WhenUsersExist()
    {
        // Arrange
        await SeedTestData();
        var user = await _context.Users.FirstAsync();
        var tenant = await _context.Tenants.FirstAsync();
        var role = await _context.Roles.FirstAsync(r => r.Scope == RoleScope.Tenant);

        var userRole = new UserRoles
        {
            UserId = user.Id,
            RoleId = role.Id,
            TenantId = tenant.Id,
            Scope = RoleScope.Tenant
        };

        _context.UserRoles.Add(userRole);
        await _context.SaveChangesAsync();

        // Act
        var result = await _userService.GetTenantUsers(tenant.Id);

        // Assert
        var resultList = result.ToList();
        Assert.Single(resultList);
        Assert.Equal(user.Id, resultList[0].UserId);
        Assert.Equal(user.Email, resultList[0].Email);
        Assert.Single(resultList[0].Roles);
        Assert.Equal(role.Name, resultList[0].Roles[0].Name);
    }

    [Fact]
    public async Task GetTenantUsers_ReturnsEmpty_WhenNoUsersExist()
    {
        // Arrange
        await SeedTestData();
        var tenant = await _context.Tenants.FirstAsync();

        // Act
        var result = await _userService.GetTenantUsers(tenant.Id);

        // Assert
        Assert.Empty(result);
    }

    #endregion

    #region GetSiteUsers Tests

    [Fact]
    public async Task GetSiteUsers_ReturnsUsersWithRoles_WhenUsersExist()
    {
        // Arrange
        await SeedTestData();
        var user = await _context.Users.FirstAsync();
        var site = await _context.Sites.FirstAsync();
        var role = await _context.Roles.FirstAsync(r => r.Scope == RoleScope.Site);

        var userRole = new UserRoles
        {
            UserId = user.Id,
            RoleId = role.Id,
            TenantId = site.TenantId,
            SiteId = site.Id,
            Scope = RoleScope.Site
        };

        _context.UserRoles.Add(userRole);
        await _context.SaveChangesAsync();

        // Act
        var result = await _userService.GetSiteUsers(site.Id);

        // Assert
        var resultList = result.ToList();
        Assert.Single(resultList);
        Assert.Equal(user.Id, resultList[0].UserId);
        Assert.Equal(user.Email, resultList[0].Email);
        Assert.Equal(site.Id, resultList[0].SiteId);
        Assert.Single(resultList[0].Roles);
        Assert.Equal(role.Name, resultList[0].Roles[0].Name);
    }

    [Fact]
    public async Task GetSiteUsers_ReturnsEmpty_WhenNoUsersExist()
    {
        // Arrange
        await SeedTestData();
        var site = await _context.Sites.FirstAsync();

        // Act
        var result = await _userService.GetSiteUsers(site.Id);

        // Assert
        Assert.Empty(result);
    }

    #endregion

    #region GetInternalUsers Tests

    [Fact]
    public async Task GetInternalUsers_ReturnsUsersWithRoles_WhenUsersExist()
    {
        // Arrange
        await SeedTestData();
        var user = await _context.Users.FirstAsync();
        var role = await _context.Roles.FirstAsync(r => r.Scope == RoleScope.Internal);

        var userRole = new UserRoles
        {
            UserId = user.Id,
            RoleId = role.Id,
            Scope = RoleScope.Internal
        };

        _context.UserRoles.Add(userRole);
        await _context.SaveChangesAsync();

        // Act
        var result = await _userService.GetInternalUsers();

        // Assert
        var resultList = result.ToList();
        Assert.Single(resultList);
        Assert.Equal(user.Id, resultList[0].UserId);
        Assert.Equal(user.Email, resultList[0].Email);
        Assert.Single(resultList[0].Roles);
        Assert.Equal(role.Name, resultList[0].Roles[0].Name);
    }

    [Fact]
    public async Task GetInternalUsers_ReturnsEmpty_WhenNoUsersExist()
    {
        // Act
        var result = await _userService.GetInternalUsers();

        // Assert
        Assert.Empty(result);
    }

    #endregion

    #region AddUserToRole Tests

    [Fact]
    public async Task AddUserToRole_ReturnsTrue_WhenUserExistsAndRoleValid()
    {
        // Arrange
        await SeedTestData();
        var user = await _context.Users.FirstAsync();
        var role = await _context.Roles.FirstAsync(r => r.Scope == RoleScope.Tenant);
        var tenant = await _context.Tenants.FirstAsync();

        var dto = new AddUserToRoleDto
        {
            Email = user.Email!,
            RoleId = role.Id.ToString(),
            TenantId = tenant.Id,
            Scope = RoleScope.Tenant
        };

        _mockUserManager.Setup(x => x.FindByEmailAsync(user.Email!))
            .ReturnsAsync(user);

        // Act
        var result = await _userService.AddUserToRole(dto, RoleScope.Tenant);

        // Assert
        Assert.True(result);
        var userRole = await _context.UserRoles.FirstOrDefaultAsync(ur => ur.UserId == user.Id && ur.RoleId == role.Id);
        Assert.NotNull(userRole);
        Assert.Equal(tenant.Id, userRole.TenantId);
        Assert.Equal(RoleScope.Tenant, userRole.Scope);
        _mockUow.Verify(x => x.CompleteAsync(), Times.Once);
    }

    [Fact]
    public async Task AddUserToRole_CreatesPlaceholderUser_WhenUserDoesNotExist()
    {
        // Arrange
        await SeedTestData();
        var role = await _context.Roles.FirstAsync(r => r.Scope == RoleScope.Tenant);
        var tenant = await _context.Tenants.FirstAsync();
        var email = "newuser@test.com";

        var dto = new AddUserToRoleDto
        {
            Email = email,
            RoleId = role.Id.ToString(),
            TenantId = tenant.Id,
            Scope = RoleScope.Tenant
        };

        var placeholderUser = new AuthUser
        {
            Id = Guid.NewGuid(),
            Email = email,
            UserName = email,
            EmailConfirmed = false
        };

        _mockUserManager.Setup(x => x.FindByEmailAsync(email))
            .ReturnsAsync((AuthUser?)null);

        _mockUserManager.Setup(x => x.CreateAsync(It.IsAny<AuthUser>()))
            .ReturnsAsync(IdentityResult.Success)
            .Callback<AuthUser>(user => _context.Users.Add(user));

        // Act
        var result = await _userService.AddUserToRole(dto, RoleScope.Tenant);

        // Assert
        Assert.True(result);
        _mockUserManager.Verify(x => x.CreateAsync(It.Is<AuthUser>(u => u.Email == email)), Times.Once);
        _mockUow.Verify(x => x.CompleteAsync(), Times.Once);
    }

    [Fact]
    public async Task AddUserToRole_ThrowsNotFoundException_WhenRoleDoesNotExist()
    {
        // Arrange
        await SeedTestData();
        var user = await _context.Users.FirstAsync();
        var nonExistentRoleId = Guid.NewGuid();

        var dto = new AddUserToRoleDto
        {
            Email = user.Email!,
            RoleId = nonExistentRoleId.ToString(),
            TenantId = Guid.NewGuid(),
            Scope = RoleScope.Tenant
        };

        _mockUserManager.Setup(x => x.FindByEmailAsync(user.Email!))
            .ReturnsAsync(user);

        // Act & Assert
        await Assert.ThrowsAsync<NotFoundException>(() => _userService.AddUserToRole(dto, RoleScope.Tenant));
    }

    [Fact]
    public async Task AddUserToRole_ThrowsInvalidDataException_WhenRoleScopeMismatch()
    {
        // Arrange
        await SeedTestData();
        var user = await _context.Users.FirstAsync();
        var role = await _context.Roles.FirstAsync(r => r.Scope == RoleScope.Site);

        var dto = new AddUserToRoleDto
        {
            Email = user.Email!,
            RoleId = role.Id.ToString(),
            TenantId = Guid.NewGuid(),
            Scope = RoleScope.Tenant
        };

        _mockUserManager.Setup(x => x.FindByEmailAsync(user.Email!))
            .ReturnsAsync(user);

        // Act & Assert
        var exception = await Assert.ThrowsAsync<InvalidDataException>(
            () => _userService.AddUserToRole(dto, RoleScope.Tenant));
        Assert.Contains("Role is not a Tenant scope role", exception.Message);
    }

    [Fact]
    public async Task AddUserToRole_ThrowsInvalidDataException_WhenUserAlreadyHasRole()
    {
        // Arrange
        await SeedTestData();
        var user = await _context.Users.FirstAsync();
        var role = await _context.Roles.FirstAsync(r => r.Scope == RoleScope.Tenant);
        var tenant = await _context.Tenants.FirstAsync();

        // Add existing role assignment
        var existingUserRole = new UserRoles
        {
            UserId = user.Id,
            RoleId = role.Id,
            TenantId = tenant.Id,
            Scope = RoleScope.Tenant
        };
        _context.UserRoles.Add(existingUserRole);
        await _context.SaveChangesAsync();

        var dto = new AddUserToRoleDto
        {
            Email = user.Email!,
            RoleId = role.Id.ToString(),
            TenantId = tenant.Id,
            Scope = RoleScope.Tenant
        };

        _mockUserManager.Setup(x => x.FindByEmailAsync(user.Email!))
            .ReturnsAsync(user);

        // Act & Assert
        var exception = await Assert.ThrowsAsync<InvalidDataException>(
            () => _userService.AddUserToRole(dto, RoleScope.Tenant));
        Assert.Contains("User is already assigned to this role", exception.Message);
    }

    #endregion

    #region RemoveUserFromRole Tests

    [Fact]
    public async Task RemoveUserFromRole_RemovesRole_WhenAssignmentExists()
    {
        // Arrange
        await SeedTestData();
        var user = await _context.Users.FirstAsync();
        var role = await _context.Roles.FirstAsync(r => r.Scope == RoleScope.Tenant);
        var tenant = await _context.Tenants.FirstAsync();

        var userRole = new UserRoles
        {
            UserId = user.Id,
            RoleId = role.Id,
            TenantId = tenant.Id,
            Scope = RoleScope.Tenant
        };
        _context.UserRoles.Add(userRole);
        await _context.SaveChangesAsync();

        var dto = new RemoveUserFromRoleDto
        {
            Email = user.Email!,
            RoleId = role.Id,
            TenantId = tenant.Id,
            Scope = RoleScope.Tenant
        };

        _mockUserManager.Setup(x => x.FindByEmailAsync(user.Email!))
            .ReturnsAsync(user);

        // Act
        await _userService.RemoveUserFromRole(dto, RoleScope.Tenant);

        // Assert
        var removedUserRole = await _context.UserRoles.FirstOrDefaultAsync(
            ur => ur.UserId == user.Id && ur.RoleId == role.Id);
        Assert.Null(removedUserRole);
        _mockUow.Verify(x => x.CompleteAsync(), Times.Once);
    }

    [Fact]
    public async Task RemoveUserFromRole_ThrowsNotFoundException_WhenUserDoesNotExist()
    {
        // Arrange
        await SeedTestData();
        var role = await _context.Roles.FirstAsync(r => r.Scope == RoleScope.Tenant);
        var nonExistentEmail = "nonexistent@test.com";

        var dto = new RemoveUserFromRoleDto
        {
            Email = nonExistentEmail,
            RoleId = role.Id,
            TenantId = Guid.NewGuid(),
            Scope = RoleScope.Tenant
        };

        _mockUserManager.Setup(x => x.FindByEmailAsync(nonExistentEmail))
            .ReturnsAsync((AuthUser?)null);

        // Act & Assert
        var exception = await Assert.ThrowsAsync<NotFoundException>(
            () => _userService.RemoveUserFromRole(dto, RoleScope.Tenant));
        Assert.Contains($"User with email {nonExistentEmail} not found", exception.Message);
    }

    [Fact]
    public async Task RemoveUserFromRole_ThrowsNotFoundException_WhenRoleDoesNotExist()
    {
        // Arrange
        await SeedTestData();
        var user = await _context.Users.FirstAsync();
        var nonExistentRoleId = Guid.NewGuid();

        var dto = new RemoveUserFromRoleDto
        {
            Email = user.Email!,
            RoleId = nonExistentRoleId,
            TenantId = Guid.NewGuid(),
            Scope = RoleScope.Tenant
        };

        _mockUserManager.Setup(x => x.FindByEmailAsync(user.Email!))
            .ReturnsAsync(user);

        // Act & Assert
        var exception = await Assert.ThrowsAsync<NotFoundException>(
            () => _userService.RemoveUserFromRole(dto, RoleScope.Tenant));
        Assert.Contains($"Role with ID {nonExistentRoleId} not found", exception.Message);
    }

    [Fact]
    public async Task RemoveUserFromRole_ThrowsNotFoundException_WhenAssignmentDoesNotExist()
    {
        // Arrange
        await SeedTestData();
        var user = await _context.Users.FirstAsync();
        var role = await _context.Roles.FirstAsync(r => r.Scope == RoleScope.Tenant);
        var tenant = await _context.Tenants.FirstAsync();

        var dto = new RemoveUserFromRoleDto
        {
            Email = user.Email!,
            RoleId = role.Id,
            TenantId = tenant.Id,
            Scope = RoleScope.Tenant
        };

        _mockUserManager.Setup(x => x.FindByEmailAsync(user.Email!))
            .ReturnsAsync(user);

        // Act & Assert
        var exception = await Assert.ThrowsAsync<NotFoundException>(
            () => _userService.RemoveUserFromRole(dto, RoleScope.Tenant));
        Assert.Contains("User role assignment not found", exception.Message);
    }

    #endregion

    #region GetUserByUserName Tests

    [Fact]
    public async Task GetUserByUserName_ReturnsUserLookupDto_WhenUserExists()
    {
        // Arrange
        await SeedTestData();
        var user = await _context.Users.FirstAsync();
        
        _mockUserManager.Setup(x => x.FindByNameAsync(user.UserName!))
            .ReturnsAsync(user);

        // Act
        var result = await _userService.GetUserByUserName(user.UserName!);

        // Assert
        Assert.NotNull(result);
        Assert.Equal(user.UserName, result.UserName);
        Assert.Equal(user.Email, result.Email);
    }

    [Fact]
    public async Task GetUserByUserName_ReturnsNull_WhenUserDoesNotExist()
    {
        // Arrange
        var nonExistentUserName = "nonexistent@test.com";
        
        _mockUserManager.Setup(x => x.FindByNameAsync(nonExistentUserName))
            .ReturnsAsync((AuthUser?)null);

        // Act
        var result = await _userService.GetUserByUserName(nonExistentUserName);

        // Assert
        Assert.Null(result);
    }

    #endregion

    #region GetUserTenants Tests

    [Fact]
    public async Task GetUserTenants_ReturnsAllTenants_WhenUserIsSystemAdmin()
    {
        // Arrange
        await SeedTestData();
        var user = await _context.Users.FirstAsync();
        var systemAdminRole = await _context.Roles.FirstAsync(r => r.Scope == RoleScope.Internal);
        var permission = await _context.Permissions.FirstAsync(p => p.Code == RolePermissionConstants.SysAdminManageTenants);

        // Set up system admin role with permission
        var rolePermission = new RolePermission
        {
            RoleId = systemAdminRole.Id,
            PermissionCode = permission.Code,
            Permission = permission
        };
        _context.RolePermissions.Add(rolePermission);

        var userRole = new UserRoles
        {
            UserId = user.Id,
            RoleId = systemAdminRole.Id,
            Scope = RoleScope.Internal
        };

        _context.UserRoles.Add(userRole);
        await _context.SaveChangesAsync();

        // Act
        var result = await _userService.GetUserTenants(user.Id, forLogin: true);

        // Assert
        var resultList = result.ToList();
        Assert.Equal(2, resultList.Count); // Should return all tenants from seed data
    }

    [Fact]
    public async Task GetUserTenants_ReturnsUserTenants_WhenUserIsRegularUser()
    {
        // Arrange
        await SeedTestData();
        var user = await _context.Users.FirstAsync();
        var tenant = await _context.Tenants.FirstAsync();
        var role = await _context.Roles.FirstAsync(r => r.Scope == RoleScope.Tenant);

        var userRole = new UserRoles
        {
            UserId = user.Id,
            RoleId = role.Id,
            TenantId = tenant.Id,
            Scope = RoleScope.Tenant
        };

        _context.UserRoles.Add(userRole);
        await _context.SaveChangesAsync();

        // Act
        var result = await _userService.GetUserTenants(user.Id, forLogin: true);

        // Assert
        var resultList = result.ToList();
        Assert.Single(resultList);
        Assert.Equal(tenant.Id, resultList[0].Id);
        Assert.Equal(tenant.Name, resultList[0].Name);
    }

    [Fact]
    public async Task GetUserTenants_ReturnsCachedResult_WhenNotForLoginAndCacheHit()
    {
        // Arrange
        await SeedTestData();
        var user = await _context.Users.FirstAsync();
        var cachedTenants = new List<TenantDto>
        {
            new() { Id = Guid.NewGuid(), Name = "Cached Tenant", Code = "CT", SubDomain = "ct" }
        };

        _mockCache.Setup(x => x.GetCachedUserTenantsAsync(user.Id))
            .ReturnsAsync(cachedTenants);

        // Act
        var result = await _userService.GetUserTenants(user.Id, forLogin: false);

        // Assert
        var resultList = result.ToList();
        Assert.Single(resultList);
        Assert.Equal("Cached Tenant", resultList[0].Name);
        _mockCache.Verify(x => x.GetCachedUserTenantsAsync(user.Id), Times.Once);
    }

    #endregion

    #region GetUserSites Tests

    [Fact]
    public async Task GetUserSites_ReturnsAllSites_WhenUserHasAllSitesAccess()
    {
        // Arrange
        await SeedTestData();
        var user = await _context.Users.FirstAsync();
        var tenant = await _context.Tenants.FirstAsync();
        var systemAdminRole = await _context.Roles.FirstAsync(r => r.Scope == RoleScope.Internal);
        var permission = await _context.Permissions.FirstAsync(p => p.Code == RolePermissionConstants.SysAdminManageTenants);

        // Set up system admin role with permission
        var rolePermission = new RolePermission
        {
            RoleId = systemAdminRole.Id,
            PermissionCode = permission.Code,
            Permission = permission
        };
        _context.RolePermissions.Add(rolePermission);

        var userRole = new UserRoles
        {
            UserId = user.Id,
            RoleId = systemAdminRole.Id,
            Scope = RoleScope.Internal
        };

        _context.UserRoles.Add(userRole);
        await _context.SaveChangesAsync();

        // Act
        var result = await _userService.GetUserSites(user.Id, tenant.Id, forLogin: true);

        // Assert
        var resultList = result.ToList();
        Assert.Equal(2, resultList.Count); // Should return all sites for the tenant
        Assert.All(resultList, site => Assert.Equal(tenant.Id, site.TenantId));
    }

    [Fact]
    public async Task GetUserSites_ReturnsUserSites_WhenUserIsRegularUser()
    {
        // Arrange
        await SeedTestData();
        var user = await _context.Users.FirstAsync();
        var tenant = await _context.Tenants.FirstAsync();
        var site = await _context.Sites.FirstAsync();
        var role = await _context.Roles.FirstAsync(r => r.Scope == RoleScope.Site);

        var userRole = new UserRoles
        {
            UserId = user.Id,
            RoleId = role.Id,
            TenantId = tenant.Id,
            SiteId = site.Id,
            Scope = RoleScope.Site
        };

        _context.UserRoles.Add(userRole);
        await _context.SaveChangesAsync();

        // Act
        var result = await _userService.GetUserSites(user.Id, tenant.Id, forLogin: true);

        // Assert
        var resultList = result.ToList();
        Assert.Single(resultList);
        Assert.Equal(site.Id, resultList[0].Id);
        Assert.Equal(site.Name, resultList[0].Name);
        Assert.Equal(tenant.Id, resultList[0].TenantId);
    }

    [Fact]
    public async Task GetUserSites_ReturnsCachedResult_WhenNotForLoginAndCacheHit()
    {
        // Arrange
        await SeedTestData();
        var user = await _context.Users.FirstAsync();
        var tenant = await _context.Tenants.FirstAsync();
        var cachedSites = new List<SiteDto>
        {
            new() { Id = Guid.NewGuid(), Name = "Cached Site", Code = "CS", TenantId = tenant.Id, IsActive = true }
        };

        _mockCache.Setup(x => x.GetCachedUserSitesAsync(user.Id, tenant.Id))
            .ReturnsAsync(cachedSites);

        // Act
        var result = await _userService.GetUserSites(user.Id, tenant.Id, forLogin: false);

        // Assert
        var resultList = result.ToList();
        Assert.Single(resultList);
        Assert.Equal("Cached Site", resultList[0].Name);
        _mockCache.Verify(x => x.GetCachedUserSitesAsync(user.Id, tenant.Id), Times.Once);
    }

    #endregion

    #region GetUserTenantCount Tests

    [Fact]
    public async Task GetUserTenantCount_ReturnsAllTenantCount_WhenUserIsSystemAdmin()
    {
        // Arrange
        await SeedTestData();
        var user = await _context.Users.FirstAsync();
        var systemAdminRole = await _context.Roles.FirstAsync(r => r.Scope == RoleScope.Internal);
        var permission = await _context.Permissions.FirstAsync(p => p.Code == RolePermissionConstants.SysAdminManageTenants);

        // Set up system admin role with permission
        var rolePermission = new RolePermission
        {
            RoleId = systemAdminRole.Id,
            PermissionCode = permission.Code,
            Permission = permission
        };
        _context.RolePermissions.Add(rolePermission);

        var userRole = new UserRoles
        {
            UserId = user.Id,
            RoleId = systemAdminRole.Id,
            Scope = RoleScope.Internal
        };

        _context.UserRoles.Add(userRole);
        await _context.SaveChangesAsync();

        // Act
        var result = await _userService.GetUserTenantCount(user.Id);

        // Assert
        Assert.Equal(2, result); // All tenants from seed data
    }

    [Fact]
    public async Task GetUserTenantCount_ReturnsUserTenantCount_WhenUserIsRegularUser()
    {
        // Arrange
        await SeedTestData();
        var user = await _context.Users.FirstAsync();
        var tenant = await _context.Tenants.FirstAsync();
        var role = await _context.Roles.FirstAsync(r => r.Scope == RoleScope.Tenant);

        var userRole = new UserRoles
        {
            UserId = user.Id,
            RoleId = role.Id,
            TenantId = tenant.Id,
            Scope = RoleScope.Tenant
        };

        _context.UserRoles.Add(userRole);
        await _context.SaveChangesAsync();

        // Act
        var result = await _userService.GetUserTenantCount(user.Id);

        // Assert
        Assert.Equal(1, result);
    }

    #endregion

    #region GetUserSiteCount Tests

    [Fact]
    public async Task GetUserSiteCount_ReturnsAllSiteCount_WhenUserHasAllSitesAccess()
    {
        // Arrange
        await SeedTestData();
        var user = await _context.Users.FirstAsync();
        var tenant = await _context.Tenants.FirstAsync();
        var systemAdminRole = await _context.Roles.FirstAsync(r => r.Scope == RoleScope.Internal);
        var permission = await _context.Permissions.FirstAsync(p => p.Code == RolePermissionConstants.SysAdminManageTenants);

        // Set up system admin role with permission
        var rolePermission = new RolePermission
        {
            RoleId = systemAdminRole.Id,
            PermissionCode = permission.Code,
            Permission = permission
        };
        _context.RolePermissions.Add(rolePermission);

        var userRole = new UserRoles
        {
            UserId = user.Id,
            RoleId = systemAdminRole.Id,
            Scope = RoleScope.Internal
        };

        _context.UserRoles.Add(userRole);
        await _context.SaveChangesAsync();

        // Act
        var result = await _userService.GetUserSiteCount(user.Id, tenant.Id);

        // Assert
        Assert.Equal(2, result); // All sites for the tenant from seed data
    }

    [Fact]
    public async Task GetUserSiteCount_ReturnsUserSiteCount_WhenUserIsRegularUser()
    {
        // Arrange
        await SeedTestData();
        var user = await _context.Users.FirstAsync();
        var tenant = await _context.Tenants.FirstAsync();
        var site = await _context.Sites.FirstAsync();
        var role = await _context.Roles.FirstAsync(r => r.Scope == RoleScope.Site);

        var userRole = new UserRoles
        {
            UserId = user.Id,
            RoleId = role.Id,
            TenantId = tenant.Id,
            SiteId = site.Id,
            Scope = RoleScope.Site
        };

        _context.UserRoles.Add(userRole);
        await _context.SaveChangesAsync();

        // Act
        var result = await _userService.GetUserSiteCount(user.Id, tenant.Id);

        // Assert
        Assert.Equal(1, result);
    }

    #endregion

    #region HasTenantAccess Tests

    [Fact]
    public async Task HasTenantAccess_ReturnsTrue_WhenUserHasAccess()
    {
        // Arrange
        await SeedTestData();
        var user = await _context.Users.FirstAsync();
        var tenant = await _context.Tenants.FirstAsync();
        var role = await _context.Roles.FirstAsync(r => r.Scope == RoleScope.Tenant);

        var userRole = new UserRoles
        {
            UserId = user.Id,
            RoleId = role.Id,
            TenantId = tenant.Id,
            Scope = RoleScope.Tenant
        };

        _context.UserRoles.Add(userRole);
        await _context.SaveChangesAsync();

        // Act
        var result = await _userService.HasTenantAccess(user.Id, tenant.Id, forLogin: true);

        // Assert
        Assert.True(result);
    }

    [Fact]
    public async Task HasTenantAccess_ReturnsFalse_WhenUserDoesNotHaveAccess()
    {
        // Arrange
        await SeedTestData();
        var user = await _context.Users.FirstAsync();
        var tenant = await _context.Tenants.FirstAsync();

        // Act
        var result = await _userService.HasTenantAccess(user.Id, tenant.Id, forLogin: true);

        // Assert
        Assert.False(result);
    }

    #endregion

    #region HasSiteAccess Tests

    [Fact]
    public async Task HasSiteAccess_ReturnsTrue_WhenUserHasAccess()
    {
        // Arrange
        await SeedTestData();
        var user = await _context.Users.FirstAsync();
        var tenant = await _context.Tenants.FirstAsync();
        var site = await _context.Sites.FirstAsync();
        var role = await _context.Roles.FirstAsync(r => r.Scope == RoleScope.Site);

        var userRole = new UserRoles
        {
            UserId = user.Id,
            RoleId = role.Id,
            TenantId = tenant.Id,
            SiteId = site.Id,
            Scope = RoleScope.Site
        };

        _context.UserRoles.Add(userRole);
        await _context.SaveChangesAsync();

        // Act
        var result = await _userService.HasSiteAccess(user.Id, site.Id, tenant.Id, forLogin: true);

        // Assert
        Assert.True(result);
    }

    [Fact]
    public async Task HasSiteAccess_ReturnsFalse_WhenUserDoesNotHaveAccess()
    {
        // Arrange
        await SeedTestData();
        var user = await _context.Users.FirstAsync();
        var tenant = await _context.Tenants.FirstAsync();
        var site = await _context.Sites.FirstAsync();

        // Act
        var result = await _userService.HasSiteAccess(user.Id, site.Id, tenant.Id, forLogin: true);

        // Assert
        Assert.False(result);
    }

    #endregion

    #region InviteUserAsync Tests

    [Fact]
    public async Task InviteUserAsync_SendsInvitation_WhenUserDoesNotExist()
    {
        // Arrange
        await SeedTestData();
        var role = await _context.Roles.FirstAsync(r => r.Scope == RoleScope.Tenant);
        var tenant = await _context.Tenants.FirstAsync();
        var email = "newuser@test.com";
        var invitedByUserId = "admin-user-id";

        var request = new InviteUserRequest
        {
            Email = email,
            RoleId = role.Id.ToString(),
            TenantId = tenant.Id,
            Scope = RoleScope.Tenant
        };

        _mockUserManager.Setup(x => x.FindByEmailAsync(email))
            .ReturnsAsync((AuthUser?)null);

        _mockUserManager.Setup(x => x.CreateAsync(It.IsAny<AuthUser>()))
            .ReturnsAsync(IdentityResult.Success);

        _mockEmailContentService.Setup(x => x.PrepareInvitationEmailAsync(
                email, It.IsAny<string>(), email, RoleScope.Tenant, tenant.Id, null))
            .ReturnsAsync(new EmailContent
            {
                ToEmail = email,
                Subject = "Invitation",
                HtmlBody = "Body",
                Branding = new BrandingContext()
            });

        _mockEmailService.Setup(x => x.SendEmailAsync(It.IsAny<EmailContent>()))
            .ReturnsAsync(true);

        // Act
        var result = await _userService.InviteUserAsync(request, RoleScope.Tenant, invitedByUserId);

        // Assert
        Assert.True(result.Success);
        Assert.Equal("Invitation sent successfully", result.Message);
        Assert.NotNull(result.InvitationId);
        _mockEmailService.Verify(x => x.SendEmailAsync(It.IsAny<EmailContent>()), Times.Once);
        _mockUow.Verify(x => x.CompleteAsync(), Times.AtLeastOnce);
    }

    [Fact]
    public async Task InviteUserAsync_ReturnsExistingUser_WhenUserHasPassword()
    {
        // Arrange
        await SeedTestData();
        var user = await _context.Users.FirstAsync();
        var role = await _context.Roles.FirstAsync(r => r.Scope == RoleScope.Tenant);
        var tenant = await _context.Tenants.FirstAsync();

        // Set user with password hash (existing complete user)
        user.PasswordHash = "existing-password-hash";
        await _context.SaveChangesAsync();

        var request = new InviteUserRequest
        {
            Email = user.Email!,
            RoleId = role.Id.ToString(),
            TenantId = tenant.Id,
            Scope = RoleScope.Tenant
        };

        _mockUserManager.Setup(x => x.FindByEmailAsync(user.Email!))
            .ReturnsAsync(user);

        // Act
        var result = await _userService.InviteUserAsync(request, RoleScope.Tenant, "admin-user-id");

        // Assert
        Assert.True(result.Success);
        Assert.Equal("User already exists - role assigned directly", result.Message);
        Assert.Null(result.InvitationId);
        _mockEmailService.Verify(x => x.SendEmailAsync(It.IsAny<EmailContent>()), Times.Never);
    }

    [Fact]
    public async Task InviteUserAsync_ReturnsFailure_WhenPendingInvitationExists()
    {
        // Arrange
        await SeedTestData();
        var role = await _context.Roles.FirstAsync(r => r.Scope == RoleScope.Tenant);
        var tenant = await _context.Tenants.FirstAsync();
        var email = "existing@test.com";

        // Add existing pending invitation
        var existingInvitation = new UserInvitation
        {
            Email = email,
            TenantId = tenant.Id,
            Scope = RoleScope.Tenant,
            IsUsed = false,
            ExpiresAt = DateTime.UtcNow.AddDays(7),
            InvitationToken = "existing-token",
            CreatedBy = "admin"
        };
        _context.UserInvitations.Add(existingInvitation);
        await _context.SaveChangesAsync();

        var request = new InviteUserRequest
        {
            Email = email,
            RoleId = role.Id.ToString(),
            TenantId = tenant.Id,
            Scope = RoleScope.Tenant
        };

        _mockUserManager.Setup(x => x.FindByEmailAsync(email))
            .ReturnsAsync((AuthUser?)null);

        _mockUserManager.Setup(x => x.CreateAsync(It.IsAny<AuthUser>()))
            .ReturnsAsync(IdentityResult.Success);

        // Act
        var result = await _userService.InviteUserAsync(request, RoleScope.Tenant, "admin-user-id");

        // Assert
        Assert.False(result.Success);
        Assert.Contains("pending invitation", result.Message);
    }

    [Fact]
    public async Task InviteUserAsync_ThrowsInvalidDataException_WhenScopeMismatch()
    {
        // Arrange
        await SeedTestData();
        var role = await _context.Roles.FirstAsync(r => r.Scope == RoleScope.Tenant);
        var tenant = await _context.Tenants.FirstAsync();

        var request = new InviteUserRequest
        {
            Email = "test@test.com",
            RoleId = role.Id.ToString(),
            TenantId = tenant.Id,
            Scope = RoleScope.Site // Mismatch with expected scope
        };

        // Act & Assert
        var exception = await Assert.ThrowsAsync<InvalidDataException>(
            () => _userService.InviteUserAsync(request, RoleScope.Tenant, "admin-user-id"));
        Assert.Contains("Request scope must be Tenant", exception.Message);
    }

    #endregion

    #region ValidateInvitationTokenAsync Tests

    [Fact]
    public async Task ValidateInvitationTokenAsync_ReturnsInvitation_WhenTokenIsValid()
    {
        // Arrange
        var token = "valid-token";
        var invitation = new UserInvitation
        {
            Email = "test@test.com",
            InvitationToken = token,
            IsUsed = false,
            ExpiresAt = DateTime.UtcNow.AddDays(1),
            Scope = RoleScope.Tenant
        };

        _context.UserInvitations.Add(invitation);
        await _context.SaveChangesAsync();

        // Act
        var result = await _userService.ValidateInvitationTokenAsync(token);

        // Assert
        Assert.NotNull(result);
        Assert.Equal(token, result.InvitationToken);
        Assert.Equal("test@test.com", result.Email);
    }

    [Fact]
    public async Task ValidateInvitationTokenAsync_ReturnsNull_WhenTokenIsInvalid()
    {
        // Act
        var result = await _userService.ValidateInvitationTokenAsync("invalid-token");

        // Assert
        Assert.Null(result);
    }

    [Fact]
    public async Task ValidateInvitationTokenAsync_ReturnsNull_WhenTokenIsExpired()
    {
        // Arrange
        var token = "expired-token";
        var invitation = new UserInvitation
        {
            Email = "test@test.com",
            InvitationToken = token,
            IsUsed = false,
            ExpiresAt = DateTime.UtcNow.AddDays(-1), // Expired
            Scope = RoleScope.Tenant
        };

        _context.UserInvitations.Add(invitation);
        await _context.SaveChangesAsync();

        // Act
        var result = await _userService.ValidateInvitationTokenAsync(token);

        // Assert
        Assert.Null(result);
    }

    [Fact]
    public async Task ValidateInvitationTokenAsync_ReturnsNull_WhenTokenIsUsed()
    {
        // Arrange
        var token = "used-token";
        var invitation = new UserInvitation
        {
            Email = "test@test.com",
            InvitationToken = token,
            IsUsed = true, // Already used
            ExpiresAt = DateTime.UtcNow.AddDays(1),
            Scope = RoleScope.Tenant
        };

        _context.UserInvitations.Add(invitation);
        await _context.SaveChangesAsync();

        // Act
        var result = await _userService.ValidateInvitationTokenAsync(token);

        // Assert
        Assert.Null(result);
    }

    #endregion

    #region GetPendingInvitationsAsync Tests

    [Fact]
    public async Task GetPendingInvitationsAsync_ReturnsInternalInvitations_WhenScopeIsInternal()
    {
        // Arrange
        var invitation = new UserInvitation
        {
            Email = "internal@test.com",
            Scope = RoleScope.Internal,
            IsUsed = false,
            ExpiresAt = DateTime.UtcNow.AddDays(1),
            InvitationToken = "token"
        };

        _context.UserInvitations.Add(invitation);
        await _context.SaveChangesAsync();

        // Act
        var result = await _userService.GetPendingInvitationsAsync(RoleScope.Internal);

        // Assert
        var resultList = result.ToList();
        Assert.Single(resultList);
        Assert.Equal("internal@test.com", resultList[0].Email);
        Assert.Equal(RoleScope.Internal, resultList[0].Scope);
    }

    [Fact]
    public async Task GetPendingInvitationsAsync_ReturnsTenantInvitations_WhenScopeIsTenant()
    {
        // Arrange
        await SeedTestData();
        var tenant = await _context.Tenants.FirstAsync();

        var invitation = new UserInvitation
        {
            Email = "tenant@test.com",
            TenantId = tenant.Id,
            Scope = RoleScope.Tenant,
            IsUsed = false,
            ExpiresAt = DateTime.UtcNow.AddDays(1),
            InvitationToken = "token"
        };

        _context.UserInvitations.Add(invitation);
        await _context.SaveChangesAsync();

        // Act
        var result = await _userService.GetPendingInvitationsAsync(RoleScope.Tenant, tenant.Id);

        // Assert
        var resultList = result.ToList();
        Assert.Single(resultList);
        Assert.Equal("tenant@test.com", resultList[0].Email);
        Assert.Equal(tenant.Id, resultList[0].TenantId);
    }

    [Fact]
    public async Task GetPendingInvitationsAsync_ReturnsSiteInvitations_WhenScopeIsSite()
    {
        // Arrange
        await SeedTestData();
        var site = await _context.Sites.FirstAsync();

        var invitation = new UserInvitation
        {
            Email = "site@test.com",
            SiteId = site.Id,
            Scope = RoleScope.Site,
            IsUsed = false,
            ExpiresAt = DateTime.UtcNow.AddDays(1),
            InvitationToken = "token"
        };

        _context.UserInvitations.Add(invitation);
        await _context.SaveChangesAsync();

        // Act
        var result = await _userService.GetPendingInvitationsAsync(RoleScope.Site, null, site.Id);

        // Assert
        var resultList = result.ToList();
        Assert.Single(resultList);
        Assert.Equal("site@test.com", resultList[0].Email);
        Assert.Equal(site.Id, resultList[0].SiteId);
    }

    [Fact]
    public async Task GetPendingInvitationsAsync_FiltersExpiredInvitations()
    {
        // Arrange
        var validInvitation = new UserInvitation
        {
            Email = "valid@test.com",
            Scope = RoleScope.Internal,
            IsUsed = false,
            ExpiresAt = DateTime.UtcNow.AddDays(1),
            InvitationToken = "valid-token"
        };

        var expiredInvitation = new UserInvitation
        {
            Email = "expired@test.com",
            Scope = RoleScope.Internal,
            IsUsed = false,
            ExpiresAt = DateTime.UtcNow.AddDays(-1), // Expired
            InvitationToken = "expired-token"
        };

        _context.UserInvitations.AddRange(validInvitation, expiredInvitation);
        await _context.SaveChangesAsync();

        // Act
        var result = await _userService.GetPendingInvitationsAsync(RoleScope.Internal);

        // Assert
        var resultList = result.ToList();
        Assert.Single(resultList);
        Assert.Equal("valid@test.com", resultList[0].Email);
    }

    [Fact]
    public async Task GetPendingInvitationsAsync_FiltersUsedInvitations()
    {
        // Arrange
        var validInvitation = new UserInvitation
        {
            Email = "valid@test.com",
            Scope = RoleScope.Internal,
            IsUsed = false,
            ExpiresAt = DateTime.UtcNow.AddDays(1),
            InvitationToken = "valid-token"
        };

        var usedInvitation = new UserInvitation
        {
            Email = "used@test.com",
            Scope = RoleScope.Internal,
            IsUsed = true, // Already used
            ExpiresAt = DateTime.UtcNow.AddDays(1),
            InvitationToken = "used-token"
        };

        _context.UserInvitations.AddRange(validInvitation, usedInvitation);
        await _context.SaveChangesAsync();

        // Act
        var result = await _userService.GetPendingInvitationsAsync(RoleScope.Internal);

        // Assert
        var resultList = result.ToList();
        Assert.Single(resultList);
        Assert.Equal("valid@test.com", resultList[0].Email);
    }

    #endregion

    #region DeleteInvitationAsync Tests

    [Fact]
    public async Task DeleteInvitationAsync_DeletesInvitationAndUnconfirmedUser_WhenUserExistsButNotConfirmed()
    {
        // Arrange
        var email = "unconfirmed@test.com";
        var user = new AuthUser
        {
            Id = Guid.NewGuid(),
            Email = email,
            UserName = email,
            EmailConfirmed = false // Not confirmed
        };

        var invitation = new UserInvitation
        {
            Email = email,
            IsUsed = false,
            ExpiresAt = DateTime.UtcNow.AddDays(1),
            InvitationToken = "token",
            Scope = RoleScope.Internal
        };

        _context.Users.Add(user);
        _context.UserInvitations.Add(invitation);
        await _context.SaveChangesAsync();

        _mockUserManager.Setup(x => x.FindByEmailAsync(email))
            .ReturnsAsync(user);

        _mockUserManager.Setup(x => x.DeleteAsync(user))
            .ReturnsAsync(IdentityResult.Success);

        // Act
        await _userService.DeleteInvitationAsync(email);

        // Assert
        _mockUserManager.Verify(x => x.DeleteAsync(user), Times.Once);
        _mockUow.Verify(x => x.CompleteAsync(), Times.Once);

        var deletedInvitation = await _context.UserInvitations.FirstOrDefaultAsync(i => i.Email == email);
        Assert.Null(deletedInvitation);
    }

    [Fact]
    public async Task DeleteInvitationAsync_DeletesOnlyInvitation_WhenUserDoesNotExist()
    {
        // Arrange
        var email = "nonexistent@test.com";
        var invitation = new UserInvitation
        {
            Email = email,
            IsUsed = false,
            ExpiresAt = DateTime.UtcNow.AddDays(1),
            InvitationToken = "token",
            Scope = RoleScope.Internal
        };

        _context.UserInvitations.Add(invitation);
        await _context.SaveChangesAsync();

        _mockUserManager.Setup(x => x.FindByEmailAsync(email))
            .ReturnsAsync((AuthUser?)null);

        // Act
        await _userService.DeleteInvitationAsync(email);

        // Assert
        _mockUserManager.Verify(x => x.DeleteAsync(It.IsAny<AuthUser>()), Times.Never);
        _mockUow.Verify(x => x.CompleteAsync(), Times.Once);

        var deletedInvitation = await _context.UserInvitations.FirstOrDefaultAsync(i => i.Email == email);
        Assert.Null(deletedInvitation);
    }

    [Fact]
    public async Task DeleteInvitationAsync_ThrowsNotFoundException_WhenInvitationDoesNotExist()
    {
        // Arrange
        var email = "nonexistent@test.com";

        // Act & Assert
        var exception = await Assert.ThrowsAsync<NotFoundException>(
            () => _userService.DeleteInvitationAsync(email));
        Assert.Contains("Open invitation does not exist", exception.Message);
    }

    [Fact]
    public async Task DeleteInvitationAsync_ThrowsInvalidDataException_WhenUserAlreadyAcceptedInvite()
    {
        // Arrange
        var email = "confirmed@test.com";
        var user = new AuthUser
        {
            Id = Guid.NewGuid(),
            Email = email,
            UserName = email,
            EmailConfirmed = true // Already confirmed
        };

        var invitation = new UserInvitation
        {
            Email = email,
            IsUsed = false,
            ExpiresAt = DateTime.UtcNow.AddDays(1),
            InvitationToken = "token",
            Scope = RoleScope.Internal
        };

        _context.Users.Add(user);
        _context.UserInvitations.Add(invitation);
        await _context.SaveChangesAsync();

        _mockUserManager.Setup(x => x.FindByEmailAsync(email))
            .ReturnsAsync(user);

        // Act & Assert
        var exception = await Assert.ThrowsAsync<InvalidDataException>(
            () => _userService.DeleteInvitationAsync(email));
        Assert.Contains("User already accepted invite", exception.Message);
    }

    #endregion
}