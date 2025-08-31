using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using Moq;
using PlatformStarterCommon.Core.Common.Auth;
using PlatformStarterCommon.Core.Common.Constants;
using PlatformStarterCommon.Core.Common.Services;
using PlatformApi.Data;
using PlatformApi.Models;
using PlatformApi.Services;

namespace PlatformApiTests.Services
{
    public class PermissionServiceTests : IDisposable
    {
        private readonly PlatformDbContext _context;
        private readonly Mock<ILogger<PermissionService>> _mockLogger;
        private readonly Mock<IUnitOfWork<PlatformDbContext>> _mockUow;
        private readonly Mock<ITenantService> _mockTenantService;
        private readonly Mock<ICacheService> _mockCache;
        private readonly PermissionService _permissionService;

        public PermissionServiceTests()
        {
            var options = new DbContextOptionsBuilder<PlatformDbContext>()
                .UseInMemoryDatabase(databaseName: Guid.NewGuid().ToString())
                .Options;

            _context = new PlatformDbContext(options);
            _mockLogger = new Mock<ILogger<PermissionService>>();
            _mockUow = new Mock<IUnitOfWork<PlatformDbContext>>();
            _mockTenantService = new Mock<ITenantService>();
            _mockCache = new Mock<ICacheService>();

            // Setup UOW to actually save to context for persistence tests
            _mockUow.Setup(x => x.CompleteAsync()).Returns(async () => await _context.SaveChangesAsync());

            _permissionService = new PermissionService(
                _mockLogger.Object,
                _context,
                _mockUow.Object,
                _mockTenantService.Object,
                _mockCache.Object
            );
        }

        public void Dispose()
        {
            _context.Dispose();
        }

        #region Permission CRUD Tests

        [Fact]
        public async Task GetAllPermissions_ReturnsAllPermissions_WhenNoScopeFilter()
        {
            // Arrange
            var permissions = new List<Permission>
            {
                new Permission { Code = "perm1", Description = "Permission 1", RoleScope = RoleScope.Tenant },
                new Permission { Code = "perm2", Description = "Permission 2", RoleScope = RoleScope.Site },
                new Permission { Code = "perm3", Description = "Permission 3", RoleScope = null }
            };
            
            _context.Permissions.AddRange(permissions);
            await _context.SaveChangesAsync();

            // Act
            var result = await _permissionService.GetAllPermissions();

            // Assert
            Assert.Equal(3, result.Count());
        }

        [Fact]
        public async Task GetAllPermissions_FiltersCorrectly_WhenScopeProvided()
        {
            // Arrange
            var permissions = new List<Permission>
            {
                new Permission { Code = "perm1", Description = "Permission 1", RoleScope = RoleScope.Tenant },
                new Permission { Code = "perm2", Description = "Permission 2", RoleScope = RoleScope.Site },
                new Permission { Code = "perm3", Description = "Permission 3", RoleScope = null }
            };
            
            _context.Permissions.AddRange(permissions);
            await _context.SaveChangesAsync();

            // Act
            var result = await _permissionService.GetAllPermissions((int)RoleScope.Tenant);

            // Assert
            var resultList = result.ToList();
            Assert.Equal(2, resultList.Count); // Tenant scope + null scope permissions
            Assert.Contains(resultList, p => p.Code == "perm1");
            Assert.Contains(resultList, p => p.Code == "perm3");
        }

        [Fact]
        public async Task GetPermissionByCode_ReturnsPermission_WhenExists()
        {
            // Arrange
            var permission = new Permission { Code = "test-perm", Description = "Test Permission" };
            _context.Permissions.Add(permission);
            await _context.SaveChangesAsync();

            // Act
            var result = await _permissionService.GetPermissionByCode("test-perm");

            // Assert
            Assert.NotNull(result);
            Assert.Equal("test-perm", result.Code);
            Assert.Equal("Test Permission", result.Description);
        }

        [Fact]
        public async Task GetPermissionByCode_ReturnsNull_WhenNotExists()
        {
            // Act
            var result = await _permissionService.GetPermissionByCode("nonexistent");

            // Assert
            Assert.Null(result);
        }

        [Fact]
        public async Task AddPermission_AddsSuccessfully_AndReturnsPermission()
        {
            // Arrange
            var permission = new Permission { Code = "new-perm", Description = "New Permission" };

            // Act
            var result = await _permissionService.AddPermission(permission);

            // Assert
            Assert.Equal(permission, result);
            var addedPermission = await _context.Permissions.FindAsync("new-perm");
            Assert.NotNull(addedPermission);
            Assert.Equal("New Permission", addedPermission.Description);
        }

        [Fact]
        public async Task AddPermissionsMulti_AddsAllPermissions_WhenValid()
        {
            // Arrange
            var permissions = new Permission[]
            {
                new Permission { Code = "multi1", Description = "Multi 1" },
                new Permission { Code = "multi2", Description = "Multi 2" },
                new Permission { Code = "multi3", Description = "Multi 3" }
            };

            // Act
            var result = await _permissionService.AddPermissionsMulti(permissions);

            // Assert
            Assert.Equal(3, result);
            var addedPermissions = await _context.Permissions
                .Where(p => p.Code.StartsWith("multi"))
                .ToListAsync();
            Assert.Equal(3, addedPermissions.Count);
        }

        [Fact]
        public async Task AddPermissionsMulti_ThrowsArgumentException_WhenDatabaseError()
        {
            // Arrange
            var permissions = new Permission[]
            {
                new Permission { Code = "dup", Description = "Duplicate 1" },
                new Permission { Code = "dup", Description = "Duplicate 2" } // Same code
            };

            // Act & Assert
            await Assert.ThrowsAsync<ArgumentException>(() => 
                _permissionService.AddPermissionsMulti(permissions));
        }

        [Fact]
        public async Task UpdatePermission_UpdatesSuccessfully_WhenValidData()
        {
            // Arrange
            var originalPermission = new Permission { Code = "update-test", Description = "Original" };
            _context.Permissions.Add(originalPermission);
            await _context.SaveChangesAsync();

            // Clear tracking to avoid issues
            _context.ChangeTracker.Clear();
            
            var updatedPermission = new Permission { Code = "update-test", Description = "Updated" };

            // Act
            var result = await _permissionService.UpdatePermission("update-test", updatedPermission);

            // Assert
            Assert.True(result);
            var permission = await _context.Permissions.FindAsync("update-test");
            Assert.Equal("Updated", permission!.Description);
        }

        [Fact]
        public async Task UpdatePermission_ThrowsInvalidDataException_WhenCodeMismatch()
        {
            // Arrange
            var permission = new Permission { Code = "different-code", Description = "Test" };

            // Act & Assert
            await Assert.ThrowsAsync<InvalidDataException>(() => 
                _permissionService.UpdatePermission("original-code", permission));
        }

        [Fact]
        public async Task UpdatePermission_ThrowsNotFoundException_WhenPermissionNotExists()
        {
            // Arrange
            var permission = new Permission { Code = "nonexistent", Description = "Test" };

            // Act & Assert
            await Assert.ThrowsAsync<NotFoundException>(() => 
                _permissionService.UpdatePermission("nonexistent", permission));
        }

        [Fact]
        public async Task DeletePermission_DeletesSuccessfully_WhenExists()
        {
            // Arrange
            var permission = new Permission { Code = "delete-test", Description = "To Delete" };
            _context.Permissions.Add(permission);
            await _context.SaveChangesAsync();

            // Clear tracking to avoid issues
            _context.ChangeTracker.Clear();

            // Act
            var result = await _permissionService.DeletePermission("delete-test");

            // Assert
            Assert.True(result);
            var deletedPermission = await _context.Permissions.FindAsync("delete-test");
            Assert.Null(deletedPermission);
        }

        [Fact]
        public async Task DeletePermission_ThrowsNotFoundException_WhenNotExists()
        {
            // Act & Assert
            await Assert.ThrowsAsync<NotFoundException>(() => 
                _permissionService.DeletePermission("nonexistent"));
        }

        #endregion

        #region Role CRUD Tests

        [Fact]
        public async Task GetAllRoles_ReturnsAllRoles_WithoutPermissions()
        {
            // Arrange
            var roles = new List<Role>
            {
                new Role { Id = Guid.Parse("00000000-0000-0000-0000-000000000001"), Name = "Role1", Scope = RoleScope.Tenant },
                new Role { Id = Guid.Parse("00000000-0000-0000-0000-000000000002"), Name = "Role2", Scope = RoleScope.Site }
            };
            
            _context.Roles.AddRange(roles);
            await _context.SaveChangesAsync();

            // Clear tracking to avoid issues
            _context.ChangeTracker.Clear();

            // Act
            var result = await _permissionService.GetAllRoles(false);

            // Assert
            var rolesList = result.ToList();
            Assert.Equal(2, rolesList.Count);
            Assert.All(rolesList, role => Assert.Empty(role.RolePermissions!));
        }

        [Fact]
        public async Task GetAllRoles_ReturnsAllRoles_WithPermissions()
        {
            // Arrange
            var role = new Role { Id = Guid.Parse("00000000-0000-0000-0000-000000000001"), Name = "TestRole", Scope = RoleScope.Tenant };
            var permission = new Permission { Code = "test-perm", Description = "Test Permission" };
            var rolePermission = new RolePermission 
            { 
                RoleId = role.Id, 
                PermissionCode = permission.Code,
                Permission = permission
            };
            
            _context.Roles.Add(role);
            _context.Permissions.Add(permission);
            _context.RolePermissions.Add(rolePermission);
            await _context.SaveChangesAsync();

            // Act
            var result = await _permissionService.GetAllRoles(true);

            // Assert
            var rolesList = result.ToList();
            Assert.Single(rolesList);
            Assert.NotNull(rolesList[0].RolePermissions);
            Assert.Single(rolesList[0].RolePermissions!);
        }

        [Fact]
        public async Task GetRoleById_ReturnsRole_WhenExists()
        {
            // Arrange
            var roleId = Guid.Parse("00000000-0000-0000-0000-000000000001");
            var role = new Role { Id = roleId, Name = "TestRole", Scope = RoleScope.Tenant };
            _context.Roles.Add(role);
            await _context.SaveChangesAsync();

            // Act
            var result = await _permissionService.GetRoleById(roleId.ToString(), false);

            // Assert
            Assert.NotNull(result);
            Assert.Equal(roleId, result.Id);
            Assert.Equal("TestRole", result.Name);
        }

        [Fact]
        public async Task GetRoleById_ReturnsNull_WhenNotExists()
        {
            // Act
            var result = await _permissionService.GetRoleById(Guid.NewGuid().ToString(), false);

            // Assert
            Assert.Null(result);
        }

        [Fact]
        public async Task GetRoleByName_ReturnsRole_WhenExists()
        {
            // Arrange
            var role = new Role { Id = Guid.Parse("00000000-0000-0000-0000-000000000001"), Name = "TestRole", Scope = RoleScope.Tenant };
            _context.Roles.Add(role);
            await _context.SaveChangesAsync();

            // Act
            var result = await _permissionService.GetRoleByName("TestRole", false);

            // Assert
            Assert.NotNull(result);
            Assert.Equal("TestRole", result.Name);
        }

        [Fact]
        public async Task GetRoleByName_ReturnsNull_WhenNotExists()
        {
            // Act
            var result = await _permissionService.GetRoleByName("NonexistentRole", false);

            // Assert
            Assert.Null(result);
        }

        [Fact]
        public async Task AddRole_AddsSuccessfully_AndReturnsRole()
        {
            // Arrange
            var role = new Role { Id = Guid.Parse("00000000-0000-0000-0000-000000000001"), Name = "NewRole", Scope = RoleScope.Tenant };

            // Act
            var result = await _permissionService.AddRole(role);

            // Assert
            Assert.Equal(role, result);
            var addedRole = await _context.Roles.FindAsync(role.Id);
            Assert.NotNull(addedRole);
            Assert.Equal("NewRole", addedRole.Name);
        }

        [Fact]
        public async Task UpdateRole_UpdatesSuccessfully_WhenValidData()
        {
            // Arrange
            var roleId = Guid.Parse("00000000-0000-0000-0000-000000000001");
            var originalRole = new Role { Id = roleId, Name = "Original", Scope = RoleScope.Tenant };
            _context.Roles.Add(originalRole);
            await _context.SaveChangesAsync();

            // Clear tracking to avoid issues
            _context.ChangeTracker.Clear();
            
            var updatedRole = new Role { Id = roleId, Name = "Updated", Scope = RoleScope.Site };

            // Act
            var result = await _permissionService.UpdateRole(roleId.ToString(), updatedRole);

            // Assert
            Assert.True(result);
            var role = await _context.Roles.FindAsync(roleId);
            Assert.Equal("Updated", role!.Name);
            Assert.Equal(RoleScope.Site, role.Scope);
        }

        [Fact]
        public async Task UpdateRole_ThrowsInvalidDataException_WhenIdMismatch()
        {
            // Arrange
            var role = new Role { Id = Guid.Parse("00000000-0000-0000-0000-000000000001"), Name = "Test", Scope = RoleScope.Tenant };

            // Act & Assert
            await Assert.ThrowsAsync<InvalidDataException>(() => 
                _permissionService.UpdateRole(Guid.Parse("00000000-0000-0000-0000-000000000002").ToString(), role));
        }

        [Fact]
        public async Task UpdateRole_ThrowsNotFoundException_WhenRoleNotExists()
        {
            // Arrange
            var roleId = Guid.Parse("00000000-0000-0000-0000-000000000001");
            var role = new Role { Id = roleId, Name = "Test", Scope = RoleScope.Tenant };

            // Act & Assert
            await Assert.ThrowsAsync<NotFoundException>(() => 
                _permissionService.UpdateRole(roleId.ToString(), role));
        }

        [Fact]
        public async Task DeleteRole_DeletesSuccessfully_WhenNoPermissions()
        {
            // Arrange
            var roleId = Guid.Parse("00000000-0000-0000-0000-000000000001");
            var role = new Role { Id = roleId, Name = "ToDelete", Scope = RoleScope.Tenant };
            _context.Roles.Add(role);
            await _context.SaveChangesAsync();

            // Clear tracking to avoid issues
            _context.ChangeTracker.Clear();

            // Act
            var result = await _permissionService.DeleteRole(roleId.ToString());

            // Assert
            Assert.True(result);
            var deletedRole = await _context.Roles.FindAsync(roleId);
            Assert.Null(deletedRole);
        }

        [Fact]
        public async Task DeleteRole_ThrowsInvalidDataException_WhenHasPermissions()
        {
            // Arrange
            var roleId = Guid.Parse("00000000-0000-0000-0000-000000000001");
            var role = new Role { Id = roleId, Name = "RoleWithPermissions", Scope = RoleScope.Tenant };
            var permission = new Permission { Code = "test-perm", Description = "Test" };
            var rolePermission = new RolePermission 
            { 
                RoleId = roleId, 
                PermissionCode = permission.Code,
                Permission = permission
            };
            
            _context.Roles.Add(role);
            _context.Permissions.Add(permission);
            _context.RolePermissions.Add(rolePermission);
            await _context.SaveChangesAsync();

            // Act & Assert
            await Assert.ThrowsAsync<InvalidDataException>(() => 
                _permissionService.DeleteRole(roleId.ToString()));
        }

        [Fact]
        public async Task DeleteRole_ThrowsNotFoundException_WhenRoleNotExists()
        {
            // Act & Assert
            await Assert.ThrowsAsync<NotFoundException>(() => 
                _permissionService.DeleteRole(Guid.NewGuid().ToString()));
        }

        #endregion

        #region Role-Permission Management Tests

        [Fact]
        public async Task AddPermissionToRole_AddsSuccessfully_WhenValidData()
        {
            // Arrange
            var roleId = Guid.Parse("00000000-0000-0000-0000-000000000001");
            var role = new Role { Id = roleId, Name = "TestRole", Scope = RoleScope.Tenant };
            var permission = new Permission { Code = "test-perm", Description = "Test", RoleScope = RoleScope.Tenant };
            
            _context.Roles.Add(role);
            _context.Permissions.Add(permission);
            await _context.SaveChangesAsync();

            // Act
            var result = await _permissionService.AddPermissionToRole(roleId.ToString(), "test-perm");

            // Assert
            Assert.NotNull(result);
            Assert.Equal(roleId, result.Id);
            
            var rolePermission = await _context.RolePermissions
                .FirstOrDefaultAsync(rp => rp.RoleId == roleId && rp.PermissionCode == "test-perm");
            Assert.NotNull(rolePermission);
        }

        [Fact]
        public async Task AddPermissionToRole_ThrowsNotFoundException_WhenRoleNotExists()
        {
            // Arrange
            var permission = new Permission { Code = "test-perm", Description = "Test" };
            _context.Permissions.Add(permission);
            await _context.SaveChangesAsync();

            // Act & Assert
            await Assert.ThrowsAsync<NotFoundException>(() => 
                _permissionService.AddPermissionToRole(Guid.NewGuid().ToString(), "test-perm"));
        }

        [Fact]
        public async Task AddPermissionToRole_ThrowsNotFoundException_WhenPermissionNotExists()
        {
            // Arrange
            var roleId = Guid.Parse("00000000-0000-0000-0000-000000000001");
            var role = new Role { Id = roleId, Name = "TestRole", Scope = RoleScope.Tenant };
            _context.Roles.Add(role);
            await _context.SaveChangesAsync();

            // Act & Assert
            await Assert.ThrowsAsync<NotFoundException>(() => 
                _permissionService.AddPermissionToRole(roleId.ToString(), "nonexistent-perm"));
        }

        [Fact]
        public async Task AddPermissionToRole_ThrowsInvalidDataException_WhenIncompatibleScope()
        {
            // Arrange
            var roleId = Guid.Parse("00000000-0000-0000-0000-000000000001");
            var role = new Role { Id = roleId, Name = "SiteRole", Scope = RoleScope.Site };
            var permission = new Permission { Code = "internal-perm", Description = "Internal Permission", RoleScope = RoleScope.Internal };
            
            _context.Roles.Add(role);
            _context.Permissions.Add(permission);
            await _context.SaveChangesAsync();

            // Act & Assert
            await Assert.ThrowsAsync<InvalidDataException>(() => 
                _permissionService.AddPermissionToRole(roleId.ToString(), "internal-perm"));
        }

        [Fact]
        public async Task AddPermissionToRole_ThrowsInvalidDataException_WhenAlreadyAssigned()
        {
            // Arrange
            var roleId = Guid.Parse("00000000-0000-0000-0000-000000000001");
            var role = new Role { Id = roleId, Name = "TestRole", Scope = RoleScope.Tenant };
            var permission = new Permission { Code = "test-perm", Description = "Test", RoleScope = RoleScope.Tenant };
            var rolePermission = new RolePermission { RoleId = roleId, PermissionCode = "test-perm" };
            
            _context.Roles.Add(role);
            _context.Permissions.Add(permission);
            _context.RolePermissions.Add(rolePermission);
            await _context.SaveChangesAsync();

            // Act & Assert
            await Assert.ThrowsAsync<InvalidDataException>(() => 
                _permissionService.AddPermissionToRole(roleId.ToString(), "test-perm"));
        }

        [Fact]
        public async Task RemovePermissionFromRole_RemovesSuccessfully_WhenExists()
        {
            // Arrange
            var roleId = Guid.Parse("00000000-0000-0000-0000-000000000001");
            var role = new Role { Id = roleId, Name = "TestRole", Scope = RoleScope.Tenant };
            var permission = new Permission { Code = "test-perm", Description = "Test" };
            var rolePermission = new RolePermission { RoleId = roleId, PermissionCode = "test-perm" };
            
            _context.Roles.Add(role);
            _context.Permissions.Add(permission);
            _context.RolePermissions.Add(rolePermission);
            await _context.SaveChangesAsync();

            // Act
            var result = await _permissionService.RemovePermissionFromRole(roleId.ToString(), "test-perm");

            // Assert
            Assert.NotNull(result);
            Assert.Equal(roleId, result.Id);
            
            var removedRolePermission = await _context.RolePermissions
                .FirstOrDefaultAsync(rp => rp.RoleId == roleId && rp.PermissionCode == "test-perm");
            Assert.Null(removedRolePermission);
        }

        [Fact]
        public async Task RemovePermissionFromRole_ThrowsNotFoundException_WhenRoleNotExists()
        {
            // Act & Assert
            await Assert.ThrowsAsync<NotFoundException>(() => 
                _permissionService.RemovePermissionFromRole(Guid.NewGuid().ToString(), "test-perm"));
        }

        [Fact]
        public async Task RemovePermissionFromRole_ThrowsNotFoundException_WhenRolePermissionNotExists()
        {
            // Arrange
            var roleId = Guid.Parse("00000000-0000-0000-0000-000000000001");
            var role = new Role { Id = roleId, Name = "TestRole", Scope = RoleScope.Tenant };
            _context.Roles.Add(role);
            await _context.SaveChangesAsync();

            // Act & Assert
            await Assert.ThrowsAsync<NotFoundException>(() => 
                _permissionService.RemovePermissionFromRole(roleId.ToString(), "nonexistent-perm"));
        }

        [Fact]
        public async Task AddPermissionsToRole_AddsMultiplePermissions_WhenValid()
        {
            // Arrange
            var roleId = Guid.Parse("00000000-0000-0000-0000-000000000001");
            var role = new Role { Id = roleId, Name = "TestRole", Scope = RoleScope.Tenant };
            var permissions = new List<Permission>
            {
                new Permission { Code = "perm1", Description = "Permission 1", RoleScope = RoleScope.Tenant },
                new Permission { Code = "perm2", Description = "Permission 2", RoleScope = RoleScope.Site }
            };
            
            _context.Roles.Add(role);
            _context.Permissions.AddRange(permissions);
            await _context.SaveChangesAsync();

            // Act
            var result = await _permissionService.AddPermissionsToRole(roleId.ToString(), new[] { "perm1", "perm2" });

            // Assert
            Assert.NotNull(result);
            Assert.Equal(roleId, result.Id);
            
            var rolePermissions = await _context.RolePermissions
                .Where(rp => rp.RoleId == roleId)
                .ToListAsync();
            Assert.Equal(2, rolePermissions.Count);
        }

        [Fact]
        public async Task AddPermissionsToRole_ThrowsInvalidDataException_WhenSomePermissionsNotExist()
        {
            // Arrange
            var roleId = Guid.Parse("00000000-0000-0000-0000-000000000001");
            var role = new Role { Id = roleId, Name = "TestRole", Scope = RoleScope.Tenant };
            var permission = new Permission { Code = "perm1", Description = "Permission 1", RoleScope = RoleScope.Tenant };
            
            _context.Roles.Add(role);
            _context.Permissions.Add(permission);
            await _context.SaveChangesAsync();

            // Act & Assert
            await Assert.ThrowsAsync<InvalidDataException>(() => 
                _permissionService.AddPermissionsToRole(roleId.ToString(), new[] { "perm1", "nonexistent" }));
        }

        [Fact]
        public async Task AddPermissionsToRole_SkipsExistingPermissions_AddsNewOnes()
        {
            // Arrange
            var roleId = Guid.Parse("00000000-0000-0000-0000-000000000001");
            var role = new Role { Id = roleId, Name = "TestRole", Scope = RoleScope.Tenant };
            var permissions = new List<Permission>
            {
                new Permission { Code = "perm1", Description = "Permission 1", RoleScope = RoleScope.Tenant },
                new Permission { Code = "perm2", Description = "Permission 2", RoleScope = RoleScope.Tenant }
            };
            var existingRolePermission = new RolePermission { RoleId = roleId, PermissionCode = "perm1" };
            
            _context.Roles.Add(role);
            _context.Permissions.AddRange(permissions);
            _context.RolePermissions.Add(existingRolePermission);
            await _context.SaveChangesAsync();

            // Act
            var result = await _permissionService.AddPermissionsToRole(roleId.ToString(), new[] { "perm1", "perm2" });

            // Assert
            Assert.NotNull(result);
            var rolePermissions = await _context.RolePermissions
                .Where(rp => rp.RoleId == roleId)
                .ToListAsync();
            Assert.Equal(2, rolePermissions.Count); // Still only 2, perm1 was skipped
        }

        #endregion

        #region Hierarchical Permission Scope Tests

        [Theory]
        [InlineData(RoleScope.Internal, RoleScope.Internal, true)]
        [InlineData(RoleScope.Internal, RoleScope.Tenant, true)]
        [InlineData(RoleScope.Internal, RoleScope.Site, true)]
        [InlineData(RoleScope.Internal, RoleScope.Default, true)]
        [InlineData(RoleScope.Tenant, RoleScope.Internal, false)]
        [InlineData(RoleScope.Tenant, RoleScope.Tenant, true)]
        [InlineData(RoleScope.Tenant, RoleScope.Site, true)]
        [InlineData(RoleScope.Tenant, RoleScope.Default, true)]
        [InlineData(RoleScope.Site, RoleScope.Internal, false)]
        [InlineData(RoleScope.Site, RoleScope.Tenant, false)]
        [InlineData(RoleScope.Site, RoleScope.Site, true)]
        [InlineData(RoleScope.Site, RoleScope.Default, true)]
        [InlineData(RoleScope.Default, RoleScope.Internal, false)]
        [InlineData(RoleScope.Default, RoleScope.Tenant, false)]
        [InlineData(RoleScope.Default, RoleScope.Site, false)]
        [InlineData(RoleScope.Default, RoleScope.Default, true)]
        public void CanPermissionBeAssignedToRole_ReturnsCorrectResult_ForScopeHierarchy(
            RoleScope roleScope, RoleScope permissionScope, bool expected)
        {
            // Act
            var result = PermissionService.CanPermissionBeAssignedToRole(permissionScope, roleScope);

            // Assert
            Assert.Equal(expected, result);
        }

        [Theory]
        [InlineData(RoleScope.Internal, true)]
        [InlineData(RoleScope.Tenant, true)]
        [InlineData(RoleScope.Site, true)]
        [InlineData(RoleScope.Default, true)]
        public void CanPermissionBeAssignedToRole_ReturnsTrue_ForNullPermissionScope(RoleScope roleScope, bool expected)
        {
            // Act
            var result = PermissionService.CanPermissionBeAssignedToRole(null, roleScope);

            // Assert
            Assert.Equal(expected, result);
        }

        [Fact]
        public async Task AddPermissionToRole_ValidatesHierarchy_InternalRoleCanHaveAllScopes()
        {
            // Arrange
            var roleId = Guid.Parse("00000000-0000-0000-0000-000000000001");
            var role = new Role { Id = roleId, Name = "InternalRole", Scope = RoleScope.Internal };
            var permission = new Permission { Code = "site-perm", Description = "Site Permission", RoleScope = RoleScope.Site };
            
            _context.Roles.Add(role);
            _context.Permissions.Add(permission);
            await _context.SaveChangesAsync();

            // Act
            var result = await _permissionService.AddPermissionToRole(roleId.ToString(), "site-perm");

            // Assert
            Assert.NotNull(result);
            var rolePermission = await _context.RolePermissions
                .FirstOrDefaultAsync(rp => rp.RoleId == roleId && rp.PermissionCode == "site-perm");
            Assert.NotNull(rolePermission);
        }

        [Fact]
        public async Task AddPermissionToRole_ValidatesHierarchy_SiteRoleCannotHaveInternalPermission()
        {
            // Arrange
            var roleId = Guid.Parse("00000000-0000-0000-0000-000000000001");
            var role = new Role { Id = roleId, Name = "SiteRole", Scope = RoleScope.Site };
            var permission = new Permission { Code = "internal-perm", Description = "Internal Permission", RoleScope = RoleScope.Internal };
            
            _context.Roles.Add(role);
            _context.Permissions.Add(permission);
            await _context.SaveChangesAsync();

            // Act & Assert
            var exception = await Assert.ThrowsAsync<InvalidDataException>(() => 
                _permissionService.AddPermissionToRole(roleId.ToString(), "internal-perm"));
            
            Assert.Contains("cannot be assigned to role with scope", exception.Message);
        }

        #endregion

        #region Cache Management Tests

        [Fact]
        public async Task GetAllRolesWithPermissionsCached_ReturnsFromCache_WhenAvailable()
        {
            // Arrange
            var cachedRoles = new List<CommonRolesPermission>
            {
                new CommonRolesPermission
                {
                    Id = "cached-role",
                    Name = "Cached Role",
                    Permissions = new List<CommonPermission>
                    {
                        new CommonPermission { Code = "cached-perm" }
                    }
                }
            };

            _mockCache.Setup(x => x.TryGetAsync<List<CommonRolesPermission>>(CommonConstants.PermissionRoleCacheKey))
                .ReturnsAsync((true, cachedRoles));

            // Act
            var result = await _permissionService.GetAllRolesWithPermissionsCached();

            // Assert
            Assert.Single(result);
            Assert.Equal("cached-role", result[0].Id);
            Assert.Equal("Cached Role", result[0].Name);
            
            // Verify cache was checked but database wasn't queried
            _mockCache.Verify(x => x.TryGetAsync<List<CommonRolesPermission>>(CommonConstants.PermissionRoleCacheKey), Times.Once);
        }

        [Fact]
        public async Task GetAllRolesWithPermissionsCached_FetchesFromDatabase_WhenNotInCache()
        {
            // Arrange
            var role = new Role 
            { 
                Id = Guid.Parse("00000000-0000-0000-0000-000000000001"), 
                Name = "TestRole", 
                Scope = RoleScope.Tenant 
            };
            var permission = new Permission { Code = "test-perm", Description = "Test Permission" };
            var rolePermission = new RolePermission 
            { 
                RoleId = role.Id, 
                PermissionCode = permission.Code,
                Permission = permission
            };
            
            _context.Roles.Add(role);
            _context.Permissions.Add(permission);
            _context.RolePermissions.Add(rolePermission);
            await _context.SaveChangesAsync();

            _mockCache.Setup(x => x.TryGetAsync<List<CommonRolesPermission>>(CommonConstants.PermissionRoleCacheKey))
                .ReturnsAsync((false, (List<CommonRolesPermission>?)null));

            // Act
            var result = await _permissionService.GetAllRolesWithPermissionsCached();

            // Assert
            Assert.Single(result);
            Assert.Equal(role.Id.ToString(), result[0].Id);
            Assert.Equal("TestRole", result[0].Name);
            Assert.Single(result[0].Permissions!);
            Assert.Equal("test-perm", result[0].Permissions![0].Code);

            // Verify cache was checked
            _mockCache.Verify(x => x.TryGetAsync<List<CommonRolesPermission>>(CommonConstants.PermissionRoleCacheKey), Times.Once);
        }

        [Fact]
        public void InvalidateRolePermissionCache_CallsCacheRemove()
        {
            // Act
            _permissionService.InvalidateRolePermissionCache();

            // Wait a moment for the background task
            Thread.Sleep(100);

            // Assert
            _mockCache.Verify(x => x.RemoveAsync(CommonConstants.PermissionRoleCacheKey), Times.Once);
        }

        [Fact]
        public async Task AddPermissionToRole_InvalidatesCache_AfterSuccess()
        {
            // Arrange
            var roleId = Guid.Parse("00000000-0000-0000-0000-000000000001");
            var role = new Role { Id = roleId, Name = "TestRole", Scope = RoleScope.Tenant };
            var permission = new Permission { Code = "test-perm", Description = "Test", RoleScope = RoleScope.Tenant };
            
            _context.Roles.Add(role);
            _context.Permissions.Add(permission);
            await _context.SaveChangesAsync();

            // Act
            await _permissionService.AddPermissionToRole(roleId.ToString(), "test-perm");

            // Wait a moment for the background cache invalidation task
            Thread.Sleep(100);

            // Assert
            _mockCache.Verify(x => x.RemoveAsync(CommonConstants.PermissionRoleCacheKey), Times.Once);
        }

        [Fact]
        public async Task RemovePermissionFromRole_InvalidatesCache_AfterSuccess()
        {
            // Arrange
            var roleId = Guid.Parse("00000000-0000-0000-0000-000000000001");
            var role = new Role { Id = roleId, Name = "TestRole", Scope = RoleScope.Tenant };
            var permission = new Permission { Code = "test-perm", Description = "Test" };
            var rolePermission = new RolePermission { RoleId = roleId, PermissionCode = "test-perm" };
            
            _context.Roles.Add(role);
            _context.Permissions.Add(permission);
            _context.RolePermissions.Add(rolePermission);
            await _context.SaveChangesAsync();

            // Act
            await _permissionService.RemovePermissionFromRole(roleId.ToString(), "test-perm");

            // Wait a moment for the background cache invalidation task
            Thread.Sleep(100);

            // Assert
            _mockCache.Verify(x => x.RemoveAsync(CommonConstants.PermissionRoleCacheKey), Times.Once);
        }

        #endregion

        #region Error Handling Tests

        [Fact]
        public async Task AddPermissionToRole_ThrowsServiceException_WhenDatabaseError()
        {
            // Arrange
            var roleId = Guid.Parse("00000000-0000-0000-0000-000000000001");
            var role = new Role { Id = roleId, Name = "TestRole", Scope = RoleScope.Tenant };
            var permission = new Permission { Code = "test-perm", Description = "Test", RoleScope = RoleScope.Tenant };
            
            _context.Roles.Add(role);
            _context.Permissions.Add(permission);
            await _context.SaveChangesAsync();

            // Setup UOW to throw exception
            _mockUow.Setup(x => x.CompleteAsync()).ThrowsAsync(new Exception("Database error"));

            // Act & Assert
            await Assert.ThrowsAsync<ServiceException>(() => 
                _permissionService.AddPermissionToRole(roleId.ToString(), "test-perm"));
        }

        [Fact]
        public async Task RemovePermissionFromRole_ThrowsServiceException_WhenDatabaseError()
        {
            // Arrange
            var roleId = Guid.Parse("00000000-0000-0000-0000-000000000001");
            var role = new Role { Id = roleId, Name = "TestRole", Scope = RoleScope.Tenant };
            var permission = new Permission { Code = "test-perm", Description = "Test" };
            var rolePermission = new RolePermission { RoleId = roleId, PermissionCode = "test-perm" };
            
            _context.Roles.Add(role);
            _context.Permissions.Add(permission);
            _context.RolePermissions.Add(rolePermission);
            await _context.SaveChangesAsync();

            // Setup UOW to throw exception
            _mockUow.Setup(x => x.CompleteAsync()).ThrowsAsync(new Exception("Database error"));

            // Act & Assert
            await Assert.ThrowsAsync<ServiceException>(() => 
                _permissionService.RemovePermissionFromRole(roleId.ToString(), "test-perm"));
        }

        [Fact]
        public async Task AddPermissionsToRole_ThrowsServiceException_WhenDatabaseError()
        {
            // Arrange
            var roleId = Guid.Parse("00000000-0000-0000-0000-000000000001");
            var role = new Role { Id = roleId, Name = "TestRole", Scope = RoleScope.Tenant };
            var permission = new Permission { Code = "test-perm", Description = "Test", RoleScope = RoleScope.Tenant };
            
            _context.Roles.Add(role);
            _context.Permissions.Add(permission);
            await _context.SaveChangesAsync();

            // Setup UOW to throw exception
            _mockUow.Setup(x => x.CompleteAsync()).ThrowsAsync(new Exception("Database error"));

            // Act & Assert
            await Assert.ThrowsAsync<ServiceException>(() => 
                _permissionService.AddPermissionsToRole(roleId.ToString(), new[] { "test-perm" }));
        }

        #endregion
    }
}