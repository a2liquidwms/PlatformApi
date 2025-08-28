using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text.Json;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.DependencyInjection;
using NetStarterCommon.Core.Common.Models;
using NetStarterCommon.Core.Common.Permissions;
using PlatformApi;
using PlatformApi.Common.Constants;
using PlatformApi.Common.Permissions;
using PlatformApi.Models;
using PlatformApi.Services;
using RedClayAuthApi;

namespace PlatformApiTests.Root
{
    public class PermissionsAuthServerMiddlewareTests
    {
        private readonly Mock<IServiceScopeFactory> _mockServiceScopeFactory;
        private readonly Mock<IMemoryCache> _mockMemoryCache;
        private readonly Mock<ILogger<PermissionsAuthServerMiddleware>> _mockLogger;
        private readonly Mock<IPermissionService> _mockPermissionService;
        private readonly HttpContext _httpContext;
        private readonly Mock<RequestDelegate> _nextDelegate;

        public PermissionsAuthServerMiddlewareTests()
        {
            _mockServiceScopeFactory = new Mock<IServiceScopeFactory>();
            _mockMemoryCache = new Mock<IMemoryCache>();
            _mockLogger = new Mock<ILogger<PermissionsAuthServerMiddleware>>();
            _mockPermissionService = new Mock<IPermissionService>();
            _nextDelegate = new Mock<RequestDelegate>();
            _httpContext = new DefaultHttpContext();

            // Setup service scope factory
            var serviceScope = new Mock<IServiceScope>();
            var serviceProvider = new Mock<IServiceProvider>();
            serviceProvider.Setup(x => x.GetService(typeof(IPermissionService)))
                .Returns(_mockPermissionService.Object);
            serviceScope.Setup(x => x.ServiceProvider).Returns(serviceProvider.Object);
            
            _mockServiceScopeFactory.Setup(x => x.CreateScope()).Returns(serviceScope.Object);
        }

        private void SetupAuthenticatedUser(string userId, List<string> roles, List<string> adminRoles)
        {
            var claims = new List<Claim>
            {
                new Claim(JwtRegisteredClaimNames.Sub, userId)
            };

            // Add roles claim if any
            if (roles.Any())
            {
                var rolesJson = JsonSerializer.Serialize(roles.ToArray());
                claims.Add(new Claim(CommonConstants.RolesClaim, rolesJson));
            }

            // Add admin roles claim if any
            if (adminRoles.Any())
            {
                var adminRolesJson = JsonSerializer.Serialize(adminRoles.ToArray());
                claims.Add(new Claim(CommonConstants.AdminRolesClaim, adminRolesJson));
            }

            var identity = new ClaimsIdentity(claims, "Bearer");
            var principal = new ClaimsPrincipal(identity);
            _httpContext.User = principal;

            // Add Bearer token
            _httpContext.Request.Headers["Authorization"] = "Bearer test_token";
        }

        [Fact]
        public async Task InvokeAsync_SkipsMiddleware_WhenPathIsAuthLogin()
        {
            // Arrange
            var middleware = new PermissionsAuthServerMiddleware(
                _nextDelegate.Object,
                _mockLogger.Object,
                _mockServiceScopeFactory.Object,
                _mockMemoryCache.Object);

            _httpContext.Request.Path = "/api/v1/auth/login";

            // Act
            await middleware.InvokeAsync(_httpContext);

            // Assert
            _nextDelegate.Verify(next => next(_httpContext), Times.Once);
            Assert.False(_httpContext.Items.ContainsKey(PermissionConstants.PermissionContext));
        }

        [Fact]
        public async Task InvokeAsync_ProcessesPermissions_WhenUserIsAuthenticated()
        {
            // Arrange
            var userId = "test-user-id";
            var userRoles = new List<string> { "User", "Manager" };
            SetupAuthenticatedUser(userId, userRoles, new List<string>());

            // Mock cache miss
            object? cacheValue = null;
            _mockMemoryCache.Setup(x => x.TryGetValue(CommonConstants.PermissionRoleCacheKey, out cacheValue))
                .Returns(false);

            // Mock permission service
            var testRole1 = new AuthRole
            {
                Id = "role1",
                Name = "User",
                RolePermissions = new List<RolePermission>
                {
                    new RolePermission 
                    { 
                        UserRoleId = "role1",
                        PermissionCode = "read:data",
                        Permission = new Permission { Code = "read:data" } 
                    },
                    new RolePermission 
                    { 
                        UserRoleId = "role1",
                        PermissionCode = "write:data",
                        Permission = new Permission { Code = "write:data" } 
                    }
                }
            };

            var testRole2 = new AuthRole
            {
                Id = "role2",
                Name = "Manager",
                RolePermissions = new List<RolePermission>
                {
                    new RolePermission 
                    { 
                        UserRoleId = "role2",
                        PermissionCode = "manage:users",
                        Permission = new Permission { Code = "manage:users" } 
                    }
                }
            };

            _mockPermissionService.Setup(x => x.GetAllRoles(true))
                .ReturnsAsync(new List<AuthRole> { testRole1, testRole2 });

            // Mock cache set
            var cacheEntry = new Mock<ICacheEntry>();
            _mockMemoryCache.Setup(x => x.CreateEntry(CommonConstants.PermissionRoleCacheKey))
                .Returns(cacheEntry.Object);

            var middleware = new PermissionsAuthServerMiddleware(
                _nextDelegate.Object,
                _mockLogger.Object,
                _mockServiceScopeFactory.Object,
                _mockMemoryCache.Object);

            // Act
            await middleware.InvokeAsync(_httpContext);

            // Assert
            _nextDelegate.Verify(next => next(_httpContext), Times.Once);
            Assert.True(_httpContext.Items.ContainsKey(PermissionConstants.PermissionContext));
            
            var permissions = _httpContext.Items[PermissionConstants.PermissionContext] as List<CommonPermission>;
            Assert.NotNull(permissions);
            Assert.Equal(3, permissions.Count);
            Assert.Contains(permissions, p => p.Code == "read:data");
            Assert.Contains(permissions, p => p.Code == "write:data");
            Assert.Contains(permissions, p => p.Code == "manage:users");
        }

        [Fact]
        public async Task InvokeAsync_UsesCache_WhenRolesAreCached()
        {
            // Arrange
            var userId = "test-user-id";
            var userRoles = new List<string> { "User" };
            SetupAuthenticatedUser(userId, userRoles, new List<string>());

            // Mock cache hit
            var cachedRoles = new List<CommonRolesPermission>
            {
                new CommonRolesPermission
                {
                    Id = "role1",
                    Name = "User",
                    Permissions = new List<CommonPermission>
                    {
                        new CommonPermission { Code = "cached:permission" }
                    }
                }
            };

            object cacheValue = cachedRoles;
            _mockMemoryCache.Setup(x => x.TryGetValue(CommonConstants.PermissionRoleCacheKey, out cacheValue!))
                .Returns(true);

            var middleware = new PermissionsAuthServerMiddleware(
                _nextDelegate.Object,
                _mockLogger.Object,
                _mockServiceScopeFactory.Object,
                _mockMemoryCache.Object);

            // Act
            await middleware.InvokeAsync(_httpContext);

            // Assert
            // Verify that permission service was not called
            _mockPermissionService.Verify(x => x.GetAllRoles(It.IsAny<bool>()), Times.Never);
            
            // Verify permissions were set
            var permissions = _httpContext.Items[PermissionConstants.PermissionContext] as List<CommonPermission>;
            Assert.NotNull(permissions);
            Assert.Single(permissions);
            Assert.Equal("cached:permission", permissions[0].Code);
        }

        [Fact]
        public async Task InvokeAsync_HandlesAdminRolesClaim()
        {
            // Arrange
            var userId = "test-user-id";
            var userRoles = new List<string> { "User" };
            var adminRoles = new List<string> { "Admin" };
            SetupAuthenticatedUser(userId, userRoles, adminRoles);

            // Mock cache miss
            object? cacheValue = null;
            _mockMemoryCache.Setup(x => x.TryGetValue(CommonConstants.PermissionRoleCacheKey, out cacheValue))
                .Returns(false);

            // Mock permission service
            var userRole = new AuthRole
            {
                Id = "role1",
                Name = "User",
                RolePermissions = new List<RolePermission>
                {
                    new RolePermission 
                    { 
                        UserRoleId = "role1",
                        PermissionCode = "user:permission",
                        Permission = new Permission { Code = "user:permission" } 
                    }
                }
            };

            var adminRole = new AuthRole
            {
                Id = "role2",
                Name = "Admin",
                RolePermissions = new List<RolePermission>
                {
                    new RolePermission 
                    { 
                        UserRoleId = "role2",
                        PermissionCode = "admin:permission",
                        Permission = new Permission { Code = "admin:permission" } 
                    }
                }
            };

            _mockPermissionService.Setup(x => x.GetAllRoles(true))
                .ReturnsAsync(new List<AuthRole> { userRole, adminRole });

            // Mock cache set
            var cacheEntry = new Mock<ICacheEntry>();
            _mockMemoryCache.Setup(x => x.CreateEntry(CommonConstants.PermissionRoleCacheKey))
                .Returns(cacheEntry.Object);

            var middleware = new PermissionsAuthServerMiddleware(
                _nextDelegate.Object,
                _mockLogger.Object,
                _mockServiceScopeFactory.Object,
                _mockMemoryCache.Object);

            // Act
            await middleware.InvokeAsync(_httpContext);

            // Assert
            var permissions = _httpContext.Items[PermissionConstants.PermissionContext] as List<CommonPermission>;
            Assert.NotNull(permissions);
            Assert.Equal(2, permissions.Count);
            Assert.Contains(permissions, p => p.Code == "user:permission");
            Assert.Contains(permissions, p => p.Code == "admin:permission");
        }

        [Fact]
        public async Task InvokeAsync_SkipsProcessing_WhenUserNotAuthenticated()
        {
            // Arrange
            var middleware = new PermissionsAuthServerMiddleware(
                _nextDelegate.Object,
                _mockLogger.Object,
                _mockServiceScopeFactory.Object,
                _mockMemoryCache.Object);

            // Act
            await middleware.InvokeAsync(_httpContext);

            // Assert
            _nextDelegate.Verify(next => next(_httpContext), Times.Once);
            Assert.False(_httpContext.Items.ContainsKey(PermissionConstants.PermissionContext));
            _mockPermissionService.Verify(x => x.GetAllRoles(It.IsAny<bool>()), Times.Never);
        }

        [Fact]
        public async Task InvokeAsync_ThrowsServiceException_WhenNoRolesReturned()
        {
            // Arrange
            var userId = "test-user-id";
            var userRoles = new List<string> { "User" };
            SetupAuthenticatedUser(userId, userRoles, new List<string>());

            // Mock cache miss
            object? cacheValue = null;
            _mockMemoryCache.Setup(x => x.TryGetValue(CommonConstants.PermissionRoleCacheKey, out cacheValue))
                .Returns(false);

            // Mock permission service to return empty list
            _mockPermissionService.Setup(x => x.GetAllRoles(true))
                .ReturnsAsync(new List<AuthRole>());

            var middleware = new PermissionsAuthServerMiddleware(
                _nextDelegate.Object,
                _mockLogger.Object,
                _mockServiceScopeFactory.Object,
                _mockMemoryCache.Object);

            // Act & Assert
            await Assert.ThrowsAsync<ServiceException>(() => 
                middleware.InvokeAsync(_httpContext));
        }

        [Fact]
        public async Task InvokeAsync_ExtractsUniquePermissions_FromMultipleRoles()
        {
            // Arrange
            var userId = "test-user-id";
            var userRoles = new List<string> { "User", "Manager" };
            SetupAuthenticatedUser(userId, userRoles, new List<string>());

            // Mock cache miss
            object? cacheValue = null;
            _mockMemoryCache.Setup(x => x.TryGetValue(CommonConstants.PermissionRoleCacheKey, out cacheValue))
                .Returns(false);

            // Mock permission service with overlapping permissions
            var role1 = new AuthRole
            {
                Id = "role1",
                Name = "User",
                RolePermissions = new List<RolePermission>
                {
                    new RolePermission 
                    { 
                        UserRoleId = "role1",
                        PermissionCode = "common:permission",
                        Permission = new Permission { Code = "common:permission" } 
                    },
                    new RolePermission 
                    { 
                        UserRoleId = "role1",
                        PermissionCode = "user:permission",
                        Permission = new Permission { Code = "user:permission" } 
                    }
                }
            };

            var role2 = new AuthRole
            {
                Id = "role2",
                Name = "Manager",
                RolePermissions = new List<RolePermission>
                {
                    new RolePermission 
                    { 
                        UserRoleId = "role2",
                        PermissionCode = "common:permission",
                        Permission = new Permission { Code = "common:permission" } 
                    },
                    new RolePermission 
                    { 
                        UserRoleId = "role2",
                        PermissionCode = "manager:permission",
                        Permission = new Permission { Code = "manager:permission" } 
                    }
                }
            };

            _mockPermissionService.Setup(x => x.GetAllRoles(true))
                .ReturnsAsync(new List<AuthRole> { role1, role2 });

            // Mock cache set
            var cacheEntry = new Mock<ICacheEntry>();
            _mockMemoryCache.Setup(x => x.CreateEntry(CommonConstants.PermissionRoleCacheKey))
                .Returns(cacheEntry.Object);

            var middleware = new PermissionsAuthServerMiddleware(
                _nextDelegate.Object,
                _mockLogger.Object,
                _mockServiceScopeFactory.Object,
                _mockMemoryCache.Object);

            // Act
            await middleware.InvokeAsync(_httpContext);

            // Assert
            var permissions = _httpContext.Items[PermissionConstants.PermissionContext] as List<CommonPermission>;
            Assert.NotNull(permissions);
            Assert.Equal(3, permissions.Count); // Should have only unique permissions
            Assert.Contains(permissions, p => p.Code == "common:permission");
            Assert.Contains(permissions, p => p.Code == "user:permission");
            Assert.Contains(permissions, p => p.Code == "manager:permission");
        }
    }
}


// using System.Security.Claims;
// using Moq;
// using PlatformApi.Models;
// using PlatformApi.Services;
// using NetStarterCommon.Common.Constants;
// using NetStarterCommon.Common.Models;
// using NetStarterCommon.Common.Permissions;
// using Xunit;
//
// namespace PlatformApi.Tests.Root
// {
//     public class PermissionsAuthServerMiddlewareEdgeCasesTests
//     {
//         private readonly Mock<ILogger<PermissionsAuthServerMiddleware>> _loggerMock;
//         private readonly Mock<IServiceScopeFactory> _serviceScopeFactoryMock;
//         private readonly Mock<IServiceScope> _serviceScopeMock;
//         private readonly Mock<IServiceProvider> _serviceProviderMock;
//         private readonly Mock<IUserService> _userServiceMock;
//         private readonly RequestDelegate _nextDelegate;
//
//         public PermissionsAuthServerMiddlewareEdgeCasesTests()
//         {
//             _loggerMock = new Mock<ILogger<PermissionsAuthServerMiddleware>>();
//             _serviceScopeFactoryMock = new Mock<IServiceScopeFactory>();
//             _serviceScopeMock = new Mock<IServiceScope>();
//             _serviceProviderMock = new Mock<IServiceProvider>();
//             _userServiceMock = new Mock<IUserService>();
//             _nextDelegate = (HttpContext context) => Task.CompletedTask;
//
//             // Setup service scope
//             _serviceScopeFactoryMock.Setup(x => x.CreateScope())
//                 .Returns(_serviceScopeMock.Object);
//             _serviceScopeMock.Setup(x => x.ServiceProvider)
//                 .Returns(_serviceProviderMock.Object);
//             _serviceProviderMock.Setup(x => x.GetService(typeof(IUserService)))
//                 .Returns(_userServiceMock.Object);
//         }
//
//         [Fact]
//         public async Task InvokeAsync_TenantEnabledButNotInContext_PassesNullTenant()
//         {
//             // Arrange
//             var userId = Guid.NewGuid().ToString();
//             var middleware = new PermissionsAuthServerMiddleware(
//                 _nextDelegate,
//                 _loggerMock.Object,
//                 _serviceScopeFactoryMock.Object,
//                 true // Use tenant, but we won't add one to the context
//             );
//
//             var permissions = new List<Permission>
//             {
//                 new Permission { Code = "PERMISSION_WITHOUT_TENANT" }
//             };
//
//             _userServiceMock.Setup(x => x.GetUserPermissions(userId, null))
//                 .ReturnsAsync(permissions);
//
//             var context = CreateAuthenticatedContext(userId);
//             // Intentionally not setting tenant in context
//
//             // Act
//             await middleware.InvokeAsync(context);
//
//             // Assert
//             _userServiceMock.Verify(x => x.GetUserPermissions(userId, null), Times.Once);
//             var permissionsResult = context.Items[PermissionConstants.PermissionContext] as List<CommonPermission>;
//             Assert.NotNull(permissionsResult);
//             Assert.Single(permissionsResult!);
//         }
//
//         [Fact]
//         public async Task InvokeAsync_TenantInContextButWrongType_PassesNullTenant()
//         {
//             // Arrange
//             var userId = Guid.NewGuid().ToString();
//             var middleware = new PermissionsAuthServerMiddleware(
//                 _nextDelegate,
//                 _loggerMock.Object,
//                 _serviceScopeFactoryMock.Object,
//                 true // Use tenant
//             );
//
//             var permissions = new List<Permission>
//             {
//                 new Permission { Code = "PERMISSION_WRONG_TENANT_TYPE" }
//             };
//
//             _userServiceMock.Setup(x => x.GetUserPermissions(userId, null))
//                 .ReturnsAsync(permissions);
//
//             var context = CreateAuthenticatedContext(userId);
//             // Set tenant but with wrong type (string instead of Guid)
//             context.Items[CommonConstants.TenantHttpContext] = "not-a-guid";
//
//             // Act
//             await middleware.InvokeAsync(context);
//
//             // Assert
//             _userServiceMock.Verify(x => x.GetUserPermissions(userId, null), Times.Once);
//             var permissionsResult = context.Items[PermissionConstants.PermissionContext] as List<CommonPermission>;
//             Assert.NotNull(permissionsResult);
//             Assert.Single(permissionsResult!);
//         }
//
//         [Fact]
//         public async Task InvokeAsync_ServiceReturnsNullPermissions_SetsNullInContext()
//         {
//             // Arrange
//             var userId = Guid.NewGuid().ToString();
//             var middleware = new PermissionsAuthServerMiddleware(
//                 _nextDelegate,
//                 _loggerMock.Object,
//                 _serviceScopeFactoryMock.Object
//             );
//
//             _userServiceMock.Setup(x => x.GetUserPermissions(userId, null))
//                 .ReturnsAsync((IEnumerable<Permission>?)null);
//
//             var context = CreateAuthenticatedContext(userId);
//
//             // Act
//             await middleware.InvokeAsync(context);
//
//             // Assert
//             _userServiceMock.Verify(x => x.GetUserPermissions(userId, null), Times.Once);
//             Assert.Null(context.Items[PermissionConstants.PermissionContext]);
//         }
//
//         [Fact]
//         public async Task InvokeAsync_ServiceReturnsEmptyPermissions_SetsEmptyListInContext()
//         {
//             // Arrange
//             var userId = Guid.NewGuid().ToString();
//             var middleware = new PermissionsAuthServerMiddleware(
//                 _nextDelegate,
//                 _loggerMock.Object,
//                 _serviceScopeFactoryMock.Object
//             );
//
//             _userServiceMock.Setup(x => x.GetUserPermissions(userId, null))
//                 .ReturnsAsync(new List<Permission>());
//
//             var context = CreateAuthenticatedContext(userId);
//
//             // Act
//             await middleware.InvokeAsync(context);
//
//             // Assert
//             _userServiceMock.Verify(x => x.GetUserPermissions(userId, null), Times.Once);
//             var permissionsResult = context.Items[PermissionConstants.PermissionContext] as List<CommonPermission>;
//             Assert.NotNull(permissionsResult);
//             Assert.Empty(permissionsResult!);
//         }
//
//         [Fact]
//         public async Task InvokeAsync_NoAuthHeader_ReturnsEmptyToken()
//         {
//             // Arrange
//             var userId = Guid.NewGuid().ToString();
//             var middleware = new PermissionsAuthServerMiddleware(
//                 _nextDelegate,
//                 _loggerMock.Object,
//                 _serviceScopeFactoryMock.Object
//             );
//
//             _userServiceMock.Setup(x => x.GetUserPermissions(userId, null))
//                 .ReturnsAsync(new List<Permission>());
//
//             var context = CreateAuthenticatedContext(userId);
//             // Remove the authorization header
//             context.Request.Headers.Remove("Authorization");
//
//             // Act
//             await middleware.InvokeAsync(context);
//
//             // Assert
//             _userServiceMock.Verify(x => x.GetUserPermissions(userId, null), Times.Once);
//             // Should still work, but with empty token
//             var permissionsResult = context.Items[PermissionConstants.PermissionContext] as List<CommonPermission>;
//             Assert.Empty(permissionsResult!);
//         }
//
//         [Fact]
//         public async Task InvokeAsync_UserServiceNotResolved_LogsError()
//         {
//             // Arrange
//             var userId = Guid.NewGuid().ToString();
//             var middleware = new PermissionsAuthServerMiddleware(
//                 _nextDelegate,
//                 _loggerMock.Object,
//                 _serviceScopeFactoryMock.Object
//             );
//
//             // Setup to return null for the service
//             _serviceProviderMock.Setup(x => x.GetService(typeof(IUserService)))
//                 .Returns(null!);
//
//             var context = CreateAuthenticatedContext(userId);
//
//             // Act
//             await middleware.InvokeAsync(context);
//
//             // Assert
//             // Check that an error was logged
//             _loggerMock.Verify(logger => logger.Log(
//                 LogLevel.Error,
//                 It.IsAny<EventId>(),
//                 It.Is<It.IsAnyType>((v, t) => true),
//                 It.IsAny<Exception>(),
//                 It.IsAny<Func<It.IsAnyType, Exception?, string>>()),
//                 Times.Once);
//             Assert.Null(context.Items[PermissionConstants.PermissionContext]);
//         }
//
//         // Helper method to create authenticated HTTP context
//         private HttpContext CreateAuthenticatedContext(string userId)
//         {
//             var context = new DefaultHttpContext();
//             var claims = new List<Claim>
//             {
//                 new Claim(CommonConstants.ClaimUserId, userId)
//             };
//             var identity = new ClaimsIdentity(claims, "TestAuthType");
//             var user = new ClaimsPrincipal(identity);
//             context.User = user;
//             
//             // Set authenticated to true
//             var authType = "TestAuthType";
//             var modifiableIdentity = new ClaimsIdentity(claims, authType, "name", "role");
//             var modifiableUser = new ClaimsPrincipal(modifiableIdentity);
//             context.User = modifiableUser;
//
//             // Add authorization header
//             context.Request.Headers["Authorization"] = "Bearer test-token";
//
//             return context;
//         }
//     }
// }