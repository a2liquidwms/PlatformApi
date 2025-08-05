using System.Security.Claims;
using AutoMapper;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;
using Moq;
using NetStarterCommon.Core.Common.Tenant;
using PlatformApi.Common.Constants;
using PlatformApi.Controllers;
using PlatformApi.Models;
using PlatformApi.Models.DTOs;
using PlatformApi.Services;
using Xunit;

namespace PlatformApiTests.Controllers
{
    public class OldUserControllerTests
    {
        private readonly Mock<IOldUserService> _mockUserService;
        private readonly Mock<IMapper> _mockMapper;
        private readonly Mock<ILogger<OldUserController>> _mockLogger;
        private readonly Mock<IHttpContextAccessor> _mockHttpContextAccessor;
        private readonly Mock<ILogger<TenantHelper>> _mockTenantHelperLogger;
        private readonly TenantHelper _tenantHelper;
        private readonly OldUserController _controller;
        private readonly Guid _testTenantId = Guid.NewGuid();

        public OldUserControllerTests()
        {
            _mockUserService = new Mock<IOldUserService>();
            _mockMapper = new Mock<IMapper>();
            _mockLogger = new Mock<ILogger<OldUserController>>();
            _mockHttpContextAccessor = new Mock<IHttpContextAccessor>();
            _mockTenantHelperLogger = new Mock<ILogger<TenantHelper>>();

            // Setup HttpContext for TenantHelper
            var httpContext = new DefaultHttpContext();
            httpContext.Items[CommonConstants.TenantHttpContext] = _testTenantId;
            _mockHttpContextAccessor.Setup(x => x.HttpContext).Returns(httpContext);

            // Create concrete TenantHelper instance
            _tenantHelper = new TenantHelper(_mockHttpContextAccessor.Object, _mockTenantHelperLogger.Object);
            
            _controller = new OldUserController(
                _mockLogger.Object,
                _mockMapper.Object,
                _mockUserService.Object,
                _tenantHelper);
        }

        private void SetupUserContext(string userId)
        {
            var claims = new List<Claim> 
            {
                new Claim(CommonConstants.ClaimUserId, userId),
                new Claim(Microsoft.IdentityModel.JsonWebTokens.JwtRegisteredClaimNames.Sub, userId)
            };
            
            var identity = new ClaimsIdentity(claims, "TestAuthType");
            var claimsPrincipal = new ClaimsPrincipal(identity);
            
            _controller.ControllerContext = new ControllerContext
            {
                HttpContext = new DefaultHttpContext { User = claimsPrincipal }
            };

            // Also update the HttpContext in the TenantHelper
            _controller.HttpContext.Items[CommonConstants.TenantHttpContext] = _testTenantId;
        }

        [Fact]
        public async Task GetMyRoles_WithTenantId_ReturnsRoles()
        {
            // Arrange
            var userId = "user123";
            var tenantId = Guid.NewGuid();
            SetupUserContext(userId);

            var roles = new List<AuthRole>
            {
                new AuthRole { Id = "role1", Name = "Admin" },
                new AuthRole { Id = "role2", Name = "User" }
            };

            var roleDtos = new List<RoleDto>
            {
                new RoleDto { Id = "role1", Name = "Admin" },
                new RoleDto { Id = "role2", Name = "User" }
            };

            _mockUserService.Setup(x => x.GetUserRoles(userId, tenantId))
                .ReturnsAsync(roles);

            _mockMapper.Setup(x => x.Map<IEnumerable<RoleDto>>(roles))
                .Returns(roleDtos);

            // Act
            var result = await _controller.GetMyRoles(tenantId);

            // Assert
            var okResult = Assert.IsType<OkObjectResult>(result.Result);
            var returnedRoles = Assert.IsAssignableFrom<IEnumerable<RoleDto>>(okResult.Value);
            Assert.Equal(2, returnedRoles.Count());
        }

        [Fact]
        public async Task GetMyTenants_ReturnsUserTenants()
        {
            // Arrange
            var userId = "user123";
            SetupUserContext(userId);

            var tenants = new List<Tenant>
            {
                new Tenant { Id = Guid.NewGuid(), Code = "TEN1", Name = "Tenant 1", SubDomain = "ten1" },
                new Tenant { Id = Guid.NewGuid(), Code = "TEN2", Name = "Tenant 2", SubDomain = "ten2" }
            };

            var tenantDtos = new List<TenantDto>
            {
                new TenantDto { Id = tenants[0].Id, Code = "TEN1", Name = "Tenant 1", SubDomain = "ten1" },
                new TenantDto { Id = tenants[1].Id, Code = "TEN2", Name = "Tenant 2", SubDomain = "ten2" }
            };

            _mockUserService.Setup(x => x.GetUserTenants(userId))
                .ReturnsAsync(tenants);

            _mockMapper.Setup(x => x.Map<IEnumerable<TenantDto>>(tenants))
                .Returns(tenantDtos);

            // Act
            var result = await _controller.GetMyTenants();

            // Assert
            var okResult = Assert.IsType<OkObjectResult>(result.Result);
            var returnedTenants = Assert.IsAssignableFrom<IEnumerable<TenantDto>>(okResult.Value);
            Assert.Equal(2, returnedTenants.Count());
        }

        [Fact]
        public async Task GetMyPermissions_ReturnsPermissions()
        {
            // Arrange
            var userId = "user123";
            var tenantId = Guid.NewGuid();
            SetupUserContext(userId);

            var permissions = new List<Permission>
            {
                new Permission { Code = "create:user", Description = "Create User" },
                new Permission { Code = "delete:user", Description = "Delete User" }
            };

            var permissionDtos = new List<PermissionDto>
            {
                new PermissionDto { Code = "create:user", Description = "Create User" },
                new PermissionDto { Code = "delete:user", Description = "Delete User" }
            };

            _mockUserService.Setup(x => x.GetUserPermissions(userId, tenantId))
                .ReturnsAsync(permissions);

            _mockMapper.Setup(x => x.Map<IEnumerable<PermissionDto>>(permissions))
                .Returns(permissionDtos);

            // Act
            var result = await _controller.GetMyPermissions(tenantId);

            // Assert
            var okResult = Assert.IsType<OkObjectResult>(result.Result);
            var returnedPermissions = Assert.IsAssignableFrom<IEnumerable<PermissionDto>>(okResult.Value);
            Assert.Equal(2, returnedPermissions.Count());
        }

        [Fact]
        public async Task CheckPermissions_ReturnsPermissionStatus()
        {
            // Arrange
            var userId = "user123";
            var tenantId = Guid.NewGuid();
            var permissionCode = "create:user";
            SetupUserContext(userId);

            _mockUserService.Setup(x => x.DoesUserHavePermission(userId, permissionCode, tenantId))
                .ReturnsAsync(true);

            // Act
            var result = await _controller.CheckPermissions(tenantId, permissionCode);

            // Assert
            var okResult = Assert.IsType<OkObjectResult>(result.Result);
            var hasPermission = Assert.IsType<bool>(okResult.Value);
            Assert.True(hasPermission);
        }

        [Fact]
        public async Task GetTenantUsers_ReturnsUsersWithNonGuestRoles()
        {
            // Arrange
            SetupUserContext("admin123");

            var usersWithRoles = new List<TenantUserWithRolesDto>
            {
                new TenantUserWithRolesDto
                {
                    UserId = "user1",
                    Email = "user1@test.com",
                    Roles = new List<RoleNoPermissionDto>
                    {
                        new RoleNoPermissionDto { Id = "role1", Name = "Admin" }
                    }
                },
                new TenantUserWithRolesDto
                {
                    UserId = "user2",
                    Email = "user2@test.com",
                    Roles = new List<RoleNoPermissionDto>
                    {
                        new RoleNoPermissionDto { Id = "role2", Name = "Manager" }
                    }
                }
            };

            _mockUserService.Setup(x => x.GetTenantUsersWithNonGuestRoles(_testTenantId))
                .ReturnsAsync(usersWithRoles);

            // Act
            var result = await _controller.GetTenantUsers();

            // Assert
            var okResult = Assert.IsType<OkObjectResult>(result.Result);
            var returnedUsers = Assert.IsAssignableFrom<IEnumerable<TenantUserWithRolesDto>>(okResult.Value);
            Assert.Equal(2, returnedUsers.Count());
            
            var firstUser = returnedUsers.First();
            Assert.Equal("user1@test.com", firstUser.Email);
            Assert.Single(firstUser.Roles);
            Assert.Equal("Admin", firstUser.Roles.First().Name);
        }

        [Fact]
        public async Task AddUserToTenant_WithValidEmail_ReturnsOk()
        {
            // Arrange
            SetupUserContext("admin123");

            var request = new AddUserToRoleRequest
            {
                Email = "test@example.com",
                RoleId = "custom-role-id"
            };

            var user = new AuthUser { Id = "user1", Email = "test@example.com" };

            _mockUserService.Setup(x => x.GetUserByEmail(request.Email))
                .ReturnsAsync(user);

            _mockUserService.Setup(x => x.AddUserToRole(user.Id, _testTenantId, request.RoleId))
                .ReturnsAsync(true);

            // Act
            var result = await _controller.AddUserToTenant(request);

            // Assert
            var okResult = Assert.IsType<OkObjectResult>(result);
            var response = okResult.Value;
            Assert.NotNull(response);
        }

        [Fact]
        public async Task AddUserToTenant_WithInvalidEmail_ReturnsBadRequest()
        {
            // Arrange
            SetupUserContext("admin123");

            var request = new AddUserToRoleRequest
            {
                Email = "nonexistent@example.com",
                RoleId = "custom-role-id"
            };

            _mockUserService.Setup(x => x.GetUserByEmail(request.Email))
                .ReturnsAsync((AuthUser?)null);

            // Act
            var result = await _controller.AddUserToTenant(request);

            // Assert
            var badRequestResult = Assert.IsType<BadRequestObjectResult>(result);
            Assert.Equal("User not found", badRequestResult.Value);
        }

        [Fact]
        public async Task RemoveUserFromRole_WithValidData_ReturnsOk()
        {
            // Arrange
            SetupUserContext("admin123");

            var request = new RemoveUserFromRoleRequest
            {
                Email = "test@example.com",
                RoleId = "custom-role-id"
            };

            var user = new AuthUser { Id = "user1", Email = "test@example.com" };

            _mockUserService.Setup(x => x.GetUserByEmail(request.Email))
                .ReturnsAsync(user);

            _mockUserService.Setup(x => x.RemoveUserFromRole(user.Id, _testTenantId, request.RoleId))
                .ReturnsAsync(true);

            // Act
            var result = await _controller.RemoveUserFromRole(request);

            // Assert
            var okResult = Assert.IsType<OkObjectResult>(result);
            var response = okResult.Value;
            Assert.NotNull(response);
        }

        [Fact]
        public async Task RemoveUserFromRole_WithInvalidEmail_ReturnsBadRequest()
        {
            // Arrange
            SetupUserContext("admin123");

            var request = new RemoveUserFromRoleRequest
            {
                Email = "nonexistent@example.com",
                RoleId = "custom-role-id"
            };

            _mockUserService.Setup(x => x.GetUserByEmail(request.Email))
                .ReturnsAsync((AuthUser?)null);

            // Act
            var result = await _controller.RemoveUserFromRole(request);

            // Assert
            var badRequestResult = Assert.IsType<BadRequestObjectResult>(result);
            Assert.Equal("User not found", badRequestResult.Value);
        }

        [Fact]
        public async Task GetMyRoles_ThrowsInvalidOperationException_WhenUserIdNotFound()
        {
            // Arrange
            _controller.ControllerContext = new ControllerContext
            {
                HttpContext = new DefaultHttpContext() // No claims set
            };

            // Act & Assert
            await Assert.ThrowsAsync<InvalidOperationException>(() => _controller.GetMyRoles(null));
        }

        [Fact]
        public async Task GetMyTenants_ThrowsInvalidOperationException_WhenUserIdNotFound()
        {
            // Arrange
            _controller.ControllerContext = new ControllerContext
            {
                HttpContext = new DefaultHttpContext() // No claims set
            };

            // Act & Assert
            await Assert.ThrowsAsync<InvalidOperationException>(() => _controller.GetMyTenants());
        }

        [Fact]
        public async Task GetMyPermissions_ThrowsInvalidOperationException_WhenUserIdNotFound()
        {
            // Arrange
            _controller.ControllerContext = new ControllerContext
            {
                HttpContext = new DefaultHttpContext() // No claims set
            };

            // Act & Assert
            await Assert.ThrowsAsync<InvalidOperationException>(() => _controller.GetMyPermissions(null));
        }

        [Fact]
        public async Task CheckPermissions_ThrowsInvalidOperationException_WhenUserIdNotFound()
        {
            // Arrange
            _controller.ControllerContext = new ControllerContext
            {
                HttpContext = new DefaultHttpContext() // No claims set
            };

            // Act & Assert
            await Assert.ThrowsAsync<InvalidOperationException>(() => _controller.CheckPermissions(null, "test:permission"));
        }
    }
}