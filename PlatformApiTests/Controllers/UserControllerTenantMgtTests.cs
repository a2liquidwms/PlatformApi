using AutoMapper;
using Microsoft.AspNetCore.Http;
using NetStarterCommon.Core.Common.Constants;
using NetStarterCommon.Core.Common.Tenant;
using PlatformApi.Controllers;
using PlatformApi.Models;
using PlatformApi.Models.DTOs;
using PlatformApi.Services;

namespace PlatformApiTests.Controllers
{
    public class UserControllerTenantUserMgtTests
    {
        private readonly Mock<IUserService> _mockUserService;
        private readonly Mock<IMapper> _mockMapper;
        private readonly Mock<ILogger<UserController>> _mockLogger;
        private readonly Mock<IHttpContextAccessor> _mockHttpContextAccessor;
        private readonly Mock<ILogger<TenantHelper>> _mockTenantHelperLogger;
        private readonly TenantHelper _tenantHelper;
        private readonly UserController _controller;
        private readonly Guid _testTenantId = Guid.NewGuid();

        public UserControllerTenantUserMgtTests()
        {
            _mockUserService = new Mock<IUserService>();
            _mockMapper = new Mock<IMapper>();
            _mockLogger = new Mock<ILogger<UserController>>();
            _mockHttpContextAccessor = new Mock<IHttpContextAccessor>();
            _mockTenantHelperLogger = new Mock<ILogger<TenantHelper>>();

            // Setup HttpContext for TenantHelper
            var httpContext = new DefaultHttpContext();
            httpContext.Items[CommonConstants.TenantHttpContext] = _testTenantId;
            _mockHttpContextAccessor.Setup(x => x.HttpContext).Returns(httpContext);

            // Create concrete TenantHelper instance
            _tenantHelper = new TenantHelper(_mockHttpContextAccessor.Object, _mockTenantHelperLogger.Object);

            _controller = new UserController(
                _mockLogger.Object,
                _mockMapper.Object,
                _mockUserService.Object,
                _tenantHelper);
        }

        private void SetupTenantContext()
        {
            _controller.ControllerContext = new ControllerContext
            {
                HttpContext = new DefaultHttpContext()
            };
            _controller.HttpContext.Items[CommonConstants.TenantHttpContext] = _testTenantId;
            
            // Update the TenantHelper's HttpContext as well
            _mockHttpContextAccessor.Setup(x => x.HttpContext).Returns(_controller.HttpContext);
        }

        [Fact]
        public async Task GetTenantUsers_ReturnsUsersWithNonGuestRoles()
        {
            // Arrange
            SetupTenantContext();

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
        public async Task AddUserToTenant_WithValidEmailAndRole_ReturnsOk()
        {
            // Arrange
            SetupTenantContext();

            var request = new AddUserToRoleRequest // Updated to match controller parameter
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
            SetupTenantContext();

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
            SetupTenantContext();

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
            SetupTenantContext();

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
        public async Task AddUserToTenant_ServiceThrowsException_ReturnsBadRequest()
        {
            // Arrange
            SetupTenantContext();

            var request = new AddUserToRoleRequest
            {
                Email = "test@example.com",
                RoleId = "custom-role-id"
            };

            var user = new AuthUser { Id = "user1", Email = "test@example.com" };

            _mockUserService.Setup(x => x.GetUserByEmail(request.Email))
                .ReturnsAsync(user);

            _mockUserService.Setup(x => x.AddUserToRole(user.Id, _testTenantId, request.RoleId))
                .ThrowsAsync(new InvalidOperationException("Test exception"));

            // Act
            var result = await _controller.AddUserToTenant(request);

            // Assert
            var badRequestResult = Assert.IsType<BadRequestObjectResult>(result);
            Assert.Contains("Test exception", badRequestResult.Value!.ToString());
        }

        [Fact]
        public async Task RemoveUserFromRole_ServiceThrowsException_ReturnsBadRequest()
        {
            // Arrange
            SetupTenantContext();

            var request = new RemoveUserFromRoleRequest
            {
                Email = "test@example.com",
                RoleId = "custom-role-id"
            };

            var user = new AuthUser { Id = "user1", Email = "test@example.com" };

            _mockUserService.Setup(x => x.GetUserByEmail(request.Email))
                .ReturnsAsync(user);

            _mockUserService.Setup(x => x.RemoveUserFromRole(user.Id, _testTenantId, request.RoleId))
                .ThrowsAsync(new InvalidOperationException("Test exception"));

            // Act
            var result = await _controller.RemoveUserFromRole(request);

            // Assert
            var badRequestResult = Assert.IsType<BadRequestObjectResult>(result);
            Assert.Contains("Test exception", badRequestResult.Value!.ToString());
        }
    }
}