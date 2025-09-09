using AutoMapper;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;
using Moq;
using PlatformStarterCommon.Core.Common.Constants;
using PlatformStarterCommon.Core.Common.Tenant;
using PlatformApi.Controllers;
using PlatformApi.Models;
using PlatformApi.Models.DTOs;
using PlatformApi.Services;

namespace PlatformApiTests.Controllers
{
    public class PermissionControllerTests
    {
        private readonly Mock<IPermissionService> _mockPermissionService;
        private readonly Mock<ILogger<PermissionController>> _mockLogger;
        private readonly Mock<IMapper> _mockMapper;
        private readonly Mock<TenantHelper> _mockTenantHelper;
        private readonly PermissionController _controller;

        public PermissionControllerTests()
        {
            _mockPermissionService = new Mock<IPermissionService>();
            _mockLogger = new Mock<ILogger<PermissionController>>();
            _mockMapper = new Mock<IMapper>();
            _mockTenantHelper = new Mock<TenantHelper>(Mock.Of<Microsoft.AspNetCore.Http.IHttpContextAccessor>(), Mock.Of<ILogger<TenantHelper>>());
            
            _controller = new PermissionController(
                _mockLogger.Object,
                _mockMapper.Object,
                _mockPermissionService.Object,
                _mockTenantHelper.Object);
        }

        [Fact]
        public async Task GetAllRoles_ReturnsOkResult_WithRoles()
        {
            // Arrange
            var roles = new List<Role>
            {
                new Role { Id = Guid.Parse("00000000-0000-0000-0000-000000000001"), Name = "Admin", Scope = RoleScope.Tenant },
                new Role { Id = Guid.Parse("00000000-0000-0000-0000-000000000002"), Name = "User", Scope = RoleScope.Tenant }
            };

            var roleDtos = new List<RoleDto>
            {
                new RoleDto { Id = Guid.Parse("00000000-0000-0000-0000-000000000001").ToString(), Name = "Admin" },
                new RoleDto { Id = Guid.Parse("00000000-0000-0000-0000-000000000002").ToString(), Name = "User" }
            };

            _mockPermissionService.Setup(x => x.GetAllRoles(false))
                .ReturnsAsync(roles);

            _mockMapper.Setup(x => x.Map<IEnumerable<RoleDto>>(roles))
                .Returns(roleDtos);

            // Act
            var result = await _controller.GetAllRoles();

            // Assert
            var okResult = Assert.IsType<OkObjectResult>(result.Result);
            var returnedRoles = Assert.IsAssignableFrom<IEnumerable<RoleDto>>(okResult.Value);
            Assert.Equal(2, returnedRoles.Count());
        }

        [Fact]
        public async Task GetRoleById_ReturnsOkResult_WithRole_WhenRoleExists()
        {
            // Arrange
            var roleId = Guid.Parse("00000000-0000-0000-0000-000000000001").ToString();
            var role = new Role { Id = Guid.Parse(roleId), Name = "Admin", Scope = RoleScope.Tenant };
            var roleDto = new RoleDto { Id = roleId, Name = "Admin" };

            _mockPermissionService.Setup(x => x.GetRoleById(roleId, true))
                .ReturnsAsync(role);

            _mockMapper.Setup(x => x.Map<RoleDto>(role))
                .Returns(roleDto);

            // Act
            var result = await _controller.GetRoleById(roleId);

            // Assert
            var okResult = Assert.IsType<OkObjectResult>(result.Result);
            var returnedRole = Assert.IsType<RoleDto>(okResult.Value);
            Assert.Equal(roleId, returnedRole.Id);
        }

        [Fact]
        public async Task GetRoleById_ReturnsNotFound_WhenRoleDoesNotExist()
        {
            // Arrange
            var roleId = Guid.Parse("00000000-0000-0000-0000-000000000010").ToString();

            _mockPermissionService.Setup(x => x.GetRoleById(roleId, true))
                .ThrowsAsync(new NotFoundException());

            // Act
            var result = await _controller.GetRoleById(roleId);

            // Assert
            Assert.IsType<NotFoundResult>(result.Result);
        }

        [Fact]
        public async Task AddRole_ReturnsCreatedAtAction_WithRole()
        {
            // Arrange
            var roleCreateDto = new RoleCreateDto { Name = "Admin", Scope = RoleScope.Tenant };
            var role = new Role { Id = Guid.Parse("00000000-0000-0000-0000-000000000001"), Name = "Admin", Scope = RoleScope.Tenant };

            _mockMapper.Setup(x => x.Map<Role>(roleCreateDto))
                .Returns(role);

            _mockPermissionService.Setup(x => x.AddRole(role))
                .ReturnsAsync(role);

            // Act
            var result = await _controller.AddRole(roleCreateDto);

            // Assert
            var createdAtActionResult = Assert.IsType<CreatedAtActionResult>(result.Result);
            Assert.Equal(nameof(PermissionController.GetRoleById), createdAtActionResult.ActionName);
            Assert.Equal(role.Id, createdAtActionResult.RouteValues!["id"]);
            Assert.Equal(role, createdAtActionResult.Value);
        }

        [Fact]
        public async Task UpdateRole_ReturnsNoContent_WhenUpdateSucceeds()
        {
            // Arrange
            var roleId = Guid.Parse("00000000-0000-0000-0000-000000000001").ToString();
            var roleDto = new RoleDto { Id = roleId, Name = "Updated Admin" };
            var role = new Role { Id = Guid.Parse(roleId), Name = "Updated Admin", Scope = RoleScope.Tenant };

            _mockMapper.Setup(x => x.Map<Role>(roleDto))
                .Returns(role);

            _mockPermissionService.Setup(x => x.UpdateRole(roleId, role))
                .ReturnsAsync(true);

            // Act
            var result = await _controller.UpdateRole(roleId, roleDto);

            // Assert
            Assert.IsType<NoContentResult>(result);
        }

        [Fact]
        public async Task UpdateRole_ReturnsBadRequest_WhenUpdateFails()
        {
            // Arrange
            var roleId = Guid.Parse("00000000-0000-0000-0000-000000000001").ToString();
            var roleDto = new RoleDto { Id = roleId, Name = "Updated Admin" };
            var role = new Role { Id = Guid.Parse(roleId), Name = "Updated Admin", Scope = RoleScope.Tenant };

            _mockMapper.Setup(x => x.Map<Role>(roleDto))
                .Returns(role);

            _mockPermissionService.Setup(x => x.UpdateRole(roleId, role))
                .ReturnsAsync(false);

            // Act
            var result = await _controller.UpdateRole(roleId, roleDto);

            // Assert
            var badRequestResult = Assert.IsType<BadRequestObjectResult>(result);
            Assert.Equal(ErrorMessages.ErrorSaving, badRequestResult.Value);
        }

        [Fact]
        public async Task UpdateRole_ReturnsNotFound_WhenRoleDoesNotExist()
        {
            // Arrange
            var roleId = Guid.Parse("00000000-0000-0000-0000-000000000010").ToString();
            var roleDto = new RoleDto { Id = roleId, Name = "Admin" };
            var role = new Role { Id = Guid.Parse(roleId), Name = "Admin", Scope = RoleScope.Tenant };

            _mockMapper.Setup(x => x.Map<Role>(roleDto))
                .Returns(role);

            _mockPermissionService.Setup(x => x.UpdateRole(roleId, role))
                .ThrowsAsync(new NotFoundException());

            // Act
            var result = await _controller.UpdateRole(roleId, roleDto);

            // Assert
            Assert.IsType<NotFoundResult>(result);
        }

        [Fact]
        public async Task DeleteRole_ReturnsNoContent_WhenDeleteSucceeds()
        {
            // Arrange
            var roleId = Guid.Parse("00000000-0000-0000-0000-000000000001").ToString();

            _mockPermissionService.Setup(x => x.DeleteRole(roleId))
                .ReturnsAsync(true);

            // Act
            var result = await _controller.DeleteRole(roleId);

            // Assert
            Assert.IsType<NoContentResult>(result);
        }

        [Fact]
        public async Task DeleteRole_ReturnsBadRequest_WhenDeleteFails()
        {
            // Arrange
            var roleId = Guid.Parse("00000000-0000-0000-0000-000000000001").ToString();

            _mockPermissionService.Setup(x => x.DeleteRole(roleId))
                .ReturnsAsync(false);

            // Act
            var result = await _controller.DeleteRole(roleId);

            // Assert
            var badRequestResult = Assert.IsType<BadRequestObjectResult>(result);
            Assert.Equal(ErrorMessages.ErrorSaving, badRequestResult.Value);
        }
        
        [Fact]
        public async Task DeleteRole_ReturnsNotFound_WhenRoleDoesNotExist()
        {
            // Arrange
            var roleId = Guid.Parse("00000000-0000-0000-0000-000000000010").ToString();

            _mockPermissionService.Setup(x => x.DeleteRole(roleId))
                .ThrowsAsync(new NotFoundException());

            // Act
            var result = await _controller.DeleteRole(roleId);

            // Assert
            Assert.IsType<NotFoundResult>(result);
        }
        
        [Fact]
        public async Task GetAllPermissions_ReturnsOkResult_WithPermissions()
        {
            // Arrange
            var permissions = new List<Permission>
            {
                new Permission { Code = "perm1", Description = "Permission 1" },
                new Permission { Code = "perm2", Description = "Permission 2" }
            };

            var permissionDtos = new List<PermissionDto>
            {
                new PermissionDto { Code = "perm1", Description = "Permission 1" },
                new PermissionDto { Code = "perm2", Description = "Permission 2" }
            };

            _mockPermissionService.Setup(x => x.GetAllPermissions(It.IsAny<int?>()))
                .ReturnsAsync(permissions);

            _mockMapper.Setup(x => x.Map<IEnumerable<PermissionDto>>(permissions))
                .Returns(permissionDtos);

            // Act
            var result = await _controller.GetAllPermissions();

            // Assert
            var okResult = Assert.IsType<OkObjectResult>(result.Result);
            var returnedPermissions = Assert.IsAssignableFrom<IEnumerable<PermissionDto>>(okResult.Value);
            Assert.Equal(2, returnedPermissions.Count());
        }
        
        [Fact]
        public async Task GetPermissionByCode_ReturnsOkResult_WithPermission_WhenPermissionExists()
        {
            // Arrange
            var permissionCode = "perm1";
            var permission = new Permission { Code = permissionCode, Description = "Permission 1" };
            var permissionDto = new PermissionDto { Code = permissionCode, Description = "Permission 1" };

            _mockPermissionService.Setup(x => x.GetPermissionByCode(permissionCode))
                .ReturnsAsync(permission);

            _mockMapper.Setup(x => x.Map<PermissionDto>(permission))
                .Returns(permissionDto);

            // Act
            var result = await _controller.GetPermissionByCode(permissionCode);

            // Assert
            var okResult = Assert.IsType<OkObjectResult>(result);
            var returnedPermission = Assert.IsType<PermissionDto>(okResult.Value);
            Assert.Equal(permissionCode, returnedPermission.Code);
        }
        
        [Fact]
        public async Task GetPermissionByCode_ReturnsNotFound_WhenPermissionDoesNotExist()
        {
            // Arrange
            var permissionCode = "nonexistent";

            _mockPermissionService.Setup(x => x.GetPermissionByCode(permissionCode))
                .ThrowsAsync(new NotFoundException());

            // Act
            var result = await _controller.GetPermissionByCode(permissionCode);

            // Assert
            Assert.IsType<NotFoundResult>(result);
        }
        
        [Fact]
        public async Task AddPermission_ReturnsCreatedAtAction_WithPermission()
        {
            // Arrange
            var permissionCreateDto = new PermissionCreateDto { Code = "perm1", Description = "Permission 1" };
            var permission = new Permission { Code = "perm1", Description = "Permission 1" };

            _mockMapper.Setup(x => x.Map<Permission>(permissionCreateDto))
                .Returns(permission);

            _mockPermissionService.Setup(x => x.AddPermission(permission))
                .ReturnsAsync(permission);

            // Act
            var result = await _controller.AddPermission(permissionCreateDto);

            // Assert
            var createdAtActionResult = Assert.IsType<CreatedAtActionResult>(result.Result);
            Assert.Equal(nameof(PermissionController.GetPermissionByCode), createdAtActionResult.ActionName);
            Assert.Equal(permission.Code, createdAtActionResult.RouteValues!["code"]);
            Assert.Equal(permission, createdAtActionResult.Value);
        }
        
        [Fact]
        public async Task AddPermissionMulti_ReturnsOkResult_WithCount()
        {
            // Arrange
            var permissionCreateDtos = new[]
            {
                new PermissionCreateDto { Code = "perm1", Description = "Permission 1" },
                new PermissionCreateDto { Code = "perm2", Description = "Permission 2" }
            };
            
            var permissions = new[]
            {
                new Permission { Code = "perm1", Description = "Permission 1" },
                new Permission { Code = "perm2", Description = "Permission 2" }
            };

            _mockMapper.Setup(x => x.Map<Permission[]>(permissionCreateDtos))
                .Returns(permissions);

            _mockPermissionService.Setup(x => x.AddPermissionsMulti(permissions))
                .ReturnsAsync(2);

            // Act
            var result = await _controller.AddPermissionMulti(permissionCreateDtos);

            // Assert
            var okResult = Assert.IsType<OkObjectResult>(result.Result);
            Assert.Equal("2 permissions created", okResult.Value);
        }
        
        [Fact]
        public async Task AddPermissionMulti_ReturnsBadRequest_WhenArgumentException()
        {
            // Arrange
            var permissionCreateDtos = new[]
            {
                new PermissionCreateDto { Code = "perm1", Description = "Permission 1" },
                new PermissionCreateDto { Code = "perm1", Description = "Duplicate Code" } // Duplicate code
            };
            
            var permissions = new[]
            {
                new Permission { Code = "perm1", Description = "Permission 1" },
                new Permission { Code = "perm1", Description = "Duplicate Code" }
            };

            _mockMapper.Setup(x => x.Map<Permission[]>(permissionCreateDtos))
                .Returns(permissions);

            _mockPermissionService.Setup(x => x.AddPermissionsMulti(permissions))
                .ThrowsAsync(new ArgumentException("Duplicate permission code"));

            // Act
            var result = await _controller.AddPermissionMulti(permissionCreateDtos);

            // Assert
            Assert.IsType<BadRequestObjectResult>(result.Result);
        }
        
        [Fact]
        public async Task UpdatePermission_ReturnsNoContent_WhenUpdateSucceeds()
        {
            // Arrange
            var permissionCode = "perm1";
            var permissionCreateDto = new PermissionCreateDto { Code = permissionCode, Description = "Updated Permission" };
            var permission = new Permission { Code = permissionCode, Description = "Updated Permission" };

            _mockMapper.Setup(x => x.Map<Permission>(permissionCreateDto))
                .Returns(permission);

            _mockPermissionService.Setup(x => x.UpdatePermission(permissionCode, permission))
                .ReturnsAsync(true);

            // Act
            var result = await _controller.UpdatePermission(permissionCode, permissionCreateDto);

            // Assert
            Assert.IsType<NoContentResult>(result);
        }
        
        [Fact]
        public async Task UpdatePermission_ReturnsBadRequest_WhenUpdateFails()
        {
            // Arrange
            var permissionCode = "perm1";
            var permissionCreateDto = new PermissionCreateDto { Code = permissionCode, Description = "Updated Permission" };
            var permission = new Permission { Code = permissionCode, Description = "Updated Permission" };

            _mockMapper.Setup(x => x.Map<Permission>(permissionCreateDto))
                .Returns(permission);

            _mockPermissionService.Setup(x => x.UpdatePermission(permissionCode, permission))
                .ReturnsAsync(false);

            // Act
            var result = await _controller.UpdatePermission(permissionCode, permissionCreateDto);

            // Assert
            var badRequestResult = Assert.IsType<BadRequestObjectResult>(result);
            Assert.Equal(ErrorMessages.ErrorSaving, badRequestResult.Value);
        }
        
        [Fact]
        public async Task UpdatePermission_ReturnsNotFound_WhenPermissionDoesNotExist()
        {
            // Arrange
            var permissionCode = "nonexistent";
            var permissionCreateDto = new PermissionCreateDto { Code = permissionCode, Description = "Permission" };
            var permission = new Permission { Code = permissionCode, Description = "Permission" };

            _mockMapper.Setup(x => x.Map<Permission>(permissionCreateDto))
                .Returns(permission);

            _mockPermissionService.Setup(x => x.UpdatePermission(permissionCode, permission))
                .ThrowsAsync(new NotFoundException());

            // Act
            var result = await _controller.UpdatePermission(permissionCode, permissionCreateDto);

            // Assert
            Assert.IsType<NotFoundResult>(result);
        }
        
        [Fact]
        public async Task DeletePermission_ReturnsNoContent_WhenDeleteSucceeds()
        {
            // Arrange
            var permissionCode = "perm1";

            _mockPermissionService.Setup(x => x.DeletePermission(permissionCode))
                .ReturnsAsync(true);

            // Act
            var result = await _controller.DeletePermission(permissionCode);

            // Assert
            Assert.IsType<NoContentResult>(result);
        }
        
        [Fact]
        public async Task DeletePermission_ReturnsBadRequest_WhenDeleteFails()
        {
            // Arrange
            var permissionCode = "perm1";

            _mockPermissionService.Setup(x => x.DeletePermission(permissionCode))
                .ReturnsAsync(false);

            // Act
            var result = await _controller.DeletePermission(permissionCode);

            // Assert
            var badRequestResult = Assert.IsType<BadRequestObjectResult>(result);
            Assert.Equal(ErrorMessages.ErrorSaving, badRequestResult.Value);
        }
        
        [Fact]
        public async Task DeletePermission_ReturnsNotFound_WhenPermissionDoesNotExist()
        {
            // Arrange
            var permissionCode = "nonexistent";

            _mockPermissionService.Setup(x => x.DeletePermission(permissionCode))
                .ThrowsAsync(new NotFoundException());

            // Act
            var result = await _controller.DeletePermission(permissionCode);

            // Assert
            Assert.IsType<NotFoundResult>(result);
        }
        
        [Fact]
        public async Task AddPermissionToRole_ReturnsOkResult_WithUpdatedRole()
        {
            // Arrange
            var roleId = Guid.Parse("00000000-0000-0000-0000-000000000001").ToString();
            var permissionCode = "perm1";
            var role = new Role { Id = Guid.Parse(roleId), Name = "Admin", Scope = RoleScope.Tenant };
            var roleDto = new RoleDto { Id = roleId, Name = "Admin" };

            _mockPermissionService.Setup(x => x.AddPermissionToRole(roleId, permissionCode))
                .ReturnsAsync(role);

            _mockMapper.Setup(x => x.Map<RoleDto>(role))
                .Returns(roleDto);

            // Act
            var result = await _controller.AddPermissionToRole(roleId, permissionCode);

            // Assert
            var okResult = Assert.IsType<OkObjectResult>(result.Result);
            var returnedRole = Assert.IsType<RoleDto>(okResult.Value);
            Assert.Equal(roleId, returnedRole.Id);
        }

        [Fact]
        public async Task AddPermissionToRole_ReturnsNotFound_WhenRoleOrPermissionNotFound()
        {
            // Arrange
            var roleId = "nonexistent";
            var permissionCode = "perm1";

            _mockPermissionService.Setup(x => x.AddPermissionToRole(roleId, permissionCode))
                .ThrowsAsync(new NotFoundException("Role not found"));

            // Act
            var result = await _controller.AddPermissionToRole(roleId, permissionCode);

            // Assert
            var notFoundResult = Assert.IsType<NotFoundObjectResult>(result.Result);
            Assert.Equal("Role not found", notFoundResult.Value);
        }

        [Fact]
        public async Task AddPermissionToRole_ReturnsBadRequest_WhenInvalidDataException()
        {
            // Arrange
            var roleId = "role1";
            var permissionCode = "perm1";

            _mockPermissionService.Setup(x => x.AddPermissionToRole(roleId, permissionCode))
                .ThrowsAsync(new InvalidDataException("Permission already assigned to role"));

            // Act
            var result = await _controller.AddPermissionToRole(roleId, permissionCode);

            // Assert
            var badRequestResult = Assert.IsType<BadRequestObjectResult>(result.Result);
            Assert.Equal("Permission already assigned to role", badRequestResult.Value);
        }

        [Fact]
        public async Task RemovePermissionFromRole_ReturnsOkResult_WithUpdatedRole()
        {
            // Arrange
            var roleId = Guid.Parse("00000000-0000-0000-0000-000000000001").ToString();
            var permissionCode = "perm1";
            var role = new Role { Id = Guid.Parse(roleId), Name = "Admin", Scope = RoleScope.Tenant };
            var roleDto = new RoleDto { Id = roleId, Name = "Admin" };

            _mockPermissionService.Setup(x => x.RemovePermissionFromRole(roleId, permissionCode))
                .ReturnsAsync(role);

            _mockMapper.Setup(x => x.Map<RoleDto>(role))
                .Returns(roleDto);

            // Act
            var result = await _controller.RemovePermissionFromRole(roleId, permissionCode);

            // Assert
            var okResult = Assert.IsType<OkObjectResult>(result.Result);
            var returnedRole = Assert.IsType<RoleDto>(okResult.Value);
            Assert.Equal(roleId, returnedRole.Id);
        }

        [Fact]
        public async Task RemovePermissionFromRole_ReturnsNotFound_WhenRoleOrPermissionNotFound()
        {
            // Arrange
            var roleId = "nonexistent";
            var permissionCode = "perm1";

            _mockPermissionService.Setup(x => x.RemovePermissionFromRole(roleId, permissionCode))
                .ThrowsAsync(new NotFoundException("Role not found"));

            // Act
            var result = await _controller.RemovePermissionFromRole(roleId, permissionCode);

            // Assert
            var notFoundResult = Assert.IsType<NotFoundObjectResult>(result.Result);
            Assert.Equal("Role not found", notFoundResult.Value);
        }
        
        
    //     [Fact]
    //     public async Task AddPermissionsToRole_ReturnsOkResult_WithUpdatedRole()
    //     {
    //         // Arrange
    //         var roleId = "role1";
    //         var permissionCodes = new[] { "perm1", "perm2" };
    //         
    //         var role = new AuthRole
    //         {
    //             Id = roleId,
    //             Name = "Admin",
    //             RolePermissions = new List<RolePermission>
    //             {
    //                 new RolePermission { UserRoleId = roleId, PermissionCode = "perm1" },
    //                 new RolePermission { UserRoleId = roleId, PermissionCode = "perm2" }
    //             }
    //         };
    //         
    //         var roleDto = new RoleDto
    //         {
    //             Id = roleId,
    //             Name = "Admin",
    //             Permissions = new List<PermissionDto>
    //             {
    //                 new PermissionDto { Code = "perm1" },
    //                 new PermissionDto { Code = "perm2" }
    //             }
    //         };
    //
    //         _mockPermissionService.Setup(x => x.AddPermissionsToRole(roleId, permissionCodes))
    //             .ReturnsAsync(role);
    //             
    //         _mockMapper.Setup(x => x.Map<RoleDto>(role))
    //             .Returns(roleDto);
    //
    //         // Act
    //         var result = await _controller.AddPermissionsToRole(roleId, permissionCodes);
    //
    //         // Assert
    //         var okResult = Assert.IsType<OkObjectResult>(result.Result);
    //         var returnedRole = Assert.IsType<RoleDto>(okResult.Value);
    //      
    //         Assert.Equal(roleId, returnedRole.Id);
    //         Assert.Equal(2, returnedRole.Permissions!.Count);
    //     }
    }
}