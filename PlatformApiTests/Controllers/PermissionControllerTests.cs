using AutoMapper;
using PlatformApi.Common.Constants;
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
        private readonly PermissionController _controller;

        public PermissionControllerTests()
        {
            _mockPermissionService = new Mock<IPermissionService>();
            _mockLogger = new Mock<ILogger<PermissionController>>();
            _mockMapper = new Mock<IMapper>();
            
            _controller = new PermissionController(
                _mockLogger.Object,
                _mockMapper.Object,
                _mockPermissionService.Object);
        }

        [Fact]
        public async Task GetAllRoles_ReturnsOkResult_WithRoles()
        {
            // Arrange
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
            var roleId = "role1";
            var role = new AuthRole { Id = roleId, Name = "Admin" };
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
            var roleId = "nonexistent";

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
            var roleCreateDto = new RoleCreateDto { Name = "Admin" };
            var role = new AuthRole { Id = "role1", Name = "Admin" };

            _mockMapper.Setup(x => x.Map<AuthRole>(roleCreateDto))
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
            var roleId = "role1";
            var roleDto = new RoleDto { Id = roleId, Name = "Updated Admin" };
            var role = new AuthRole { Id = roleId, Name = "Updated Admin" };

            _mockMapper.Setup(x => x.Map<AuthRole>(roleDto))
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
            var roleId = "role1";
            var roleDto = new RoleDto { Id = roleId, Name = "Updated Admin" };
            var role = new AuthRole { Id = roleId, Name = "Updated Admin" };

            _mockMapper.Setup(x => x.Map<AuthRole>(roleDto))
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
            var roleId = "nonexistent";
            var roleDto = new RoleDto { Id = roleId, Name = "Admin" };
            var role = new AuthRole { Id = roleId, Name = "Admin" };

            _mockMapper.Setup(x => x.Map<AuthRole>(roleDto))
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
            var roleId = "role1";

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
            var roleId = "role1";

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
            var roleId = "nonexistent";

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

            _mockPermissionService.Setup(x => x.GetAllPermissions())
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