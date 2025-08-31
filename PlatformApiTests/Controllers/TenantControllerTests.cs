using AutoMapper;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using Moq;
using PlatformStarterCommon.Core.Common.Constants;
using PlatformStarterCommon.Core.Common.Tenant;
using PlatformApi.Controllers;
using PlatformApi.Models;
using PlatformApi.Models.DTOs;
using PlatformApi.Services;
using Xunit;

namespace PlatformApiTests.Controllers
{
    public class TenantControllerTests
    {
        private readonly Mock<ILogger<TenantController>> _loggerMock;
        private readonly Mock<IMapper> _mapperMock;
        private readonly Mock<ITenantService> _tenantServiceMock;
        private readonly TenantHelper _tenantHelper;
        private readonly TenantController _controller;

        public TenantControllerTests()
        {
            _loggerMock = new Mock<ILogger<TenantController>>();
            _mapperMock = new Mock<IMapper>(); 
            _tenantServiceMock = new Mock<ITenantService>();
            
            // Create TenantHelper instance
            var mockHttpContextAccessor = new Mock<IHttpContextAccessor>();
            var mockTenantHelperLogger = new Mock<ILogger<TenantHelper>>();
            var httpContext = new DefaultHttpContext();
            mockHttpContextAccessor.Setup(x => x.HttpContext).Returns(httpContext);
            _tenantHelper = new TenantHelper(mockHttpContextAccessor.Object, mockTenantHelperLogger.Object);
            
            _controller = new TenantController(_loggerMock.Object, _mapperMock.Object, _tenantServiceMock.Object, _tenantHelper);
        }

        [Fact]
        public async Task GetAll_ReturnsOkResult_WithMappedTenants()
        {
            // Arrange
            var tenants = new List<Tenant>
            {
                new Tenant { Id = Guid.NewGuid(), Code = "TEN1", Name = "Tenant 1", SubDomain = "tenant1"},
                new Tenant { Id = Guid.NewGuid(), Code = "TEN2", Name = "Tenant 2", SubDomain = "tenant2" }
            };

            var tenantDtos = new List<TenantDto>
            {
                new TenantDto { Id = tenants[0].Id, Code = tenants[0].Code, Name = tenants[0].Name, SubDomain = tenants[0].SubDomain },
                new TenantDto { Id = tenants[1].Id, Code = tenants[1].Code, Name = tenants[1].Name , SubDomain = "tenant2" }
            };

            _tenantServiceMock.Setup(s => s.GetAll()).ReturnsAsync(tenants);
            _mapperMock.Setup(m => m.Map<IEnumerable<TenantDto>>(tenants)).Returns(tenantDtos);

            // Act
            var result = await _controller.GetAll();

            // Assert
            var okResult = Assert.IsType<OkObjectResult>(result.Result);
            var returnedTenants = Assert.IsAssignableFrom<IEnumerable<TenantDto>>(okResult.Value);
            Assert.Equal(tenantDtos, returnedTenants);
        }

        [Fact]
        public async Task GetById_WithExistingId_ReturnsOkResult_WithMappedTenant()
        {
            // Arrange
            var tenantId = Guid.NewGuid();
            var tenant = new Tenant { Id = tenantId, Code = "TEST", Name = "Test Tenant", SubDomain = "test" };
            var tenantDto = new TenantDto { Id = tenantId, Code = "TEST", Name = "Test Tenant", SubDomain = "test" };

            _tenantServiceMock.Setup(s => s.GetById(tenantId)).ReturnsAsync(tenant);
            _mapperMock.Setup(m => m.Map<TenantDto>(tenant)).Returns(tenantDto);

            // Act
            var result = await _controller.GetById(tenantId);

            // Assert
            var okResult = Assert.IsType<OkObjectResult>(result.Result);
            var returnedTenant = Assert.IsType<TenantDto>(okResult.Value);
            Assert.Equal(tenantDto, returnedTenant);
        }

        [Fact]
        public async Task GetById_WithNonExistingId_ReturnsNotFound()
        {
            // Arrange
            var nonExistingId = Guid.NewGuid();
            _tenantServiceMock.Setup(s => s.GetById(nonExistingId)).ReturnsAsync((Tenant)null!);

            // Act
            var result = await _controller.GetById(nonExistingId);

            // Assert
            Assert.IsType<NotFoundResult>(result.Result);
        }

        [Fact]
        public async Task GetById_WhenServiceThrowsNotFoundException_ReturnsNotFound()
        {
            // Arrange
            var tenantId = Guid.NewGuid();
            _tenantServiceMock.Setup(s => s.GetById(tenantId)).ThrowsAsync(new NotFoundException());

            // Act
            var result = await _controller.GetById(tenantId);

            // Assert
            Assert.IsType<NotFoundResult>(result.Result);
        }

        [Fact]
        public async Task Add_WithValidData_ReturnsCreatedAtAction()
        {
            // Arrange
            var tenantDto = new TenantDto { Code = "NEW", Name = "New Tenant", SubDomain = "new"};
            var tenant = new Tenant { Code = "NEW", Name = "New Tenant", SubDomain = "new" };
            var createdTenant = new Tenant { Id = Guid.NewGuid(), Code = "NEW", Name = "New Tenant", SubDomain = "new"};

            _mapperMock.Setup(m => m.Map<Tenant>(tenantDto)).Returns(tenant);
            _tenantServiceMock.Setup(s => s.Add(tenant)).ReturnsAsync(createdTenant);

            // Act
            var result = await _controller.Add(tenantDto);

            // Assert
            var createdAtActionResult = Assert.IsType<CreatedAtActionResult>(result.Result);
            Assert.Equal(nameof(TenantController.GetById), createdAtActionResult.ActionName);
            Assert.Equal(createdTenant.Id, createdAtActionResult.RouteValues!["id"]);
            Assert.Equal(createdTenant, createdAtActionResult.Value);
        }

        [Fact]
        public async Task Update_WithValidIdAndData_ReturnsNoContent()
        {
            // Arrange
            var tenantId = Guid.NewGuid();
            var tenantDto = new TenantDto { Id = tenantId, Code = "UPD", Name = "Updated Tenant" ,SubDomain = "upd"};
            var tenant = new Tenant { Id = tenantId, Code = "UPD", Name = "Updated Tenant", SubDomain = "upd"};

            _mapperMock.Setup(m => m.Map<Tenant>(tenantDto)).Returns(tenant);
            _tenantServiceMock.Setup(s => s.Update(tenantId, tenant)).ReturnsAsync(true);

            // Act
            var result = await _controller.Update(tenantId, tenantDto);

            // Assert
            Assert.IsType<NoContentResult>(result);
        }

        [Fact]
        public async Task Update_WhenServiceReturnsFalse_ReturnsBadRequest()
        {
            // Arrange
            var tenantId = Guid.NewGuid();
            var tenantDto = new TenantDto { Id = tenantId, Code="Code",  Name = "Updated Tenant", SubDomain = "code" };
            var tenant = new Tenant { Id = tenantId,  Code="Code", Name = "Updated Tenant", SubDomain = "code" };

            _mapperMock.Setup(m => m.Map<Tenant>(tenantDto)).Returns(tenant);
            _tenantServiceMock.Setup(s => s.Update(tenantId, tenant)).ReturnsAsync(false);

            // Act
            var result = await _controller.Update(tenantId, tenantDto);

            // Assert
            var badRequestResult = Assert.IsType<BadRequestObjectResult>(result);
            Assert.Equal(ErrorMessages.ErrorSaving, badRequestResult.Value);
        }

        [Fact]
        public async Task Update_WhenServiceThrowsInvalidDataException_ReturnsBadRequest()
        {
            // Arrange
            var tenantId = Guid.NewGuid();
            var tenantDto = new TenantDto { Id = tenantId, Code = "UPD", Name = "Updated Tenant", SubDomain = "code" };
            var tenant = new Tenant { Id = tenantId, Code = "UPD", Name = "Updated Tenant", SubDomain = "code" };
            var exceptionMessage = "Invalid data";

            _mapperMock.Setup(m => m.Map<Tenant>(tenantDto)).Returns(tenant);
            _tenantServiceMock.Setup(s => s.Update(tenantId, tenant)).ThrowsAsync(new InvalidDataException(exceptionMessage));

            // Act
            var result = await _controller.Update(tenantId, tenantDto);

            // Assert
            var badRequestResult = Assert.IsType<BadRequestObjectResult>(result);
            Assert.Equal(exceptionMessage, badRequestResult.Value);
        }

        [Fact]
        public async Task Update_WhenServiceThrowsNotFoundException_ReturnsNotFound()
        {
            // Arrange
            var tenantId = Guid.NewGuid();
            var tenantDto = new TenantDto { Id = tenantId, Code="Code", Name = "Updated Tenant", SubDomain = "code" };
            var tenant = new Tenant { Id = tenantId, Code="Code", Name = "Updated Tenant", SubDomain = "code" };

            _mapperMock.Setup(m => m.Map<Tenant>(tenantDto)).Returns(tenant);
            _tenantServiceMock.Setup(s => s.Update(tenantId, tenant)).ThrowsAsync(new NotFoundException());

            // Act
            var result = await _controller.Update(tenantId, tenantDto);

            // Assert
            Assert.IsType<NotFoundResult>(result);
        }

        [Fact]
        public async Task Delete_WithValidId_ReturnsNoContent()
        {
            // Arrange
            var tenantId = Guid.NewGuid();
            _tenantServiceMock.Setup(s => s.Delete(tenantId)).ReturnsAsync(true);

            // Act
            var result = await _controller.Delete(tenantId);

            // Assert
            Assert.IsType<NoContentResult>(result);
        }

        [Fact]
        public async Task Delete_WhenServiceReturnsFalse_ReturnsBadRequest()
        {
            // Arrange
            var tenantId = Guid.NewGuid();
            _tenantServiceMock.Setup(s => s.Delete(tenantId)).ReturnsAsync(false);

            // Act
            var result = await _controller.Delete(tenantId);

            // Assert
            var badRequestResult = Assert.IsType<BadRequestObjectResult>(result);
            Assert.Equal(ErrorMessages.ErrorSaving, badRequestResult.Value);
        }

        [Fact]
        public async Task Delete_WhenServiceThrowsNotFoundException_ReturnsNotFound()
        {
            // Arrange
            var tenantId = Guid.NewGuid();
            _tenantServiceMock.Setup(s => s.Delete(tenantId)).ThrowsAsync(new NotFoundException());

            // Act
            var result = await _controller.Delete(tenantId);

            // Assert
            Assert.IsType<NotFoundResult>(result);
        }
    }
}