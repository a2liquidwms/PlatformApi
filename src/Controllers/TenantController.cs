using AutoMapper;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using PlatformApi.Common.Constants;
using PlatformApi.Common.Permissions;
using PlatformApi.Common.Tenant;
using PlatformApi.Data;
using PlatformApi.Models;
using PlatformApi.Models.DTOs;
using PlatformApi.Services;

namespace PlatformApi.Controllers;

[Route("api/v1/[controller]")]
[ApiController]
public class TenantController : ControllerBase
{
    private readonly ILogger<TenantController> _logger;
    private readonly IMapper _mapper;
    private readonly ITenantService _tenantService;
    private readonly TenantHelper _tenantHelper;

    public TenantController(ILogger<TenantController> logger,IMapper mapper, ITenantService tenantService, TenantHelper tenantHelper)
    {
        _tenantService = tenantService;
        _logger = logger;
        _mapper = mapper;
        _tenantHelper = tenantHelper;
    }
    
    [RequirePermission(RolePermissionConstants.SysAdminManageTenants)]
    [HttpGet]
    public async Task<ActionResult<IEnumerable<TenantDto>>> GetAll()
    {
        var result = await _tenantService.GetAll();
        return Ok(_mapper.Map<IEnumerable<TenantDto>>(result));
    } 
    
    [RequirePermission(RolePermissionConstants.SysAdminManageTenants)]
    [HttpGet("{id}")]
    public async Task<ActionResult<TenantDto>> GetById(Guid id)
    {
        try
        {
            var obj = await _tenantService.GetById(id);
            
            if (obj == null)
            {
                return NotFound();
            }

            return Ok(_mapper.Map<TenantDto>(obj));
        }
        catch (NotFoundException)
        {
            return NotFound();
        }
    }
    
    [RequirePermission(RolePermissionConstants.SysAdminManageTenants)]
    [HttpPost]
    public async Task<ActionResult<TenantDto>> Add(TenantDto objDto)
    {
        try
        {
            var obj = _mapper.Map<Tenant>(objDto);
            var result = await _tenantService.Add(obj);
            
            return CreatedAtAction(nameof(GetById), new { id = result.Id }, result);
        }
        catch (InvalidDataException ex)
        {
            _logger.LogWarning("Failed to create tenant {TenantName}: {Message}", objDto.Name, ex.Message);
            return BadRequest(ex.Message);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Unexpected error creating tenant {TenantName}", objDto.Name);
            return StatusCode(500, "Internal server error");
        }
    }
    
    [RequirePermission(RolePermissionConstants.SysAdminManageTenants)]
    [HttpPut("{id}")]
    public async Task<IActionResult> Update(Guid id, TenantDto objDto)
    {
        try
        {
            var obj = _mapper.Map<Tenant>(objDto);
            
            var result = await _tenantService.Update(id, obj);

            if (!result) return BadRequest(ErrorMessages.ErrorSaving);

            return NoContent();
        }
        catch (InvalidDataException ex)
        {
            _logger.LogWarning("Failed to update tenant {TenantId}: {Message}", id, ex.Message);
            return BadRequest(ex.Message);
        }
        catch (NotFoundException)
        {
            _logger.LogWarning("Tenant {TenantId} not found for update", id);
            return NotFound();
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Unexpected error updating tenant {TenantId}", id);
            return StatusCode(500, "Internal server error");
        }
    }
    
    [RequirePermission(RolePermissionConstants.SysAdminManageTenants)]
    [HttpDelete("{id}")]
    public async Task<IActionResult> Delete(Guid id)
    {
        try
        {
            var result = await _tenantService.Delete(id);

            if (!result) return BadRequest(ErrorMessages.ErrorSaving);

            return NoContent();
        } 
        catch (NotFoundException)
        {
            _logger.LogWarning("Tenant {TenantId} not found for deletion", id);
            return NotFound();
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Unexpected error deleting tenant {TenantId}", id);
            return StatusCode(500, "Internal server error");
        }
    }
    
    [AllowAnonymous]
    [HttpGet("config/id/{id}")]
    public async Task<ActionResult<TenantConfigDto>> GetTenantConfigById(Guid id)
    {
        try
        {
            var config = await _tenantService.GetTenantConfigById(id);
            
            if (config == null)
            {
                return NotFound();
            }
            
            var tenantConfigDto = _mapper.Map<TenantConfigDto>(config);
            tenantConfigDto.SubDomain = config.Tenant!.SubDomain;
            tenantConfigDto.TenantName = config.Tenant!.Name;

            return Ok(tenantConfigDto);
        }
        catch (NotFoundException)
        {
            return NotFound();
        }
    }
    
    [AllowAnonymous]
    [HttpGet("config/subdomain/{subdomain}")]
    public async Task<ActionResult<TenantConfigDto>> GetTenantConfigBySubDomain(string subdomain)
    {
        try
        {
            var config = await _tenantService.GetTenantConfigBySubdomain(subdomain);
            
            if (config == null)
            {
                return NotFound();
            }

            var tenantConfigDto = _mapper.Map<TenantConfigDto>(config);
            tenantConfigDto.SubDomain = config.Tenant!.SubDomain;
            tenantConfigDto.TenantName = config.Tenant!.Name;

            return Ok(tenantConfigDto);
        }
        catch (NotFoundException)
        {
            return NotFound();
        }
    }
    
    [RequirePermission(RolePermissionConstants.SysAdminManageTenants)]
    [HttpPut("config/id/{id}")]
    public async Task<IActionResult> EditTenantConfig(Guid id, TenantConfigCreateDto obj)
    {
        try
        {
            var tenantConfig = new TenantConfig()
            {
                TenantId = id,
                LogoPath = obj.LogoPath,
                PrimaryColor = obj.PrimaryColor,
            };
            
            var result = await _tenantService.UpdateTenantConfig(id, tenantConfig);
            
            if (!result) return BadRequest(ErrorMessages.ErrorSaving);
            
            return NoContent();
        }
        catch (InvalidDataException ex)
        {
            _logger.LogWarning("Failed to update tenant config for {TenantId}: {Message}", id, ex.Message);
            return BadRequest(ex.Message);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Unexpected error updating tenant config for {TenantId}", id);
            return StatusCode(500, "Internal server error");
        }
    }

    [RequirePermission(RolePermissionConstants.SystemAdminManageSites)]
    [HttpGet("sites/{id}")]
    public async Task<ActionResult<SiteDto>> GetSiteById(Guid id)
    {
        try
        {
            var site = await _tenantService.GetSiteById(id);
            if (site == null)
            {
                return NotFound();
            }
            return Ok(_mapper.Map<SiteDto>(site));
        }
        catch (NotFoundException)
        {
            return NotFound();
        }
    }
    
    //allow any auth user
    [RequireTenantAccess]
    [HttpGet("siteconfig/{id}")]
    public async Task<ActionResult<SiteDto>> GetSiteConfigById(Guid id)
    {
        try
        {
            var tenantId = _tenantHelper.GetTenantId();
            var siteConfig = await _tenantService.GetSiteConfigById(id, tenantId);
            if (siteConfig == null)
            {
                return NotFound();
            }
            return Ok(_mapper.Map<SiteDto>(siteConfig));
        }
        catch (InvalidDataException ex)
        {
            return BadRequest(ex.Message);
        }
        catch (NotFoundException)
        {
            return NotFound();
        }
    }

    [RequirePermission(RolePermissionConstants.SystemAdminManageSites)]
    [HttpGet("{tenantId}/sites")]
    public async Task<ActionResult<IEnumerable<SiteDto>>> GetSitesByTenantId(Guid tenantId)
    {
        var result = await _tenantService.GetSitesByTenantId(tenantId);
        return Ok(_mapper.Map<IEnumerable<SiteDto>>(result));
    }

    [RequirePermission(RolePermissionConstants.SystemAdminManageSites)]
    [HttpPost("sites")]
    public async Task<ActionResult<SiteDto>> AddSite(SiteDto siteDto)
    {
        try
        {
            var site = _mapper.Map<Site>(siteDto);
            var result = await _tenantService.AddSite(site);
            return CreatedAtAction(nameof(GetSiteById), new { id = result.Id }, _mapper.Map<SiteDto>(result));
        }
        catch (InvalidDataException ex)
        {
            _logger.LogWarning("Failed to create site {SiteName}: {Message}", siteDto.Name, ex.Message);
            return BadRequest(ex.Message);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Unexpected error creating site {SiteName}", siteDto.Name);
            return StatusCode(500, "Internal server error");
        }
    }

    [RequirePermission(RolePermissionConstants.SystemAdminManageSites)]
    [HttpPut("sites/{id}")]
    public async Task<IActionResult> UpdateSite(Guid id, SiteDto siteDto)
    {
        try
        {
            var site = _mapper.Map<Site>(siteDto);
            var result = await _tenantService.UpdateSite(id, site);
            if (!result) return BadRequest(ErrorMessages.ErrorSaving);
            return NoContent();
        }
        catch (InvalidDataException ex)
        {
            _logger.LogWarning("Failed to update site {SiteId}: {Message}", id, ex.Message);
            return BadRequest(ex.Message);
        }
        catch (NotFoundException)
        {
            _logger.LogWarning("Site {SiteId} not found for update", id);
            return NotFound();
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Unexpected error updating site {SiteId}", id);
            return StatusCode(500, "Internal server error");
        }
    }

    [RequirePermission(RolePermissionConstants.SystemAdminManageSites)]
    [HttpDelete("sites/{id}")]
    public async Task<IActionResult> DeleteSite(Guid id)
    {
        try
        {
            var result = await _tenantService.DeleteSite(id);
            if (!result) return BadRequest(ErrorMessages.ErrorSaving);
            return NoContent();
        }
        catch (NotFoundException)
        {
            _logger.LogWarning("Site {SiteId} not found for deletion", id);
            return NotFound();
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Unexpected error deleting site {SiteId}", id);
            return StatusCode(500, "Internal server error");
        }
    }
}