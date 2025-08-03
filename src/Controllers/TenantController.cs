using AutoMapper;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using NetStarterCommon.Core.Common.Constants;
using NetStarterCommon.Core.Common.Permissions;
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

    public TenantController(ILogger<TenantController> logger,IMapper mapper, ITenantService tenantService)
    {
        _tenantService = tenantService;
        _logger = logger;
        _mapper = mapper;
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
        var obj = _mapper.Map<Tenant>(objDto);
        var result = await _tenantService.Add(obj);
        
        return CreatedAtAction(nameof(GetById), new { id = result.Id }, result);

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
            return BadRequest(ex.Message);
        }
        catch (NotFoundException)
        {
            return NotFound();
        }
    }
    
    [RequirePermission(RolePermissionConstants.SysAdminManageTenants)]
    [HttpDelete("{id}")]
    public async Task<IActionResult> Delete(Guid id)
    {
        try
        {
            _logger.LogTrace("Delete Id: {id}", id);

            var result = await _tenantService.Delete(id);

            if (!result) return BadRequest(ErrorMessages.ErrorSaving);

            return NoContent();
        } catch (NotFoundException)
        {
            return NotFound();
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
                SiteName = obj.SiteName,
                GeocenterLat = obj.GeocenterLat,
                GeocenterLong = obj.GeocenterLong
            };
            
            var result = await _tenantService.UpdateTenantConfig(id, tenantConfig);
            
            if (!result) return BadRequest(ErrorMessages.ErrorSaving);
            
            return NoContent();
        }
        catch (InvalidDataException ex)
        {
            return BadRequest(ex.Message);
        }
    }
}