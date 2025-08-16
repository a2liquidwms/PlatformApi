using AutoMapper;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using PlatformApi.Common.Constants;
using PlatformApi.Common.Permissions;
using PlatformApi.Data;
using PlatformApi.Models;
using PlatformApi.Models.DTOs;
using PlatformApi.Services;

namespace PlatformApi.Controllers;

[Route("api/v1/admin/permission")]
[ApiController]
public class PermissionController : ControllerBase
{
    private readonly ILogger<PermissionController> _logger;
    private readonly IMapper _mapper;
    private readonly IPermissionService _permissionService;

    public PermissionController(ILogger<PermissionController> logger,IMapper mapper,
        IPermissionService permissionService)
    {
        _logger = logger;
        _mapper = mapper;
        _permissionService = permissionService;
    }
    
    [AllowAnonymous]
    [HttpGet( "roles")]
    public async Task<ActionResult<IEnumerable<RoleDto>>> GetAllRoles([FromQuery] bool includePermissions = false)
    {
        var result = await _permissionService.GetAllRoles(includePermissions);
        
        return Ok(_mapper.Map<IEnumerable<RoleDto>>(result));
    }
    
    [RequirePermission(RolePermissionConstants.SysAdminManagePermissions)]
    [HttpGet("roles/{id}")]
    public async Task<ActionResult<RoleDto>> GetRoleById(string id,[FromQuery] bool includePermissions = true )
    {
        try
        {
            var obj = await _permissionService.GetRoleById(id, includePermissions);
            
            if (obj == null)
            {
                return NotFound("Role not found");
            }

            return Ok(_mapper.Map<RoleDto>(obj));
        }
        catch (NotFoundException)
        {
            return NotFound();
        }
    }
    
    [RequirePermission(RolePermissionConstants.SysAdminManagePermissions)]
    [HttpPost ("roles")]
    public async Task<ActionResult<RoleDto>> AddRole(RoleCreateDto objCreateDto)
    {
        var obj = _mapper.Map<Role>(objCreateDto);
        var result = await _permissionService.AddRole(obj);
        
        return CreatedAtAction(nameof(GetRoleById), new { id = result.Id }, result);

    }
    
    [RequirePermission(RolePermissionConstants.SysAdminManagePermissions)]
    [HttpPut("roles/{id}")]
    [ProducesResponseType(typeof(void), 204)]
    public async Task<ActionResult> UpdateRole(string id, RoleDto objDto)
    {
        try
        {
            var obj = _mapper.Map<Role>(objDto);
            
            var result = await _permissionService.UpdateRole(id, obj);
    
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
    
    [RequirePermission(RolePermissionConstants.SysAdminManagePermissions)]
    [HttpDelete("roles/{id}")]
    public async Task<ActionResult> DeleteRole(string id)
    {
        try
        {
            _logger.LogTrace("Delete Id: {id}", id);
    
            var result = await _permissionService.DeleteRole(id);
    
            if (!result) return BadRequest(ErrorMessages.ErrorSaving);
    
            return NoContent();
        } catch (NotFoundException)
        {
            return NotFound();
        } catch (InvalidDataException ex)
        {
            return BadRequest(ex.Message);
        }
        
    }
    
    [RequirePermission(RolePermissionConstants.SysAdminManagePermissions)]
    //permissions
    [HttpGet( "permissions")]
    public async Task<ActionResult<IEnumerable<PermissionDto>>> GetAllPermissions([FromQuery] int? scope = null)
    {
        var result = await _permissionService.GetAllPermissions(scope);
        
        return Ok(_mapper.Map<IEnumerable<PermissionDto>>(result));
    } 
    
    [RequirePermission(RolePermissionConstants.SysAdminManagePermissions)]
    [HttpGet("permissions/{code}")]
    public async Task<IActionResult> GetPermissionByCode(string code)
    {
        try
        {
            var obj = await _permissionService.GetPermissionByCode(code);
            
            if (obj == null)
            {
                return NotFound();
            }

            return Ok(_mapper.Map<PermissionDto>(obj));
        }
        catch (NotFoundException)
        {
            return NotFound();
        }
    }
    
    [RequirePermission(RolePermissionConstants.SysAdminManagePermissions)]
    [HttpPost("permissions")]
    public async Task<ActionResult<PermissionDto>> AddPermission(PermissionCreateDto objCreateMetaDto)
    {
        var obj = _mapper.Map<Permission>(objCreateMetaDto);
        var result = await _permissionService.AddPermission(obj);
        
        return CreatedAtAction(nameof(GetPermissionByCode), new { code = result.Code }, result);
    }
    
    [RequirePermission(RolePermissionConstants.SysAdminManagePermissions)]
    [HttpPost("permissions/multi")]
    public async Task<ActionResult<PermissionDto>> AddPermissionMulti(PermissionCreateDto[] objCreateDtos)
    {
        var resultCount = 0;
        try
        {
            var objs = _mapper.Map<Permission[]>(objCreateDtos);
            resultCount = await _permissionService.AddPermissionsMulti(objs);
        }
        catch (ArgumentException ex)
        {
            return BadRequest(ex.Message);
        }

        return Ok($"{resultCount} permissions created");
    }
    
    [RequirePermission(RolePermissionConstants.SysAdminManagePermissions)]
    [HttpPut("permissions/{code}")]
    [ProducesResponseType(typeof(void), 204)]
    public async Task<IActionResult> UpdatePermission(string code, PermissionCreateDto objMetaDto)
    {
        try
        {
            var obj = _mapper.Map<Permission>(objMetaDto);
            
            var result = await _permissionService.UpdatePermission(code, obj);
    
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
    
    [RequirePermission(RolePermissionConstants.SysAdminManagePermissions)]
    [HttpDelete("permissions/{code}")]
    [ProducesResponseType(typeof(void), 204)]
    public async Task<IActionResult> DeletePermission(string code)
    {
        try
        {
            _logger.LogTrace("Delete Code: {code}", code);
    
            var result = await _permissionService.DeletePermission(code);
    
            if (!result) return BadRequest(ErrorMessages.ErrorSaving);
    
            return NoContent();
        } catch (NotFoundException)
        {
            return NotFound();
        }
    }
    
    // [RequirePermission(RolePermissionConstants.SysAdminManagePermissions)]
    // [HttpPost("permissions/add/role/{roleId}")]
    // public async Task<ActionResult<RoleDto>> AddPermissionsToRole(string roleId, string[] permissionCodes)
    // {
    //     var result = await _permissionService.AddPermissionsToRole(roleId, permissionCodes);
    //     
    //     return Ok(_mapper.Map<RoleDto>(result));
    // }

    [RequirePermission(RolePermissionConstants.SysAdminManagePermissions)]
    [HttpPost("roles/{roleId}/permission/{permissionCode}")]
    public async Task<ActionResult<RoleDto>> AddPermissionToRole(string roleId, string permissionCode)
    {
        try
        {
            var result = await _permissionService.AddPermissionToRole(roleId, permissionCode);
            return Ok(_mapper.Map<RoleDto>(result));
        }
        catch (NotFoundException ex)
        {
            return NotFound(ex.Message);
        }
        catch (InvalidDataException ex)
        {
            return BadRequest(ex.Message);
        }
        catch (ServiceException ex)
        {
            return StatusCode(500, ex.Message);
        }
    }

    [RequirePermission(RolePermissionConstants.SysAdminManagePermissions)]
    [HttpDelete("roles/{roleId}/permission/{permissionCode}")]
    public async Task<ActionResult<RoleDto>> RemovePermissionFromRole(string roleId, string permissionCode)
    {
        try
        {
            var result = await _permissionService.RemovePermissionFromRole(roleId, permissionCode);
            return Ok(_mapper.Map<RoleDto>(result));
        }
        catch (NotFoundException ex)
        {
            return NotFound(ex.Message);
        }
        catch (ServiceException ex)
        {
            return StatusCode(500, ex.Message);
        }
    }
    
}