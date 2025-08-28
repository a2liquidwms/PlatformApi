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
        try
        {
            var obj = _mapper.Map<Role>(objCreateDto);
            var result = await _permissionService.AddRole(obj);
            
            _logger.LogInformation("Role {RoleName} created successfully with ID {RoleId}", objCreateDto.Name, result.Id);
            return CreatedAtAction(nameof(GetRoleById), new { id = result.Id }, result);
        }
        catch (InvalidDataException ex)
        {
            _logger.LogWarning("Failed to create role {RoleName}: {Message}", objCreateDto.Name, ex.Message);
            return BadRequest(ex.Message);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Unexpected error creating role {RoleName}", objCreateDto.Name);
            return StatusCode(500, "Internal server error");
        }
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
    
            _logger.LogInformation("Role {RoleId} updated successfully", id);
            return NoContent();
        }
        catch (InvalidDataException ex)
        {
            _logger.LogWarning("Failed to update role {RoleId}: {Message}", id, ex.Message);
            return BadRequest(ex.Message);
        }
        catch (NotFoundException)
        {
            _logger.LogWarning("Role {RoleId} not found for update", id);
            return NotFound();
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Unexpected error updating role {RoleId}", id);
            return StatusCode(500, "Internal server error");
        }
    }
    
    [RequirePermission(RolePermissionConstants.SysAdminManagePermissions)]
    [HttpDelete("roles/{id}")]
    public async Task<ActionResult> DeleteRole(string id)
    {
        try
        {
            var result = await _permissionService.DeleteRole(id);
    
            if (!result) return BadRequest(ErrorMessages.ErrorSaving);
    
            _logger.LogInformation("Role {RoleId} deleted successfully", id);
            return NoContent();
        } 
        catch (NotFoundException)
        {
            _logger.LogWarning("Role {RoleId} not found for deletion", id);
            return NotFound();
        } 
        catch (InvalidDataException ex)
        {
            _logger.LogWarning("Failed to delete role {RoleId}: {Message}", id, ex.Message);
            return BadRequest(ex.Message);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Unexpected error deleting role {RoleId}", id);
            return StatusCode(500, "Internal server error");
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
        try
        {
            var obj = _mapper.Map<Permission>(objCreateMetaDto);
            var result = await _permissionService.AddPermission(obj);
            
            _logger.LogInformation("Permission {PermissionCode} created successfully", objCreateMetaDto.Code);
            return CreatedAtAction(nameof(GetPermissionByCode), new { code = result.Code }, result);
        }
        catch (InvalidDataException ex)
        {
            _logger.LogWarning("Failed to create permission {PermissionCode}: {Message}", objCreateMetaDto.Code, ex.Message);
            return BadRequest(ex.Message);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Unexpected error creating permission {PermissionCode}", objCreateMetaDto.Code);
            return StatusCode(500, "Internal server error");
        }
    }
    
    [RequirePermission(RolePermissionConstants.SysAdminManagePermissions)]
    [HttpPost("permissions/multi")]
    public async Task<ActionResult<PermissionDto>> AddPermissionMulti(PermissionCreateDto[] objCreateDtos)
    {
        try
        {
            var objs = _mapper.Map<Permission[]>(objCreateDtos);
            var resultCount = await _permissionService.AddPermissionsMulti(objs);
            
            _logger.LogInformation("Multiple permissions created successfully");
            return Ok($"{resultCount} permissions created");
        }
        catch (ArgumentException ex)
        {
            _logger.LogWarning("Failed to create multiple permissions: {Message}", ex.Message);
            return BadRequest(ex.Message);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Unexpected error creating multiple permissions");
            return StatusCode(500, "Internal server error");
        }
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
    
            _logger.LogInformation("Permission {PermissionCode} updated successfully", code);
            return NoContent();
        }
        catch (InvalidDataException ex)
        {
            _logger.LogWarning("Failed to update permission {PermissionCode}: {Message}", code, ex.Message);
            return BadRequest(ex.Message);
        }
        catch (NotFoundException)
        {
            _logger.LogWarning("Permission {PermissionCode} not found for update", code);
            return NotFound();
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Unexpected error updating permission {PermissionCode}", code);
            return StatusCode(500, "Internal server error");
        }
    }
    
    [RequirePermission(RolePermissionConstants.SysAdminManagePermissions)]
    [HttpDelete("permissions/{code}")]
    [ProducesResponseType(typeof(void), 204)]
    public async Task<IActionResult> DeletePermission(string code)
    {
        try
        {
            var result = await _permissionService.DeletePermission(code);
    
            if (!result) return BadRequest(ErrorMessages.ErrorSaving);
    
            _logger.LogInformation("Permission {PermissionCode} deleted successfully", code);
            return NoContent();
        } 
        catch (NotFoundException)
        {
            _logger.LogWarning("Permission {PermissionCode} not found for deletion", code);
            return NotFound();
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Unexpected error deleting permission {PermissionCode}", code);
            return StatusCode(500, "Internal server error");
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
            _logger.LogInformation("Permission {PermissionCode} added to role {RoleId}", permissionCode, roleId);
            return Ok(_mapper.Map<RoleDto>(result));
        }
        catch (NotFoundException ex)
        {
            _logger.LogWarning("Failed to add permission {PermissionCode} to role {RoleId}: {Message}", permissionCode, roleId, ex.Message);
            return NotFound(ex.Message);
        }
        catch (InvalidDataException ex)
        {
            _logger.LogWarning("Invalid data adding permission {PermissionCode} to role {RoleId}: {Message}", permissionCode, roleId, ex.Message);
            return BadRequest(ex.Message);
        }
        catch (ServiceException ex)
        {
            _logger.LogError(ex, "Service error adding permission {PermissionCode} to role {RoleId}", permissionCode, roleId);
            return StatusCode(500, ex.Message);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Unexpected error adding permission {PermissionCode} to role {RoleId}", permissionCode, roleId);
            return StatusCode(500, "Internal server error");
        }
    }

    [RequirePermission(RolePermissionConstants.SysAdminManagePermissions)]
    [HttpDelete("roles/{roleId}/permission/{permissionCode}")]
    public async Task<ActionResult<RoleDto>> RemovePermissionFromRole(string roleId, string permissionCode)
    {
        try
        {
            var result = await _permissionService.RemovePermissionFromRole(roleId, permissionCode);
            _logger.LogInformation("Permission {PermissionCode} removed from role {RoleId}", permissionCode, roleId);
            return Ok(_mapper.Map<RoleDto>(result));
        }
        catch (NotFoundException ex)
        {
            _logger.LogWarning("Failed to remove permission {PermissionCode} from role {RoleId}: {Message}", permissionCode, roleId, ex.Message);
            return NotFound(ex.Message);
        }
        catch (ServiceException ex)
        {
            _logger.LogError(ex, "Service error removing permission {PermissionCode} from role {RoleId}", permissionCode, roleId);
            return StatusCode(500, ex.Message);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Unexpected error removing permission {PermissionCode} from role {RoleId}", permissionCode, roleId);
            return StatusCode(500, "Internal server error");
        }
    }
    
}