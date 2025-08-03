using AutoMapper;
using PlatformApi.Models;
using PlatformApi.Models.DTOs;

namespace PlatformApi.Data;

public class MappingProfile : Profile
{
    public MappingProfile()
    {
        CreateMap<Tenant, TenantDto>().ReverseMap();
        CreateMap<TenantConfig, TenantConfigDto>().ReverseMap();
        
        CreateMap<AuthRole, RoleDto>()
            .ForMember(dest => dest.Permissions, 
                opt => opt.Condition(src => src.RolePermissions != null))
            .ForMember(dest => dest.Permissions, 
                opt => opt.MapFrom(src => src.RolePermissions!.Select(rp => rp.Permission)));
        
        CreateMap<RoleDto, AuthRole>();
        CreateMap<RoleCreateDto, AuthRole>();
        CreateMap<AuthRole, RoleNoPermissionDto>();
        CreateMap<Permission, PermissionDto>().ReverseMap();
        CreateMap<PermissionCreateDto, Permission>();
        
        // Email-related mappings (if needed for any future DTOs)
        CreateMap<AuthUser, UserProfileDto>()
            .ForMember(dest => dest.IsEmailConfirmed, opt => opt.MapFrom(src => src.EmailConfirmed));
        
        CreateMap<AuthUser, TenantUserDto>()
            .ForMember(dest => dest.Email, opt => opt.MapFrom(src => src.Email))
            .ForMember(dest => dest.Roles, opt => opt.Ignore()); // Will be populated separately in controller
        
        CreateMap<AuthUser, UserEmailDto>();
        
        // User invitation mappings
        CreateMap<UserInvitation, UserInvitationDto>();
    }
}