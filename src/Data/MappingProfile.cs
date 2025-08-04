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
        
        CreateMap<Role, RoleDto>()
            .ForMember(dest => dest.Permissions, 
                opt => opt.Condition(src => src.RolePermissions != null))
            .ForMember(dest => dest.Permissions, 
                opt => opt.MapFrom(src => src.RolePermissions!.Select(rp => rp.Permission)));
        
        CreateMap<RoleDto, Role>();
        CreateMap<RoleCreateDto, Role>();
        CreateMap<Role, RoleNoPermissionDto>();
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
        
        // New scope-aware mappings
        CreateMap<Site, SiteDto>().ReverseMap();
        CreateMap<AuthUser, SiteUserDto>()
            .ForMember(dest => dest.UserId, opt => opt.MapFrom(src => src.Id))
            .ForMember(dest => dest.Email, opt => opt.MapFrom(src => src.Email))
            .ForMember(dest => dest.Roles, opt => opt.Ignore()); // Will be populated separately
    }
}