
##MYSQL vs Postgres

```bash
// MYSQL    
// Add services to the container.
var connectionString = builder.Configuration["DBCONNECTION_AUTH"];
builder.Services.AddDbContext<PlatformDbContext>(options =>
{
options.UseMySql(connectionString, ServerVersion.AutoDetect(connectionString));
options.UseSnakeCaseNamingConvention();
}
);
  
DBCONNECTION_AUTH="server=localhost;user=platform_admin;password=Tabby12;database=platform_app_2;SslMode=none"
```

```bash
// Postgres    
// Add services to the container.
var connectionString = builder.Configuration["DBCONNECTION_AUTH"];
builder.Services.AddDbContext<PlatformDbContext>(options =>
{
options.UseMySql(connectionString, ServerVersion.AutoDetect(connectionString));
options.UseSnakeCaseNamingConvention();
}
);
  
DBCONNECTION_AUTH="server=localhost;user=platform_admin;password=Tabby12;database=platform_app_2;SslMode=none"
```