using System;
using Microsoft.EntityFrameworkCore.Metadata;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

#pragma warning disable CA1814 // Prefer jagged arrays over multidimensional

namespace PlatformApi.Migrations
{
    /// <inheritdoc />
    public partial class InitialMysql : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AlterDatabase()
                .Annotation("MySql:CharSet", "utf8mb4");

            migrationBuilder.CreateTable(
                name: "permissions",
                columns: table => new
                {
                    code = table.Column<string>(type: "varchar(50)", maxLength: 50, nullable: false)
                        .Annotation("MySql:CharSet", "utf8mb4"),
                    description = table.Column<string>(type: "varchar(50)", maxLength: 50, nullable: true)
                        .Annotation("MySql:CharSet", "utf8mb4"),
                    role_scope = table.Column<int>(type: "int", nullable: true),
                    create_date = table.Column<DateTime>(type: "datetime(6)", nullable: false),
                    create_by = table.Column<string>(type: "varchar(100)", maxLength: 100, nullable: true)
                        .Annotation("MySql:CharSet", "utf8mb4"),
                    last_mod_date = table.Column<DateTime>(type: "datetime(6)", nullable: true),
                    last_mod_by = table.Column<string>(type: "varchar(100)", maxLength: 100, nullable: true)
                        .Annotation("MySql:CharSet", "utf8mb4"),
                    modify_source = table.Column<string>(type: "varchar(25)", maxLength: 25, nullable: true)
                        .Annotation("MySql:CharSet", "utf8mb4")
                },
                constraints: table =>
                {
                    table.PrimaryKey("pk_permissions", x => x.code);
                })
                .Annotation("MySql:CharSet", "utf8mb4");

            migrationBuilder.CreateTable(
                name: "roles",
                columns: table => new
                {
                    id = table.Column<Guid>(type: "char(36)", nullable: false, collation: "ascii_general_ci"),
                    name = table.Column<string>(type: "varchar(256)", maxLength: 256, nullable: false)
                        .Annotation("MySql:CharSet", "utf8mb4"),
                    description = table.Column<string>(type: "varchar(50)", maxLength: 50, nullable: true)
                        .Annotation("MySql:CharSet", "utf8mb4"),
                    scope = table.Column<int>(type: "int", nullable: false),
                    tenant_id = table.Column<Guid>(type: "char(36)", nullable: true, collation: "ascii_general_ci"),
                    site_id = table.Column<Guid>(type: "char(36)", nullable: true, collation: "ascii_general_ci"),
                    is_system_role = table.Column<bool>(type: "tinyint(1)", nullable: false, defaultValue: false),
                    create_date = table.Column<DateTime>(type: "datetime(6)", nullable: false),
                    create_by = table.Column<string>(type: "varchar(100)", maxLength: 100, nullable: true)
                        .Annotation("MySql:CharSet", "utf8mb4"),
                    last_mod_date = table.Column<DateTime>(type: "datetime(6)", nullable: true),
                    last_mod_by = table.Column<string>(type: "varchar(100)", maxLength: 100, nullable: true)
                        .Annotation("MySql:CharSet", "utf8mb4"),
                    modify_source = table.Column<string>(type: "varchar(25)", maxLength: 25, nullable: true)
                        .Annotation("MySql:CharSet", "utf8mb4")
                },
                constraints: table =>
                {
                    table.PrimaryKey("pk_roles", x => x.id);
                })
                .Annotation("MySql:CharSet", "utf8mb4");

            migrationBuilder.CreateTable(
                name: "tenants",
                columns: table => new
                {
                    id = table.Column<Guid>(type: "char(36)", nullable: false, collation: "ascii_general_ci"),
                    code = table.Column<string>(type: "varchar(25)", maxLength: 25, nullable: false)
                        .Annotation("MySql:CharSet", "utf8mb4"),
                    name = table.Column<string>(type: "varchar(50)", maxLength: 50, nullable: false)
                        .Annotation("MySql:CharSet", "utf8mb4"),
                    sub_domain = table.Column<string>(type: "varchar(50)", maxLength: 50, nullable: false)
                        .Annotation("MySql:CharSet", "utf8mb4"),
                    create_date = table.Column<DateTime>(type: "datetime(6)", nullable: false),
                    create_by = table.Column<string>(type: "varchar(100)", maxLength: 100, nullable: true)
                        .Annotation("MySql:CharSet", "utf8mb4"),
                    last_mod_date = table.Column<DateTime>(type: "datetime(6)", nullable: true),
                    last_mod_by = table.Column<string>(type: "varchar(100)", maxLength: 100, nullable: true)
                        .Annotation("MySql:CharSet", "utf8mb4"),
                    modify_source = table.Column<string>(type: "varchar(25)", maxLength: 25, nullable: true)
                        .Annotation("MySql:CharSet", "utf8mb4")
                },
                constraints: table =>
                {
                    table.PrimaryKey("pk_tenants", x => x.id);
                })
                .Annotation("MySql:CharSet", "utf8mb4");

            migrationBuilder.CreateTable(
                name: "user_invitations",
                columns: table => new
                {
                    id = table.Column<Guid>(type: "char(36)", nullable: false, collation: "ascii_general_ci"),
                    email = table.Column<string>(type: "varchar(255)", maxLength: 255, nullable: false)
                        .Annotation("MySql:CharSet", "utf8mb4"),
                    tenant_id = table.Column<Guid>(type: "char(36)", nullable: true, collation: "ascii_general_ci"),
                    site_id = table.Column<Guid>(type: "char(36)", nullable: true, collation: "ascii_general_ci"),
                    invitation_token = table.Column<string>(type: "varchar(255)", maxLength: 255, nullable: false)
                        .Annotation("MySql:CharSet", "utf8mb4"),
                    scope = table.Column<int>(type: "int", nullable: false),
                    expires_at = table.Column<DateTime>(type: "datetime(6)", nullable: false),
                    is_used = table.Column<bool>(type: "tinyint(1)", nullable: false),
                    create_date = table.Column<DateTime>(type: "datetime(6)", nullable: false),
                    create_by = table.Column<string>(type: "varchar(100)", maxLength: 100, nullable: true)
                        .Annotation("MySql:CharSet", "utf8mb4"),
                    last_mod_date = table.Column<DateTime>(type: "datetime(6)", nullable: true),
                    last_mod_by = table.Column<string>(type: "varchar(100)", maxLength: 100, nullable: true)
                        .Annotation("MySql:CharSet", "utf8mb4"),
                    modify_source = table.Column<string>(type: "varchar(25)", maxLength: 25, nullable: true)
                        .Annotation("MySql:CharSet", "utf8mb4")
                },
                constraints: table =>
                {
                    table.PrimaryKey("pk_user_invitations", x => x.id);
                })
                .Annotation("MySql:CharSet", "utf8mb4");

            migrationBuilder.CreateTable(
                name: "users",
                columns: table => new
                {
                    id = table.Column<Guid>(type: "char(36)", nullable: false, collation: "ascii_general_ci"),
                    user_name = table.Column<string>(type: "varchar(256)", maxLength: 256, nullable: true)
                        .Annotation("MySql:CharSet", "utf8mb4"),
                    normalized_user_name = table.Column<string>(type: "varchar(256)", maxLength: 256, nullable: true)
                        .Annotation("MySql:CharSet", "utf8mb4"),
                    email = table.Column<string>(type: "varchar(256)", maxLength: 256, nullable: true)
                        .Annotation("MySql:CharSet", "utf8mb4"),
                    normalized_email = table.Column<string>(type: "varchar(256)", maxLength: 256, nullable: true)
                        .Annotation("MySql:CharSet", "utf8mb4"),
                    email_confirmed = table.Column<bool>(type: "tinyint(1)", nullable: false),
                    password_hash = table.Column<string>(type: "longtext", nullable: true)
                        .Annotation("MySql:CharSet", "utf8mb4"),
                    security_stamp = table.Column<string>(type: "longtext", nullable: true)
                        .Annotation("MySql:CharSet", "utf8mb4"),
                    concurrency_stamp = table.Column<string>(type: "longtext", nullable: true)
                        .Annotation("MySql:CharSet", "utf8mb4"),
                    phone_number = table.Column<string>(type: "longtext", nullable: true)
                        .Annotation("MySql:CharSet", "utf8mb4"),
                    phone_number_confirmed = table.Column<bool>(type: "tinyint(1)", nullable: false),
                    two_factor_enabled = table.Column<bool>(type: "tinyint(1)", nullable: false),
                    lockout_end = table.Column<DateTimeOffset>(type: "datetime(6)", nullable: true),
                    lockout_enabled = table.Column<bool>(type: "tinyint(1)", nullable: false),
                    access_failed_count = table.Column<int>(type: "int", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("pk_users", x => x.id);
                })
                .Annotation("MySql:CharSet", "utf8mb4");

            migrationBuilder.CreateTable(
                name: "role_permissions",
                columns: table => new
                {
                    id = table.Column<Guid>(type: "char(36)", nullable: false, collation: "ascii_general_ci"),
                    permission_code = table.Column<string>(type: "varchar(50)", maxLength: 50, nullable: false)
                        .Annotation("MySql:CharSet", "utf8mb4"),
                    role_id = table.Column<Guid>(type: "char(36)", nullable: false, collation: "ascii_general_ci"),
                    create_date = table.Column<DateTime>(type: "datetime(6)", nullable: false),
                    create_by = table.Column<string>(type: "varchar(100)", maxLength: 100, nullable: true)
                        .Annotation("MySql:CharSet", "utf8mb4"),
                    last_mod_date = table.Column<DateTime>(type: "datetime(6)", nullable: true),
                    last_mod_by = table.Column<string>(type: "varchar(100)", maxLength: 100, nullable: true)
                        .Annotation("MySql:CharSet", "utf8mb4"),
                    modify_source = table.Column<string>(type: "varchar(25)", maxLength: 25, nullable: true)
                        .Annotation("MySql:CharSet", "utf8mb4")
                },
                constraints: table =>
                {
                    table.PrimaryKey("pk_role_permissions", x => x.id);
                    table.ForeignKey(
                        name: "fk_role_permissions_permissions_permission_code",
                        column: x => x.permission_code,
                        principalTable: "permissions",
                        principalColumn: "code",
                        onDelete: ReferentialAction.Cascade);
                    table.ForeignKey(
                        name: "fk_role_permissions_roles_role_id",
                        column: x => x.role_id,
                        principalTable: "roles",
                        principalColumn: "id",
                        onDelete: ReferentialAction.Cascade);
                })
                .Annotation("MySql:CharSet", "utf8mb4");

            migrationBuilder.CreateTable(
                name: "sites",
                columns: table => new
                {
                    id = table.Column<Guid>(type: "char(36)", nullable: false, collation: "ascii_general_ci"),
                    code = table.Column<string>(type: "varchar(25)", maxLength: 25, nullable: false)
                        .Annotation("MySql:CharSet", "utf8mb4"),
                    name = table.Column<string>(type: "varchar(100)", maxLength: 100, nullable: false)
                        .Annotation("MySql:CharSet", "utf8mb4"),
                    tenant_id = table.Column<Guid>(type: "char(36)", nullable: false, collation: "ascii_general_ci"),
                    is_active = table.Column<bool>(type: "tinyint(1)", nullable: false),
                    create_date = table.Column<DateTime>(type: "datetime(6)", nullable: false),
                    create_by = table.Column<string>(type: "varchar(100)", maxLength: 100, nullable: true)
                        .Annotation("MySql:CharSet", "utf8mb4"),
                    last_mod_date = table.Column<DateTime>(type: "datetime(6)", nullable: true),
                    last_mod_by = table.Column<string>(type: "varchar(100)", maxLength: 100, nullable: true)
                        .Annotation("MySql:CharSet", "utf8mb4"),
                    modify_source = table.Column<string>(type: "varchar(25)", maxLength: 25, nullable: true)
                        .Annotation("MySql:CharSet", "utf8mb4")
                },
                constraints: table =>
                {
                    table.PrimaryKey("pk_sites", x => x.id);
                    table.ForeignKey(
                        name: "fk_sites_tenants_tenant_id",
                        column: x => x.tenant_id,
                        principalTable: "tenants",
                        principalColumn: "id",
                        onDelete: ReferentialAction.Cascade);
                })
                .Annotation("MySql:CharSet", "utf8mb4");

            migrationBuilder.CreateTable(
                name: "tenant_configs",
                columns: table => new
                {
                    id = table.Column<Guid>(type: "char(36)", nullable: false, collation: "ascii_general_ci"),
                    tenant_id = table.Column<Guid>(type: "char(36)", nullable: false, collation: "ascii_general_ci"),
                    logo_path = table.Column<string>(type: "longtext", nullable: true)
                        .Annotation("MySql:CharSet", "utf8mb4"),
                    primary_color = table.Column<string>(type: "varchar(15)", maxLength: 15, nullable: true)
                        .Annotation("MySql:CharSet", "utf8mb4")
                },
                constraints: table =>
                {
                    table.PrimaryKey("pk_tenant_configs", x => x.id);
                    table.ForeignKey(
                        name: "fk_tenant_configs_tenants_tenant_id",
                        column: x => x.tenant_id,
                        principalTable: "tenants",
                        principalColumn: "id",
                        onDelete: ReferentialAction.Cascade);
                })
                .Annotation("MySql:CharSet", "utf8mb4");

            migrationBuilder.CreateTable(
                name: "user_claims",
                columns: table => new
                {
                    id = table.Column<int>(type: "int", nullable: false)
                        .Annotation("MySql:ValueGenerationStrategy", MySqlValueGenerationStrategy.IdentityColumn),
                    user_id = table.Column<Guid>(type: "char(36)", nullable: false, collation: "ascii_general_ci"),
                    claim_type = table.Column<string>(type: "longtext", nullable: true)
                        .Annotation("MySql:CharSet", "utf8mb4"),
                    claim_value = table.Column<string>(type: "longtext", nullable: true)
                        .Annotation("MySql:CharSet", "utf8mb4")
                },
                constraints: table =>
                {
                    table.PrimaryKey("pk_user_claims", x => x.id);
                    table.ForeignKey(
                        name: "fk_user_claims_users_user_id",
                        column: x => x.user_id,
                        principalTable: "users",
                        principalColumn: "id",
                        onDelete: ReferentialAction.Cascade);
                })
                .Annotation("MySql:CharSet", "utf8mb4");

            migrationBuilder.CreateTable(
                name: "user_logins",
                columns: table => new
                {
                    login_provider = table.Column<string>(type: "varchar(255)", nullable: false)
                        .Annotation("MySql:CharSet", "utf8mb4"),
                    provider_key = table.Column<string>(type: "varchar(255)", nullable: false)
                        .Annotation("MySql:CharSet", "utf8mb4"),
                    provider_display_name = table.Column<string>(type: "longtext", nullable: true)
                        .Annotation("MySql:CharSet", "utf8mb4"),
                    user_id = table.Column<Guid>(type: "char(36)", nullable: false, collation: "ascii_general_ci")
                },
                constraints: table =>
                {
                    table.PrimaryKey("pk_user_logins", x => new { x.login_provider, x.provider_key });
                    table.ForeignKey(
                        name: "fk_user_logins_users_user_id",
                        column: x => x.user_id,
                        principalTable: "users",
                        principalColumn: "id",
                        onDelete: ReferentialAction.Cascade);
                })
                .Annotation("MySql:CharSet", "utf8mb4");

            migrationBuilder.CreateTable(
                name: "user_tokens",
                columns: table => new
                {
                    user_id = table.Column<Guid>(type: "char(36)", nullable: false, collation: "ascii_general_ci"),
                    login_provider = table.Column<string>(type: "varchar(255)", nullable: false)
                        .Annotation("MySql:CharSet", "utf8mb4"),
                    name = table.Column<string>(type: "varchar(255)", nullable: false)
                        .Annotation("MySql:CharSet", "utf8mb4"),
                    value = table.Column<string>(type: "longtext", nullable: true)
                        .Annotation("MySql:CharSet", "utf8mb4")
                },
                constraints: table =>
                {
                    table.PrimaryKey("pk_user_tokens", x => new { x.user_id, x.login_provider, x.name });
                    table.ForeignKey(
                        name: "fk_user_tokens_users_user_id",
                        column: x => x.user_id,
                        principalTable: "users",
                        principalColumn: "id",
                        onDelete: ReferentialAction.Cascade);
                })
                .Annotation("MySql:CharSet", "utf8mb4");

            migrationBuilder.CreateTable(
                name: "user_refresh_tokens",
                columns: table => new
                {
                    id = table.Column<Guid>(type: "char(36)", nullable: false, collation: "ascii_general_ci"),
                    token = table.Column<string>(type: "longtext", nullable: false)
                        .Annotation("MySql:CharSet", "utf8mb4"),
                    user_id = table.Column<Guid>(type: "char(36)", nullable: false, collation: "ascii_general_ci"),
                    expires = table.Column<DateTime>(type: "datetime(6)", nullable: false),
                    is_revoked = table.Column<bool>(type: "tinyint(1)", nullable: false),
                    tenant_id = table.Column<Guid>(type: "char(36)", nullable: true, collation: "ascii_general_ci"),
                    site_id = table.Column<Guid>(type: "char(36)", nullable: true, collation: "ascii_general_ci"),
                    create_date = table.Column<DateTime>(type: "datetime(6)", nullable: false),
                    create_by = table.Column<string>(type: "varchar(100)", maxLength: 100, nullable: true)
                        .Annotation("MySql:CharSet", "utf8mb4"),
                    last_mod_date = table.Column<DateTime>(type: "datetime(6)", nullable: true),
                    last_mod_by = table.Column<string>(type: "varchar(100)", maxLength: 100, nullable: true)
                        .Annotation("MySql:CharSet", "utf8mb4"),
                    modify_source = table.Column<string>(type: "varchar(25)", maxLength: 25, nullable: true)
                        .Annotation("MySql:CharSet", "utf8mb4")
                },
                constraints: table =>
                {
                    table.PrimaryKey("pk_user_refresh_tokens", x => x.id);
                    table.ForeignKey(
                        name: "fk_user_refresh_tokens_sites_site_id",
                        column: x => x.site_id,
                        principalTable: "sites",
                        principalColumn: "id");
                    table.ForeignKey(
                        name: "fk_user_refresh_tokens_tenants_tenant_id",
                        column: x => x.tenant_id,
                        principalTable: "tenants",
                        principalColumn: "id");
                    table.ForeignKey(
                        name: "fk_user_refresh_tokens_users_user_id",
                        column: x => x.user_id,
                        principalTable: "users",
                        principalColumn: "id",
                        onDelete: ReferentialAction.Cascade);
                })
                .Annotation("MySql:CharSet", "utf8mb4");

            migrationBuilder.CreateTable(
                name: "user_roles",
                columns: table => new
                {
                    id = table.Column<Guid>(type: "char(36)", nullable: false, collation: "ascii_general_ci"),
                    user_id = table.Column<Guid>(type: "char(36)", nullable: false, collation: "ascii_general_ci"),
                    role_id = table.Column<Guid>(type: "char(36)", nullable: false, collation: "ascii_general_ci"),
                    tenant_id = table.Column<Guid>(type: "char(36)", nullable: true, collation: "ascii_general_ci"),
                    site_id = table.Column<Guid>(type: "char(36)", nullable: true, collation: "ascii_general_ci"),
                    scope = table.Column<int>(type: "int", nullable: false),
                    create_date = table.Column<DateTime>(type: "datetime(6)", nullable: false),
                    create_by = table.Column<string>(type: "varchar(100)", maxLength: 100, nullable: true)
                        .Annotation("MySql:CharSet", "utf8mb4"),
                    last_mod_date = table.Column<DateTime>(type: "datetime(6)", nullable: true),
                    last_mod_by = table.Column<string>(type: "varchar(100)", maxLength: 100, nullable: true)
                        .Annotation("MySql:CharSet", "utf8mb4"),
                    modify_source = table.Column<string>(type: "varchar(25)", maxLength: 25, nullable: true)
                        .Annotation("MySql:CharSet", "utf8mb4")
                },
                constraints: table =>
                {
                    table.PrimaryKey("pk_user_roles", x => x.id);
                    table.ForeignKey(
                        name: "fk_user_roles_roles_role_id",
                        column: x => x.role_id,
                        principalTable: "roles",
                        principalColumn: "id",
                        onDelete: ReferentialAction.Cascade);
                    table.ForeignKey(
                        name: "fk_user_roles_sites_site_id",
                        column: x => x.site_id,
                        principalTable: "sites",
                        principalColumn: "id");
                    table.ForeignKey(
                        name: "fk_user_roles_tenants_tenant_id",
                        column: x => x.tenant_id,
                        principalTable: "tenants",
                        principalColumn: "id");
                    table.ForeignKey(
                        name: "fk_user_roles_users_user_id",
                        column: x => x.user_id,
                        principalTable: "users",
                        principalColumn: "id",
                        onDelete: ReferentialAction.Cascade);
                })
                .Annotation("MySql:CharSet", "utf8mb4");

            migrationBuilder.InsertData(
                table: "permissions",
                columns: new[] { "code", "create_date", "create_by", "description", "last_mod_by", "last_mod_date", "modify_source", "role_scope" },
                values: new object[,]
                {
                    { "admins.lookup.users", new DateTime(2024, 11, 21, 0, 0, 0, 0, DateTimeKind.Utc), null, "Admins Lookup Users", null, null, null, 1 },
                    { "default:all", new DateTime(2024, 11, 21, 0, 0, 0, 0, DateTimeKind.Utc), null, "Default Basic Access Permission", null, null, null, 8 },
                    { "site.manage.config", new DateTime(2024, 11, 21, 0, 0, 0, 0, DateTimeKind.Utc), null, "Site Manage Config", null, null, null, 4 },
                    { "site.manage.users", new DateTime(2024, 11, 21, 0, 0, 0, 0, DateTimeKind.Utc), null, "Site Manage Users", null, null, null, 4 },
                    { "systemadmin.manage.permissions", new DateTime(2024, 11, 21, 0, 0, 0, 0, DateTimeKind.Utc), null, "SysAdmin Manage Permissions", null, null, null, 1 },
                    { "systemadmin.manage.sites", new DateTime(2024, 11, 21, 0, 0, 0, 0, DateTimeKind.Utc), null, "SysAdmin Manage Sites", null, null, null, 1 },
                    { "systemadmin.manage.tenants", new DateTime(2024, 11, 21, 0, 0, 0, 0, DateTimeKind.Utc), null, "SysAdmin Manage Tenants", null, null, null, 1 },
                    { "systemadmin.manage.users", new DateTime(2024, 11, 21, 0, 0, 0, 0, DateTimeKind.Utc), null, "SysAdmin Manage Users", null, null, null, 1 },
                    { "tenant.access.all.sites", new DateTime(2024, 11, 21, 0, 0, 0, 0, DateTimeKind.Utc), null, "Tenant Access All Sites", null, null, null, 2 },
                    { "tenant.admin.manage.users", new DateTime(2024, 11, 21, 0, 0, 0, 0, DateTimeKind.Utc), null, "Tenant Manage Users", null, null, null, 2 },
                    { "tenant.manage.config", new DateTime(2024, 11, 21, 0, 0, 0, 0, DateTimeKind.Utc), null, "Tenant Manage Config", null, null, null, 2 }
                });

            migrationBuilder.InsertData(
                table: "roles",
                columns: new[] { "id", "create_date", "create_by", "description", "last_mod_by", "last_mod_date", "modify_source", "name", "scope", "site_id", "tenant_id" },
                values: new object[,]
                {
                    { new Guid("08dd1343-9ab2-4439-8295-da20d3e49321"), new DateTime(2024, 11, 21, 0, 0, 0, 0, DateTimeKind.Utc), null, null, null, null, null, "SuperAdmin", 1, null, null },
                    { new Guid("87ad21c9-d406-4f00-90dd-d8d9ee99805b"), new DateTime(2024, 11, 21, 0, 0, 0, 0, DateTimeKind.Utc), null, null, null, null, null, "TenantAdmin", 2, null, null },
                    { new Guid("cc84f8ff-2699-4c69-b9a4-172076528322"), new DateTime(2024, 11, 21, 0, 0, 0, 0, DateTimeKind.Utc), null, null, null, null, null, "SiteAdmin", 4, null, null },
                    { new Guid("f47ac10b-58cc-4372-a567-0e02b2c3d479"), new DateTime(2024, 11, 21, 0, 0, 0, 0, DateTimeKind.Utc), null, null, null, null, null, "DefaultUser", 8, null, null }
                });

            migrationBuilder.InsertData(
                table: "tenants",
                columns: new[] { "id", "code", "create_date", "create_by", "last_mod_by", "last_mod_date", "modify_source", "name", "sub_domain" },
                values: new object[] { new Guid("baab4de5-fe68-4940-996e-5914f8234863"), "Default", new DateTime(2024, 11, 21, 0, 0, 0, 0, DateTimeKind.Utc), null, null, null, null, "Test Tenant", "default" });

            migrationBuilder.InsertData(
                table: "role_permissions",
                columns: new[] { "id", "create_date", "create_by", "last_mod_by", "last_mod_date", "modify_source", "permission_code", "role_id" },
                values: new object[,]
                {
                    { new Guid("1237a8e7-96cc-47d4-a2f3-9d66fe3e3f6d"), new DateTime(2024, 11, 21, 0, 0, 0, 0, DateTimeKind.Utc), null, null, null, null, "tenant.manage.config", new Guid("87ad21c9-d406-4f00-90dd-d8d9ee99805b") },
                    { new Guid("311a22a5-1100-4917-83e6-6bf7994493dd"), new DateTime(2024, 11, 21, 0, 0, 0, 0, DateTimeKind.Utc), null, null, null, null, "systemadmin.manage.tenants", new Guid("08dd1343-9ab2-4439-8295-da20d3e49321") },
                    { new Guid("70a47010-46a0-4a87-9f0e-b0326316e580"), new DateTime(2024, 11, 21, 0, 0, 0, 0, DateTimeKind.Utc), null, null, null, null, "tenant.admin.manage.users", new Guid("87ad21c9-d406-4f00-90dd-d8d9ee99805b") },
                    { new Guid("7ee43803-5d35-425f-8392-f4de1df37e05"), new DateTime(2024, 11, 21, 0, 0, 0, 0, DateTimeKind.Utc), null, null, null, null, "systemadmin.manage.users", new Guid("08dd1343-9ab2-4439-8295-da20d3e49321") },
                    { new Guid("936456cc-8ce2-4bd5-9ba4-1b79d271fe01"), new DateTime(2024, 11, 21, 0, 0, 0, 0, DateTimeKind.Utc), null, null, null, null, "site.manage.config", new Guid("cc84f8ff-2699-4c69-b9a4-172076528322") },
                    { new Guid("a0b1c2d3-e4f5-6789-abcd-ef0123456789"), new DateTime(2024, 11, 21, 0, 0, 0, 0, DateTimeKind.Utc), null, null, null, null, "tenant.access.all.sites", new Guid("08dd1343-9ab2-4439-8295-da20d3e49321") },
                    { new Guid("a1b2c3d4-e5f6-7890-abcd-ef1234567890"), new DateTime(2024, 11, 21, 0, 0, 0, 0, DateTimeKind.Utc), null, null, null, null, "default:all", new Guid("f47ac10b-58cc-4372-a567-0e02b2c3d479") },
                    { new Guid("a4b5c6d7-e8f9-0123-4567-89abcdef0123"), new DateTime(2024, 11, 21, 0, 0, 0, 0, DateTimeKind.Utc), null, null, null, null, "tenant.admin.manage.users", new Guid("08dd1343-9ab2-4439-8295-da20d3e49321") },
                    { new Guid("b5c6d7e8-f9a0-1234-5678-9abcdef01234"), new DateTime(2024, 11, 21, 0, 0, 0, 0, DateTimeKind.Utc), null, null, null, null, "tenant.manage.config", new Guid("08dd1343-9ab2-4439-8295-da20d3e49321") },
                    { new Guid("c08a610d-f07d-436e-839e-31f5b6ffc87d"), new DateTime(2024, 11, 21, 0, 0, 0, 0, DateTimeKind.Utc), null, null, null, null, "systemadmin.manage.permissions", new Guid("08dd1343-9ab2-4439-8295-da20d3e49321") },
                    { new Guid("c6d7e8f9-a0b1-2345-6789-abcdef012345"), new DateTime(2024, 11, 21, 0, 0, 0, 0, DateTimeKind.Utc), null, null, null, null, "site.manage.config", new Guid("08dd1343-9ab2-4439-8295-da20d3e49321") },
                    { new Guid("d22bec2f-9a68-4ecf-aa81-c550f57acaa9"), new DateTime(2024, 11, 21, 0, 0, 0, 0, DateTimeKind.Utc), null, null, null, null, "site.manage.users", new Guid("cc84f8ff-2699-4c69-b9a4-172076528322") },
                    { new Guid("d7e8f9a0-b1c2-3456-789a-bcdef0123456"), new DateTime(2024, 11, 21, 0, 0, 0, 0, DateTimeKind.Utc), null, null, null, null, "site.manage.users", new Guid("08dd1343-9ab2-4439-8295-da20d3e49321") },
                    { new Guid("e8f9a0b1-c2d3-4567-89ab-cdef01234567"), new DateTime(2024, 11, 21, 0, 0, 0, 0, DateTimeKind.Utc), null, null, null, null, "systemadmin.manage.sites", new Guid("08dd1343-9ab2-4439-8295-da20d3e49321") },
                    { new Guid("f9a0b1c2-d3e4-5678-9abc-def012345678"), new DateTime(2024, 11, 21, 0, 0, 0, 0, DateTimeKind.Utc), null, null, null, null, "admins.lookup.users", new Guid("08dd1343-9ab2-4439-8295-da20d3e49321") }
                });

            migrationBuilder.InsertData(
                table: "tenant_configs",
                columns: new[] { "id", "logo_path", "primary_color", "tenant_id" },
                values: new object[] { new Guid("f1e2d3c4-b5a6-9870-cdef-123456789abc"), null, "#007bff", new Guid("baab4de5-fe68-4940-996e-5914f8234863") });

            migrationBuilder.CreateIndex(
                name: "ix_role_permissions_permission_code",
                table: "role_permissions",
                column: "permission_code");

            migrationBuilder.CreateIndex(
                name: "ix_role_permissions_role_id",
                table: "role_permissions",
                column: "role_id");

            migrationBuilder.CreateIndex(
                name: "ix_roles_scope",
                table: "roles",
                column: "scope");

            migrationBuilder.CreateIndex(
                name: "ix_roles_site_id",
                table: "roles",
                column: "site_id");

            migrationBuilder.CreateIndex(
                name: "ix_roles_tenant_id",
                table: "roles",
                column: "tenant_id");

            migrationBuilder.CreateIndex(
                name: "ix_roles_tenant_id_scope",
                table: "roles",
                columns: new[] { "tenant_id", "scope" });

            migrationBuilder.CreateIndex(
                name: "ix_sites_code_tenant_id",
                table: "sites",
                columns: new[] { "code", "tenant_id" },
                unique: true);

            migrationBuilder.CreateIndex(
                name: "ix_sites_name_tenant_id",
                table: "sites",
                columns: new[] { "name", "tenant_id" },
                unique: true);

            migrationBuilder.CreateIndex(
                name: "ix_sites_tenant_id",
                table: "sites",
                column: "tenant_id");

            migrationBuilder.CreateIndex(
                name: "ix_tenant_configs_tenant_id",
                table: "tenant_configs",
                column: "tenant_id",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "ix_tenants_code",
                table: "tenants",
                column: "code",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "ix_tenants_name",
                table: "tenants",
                column: "name",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "ix_tenants_sub_domain",
                table: "tenants",
                column: "sub_domain",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "ix_user_claims_user_id",
                table: "user_claims",
                column: "user_id");

            migrationBuilder.CreateIndex(
                name: "ix_user_invitations_email",
                table: "user_invitations",
                column: "email");

            migrationBuilder.CreateIndex(
                name: "ix_user_invitations_invitation_token",
                table: "user_invitations",
                column: "invitation_token",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "ix_user_logins_user_id",
                table: "user_logins",
                column: "user_id");

            migrationBuilder.CreateIndex(
                name: "ix_user_refresh_tokens_site_id",
                table: "user_refresh_tokens",
                column: "site_id");

            migrationBuilder.CreateIndex(
                name: "ix_user_refresh_tokens_tenant_id",
                table: "user_refresh_tokens",
                column: "tenant_id");

            migrationBuilder.CreateIndex(
                name: "ix_user_refresh_tokens_user_id",
                table: "user_refresh_tokens",
                column: "user_id");

            migrationBuilder.CreateIndex(
                name: "ix_user_roles_role_id",
                table: "user_roles",
                column: "role_id");

            migrationBuilder.CreateIndex(
                name: "ix_user_roles_site_id",
                table: "user_roles",
                column: "site_id");

            migrationBuilder.CreateIndex(
                name: "ix_user_roles_tenant_id",
                table: "user_roles",
                column: "tenant_id");

            migrationBuilder.CreateIndex(
                name: "ix_user_roles_user_id",
                table: "user_roles",
                column: "user_id");

            migrationBuilder.CreateIndex(
                name: "EmailIndex",
                table: "users",
                column: "normalized_email");

            migrationBuilder.CreateIndex(
                name: "UserNameIndex",
                table: "users",
                column: "normalized_user_name",
                unique: true);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "role_permissions");

            migrationBuilder.DropTable(
                name: "tenant_configs");

            migrationBuilder.DropTable(
                name: "user_claims");

            migrationBuilder.DropTable(
                name: "user_invitations");

            migrationBuilder.DropTable(
                name: "user_logins");

            migrationBuilder.DropTable(
                name: "user_refresh_tokens");

            migrationBuilder.DropTable(
                name: "user_roles");

            migrationBuilder.DropTable(
                name: "user_tokens");

            migrationBuilder.DropTable(
                name: "permissions");

            migrationBuilder.DropTable(
                name: "roles");

            migrationBuilder.DropTable(
                name: "sites");

            migrationBuilder.DropTable(
                name: "users");

            migrationBuilder.DropTable(
                name: "tenants");
        }
    }
}
