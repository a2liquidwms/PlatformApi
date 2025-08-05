using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

#pragma warning disable CA1814 // Prefer jagged arrays over multidimensional

namespace PlatformApi.Migrations
{
    /// <inheritdoc />
    public partial class SeedRolesAndPermsDeafult : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DeleteData(
                table: "role_permissions",
                keyColumn: "id",
                keyValue: new Guid("d9b1d7aa-c58e-4a9f-9f8e-b25d7d707e44"));

            migrationBuilder.DropColumn(
                name: "is_active",
                table: "user_roles");

            migrationBuilder.DropColumn(
                name: "is_default_flg",
                table: "permissions");

            migrationBuilder.UpdateData(
                table: "permissions",
                keyColumn: "code",
                keyValue: "default:all",
                columns: new[] { "applicable_scopes", "description" },
                values: new object[] { 8, "Default Basic Access Permission" });

            migrationBuilder.InsertData(
                table: "permissions",
                columns: new[] { "code", "applicable_scopes", "create_date", "create_by", "description", "last_mod_by", "last_mod_date", "modify_source" },
                values: new object[,]
                {
                    { "systemadmin.manage.permissions", 1, new DateTime(2024, 11, 21, 0, 0, 0, 0, DateTimeKind.Utc), null, "SysAdmin Manage Permissions", null, null, null },
                    { "systemadmin.manage.tenants", 1, new DateTime(2024, 11, 21, 0, 0, 0, 0, DateTimeKind.Utc), null, "SysAdmin Manage Tenants", null, null, null },
                    { "systemadmin.manage.users", 1, new DateTime(2024, 11, 21, 0, 0, 0, 0, DateTimeKind.Utc), null, "SysAdmin Manage Users", null, null, null }
                });

            migrationBuilder.InsertData(
                table: "roles",
                columns: new[] { "id", "create_date", "create_by", "description", "last_mod_by", "last_mod_date", "modify_source", "name", "scope", "site_id", "tenant_id" },
                values: new object[] { new Guid("f47ac10b-58cc-4372-a567-0e02b2c3d479"), new DateTime(2024, 11, 21, 0, 0, 0, 0, DateTimeKind.Utc), null, null, null, null, null, "DefaultUser", 8, null, null });

            migrationBuilder.InsertData(
                table: "role_permissions",
                columns: new[] { "id", "create_date", "create_by", "last_mod_by", "last_mod_date", "modify_source", "permission_code", "role_id" },
                values: new object[,]
                {
                    { new Guid("311a22a5-1100-4917-83e6-6bf7994493dd"), new DateTime(2024, 11, 21, 0, 0, 0, 0, DateTimeKind.Utc), null, null, null, null, "systemadmin.manage.tenants", new Guid("08dd1343-9ab2-4439-8295-da20d3e49321") },
                    { new Guid("7ee43803-5d35-425f-8392-f4de1df37e05"), new DateTime(2024, 11, 21, 0, 0, 0, 0, DateTimeKind.Utc), null, null, null, null, "systemadmin.manage.users", new Guid("08dd1343-9ab2-4439-8295-da20d3e49321") },
                    { new Guid("a1b2c3d4-e5f6-7890-abcd-ef1234567890"), new DateTime(2024, 11, 21, 0, 0, 0, 0, DateTimeKind.Utc), null, null, null, null, "default:all", new Guid("f47ac10b-58cc-4372-a567-0e02b2c3d479") },
                    { new Guid("c08a610d-f07d-436e-839e-31f5b6ffc87d"), new DateTime(2024, 11, 21, 0, 0, 0, 0, DateTimeKind.Utc), null, null, null, null, "systemadmin.manage.permissions", new Guid("08dd1343-9ab2-4439-8295-da20d3e49321") }
                });
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DeleteData(
                table: "role_permissions",
                keyColumn: "id",
                keyValue: new Guid("311a22a5-1100-4917-83e6-6bf7994493dd"));

            migrationBuilder.DeleteData(
                table: "role_permissions",
                keyColumn: "id",
                keyValue: new Guid("7ee43803-5d35-425f-8392-f4de1df37e05"));

            migrationBuilder.DeleteData(
                table: "role_permissions",
                keyColumn: "id",
                keyValue: new Guid("a1b2c3d4-e5f6-7890-abcd-ef1234567890"));

            migrationBuilder.DeleteData(
                table: "role_permissions",
                keyColumn: "id",
                keyValue: new Guid("c08a610d-f07d-436e-839e-31f5b6ffc87d"));

            migrationBuilder.DeleteData(
                table: "permissions",
                keyColumn: "code",
                keyValue: "systemadmin.manage.permissions");

            migrationBuilder.DeleteData(
                table: "permissions",
                keyColumn: "code",
                keyValue: "systemadmin.manage.tenants");

            migrationBuilder.DeleteData(
                table: "permissions",
                keyColumn: "code",
                keyValue: "systemadmin.manage.users");

            migrationBuilder.DeleteData(
                table: "roles",
                keyColumn: "id",
                keyValue: new Guid("f47ac10b-58cc-4372-a567-0e02b2c3d479"));

            migrationBuilder.AddColumn<bool>(
                name: "is_active",
                table: "user_roles",
                type: "boolean",
                nullable: false,
                defaultValue: false);

            migrationBuilder.AddColumn<bool>(
                name: "is_default_flg",
                table: "permissions",
                type: "boolean",
                nullable: false,
                defaultValue: false);

            migrationBuilder.UpdateData(
                table: "permissions",
                keyColumn: "code",
                keyValue: "default:all",
                columns: new[] { "applicable_scopes", "description", "is_default_flg" },
                values: new object[] { 7, "Default Permission", true });

            migrationBuilder.InsertData(
                table: "role_permissions",
                columns: new[] { "id", "create_date", "create_by", "last_mod_by", "last_mod_date", "modify_source", "permission_code", "role_id" },
                values: new object[] { new Guid("d9b1d7aa-c58e-4a9f-9f8e-b25d7d707e44"), new DateTime(2024, 11, 21, 0, 0, 0, 0, DateTimeKind.Utc), null, null, null, null, "default:all", new Guid("08dd1343-9ab2-4439-8295-da20d3e49321") });
        }
    }
}
