using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

#pragma warning disable CA1814 // Prefer jagged arrays over multidimensional

namespace PlatformApi.Migrations
{
    /// <inheritdoc />
    public partial class SeedTenantAndSiteData : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.InsertData(
                table: "permissions",
                columns: new[] { "code", "create_date", "create_by", "description", "last_mod_by", "last_mod_date", "modify_source", "role_scope" },
                values: new object[,]
                {
                    { "site.manage.config", new DateTime(2024, 11, 21, 0, 0, 0, 0, DateTimeKind.Utc), null, "Site Manage Config", null, null, null, 4 },
                    { "site.manage.users", new DateTime(2024, 11, 21, 0, 0, 0, 0, DateTimeKind.Utc), null, "Site Manage Users", null, null, null, 4 },
                    { "tenant.admin.manage.users", new DateTime(2024, 11, 21, 0, 0, 0, 0, DateTimeKind.Utc), null, "Tenant Manage Users", null, null, null, 2 },
                    { "tenant.manage.config", new DateTime(2024, 11, 21, 0, 0, 0, 0, DateTimeKind.Utc), null, "Tenant Manage Config", null, null, null, 2 }
                });

            migrationBuilder.InsertData(
                table: "roles",
                columns: new[] { "id", "create_date", "create_by", "description", "last_mod_by", "last_mod_date", "modify_source", "name", "scope", "site_id", "tenant_id" },
                values: new object[,]
                {
                    { new Guid("87ad21c9-d406-4f00-90dd-d8d9ee99805b"), new DateTime(2024, 11, 21, 0, 0, 0, 0, DateTimeKind.Utc), null, null, null, null, null, "TenantAdmin", 2, null, null },
                    { new Guid("cc84f8ff-2699-4c69-b9a4-172076528322"), new DateTime(2024, 11, 21, 0, 0, 0, 0, DateTimeKind.Utc), null, null, null, null, null, "SiteAdmin", 4, null, null }
                });

            migrationBuilder.InsertData(
                table: "role_permissions",
                columns: new[] { "id", "create_date", "create_by", "last_mod_by", "last_mod_date", "modify_source", "permission_code", "role_id" },
                values: new object[,]
                {
                    { new Guid("1237a8e7-96cc-47d4-a2f3-9d66fe3e3f6d"), new DateTime(2024, 11, 21, 0, 0, 0, 0, DateTimeKind.Utc), null, null, null, null, "tenant.admin.manage.users", new Guid("87ad21c9-d406-4f00-90dd-d8d9ee99805b") },
                    { new Guid("70a47010-46a0-4a87-9f0e-b0326316e580"), new DateTime(2024, 11, 21, 0, 0, 0, 0, DateTimeKind.Utc), null, null, null, null, "tenant.admin.manage.users", new Guid("87ad21c9-d406-4f00-90dd-d8d9ee99805b") },
                    { new Guid("936456cc-8ce2-4bd5-9ba4-1b79d271fe01"), new DateTime(2024, 11, 21, 0, 0, 0, 0, DateTimeKind.Utc), null, null, null, null, "site.manage.config", new Guid("cc84f8ff-2699-4c69-b9a4-172076528322") },
                    { new Guid("d22bec2f-9a68-4ecf-aa81-c550f57acaa9"), new DateTime(2024, 11, 21, 0, 0, 0, 0, DateTimeKind.Utc), null, null, null, null, "site.manage.users", new Guid("cc84f8ff-2699-4c69-b9a4-172076528322") }
                });
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DeleteData(
                table: "permissions",
                keyColumn: "code",
                keyValue: "tenant.manage.config");

            migrationBuilder.DeleteData(
                table: "role_permissions",
                keyColumn: "id",
                keyValue: new Guid("1237a8e7-96cc-47d4-a2f3-9d66fe3e3f6d"));

            migrationBuilder.DeleteData(
                table: "role_permissions",
                keyColumn: "id",
                keyValue: new Guid("70a47010-46a0-4a87-9f0e-b0326316e580"));

            migrationBuilder.DeleteData(
                table: "role_permissions",
                keyColumn: "id",
                keyValue: new Guid("936456cc-8ce2-4bd5-9ba4-1b79d271fe01"));

            migrationBuilder.DeleteData(
                table: "role_permissions",
                keyColumn: "id",
                keyValue: new Guid("d22bec2f-9a68-4ecf-aa81-c550f57acaa9"));

            migrationBuilder.DeleteData(
                table: "permissions",
                keyColumn: "code",
                keyValue: "site.manage.config");

            migrationBuilder.DeleteData(
                table: "permissions",
                keyColumn: "code",
                keyValue: "site.manage.users");

            migrationBuilder.DeleteData(
                table: "permissions",
                keyColumn: "code",
                keyValue: "tenant.admin.manage.users");

            migrationBuilder.DeleteData(
                table: "roles",
                keyColumn: "id",
                keyValue: new Guid("87ad21c9-d406-4f00-90dd-d8d9ee99805b"));

            migrationBuilder.DeleteData(
                table: "roles",
                keyColumn: "id",
                keyValue: new Guid("cc84f8ff-2699-4c69-b9a4-172076528322"));
        }
    }
}
