using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace PlatformApi.Migrations
{
    /// <inheritdoc />
    public partial class SeedTenantConfigRole : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.UpdateData(
                table: "role_permissions",
                keyColumn: "id",
                keyValue: new Guid("1237a8e7-96cc-47d4-a2f3-9d66fe3e3f6d"),
                column: "permission_code",
                value: "tenant.manage.config");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.UpdateData(
                table: "role_permissions",
                keyColumn: "id",
                keyValue: new Guid("1237a8e7-96cc-47d4-a2f3-9d66fe3e3f6d"),
                column: "permission_code",
                value: "tenant.admin.manage.users");
        }
    }
}
