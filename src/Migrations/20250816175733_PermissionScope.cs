using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace PlatformApi.Migrations
{
    /// <inheritdoc />
    public partial class PermissionScope : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropColumn(
                name: "applicable_scopes",
                table: "permissions");

            migrationBuilder.AddColumn<int>(
                name: "role_scope",
                table: "permissions",
                type: "integer",
                nullable: true);

            migrationBuilder.UpdateData(
                table: "permissions",
                keyColumn: "code",
                keyValue: "default:all",
                column: "role_scope",
                value: 8);

            migrationBuilder.UpdateData(
                table: "permissions",
                keyColumn: "code",
                keyValue: "systemadmin.manage.permissions",
                column: "role_scope",
                value: 1);

            migrationBuilder.UpdateData(
                table: "permissions",
                keyColumn: "code",
                keyValue: "systemadmin.manage.tenants",
                column: "role_scope",
                value: 1);

            migrationBuilder.UpdateData(
                table: "permissions",
                keyColumn: "code",
                keyValue: "systemadmin.manage.users",
                column: "role_scope",
                value: 1);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropColumn(
                name: "role_scope",
                table: "permissions");

            migrationBuilder.AddColumn<int>(
                name: "applicable_scopes",
                table: "permissions",
                type: "integer",
                nullable: false,
                defaultValue: 0);

            migrationBuilder.UpdateData(
                table: "permissions",
                keyColumn: "code",
                keyValue: "default:all",
                column: "applicable_scopes",
                value: 8);

            migrationBuilder.UpdateData(
                table: "permissions",
                keyColumn: "code",
                keyValue: "systemadmin.manage.permissions",
                column: "applicable_scopes",
                value: 1);

            migrationBuilder.UpdateData(
                table: "permissions",
                keyColumn: "code",
                keyValue: "systemadmin.manage.tenants",
                column: "applicable_scopes",
                value: 1);

            migrationBuilder.UpdateData(
                table: "permissions",
                keyColumn: "code",
                keyValue: "systemadmin.manage.users",
                column: "applicable_scopes",
                value: 1);
        }
    }
}
