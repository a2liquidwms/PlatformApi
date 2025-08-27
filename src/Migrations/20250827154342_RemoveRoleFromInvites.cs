using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace PlatformApi.Migrations
{
    /// <inheritdoc />
    public partial class RemoveRoleFromInvites : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropColumn(
                name: "invited_roles",
                table: "user_invitations");

            migrationBuilder.AlterColumn<Guid>(
                name: "tenant_id",
                table: "user_invitations",
                type: "uuid",
                nullable: true,
                oldClrType: typeof(Guid),
                oldType: "uuid");

            migrationBuilder.AddColumn<int>(
                name: "scope",
                table: "user_invitations",
                type: "integer",
                nullable: false,
                defaultValue: 0);

            migrationBuilder.AddColumn<Guid>(
                name: "site_id",
                table: "user_invitations",
                type: "uuid",
                nullable: true);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropColumn(
                name: "scope",
                table: "user_invitations");

            migrationBuilder.DropColumn(
                name: "site_id",
                table: "user_invitations");

            migrationBuilder.AlterColumn<Guid>(
                name: "tenant_id",
                table: "user_invitations",
                type: "uuid",
                nullable: false,
                defaultValue: new Guid("00000000-0000-0000-0000-000000000000"),
                oldClrType: typeof(Guid),
                oldType: "uuid",
                oldNullable: true);

            migrationBuilder.AddColumn<string>(
                name: "invited_roles",
                table: "user_invitations",
                type: "json",
                nullable: true);
        }
    }
}
