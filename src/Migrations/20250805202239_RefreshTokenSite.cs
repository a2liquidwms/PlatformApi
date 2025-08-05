using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace PlatformApi.Migrations
{
    /// <inheritdoc />
    public partial class RefreshTokenSite : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<Guid>(
                name: "site_id",
                table: "user_refresh_tokens",
                type: "uuid",
                nullable: true);

            migrationBuilder.CreateIndex(
                name: "ix_user_refresh_tokens_site_id",
                table: "user_refresh_tokens",
                column: "site_id");

            migrationBuilder.AddForeignKey(
                name: "fk_user_refresh_tokens_sites_site_id",
                table: "user_refresh_tokens",
                column: "site_id",
                principalTable: "sites",
                principalColumn: "id");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropForeignKey(
                name: "fk_user_refresh_tokens_sites_site_id",
                table: "user_refresh_tokens");

            migrationBuilder.DropIndex(
                name: "ix_user_refresh_tokens_site_id",
                table: "user_refresh_tokens");

            migrationBuilder.DropColumn(
                name: "site_id",
                table: "user_refresh_tokens");
        }
    }
}
