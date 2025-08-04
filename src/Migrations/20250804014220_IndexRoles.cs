using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace PlatformApi.Migrations
{
    /// <inheritdoc />
    public partial class IndexRoles : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
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
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropIndex(
                name: "ix_roles_scope",
                table: "roles");

            migrationBuilder.DropIndex(
                name: "ix_roles_site_id",
                table: "roles");

            migrationBuilder.DropIndex(
                name: "ix_roles_tenant_id",
                table: "roles");

            migrationBuilder.DropIndex(
                name: "ix_roles_tenant_id_scope",
                table: "roles");
        }
    }
}
