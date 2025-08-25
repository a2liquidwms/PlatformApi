using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace PlatformApi.Migrations
{
    /// <inheritdoc />
    public partial class RemoveUserTenantsSitesTables : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "user_site");

            migrationBuilder.DropTable(
                name: "user_tenants");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "user_site",
                columns: table => new
                {
                    user_id = table.Column<Guid>(type: "uuid", nullable: false),
                    site_id = table.Column<Guid>(type: "uuid", nullable: false),
                    tenant_id = table.Column<Guid>(type: "uuid", nullable: false),
                    create_date = table.Column<DateTime>(type: "timestamp with time zone", nullable: false),
                    create_by = table.Column<string>(type: "character varying(100)", maxLength: 100, nullable: true),
                    last_mod_by = table.Column<string>(type: "character varying(100)", maxLength: 100, nullable: true),
                    last_mod_date = table.Column<DateTime>(type: "timestamp with time zone", nullable: true),
                    modify_source = table.Column<string>(type: "character varying(25)", maxLength: 25, nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("pk_user_site", x => new { x.user_id, x.site_id });
                    table.ForeignKey(
                        name: "fk_user_site_sites_site_id",
                        column: x => x.site_id,
                        principalTable: "sites",
                        principalColumn: "id",
                        onDelete: ReferentialAction.Cascade);
                    table.ForeignKey(
                        name: "fk_user_site_tenants_tenant_id",
                        column: x => x.tenant_id,
                        principalTable: "tenants",
                        principalColumn: "id",
                        onDelete: ReferentialAction.Cascade);
                    table.ForeignKey(
                        name: "fk_user_site_users_user_id",
                        column: x => x.user_id,
                        principalTable: "users",
                        principalColumn: "id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateTable(
                name: "user_tenants",
                columns: table => new
                {
                    user_id = table.Column<Guid>(type: "uuid", nullable: false),
                    tenant_id = table.Column<Guid>(type: "uuid", nullable: false),
                    create_date = table.Column<DateTime>(type: "timestamp with time zone", nullable: false),
                    create_by = table.Column<string>(type: "character varying(100)", maxLength: 100, nullable: true),
                    last_mod_by = table.Column<string>(type: "character varying(100)", maxLength: 100, nullable: true),
                    last_mod_date = table.Column<DateTime>(type: "timestamp with time zone", nullable: true),
                    modify_source = table.Column<string>(type: "character varying(25)", maxLength: 25, nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("pk_user_tenants", x => new { x.user_id, x.tenant_id });
                    table.ForeignKey(
                        name: "fk_user_tenants_tenants_tenant_id",
                        column: x => x.tenant_id,
                        principalTable: "tenants",
                        principalColumn: "id",
                        onDelete: ReferentialAction.Cascade);
                    table.ForeignKey(
                        name: "fk_user_tenants_users_user_id",
                        column: x => x.user_id,
                        principalTable: "users",
                        principalColumn: "id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateIndex(
                name: "ix_user_site_site_id",
                table: "user_site",
                column: "site_id");

            migrationBuilder.CreateIndex(
                name: "ix_user_site_tenant_id",
                table: "user_site",
                column: "tenant_id");

            migrationBuilder.CreateIndex(
                name: "ix_user_site_user_id",
                table: "user_site",
                column: "user_id");

            migrationBuilder.CreateIndex(
                name: "ix_user_tenants_tenant_id",
                table: "user_tenants",
                column: "tenant_id");

            migrationBuilder.CreateIndex(
                name: "ix_user_tenants_user_id",
                table: "user_tenants",
                column: "user_id");
        }
    }
}
