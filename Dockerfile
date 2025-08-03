# Use the official .NET 8 runtime as base
FROM mcr.microsoft.com/dotnet/aspnet:8.0 AS base
WORKDIR /app
EXPOSE 8080

# Use the official .NET 8 SDK for building
FROM mcr.microsoft.com/dotnet/sdk:8.0 AS build
ARG BUILD_CONFIGURATION=Release
WORKDIR /src

# Copy project file first for better layer caching
COPY ["src/RedClayAuthApi.csproj", "src/"]

# Copy NuGet.config to the root where dotnet restore expects it
COPY ["NuGet.config", "./"]

# Restore dependencies first - this creates a cacheable layer
RUN dotnet restore "src/RedClayAuthApi.csproj" --verbosity minimal

# Copy only the source code directory (not everything)
COPY ["src/", "src/"]

# Build and publish in one step (more efficient)
WORKDIR "/src/src"
RUN dotnet publish "RedClayAuthApi.csproj" \
    -c $BUILD_CONFIGURATION \
    -o /app/publish \
    --no-restore \
    --verbosity minimal \
    /p:UseAppHost=false

# Final runtime stage
FROM base AS final
WORKDIR /app

# Copy published app
COPY --from=build /app/publish .

# Create non-root user for security
RUN adduser --disabled-password --gecos '' --uid 1001 appuser && chown -R appuser /app
USER appuser

# Set environment variables
ENV ASPNETCORE_URLS=http://+:8080
ENV ASPNETCORE_ENVIRONMENT=Production
ENV APP_NAME=RedClayAuth

ENTRYPOINT ["dotnet", "RedClayAuthApi.dll"]