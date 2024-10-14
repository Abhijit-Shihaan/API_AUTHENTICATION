using Azure.Storage.Blobs;
using core_user_ms;
using Microsoft.Azure.Cosmos;
using System.Reflection;
using Serilog;
using Serilog.Sinks.SystemConsole.Themes;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;
using Microsoft.OpenApi.Models;

var builder = WebApplication.CreateBuilder(args);

Log.Logger = new LoggerConfiguration().WriteTo.Console(theme: SystemConsoleTheme.Literate,
    outputTemplate: "[{Timestamp:yyyy-MM-ddTHH:mm:ssZ} {Level:ERR} {Message:}] \n").MinimumLevel.Debug().CreateLogger();

builder.Services.AddControllers();
// Configure JWT authentication using Keycloak
builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(options =>
    {
        options.Authority = "https://idp.shihaantech.net/realms/medium-dev"; // Keycloak realm URL
        options.Audience = "shihaantech"; // Your client_id from Keycloak
        options.RequireHttpsMetadata = true; // Enable if your Keycloak server uses HTTPS
        options.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuer = true,
            ValidateAudience = true,
            ValidateLifetime = true,
            ValidateIssuerSigningKey = true,
            ValidAudience = "shihaantech", // Ensure this matches the 'aud' claim in your token
            ValidIssuer = "https://idp.shihaantech.net/realms/medium-dev"
        };
    });
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();
builder.Services.AddSwaggerGen(c =>
{
    c.SwaggerDoc("v1", new OpenApiInfo { Title = "Keycloak Auth API", Version = "v1" });

    // Add the "Authorize" button for JWT in Swagger
    c.AddSecurityDefinition("Bearer", new OpenApiSecurityScheme
    {
        Name = "Authorization",
        Type = SecuritySchemeType.Http,
        Scheme = "Bearer",
        BearerFormat = "JWT",
        In = ParameterLocation.Header,
        Description = "Enter 'Bearer' followed by space and your JWT token."
    });
    c.AddSecurityRequirement(new OpenApiSecurityRequirement
    {
        {
            new OpenApiSecurityScheme
            {
                Reference = new OpenApiReference
                {
                    Type = ReferenceType.SecurityScheme,
                    Id = "Bearer"
                }
            },
            new string[] {}
        }
    });
});
var root = Directory.GetCurrentDirectory();
var dotenv = Path.Combine(root, ".env_staging");
DotEnv.Load(dotenv);

var connStr = Environment.GetEnvironmentVariable("COSMOS_DB_CONN_STR");
var dbName = Environment.GetEnvironmentVariable("COSMOS_DB_NAME");
var blobConnStr = Environment.GetEnvironmentVariable("AZURE_BLOB_CONN_STR");
var apiBaseUrl = Environment.GetEnvironmentVariable("API_BASE_URL");
var appName = Environment.GetEnvironmentVariable("APP_NAME");

var blobClient = new BlobServiceClient(blobConnStr);

var cosmosClient = new CosmosClient(connStr);



builder.Services.AddSingleton(cosmosClient);

List<KeyValuePair<string, string>> keys = new List<KeyValuePair<string, string>>();
keys.Add(new KeyValuePair<string, string>("DBName", dbName));
keys.Add(new KeyValuePair<string, string>("API_BASE_URL", apiBaseUrl));
keys.Add(new KeyValuePair<string, string>("APPNAME", appName));
builder.Services.AddSingleton(keys);
builder.Services.AddSingleton<BlobServiceClient>(blobClient);

//builder.Services.AddDbContext<AgencyDBContext>(option => option.UseCosmos(connStr, dbName));

builder.Services.AddCors(options =>
{
    options.AddPolicy("AllowLocalhost", builder =>
    {
        builder.WithOrigins("https://localhost")
               .AllowAnyHeader()
               .AllowAnyMethod();
    });
});

var app = builder.Build();

if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI(c => c.SwaggerEndpoint("/swagger/v1/swagger.json", "Keycloak Auth API v1"));

}

app.UseHttpsRedirection();
app.UseAuthentication();
app.UseAuthorization();
app.UseCors("AllowMultipleOrigins");

app.MapControllers();



app.Run();