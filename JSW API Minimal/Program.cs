using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

var builder = WebApplication.CreateBuilder(args);

string key = "JJIBGVGBjn+hnusglki98u3b=nsmk";

builder.Services.AddAuthorization();
builder.Services.AddAuthentication("Bearer").AddJwtBearer(opt =>
{
    var signingKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(key));
    var signingCredentials = new SigningCredentials(signingKey, SecurityAlgorithms.HmacSha256Signature);

    opt.RequireHttpsMetadata = false;

    opt.TokenValidationParameters = new TokenValidationParameters()
    {
        ValidateAudience = false,
        ValidateIssuer = false,
        IssuerSigningKey = signingKey,
    };

});

var app = builder.Build();

app.MapGet("/", () => "Hello World!");
app.MapGet("/protected", (ClaimsPrincipal user) => user.Identity?.Name)
    .RequireAuthorization();
app.MapGet("/protectedwithscope", (ClaimsPrincipal user) => user.Identity?.Name)
    .RequireAuthorization(p => p.RequireClaim("scope", "myapi:drunken"));

app.MapGet("/auth/{user}/{password}", (string user, string password) =>
{
    if(user == "duck" && password == "123456")
    {
        var tokenHandler = new JwtSecurityTokenHandler();
        var byteKey = Encoding.UTF8.GetBytes(key);
        var tokenDes = new SecurityTokenDescriptor
        {
            Subject = new ClaimsIdentity(new Claim[]
            {
                new Claim(ClaimTypes.Name, user),
                new Claim("Scope", "myapi:drunken"),
            }),
            Expires = DateTime.UtcNow.AddHours(1),
            SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(byteKey), SecurityAlgorithms.HmacSha256Signature),
        };

        var token = tokenHandler.CreateToken(tokenDes);

        return tokenHandler.WriteToken(token);
    }
    else
    {
        return "Invalid user";
    }
});

app.Run();
