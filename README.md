# JwtSecurityTokenCustom

[![Build status](https://ci.appveyor.com/api/projects/status/td9aoirx57v268tm?svg=true)](https://ci.appveyor.com/project/mccj/jwtsecuritytokencustom)
[![NuGet](https://buildstats.info/nuget/jwtsecuritytokencustom?includePreReleases=true)](https://www.nuget.org/packages/jwtsecuritytokencustom)
[![MIT License](https://img.shields.io/badge/license-MIT-orange.svg)](https://github.com/mccj/SwaggerNSwagExtensions/blob/master/LICENSE)


## Features

 - JwtSecurityTokenCustom

## Setup

ASP.NET Core Applications
```c#
public class Startup
{
    public void ConfigureServices(IServiceCollection services)
    {
        services.AddControllers();
        services.AddJwtBearer();
    }
}
```
