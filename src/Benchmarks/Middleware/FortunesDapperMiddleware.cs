// Copyright (c) .NET Foundation. All rights reserved.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

using System;
using System.Text.Encodings.Web;
using System.Threading.Tasks;
using Benchmarks.Configuration;
using Benchmarks.Data;
using Benchmarks.Templates;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;

namespace Benchmarks.Middleware
{
    public class FortunesDapperMiddleware
    {
        private static readonly PathString _path = new PathString(Scenarios.GetPath(s => s.DbFortunesDapper));

        private readonly RequestDelegate _next;
        private readonly HtmlEncoder _htmlEncoder;

        public FortunesDapperMiddleware(RequestDelegate next, HtmlEncoder htmlEncoder)
        {
            _next = next;
            _htmlEncoder = htmlEncoder;
        }

        public async Task Invoke(HttpContext httpContext)
        {
            if (httpContext.Request.Path.StartsWithSegments(_path, StringComparison.Ordinal))
            {
                var db = httpContext.RequestServices.GetService<DapperDb>();
                var rows = await db.LoadFortunesRows();
                

                await MiddlewareHelpers.RenderFortunesHtml(rows, httpContext, _htmlEncoder, FortunesUtf16.Create);

                return;
            }

            await _next(httpContext);
        }
    }

    public static class FortunesDapperMiddlewareExtensions
    {
        public static IApplicationBuilder UseFortunesDapper(this IApplicationBuilder builder)
        {
            return builder.UseMiddleware<FortunesDapperMiddleware>();
        }
    }
}
