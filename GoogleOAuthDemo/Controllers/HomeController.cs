using Google.Apis.Auth.OAuth2;
using Google.Apis.Gmail.v1;
using GoogleOAuthDemo.Models;
using Microsoft.AspNetCore.Http.Extensions;
using Microsoft.AspNetCore.Mvc;
using System.Diagnostics;

namespace GoogleOAuthDemo.Controllers
{
    public class HomeController : Controller
    {
        private readonly ILogger<HomeController> _logger;
        private readonly IConfiguration configuration;
        private readonly ClientSecrets client_secret;

        public HomeController(ILogger<HomeController> logger, IConfiguration configuration, ClientSecrets client_secret)
        {
            _logger = logger;
            this.configuration = configuration;
            this.client_secret = client_secret;
        }

        public IActionResult Index()
        {
            return View();
        }

        public IActionResult Privacy()
        {
            return View();
        }

        public IActionResult AuthRequest()
        {
            var redirect_uri = configuration.GetValue<string>("OAuth:RedirectUrl");

            // 需安裝 Microsoft.AspNetCore.Http.Extensions 套件
            var qb = new QueryBuilder();
            qb.Add("response_type", "code");
            qb.Add("scope", GmailService.Scope.GmailSend);
            qb.Add("client_id", client_secret.ClientId);
            qb.Add("access_type", "offline");
            qb.Add("prompt", "consent");
            qb.Add("redirect_uri", redirect_uri);
            qb.Add("state", Guid.NewGuid().ToString());

            UriBuilder ub = new UriBuilder("https://accounts.google.com/o/oauth2/v2/auth");
            ub.Query = qb.ToQueryString().Value;

            return Redirect(ub.ToString());
        }

        public async Task<IActionResult> RedirectUri(string code, string state, string scope)
        {
            // TODO: Check the "state" to avoid CSRF attack
            // https://auth0.com/docs/secure/attack-protection/state-parameters

            var redirect_uri = configuration.GetValue<string>("OAuth:RedirectUrl");

            var formDataDictionary = new Dictionary<string, string>()
            {
                {"code", code },
                {"client_id", client_secret.ClientId },
                {"client_secret", client_secret.ClientSecret },
                {"redirect_uri", redirect_uri},
                {"grant_type", "authorization_code" }
            };

            var formData = new FormUrlEncodedContent(formDataDictionary);

            using HttpClient http = new HttpClient();
            var resp = await http.PostAsync("https://www.googleapis.com/oauth2/v4/token", formData);
            var str = await resp.Content.ReadAsStringAsync();

            return Content(str);
        }

        [ResponseCache(Duration = 0, Location = ResponseCacheLocation.None, NoStore = true)]
        public IActionResult Error()
        {
            return View(new ErrorViewModel { RequestId = Activity.Current?.Id ?? HttpContext.TraceIdentifier });
        }
    }
}