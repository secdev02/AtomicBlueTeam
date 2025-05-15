// entra-id-auth.cs
// Basic .NET 4.8 application for Entra ID login
// Compile with: csc /target:exe entra-id-auth.cs /r:System.Web.dll /r:System.Net.Http.dll /r:System.Web.Extensions.dll /r:System.Net.Http.WebRequest.dll

using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Net.Http;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using System.Web;
using System.Web.Script.Serialization;

namespace SimpleEntraIdLogin
{
    public class Program
    {
        // Entra ID settings
        private static readonly string Domain = "UPDATE.onmicrosoft.com";
        private static readonly string TenantId = "UPDATE";
        private static readonly string ClientId = "UPDATE";
        private static readonly string CallbackPath = "/signin-oidc";
        private static readonly string SignedOutCallbackPath = "/signout-callback-oidc";
        
        // Configuration
        // You may need to change the host/port to match what's registered in Azure portal
        // Common redirect URIs might be:
        // - http://localhost:3000/signin-oidc
        // - https://localhost:44321/signin-oidc
        // - http://127.0.0.1:3000/signin-oidc
        // - Your application's actual host URL with the CallbackPath
        
        // Change this to match what's registered in your Azure portal
        private static readonly string BaseUri = "http://localhost:3000";
        private static readonly string RedirectUri = BaseUri + CallbackPath;
        private static readonly string Authority = "https://login.microsoftonline.com/" + TenantId;
        private static readonly string LogoutUri = BaseUri + SignedOutCallbackPath;
        
        // PKCE support
        private static string CodeVerifier;
        private static string CodeChallenge;
        
        public static void Main(string[] args)
        {
            Console.WriteLine("Starting Entra ID login application...");
            Console.WriteLine("Domain: " + Domain);
            Console.WriteLine("ClientId: " + ClientId);
            Console.WriteLine("TenantId: " + TenantId);
            Console.WriteLine("Redirect URI: " + RedirectUri);
            
            // Setup TLS/SSL properly
            ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls12;
            
            // Generate PKCE code verifier and challenge
            GeneratePkceValues();
            
            // Start the HTTP listener
            HttpListener listener = new HttpListener();
            string host = new Uri(BaseUri).Host;
            int port = new Uri(BaseUri).Port;
            Console.WriteLine("Starting listener on " + BaseUri);
            listener.Prefixes.Add(BaseUri + "/");
            
            try 
            {
                listener.Start();
                Console.WriteLine("Listener started successfully");
            }
            catch (HttpListenerException ex)
            {
                Console.WriteLine("Error starting HTTP listener: " + ex.Message);
                Console.WriteLine("This might be due to:");
                Console.WriteLine("1. Another application is already using port " + port);
                Console.WriteLine("2. You need administrator privileges to bind to this port");
                Console.WriteLine("3. The URL prefix format is incorrect");
                
                Console.WriteLine("\nPress any key to exit...");
                Console.ReadKey();
                return;
            }
            
            Console.WriteLine("Listening for requests...");
            Console.WriteLine("Press Enter to start the login process...");
            Console.ReadLine();
            
            // Open the browser to initiate login
            string authorizationUrl = GetAuthorizationUrl();
            Console.WriteLine("Opening browser to URL: " + authorizationUrl);
            
            try
            {
                System.Diagnostics.Process.Start(authorizationUrl);
            }
            catch (Exception ex)
            {
                Console.WriteLine("Error opening browser: " + ex.Message);
                Console.WriteLine("Please manually open this URL in your browser:");
                Console.WriteLine(authorizationUrl);
            }
            
            // Listen for the callback
            while (true)
            {
                try
                {
                    Console.WriteLine("Waiting for incoming request...");
                    HttpListenerContext context = listener.GetContext();
                    HttpListenerRequest request = context.Request;
                    HttpListenerResponse response = context.Response;
                    
                    string path = request.Url.AbsolutePath;
                    Console.WriteLine("Received request: " + path);
                    
                    if (path == CallbackPath)
                    {
                        // Handle the authorization code callback
                        HandleCallback(request, response).Wait();
                    }
                    else if (path == SignedOutCallbackPath)
                    {
                        // Handle sign-out callback
                        HandleSignout(response);
                    }
                    else if (path == "/logout")
                    {
                        // Handle logout request
                        HandleLogoutRequest(response);
                    }
                    else
                    {
                        // Serve the default page
                        ServeDefaultPage(response);
                    }
                }
                catch (Exception ex)
                {
                    Console.WriteLine("Error handling request: " + ex.Message);
                }
            }
        }
        
        private static void GeneratePkceValues()
        {
            // Generate a random code verifier
            using (RandomNumberGenerator rng = RandomNumberGenerator.Create())
            {
                byte[] bytes = new byte[32];
                rng.GetBytes(bytes);
                CodeVerifier = Convert.ToBase64String(bytes)
                    .Replace("+", "-")
                    .Replace("/", "_")
                    .Replace("=", "");
            }
            
            // Generate the code challenge
            using (SHA256 sha256 = SHA256.Create())
            {
                byte[] challengeBytes = sha256.ComputeHash(Encoding.UTF8.GetBytes(CodeVerifier));
                CodeChallenge = Convert.ToBase64String(challengeBytes)
                    .Replace("+", "-")
                    .Replace("/", "_")
                    .Replace("=", "");
            }
        }
        
        private static string GetAuthorizationUrl()
        {
            // Construct the authorization URL
            Dictionary<string, string> queryParams = new Dictionary<string, string>
            {
                { "client_id", ClientId },
                { "response_type", "code" },
                { "redirect_uri", RedirectUri },
                { "response_mode", "query" },
                { "scope", "openid profile email" },
                { "state", Guid.NewGuid().ToString() },
                { "code_challenge", CodeChallenge },
                { "code_challenge_method", "S256" }
            };
            
            // Create query string
            StringBuilder queryString = new StringBuilder("?");
            foreach (var param in queryParams)
            {
                queryString.Append(param.Key + "=" + HttpUtility.UrlEncode(param.Value) + "&");
            }
            
            string authUrl = Authority + "/oauth2/v2.0/authorize" + queryString.ToString().TrimEnd('&');
            return authUrl;
        }
        
        private static async Task HandleCallback(HttpListenerRequest request, HttpListenerResponse response)
        {
            try
            {
                // Extract the authorization code from the query parameters
                string code = request.QueryString["code"];
                string error = request.QueryString["error"];
                string errorDescription = request.QueryString["error_description"];
                
                if (!string.IsNullOrEmpty(error))
                {
                    WriteHtmlResponse(response, "Authentication Error: " + error + "<br>Description: " + errorDescription);
                    return;
                }
                
                if (string.IsNullOrEmpty(code))
                {
                    WriteHtmlResponse(response, "Error: No authorization code received");
                    return;
                }
                
                Console.WriteLine("Received authorization code. Exchanging for token...");
                
                // Exchange the authorization code for an access token
                string tokenEndpoint = Authority + "/oauth2/v2.0/token";
                Console.WriteLine("Token endpoint: " + tokenEndpoint);
                
                var tokenRequestParams = new Dictionary<string, string>
                {
                    { "client_id", ClientId },
                    { "code", code },
                    { "redirect_uri", RedirectUri },
                    { "grant_type", "authorization_code" },
                    { "code_verifier", CodeVerifier }
                };
                
                Console.WriteLine("Sending token request with parameters:");
                foreach (var param in tokenRequestParams)
                {
                    // Don't log the actual code or code_verifier values for security
                    if (param.Key == "code" || param.Key == "code_verifier")
                    {
                        Console.WriteLine("  " + param.Key + ": [hidden]");
                    }
                    else
                    {
                        Console.WriteLine("  " + param.Key + ": " + param.Value);
                    }
                }
                
                try
                {
                    using (HttpClient client = new HttpClient())
                    {
                        // Set timeout to 30 seconds
                        client.Timeout = TimeSpan.FromSeconds(30);
                        
                        // Add common headers
                        client.DefaultRequestHeaders.Accept.Add(new System.Net.Http.Headers.MediaTypeWithQualityHeaderValue("application/json"));
                        
                        // Create the form content
                        var content = new FormUrlEncodedContent(tokenRequestParams);
                        
                        Console.WriteLine("Sending POST request to token endpoint...");
                        HttpResponseMessage tokenResponse = await client.PostAsync(tokenEndpoint, content);
                        string responseBody = await tokenResponse.Content.ReadAsStringAsync();
                        
                        Console.WriteLine("Response status: " + tokenResponse.StatusCode);
                        
                        if (tokenResponse.IsSuccessStatusCode)
                        {
                            Console.WriteLine("Token request successful. Parsing response...");
                            // Parse the token response
                            var serializer = new JavaScriptSerializer();
                            Dictionary<string, object> tokenData = serializer.Deserialize<Dictionary<string, object>>(responseBody);
                            
                            if (tokenData.ContainsKey("access_token") && tokenData.ContainsKey("id_token"))
                            {
                                string accessToken = tokenData["access_token"] as string;
                                string idToken = tokenData["id_token"] as string;
                                
                                // Display the user info
                                var userInfo = ParseIdToken(idToken);
                                string userName = userInfo.ContainsKey("name") ? userInfo["name"] : "Unknown";
                                string userEmail = userInfo.ContainsKey("preferred_username") ? userInfo["preferred_username"] : "Unknown";
                                WriteHtmlResponse(response, "Login successful!<br><br>User: " + userName + "<br>Email: " + userEmail + "<br><br><a href='/logout'>Logout</a>");
                            }
                            else
                            {
                                Console.WriteLine("Token response does not contain expected tokens. Response: " + responseBody);
                                WriteHtmlResponse(response, "Error: The token response did not contain the expected tokens. This may indicate a configuration issue with your Entra ID application.");
                            }
                        }
                        else
                        {
                            Console.WriteLine("Token request failed. Response: " + responseBody);
                            WriteHtmlResponse(response, "Error exchanging authorization code for tokens: " + responseBody);
                        }
                    }
                }
                catch (HttpRequestException httpEx)
                {
                    Console.WriteLine("HTTP Request Error: " + httpEx.Message);
                    if (httpEx.InnerException != null)
                    {
                        Console.WriteLine("Inner Exception: " + httpEx.InnerException.Message);
                    }
                    
                    WriteHtmlResponse(response, "HTTP Request Error: " + httpEx.Message + 
                        "<br><br>This might be due to:<br>" +
                        "1. Network connectivity issues<br>" +
                        "2. SSL/TLS certificate problems<br>" +
                        "3. Firewall or proxy blocking the request<br>" +
                        "<br>Please check your network configuration and try again.");
                }
                catch (TaskCanceledException)
                {
                    Console.WriteLine("Request timed out");
                    WriteHtmlResponse(response, "Error: The request to the token endpoint timed out. Please check your network connection and try again.");
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine("General Exception: " + ex.GetType().Name + ": " + ex.Message);
                if (ex.InnerException != null)
                {
                    Console.WriteLine("Inner Exception: " + ex.InnerException.Message);
                }
                
                WriteHtmlResponse(response, "Error: " + ex.Message + "<br><br>Exception Type: " + ex.GetType().Name);
            }
        }
        
        private static Dictionary<string, string> ParseIdToken(string idToken)
        {
            // Simple parser for JWT token - for demonstration purposes only
            string[] parts = idToken.Split('.');
            if (parts.Length != 3)
            {
                return new Dictionary<string, string>();
            }
            
            string payload = parts[1];
            // Add padding if needed
            int padding = payload.Length % 4;
            if (padding > 0)
            {
                payload += new string('=', 4 - padding);
            }
            
            // Decode Base64Url
            string decodedPayload = Encoding.UTF8.GetString(Convert.FromBase64String(payload));
            
            // Parse JSON
            var serializer = new JavaScriptSerializer();
            Dictionary<string, object> claims = serializer.Deserialize<Dictionary<string, object>>(decodedPayload);
            
            // Convert to string dictionary
            Dictionary<string, string> result = new Dictionary<string, string>();
            foreach (var claim in claims)
            {
                result[claim.Key] = claim.Value.ToString();
            }
            
            return result;
        }
        
        private static void HandleLogoutRequest(HttpListenerResponse response)
        {
            // Construct the logout URL
            string logoutUrl = Authority + "/oauth2/v2.0/logout?post_logout_redirect_uri=" + HttpUtility.UrlEncode(LogoutUri);
            
            // Redirect the user to the logout URL
            response.StatusCode = 302;
            response.Headers.Add("Location", logoutUrl);
            response.Close();
        }
        
        private static void HandleSignout(HttpListenerResponse response)
        {
            WriteHtmlResponse(response, "You have been signed out.<br><br><a href='/'>Home</a>");
        }
        
        private static void ServeDefaultPage(HttpListenerResponse response)
        {
            string html = "<!DOCTYPE html>\n<html>\n<head>\n    <title>Entra ID Login Demo</title>\n    <style>\n        body { font-family: Arial, sans-serif; margin: 40px; line-height: 1.6; }\n        .container { max-width: 800px; margin: 0 auto; padding: 20px; border: 1px solid #ddd; border-radius: 5px; }\n        h1 { color: #333; }\n        .button { display: inline-block; background-color: #0078d4; color: white; padding: 10px 20px; text-decoration: none; border-radius: 4px; }\n    </style>\n</head>\n<body>\n    <div class='container'>\n        <h1>Entra ID Login Demo</h1>\n        <p>This is a simple demo of Entra ID authentication using .NET Framework 4.8.</p>\n        <p>Click the button below to log in with your Entra ID account.</p>\n        <a href='" + GetAuthorizationUrl() + "' class='button'>Login with Entra ID</a>\n    </div>\n</body>\n</html>";
            
            WriteHtmlResponse(response, html);
        }
        
        private static void WriteHtmlResponse(HttpListenerResponse response, string html)
        {
            response.StatusCode = 200;
            response.ContentType = "text/html";
            
            byte[] buffer = Encoding.UTF8.GetBytes(html);
            response.ContentLength64 = buffer.Length;
            response.OutputStream.Write(buffer, 0, buffer.Length);
            response.OutputStream.Close();
        }
    }
}
