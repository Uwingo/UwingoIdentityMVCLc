//namespace UwingoIdentityMVC
//{
//    public static class GenerateClient
//    {
//        public static HttpClient Client { get; set; }
//        //public static IConfiguration _configuration{get; }

//        public static HttpClient InitializeClientBaseAddress(this IServiceCollection services, IConfiguration configuration)
//        {
//            var result = configuration.GetSection("ClientBaseUrl").Value;
//            Client = new HttpClient();
//            //var uri = url[0];
//            //string baseAddress = await Client.GetStringAsync(url);
//            Client.BaseAddress = new Uri(result.ToString());
//            //Client.DefaultRequestHeaders.Accept.Add(new System.Net.Http.Headers.MediaTypeWithQualityHeaderValue("application/json")); 
//            return Client;
//        }
//        public static string UriAddress(string uri)
//        {
//            Client = new HttpClient();
//            string url = Client.BaseAddress + uri;
//            //string baseAddress = await Client.GetStringAsync(url);

//            //Client.DefaultRequestHeaders.Accept.Add(new System.Net.Http.Headers.MediaTypeWithQualityHeaderValue("application/json")); 
//            return url;
//        }
//    }
//}

using System.Net.Http.Headers;

namespace UwingoIdentityMVC
{
    public static class GenerateClient
    {
        public static HttpClient Client { get; private set; }

        public static void InitializeClientBaseAddress(this IServiceCollection services, IConfiguration configuration)
        {
            var clientBaseUrl = configuration.GetSection("ClientBaseUrl").Value;
            var apiBaseUrl = configuration.GetSection("ApiBaseUrl").Value;
            Client = new HttpClient();
            Client.BaseAddress = new Uri(apiBaseUrl); // Set the default to API base URL
            Client.DefaultRequestHeaders.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
        }

        public static void SetBaseUrlToApi()
        {
            var apiBaseUrl = Client.BaseAddress;
            Client.BaseAddress = new Uri(apiBaseUrl.ToString());
        }

        public static void SetBaseUrlToMvc()
        {
            var clientBaseUrl = Client.BaseAddress;
            Client.BaseAddress = new Uri(clientBaseUrl.ToString());
        }
    }
}
