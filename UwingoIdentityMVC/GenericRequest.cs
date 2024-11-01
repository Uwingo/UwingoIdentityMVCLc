//namespace UwingoIdentityMVC
//{
//    public class GenericRequest<T> where T : class
//    {
//        public async Task<List<T>> GetHttpRequest(string url)
//        {
//            string ProductCategoryUrl = GenerateClient.Client.BaseAddress + url;
//            HttpResponseMessage ProductCategoryResponce = GenerateClient.Client.GetAsync($"{ProductCategoryUrl}").Result;

//            List<T> ProductCategoryApi = await ProductCategoryResponce.Content.ReadFromJsonAsync<List<T>>();
//            return ProductCategoryApi;
//        }
//    }
//}
namespace UwingoIdentityMVC
{
    public class GenericRequest<T> where T : class
    {
        public async Task<List<T>> GetHttpRequest(string url)
        {
            string fullUrl = GenerateClient.Client.BaseAddress + url;
            HttpResponseMessage response = await GenerateClient.Client.GetAsync(fullUrl);

            if (response.IsSuccessStatusCode)
            {
                return await response.Content.ReadFromJsonAsync<List<T>>();
            }

            return new List<T>();
        }
    }
}
