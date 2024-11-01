using Microsoft.Extensions.Caching.Distributed;
using Newtonsoft.Json.Linq;
using Newtonsoft.Json;

namespace UwingoIdentityMVC
{
    public class Localizer
    {
        private string _filePath;
        private readonly IDistributedCache _cache;
        public Localizer(IDistributedCache cache)
        {
            _cache = cache;
        }
        public void KrSetLanguage(string key, string value)
        {
            try
            {
                _filePath = Path.Combine(Directory.GetCurrentDirectory(), "Resources\\kr-KR.json");
                SetLanguage(key, value, _filePath);
            }
            catch (Exception ex)
            {

            }
        }
        public void EnSetLanguage(string key, string value)
        {
            try
            {
                _filePath = Path.Combine(Directory.GetCurrentDirectory(), "Resources\\en-US.json");
                SetLanguage(key, value, _filePath);
            }
            catch (Exception ex) { }
        }
        public void TrSetLanguage(string key, string value)
        {
            try
            {
                _filePath = Path.Combine(Directory.GetCurrentDirectory(), "Resources\\tr-TR.json");
                SetLanguage(key, value, _filePath);
            }
            catch (Exception ex) { }
        }
        public void UpdateLangue(string key, string krValue, string enValue, string trValue)
        {
            string krLangue = GetValue(key, "kr-KR");
            string enLangue = GetValue(key, "en-US");
            string trLangue = GetValue(key, "tr-TR");
            if (krLangue != krValue || enLangue != enValue || trLangue != trValue)
            {
                //Git dosyaya bak eğer o key varsa valusunu güncelle,eğer key yoksa key value ekle
                if (krLangue is not null) DeleteKrLanguage(key);
                if (enLangue is not null) DeleteEnLanguage(key);
                if (trLangue is not null) DeleteTrLanguage(key);

                KrSetLanguage(key, krValue);
                EnSetLanguage(key, enValue);
                TrSetLanguage(key, trValue);
            }
        }
        public void SetLanguage(string key, string value, string filePath)
        {
            string json = System.IO.File.ReadAllText(filePath);
            dynamic jsonObj = JsonConvert.DeserializeObject(json);

            var sectionPath = key.Split(":")[0];
            if (!string.IsNullOrEmpty(sectionPath))
            {
                //string relativeFilePath = System.IO.File.ReadAllText(_filePath);
                string fullFilePath = _filePath;
                if (System.IO.File.Exists(fullFilePath))
                {
                    string deger = jsonObj[sectionPath];
                    if (string.IsNullOrEmpty(deger)) jsonObj[sectionPath] = value;
                }                    //var keyPath = key.Split(":")[1];
            }
            else
                jsonObj[sectionPath] = value;

            string output = Newtonsoft.Json.JsonConvert.SerializeObject(jsonObj, Newtonsoft.Json.Formatting.Indented);
            System.IO.File.WriteAllText(_filePath, output);
        }
        public string GetValue(string key, string language)
        {
            _filePath = Path.Combine(Directory.GetCurrentDirectory(), $"Resources\\{language}.json");
            string json = System.IO.File.ReadAllText(_filePath);
            dynamic jsonObj = JsonConvert.DeserializeObject(json);
            string deger = "";
            var sectionPath = key.Split(":")[0];
            if (!string.IsNullOrEmpty(sectionPath))
            {
                //string relativeFilePath = System.IO.File.ReadAllText(_filePath);
                string fullFilePath = _filePath;
                if (System.IO.File.Exists(fullFilePath))
                {
                    deger = jsonObj[sectionPath];
                    if (string.IsNullOrEmpty(deger)) return deger;
                }
                return deger;//var keyPath = key.Split(":")[1];
            }
            else
                return "";
        }

        public void DeleteLanguage(string key)
        {

            DeleteLanguageAll(key, "en-US");
            DeleteLanguageAll(key, "kr-KR");
            DeleteLanguageAll(key, "tr-TR");

        }
        public void DeleteKrLanguage(string key)
        {
            DeleteLanguageAll(key, "kr-KR");
        }
        public void DeleteEnLanguage(string key)
        {
            DeleteLanguageAll(key, "en-US");
        }
        public void DeleteTrLanguage(string key)
        {
            DeleteLanguageAll(key, "tr-TR");
        }
        public void DeleteLanguageAll(string key, string filePath)
        {
            _filePath = Path.Combine(Directory.GetCurrentDirectory(), $"Resources\\{filePath}.json");
            string json = System.IO.File.ReadAllText(_filePath);
            dynamic jsonObj = JsonConvert.DeserializeObject(json);
            string path;

            var sectionPath = key.Split(":")[0];
            if (!string.IsNullOrEmpty(sectionPath))
            {
                //string relativeFilePath = System.IO.File.ReadAllText(_filePath);
                string fullFilePath = _filePath;
                if (System.IO.File.Exists(fullFilePath))
                {
                    string deger = jsonObj[sectionPath];
                    if (!string.IsNullOrEmpty(deger))
                    {
                        JProperty idProp = jsonObj.Property(key);
                        idProp.Remove();
                        string updatedJson = JsonConvert.SerializeObject(jsonObj, Formatting.Indented);
                        File.WriteAllText(_filePath, updatedJson);
                    }
                }
            }
        }
    }
}
