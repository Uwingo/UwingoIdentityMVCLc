namespace Entity.Models
{
    public class Tenant
    {
        public Guid Id { get; set; }
        public string Name { get; set; }
    }
}

//administrator yerine companies şirket adı falan adresi 
//bu şirketlere tenant alanı koy company ile ilişkisini kur
//Applications tablosu oluştur buraya da tenantı koy name ve dbConnection
//Ben uwingoyum tenantım belli oradan applicationsa geldim hangi uygulamayı seçersem oradaki dbConnect bilgilerini alıp ilgili dbConnectionla ilgili veritabanına gideceğim.
//Hangi kullanıcı hangi şirkette, hangi şirketin hangi uygulaamalrı bende hepsini görcem
//AspNetUserTokens tablosuna ExpireDate falan eksik TokenSettings tablosu ekle
//her company bir tenantı olacak metin öğet uwingo şirketi o tenantId'yi alacak.