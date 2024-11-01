using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace Entity.Models
{
    public class CompanyApplication
    {
        [Key]
        public Guid Id { get; set; }

        [ForeignKey("CompanyId")]
        public Guid CompanyId { get; set; }
        public Company Company { get; set; }

        [ForeignKey("ApplicationId")]
        public Guid ApplicationId { get; set; }
        public Application Application { get; set; }
        public string DbConnection { get; set; }
    }
}