using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Entity.Models
{
    public class Application
    {
        public Guid Id { get; set; }
        public string Name { get; set; }
        public ICollection<CompanyApplication> CompanyApplications { get; set; }
    }
}