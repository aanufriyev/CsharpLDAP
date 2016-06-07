using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace Novell.Directory.Ldap.Tests
{
    using Xunit;

    // This project can output the Class library as a NuGet Package.
    // To enable this option, right-click on the project and select the Properties menu item. In the Build tab select "Produce outputs on build".
    public class LdapConnectionTests
    {
        [Fact]
        public void BindSucceedes()
        {
            try
            {
                LdapConnection conn = new LdapConnection();
                
                conn.Connect("localhost", 10389);
                conn.Bind("uid=admin,ou=system", "secret");
                Console.WriteLine(" Bind Successfull");
                conn.Disconnect();
            }
            catch (LdapException e)
            {
                Console.WriteLine("Error:" + e.LdapErrorMessage);
                return;
            }
            catch (Exception e)
            {
                Console.WriteLine("Error:" + e.Message);
                return;
            }
        }
    }
}
