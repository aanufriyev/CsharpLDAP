using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace Novell.Directory.Ldap.Cli
{
    public class Program
    {
        public static void Main(string[] args)
        {
            SimpleBindSucceedes();
        }

        private static void SimpleBindSucceedes()
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
