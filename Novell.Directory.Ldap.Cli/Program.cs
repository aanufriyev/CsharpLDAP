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
            SimpleBindSucceedes().Wait();
            SecureLdapBindSucceedes().Wait();
            StartTlsLdapBindSucceedes().Wait();
        }

        private static async Task StartTlsLdapBindSucceedes()
        {
            try
            {
                LdapConnection conn = new LdapConnection();
                
                await conn.ConnectAsync("localhost", 10389);
                conn.StartTls();
                conn.Bind("uid=admin,ou=system", "secret");
                var entry = conn.Read("uid=admin,ou=system");
                Console.WriteLine("Bind Successfull");
                conn.StopTls();
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

        private static async Task SecureLdapBindSucceedes()
        {
            try
            {
                LdapConnection conn = new LdapConnection();
                conn.SecureSocketLayer = true;
                await conn.ConnectAsync("localhost", 10636);
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

        private static async Task SimpleBindSucceedes()
        {
            try
            {
                LdapConnection conn = new LdapConnection();
                await conn.ConnectAsync("localhost", 10389);
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
