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
            SecureLdapBindSucceedes();
            SimpleBindSucceedesV2();
            //StartTlsLdapBindSucceedes();
        }

        private static void StartTlsLdapBindSucceedes()
        {
            try
            {
                LdapConnection conn = new LdapConnection();
                
                conn.Connect("localhost", 10389);
                conn.startTLS();
                conn.Bind("uid=admin,ou=system", "secret");
                Console.WriteLine(" Bind Successfull");
                conn.stopTLS();
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

        private static void SecureLdapBindSucceedes()
        {
            try
            {
                LdapConnection conn = new LdapConnection();
                conn.SecureSocketLayer = true;
                conn.Connect("localhost", 10636);
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

        private static void SimpleBindSucceedesV2()
        {
            try
            {
                var conn = new LdapConnectionV2();
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
