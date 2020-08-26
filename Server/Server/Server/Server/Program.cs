using System;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Security.Cryptography;

namespace Server
{
    class Program
    {
        static void Main(string[] args)
        {

            string msg;

            Console.WriteLine("Server started at " + GetLocalIPAddress());

            TcpListener server = new TcpListener(IPAddress.Parse(GetLocalIPAddress()), 600);
            server.Start();

            Console.WriteLine("Waiting for the client...\n");
            TcpClient client = server.AcceptTcpClient();
            Console.WriteLine("Client connected!\n");

            while (true)
            {

                try
                {
                    NetworkStream networkStream = client.GetStream();
                    byte[] buffer = new byte[client.ReceiveBufferSize];


                    int bytesRead = networkStream.Read(buffer, 0, client.ReceiveBufferSize);
                    msg = Convert.ToBase64String(buffer, 0, bytesRead);
                    Console.WriteLine("Received Encrypted Message: " + msg + "\n");
                    Console.WriteLine("Decryted Message: " + DecyrptRSA(msg) + "\n");

                }
                catch
                {
                    Console.WriteLine("Closing The Server...");
                    break;
                }

            }

            client.Close();
            server.Stop();
        }

        private static string DecyrptRSA(string message)
        {

            string privateKey = "<RSAKeyValue><Modulus>21wEnTU+mcD2w0Lfo1Gv4rtcSWsQJQTNa6gio05AOkV/Er9w3Y13Ddo5wGtjJ19402S71HUeN0vbKILLJdRSES5MHSdJPSVrOqdrll/vLXxDxWs/U0UT1c8u6k/Ogx9hTtZxYwoeYqdhDblof3E75d9n2F0Zvf6iTb4cI7j6fMs=</Modulus><Exponent>AQAB</Exponent><P>/aULPE6jd5IkwtWXmReyMUhmI/nfwfkQSyl7tsg2PKdpcxk4mpPZUdEQhHQLvE84w2DhTyYkPHCtq/mMKE3MHw==</P><Q>3WV46X9Arg2l9cxb67KVlNVXyCqc/w+LWt/tbhLJvV2xCF/0rWKPsBJ9MC6cquaqNPxWWEav8RAVbmmGrJt51Q==</Q><DP>8TuZFgBMpBoQcGUoS2goB4st6aVq1FcG0hVgHhUI0GMAfYFNPmbDV3cY2IBt8Oj/uYJYhyhlaj5YTqmGTYbATQ==</DP><DQ>FIoVbZQgrAUYIHWVEYi/187zFd7eMct/Yi7kGBImJStMATrluDAspGkStCWe4zwDDmdam1XzfKnBUzz3AYxrAQ==</DQ><InverseQ>QPU3Tmt8nznSgYZ+5jUo9E0SfjiTu435ihANiHqqjasaUNvOHKumqzuBZ8NRtkUhS6dsOEb8A2ODvy7KswUxyA==</InverseQ><D>cgoRoAUpSVfHMdYXW9nA3dfX75dIamZnwPtFHq80ttagbIe4ToYYCcyUz5NElhiNQSESgS5uCgNWqWXt5PnPu4XmCXx6utco1UVH8HGLahzbAnSy6Cj3iUIQ7Gj+9gQ7PkC434HTtHazmxVgIR5l56ZjoQ8yGNCPZnsdYEmhJWk=</D></RSAKeyValue>";

            using (RSACryptoServiceProvider rsa = new RSACryptoServiceProvider(2048))
            {
                try
                {
                    rsa.FromXmlString(privateKey);

                    byte[] resultBytes = Convert.FromBase64String(message);
                    byte[] decryptedBytes = rsa.Decrypt(resultBytes, true);
                    string decryptedData = Encoding.UTF8.GetString(decryptedBytes);

                    return decryptedData;
                }
                finally
                {
                    rsa.PersistKeyInCsp = false;
                }
            }
        }

        public static string GetLocalIPAddress()
        {
            IPHostEntry host = Dns.GetHostEntry(Dns.GetHostName());

            foreach (IPAddress ip in host.AddressList)
            {
                if (ip.AddressFamily == AddressFamily.InterNetwork)
                {
                    return ip.ToString();
                }
            }
            throw new Exception("No network adapters with an IPv4 address in the system!");
        }
    }
}

