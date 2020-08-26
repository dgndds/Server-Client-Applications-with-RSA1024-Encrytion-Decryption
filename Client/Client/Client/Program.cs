using System;
using System.Text;
using System.Net.Sockets;
using System.Security.Cryptography;

namespace Client{
    class Program{
        static void Main(string[] args){

            string ipAdress = "";
            bool ipCorrect = false;
            
            NetworkStream networkStream = null;

            do {
                try{
                    Console.Write("IP of the server: ");
                    ipAdress = Console.ReadLine();
                    TcpClient client = new TcpClient(ipAdress, 600);
                    networkStream = client.GetStream();
                    ipCorrect = true;
                }catch{
                    Console.WriteLine("Cannot connect to given IP adress...");
                }
            } while (!ipCorrect);

            Console.WriteLine("Connection established to: " + ipAdress + " \n");

            while (true)
            {
                Console.Write("Message to send: ");
                byte[] bytesToSend = Convert.FromBase64String(EncyrptRSA(Console.ReadLine()));
                networkStream.Write(bytesToSend, 0, bytesToSend.Length);
            }
        }

        private static string EncyrptRSA(string message){
            string publicKey = "<RSAKeyValue><Modulus>21wEnTU+mcD2w0Lfo1Gv4rtcSWsQJQTNa6gio05AOkV/Er9w3Y13Ddo5wGtjJ19402S71HUeN0vbKILLJdRSES5MHSdJPSVrOqdrll/vLXxDxWs/U0UT1c8u6k/Ogx9hTtZxYwoeYqdhDblof3E75d9n2F0Zvf6iTb4cI7j6fMs=</Modulus><Exponent>AQAB</Exponent></RSAKeyValue>";

            using (RSACryptoServiceProvider rsa = new RSACryptoServiceProvider(2048))
            {
                try{
                    rsa.FromXmlString(publicKey);

                    byte[] encryptedData = rsa.Encrypt(Encoding.UTF8.GetBytes(message), true);

                    string base64Encrypted = Convert.ToBase64String(encryptedData);
                    Console.WriteLine("\nEncrypted Message: " + base64Encrypted + "\n");

                    return base64Encrypted;
                }finally{
                    rsa.PersistKeyInCsp = false;
                }
            }
        }
    }
}