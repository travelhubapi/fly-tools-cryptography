using System;
using System.Collections.Generic;
using System.Text;
using System.Threading.Tasks;

namespace Flytour.Tools.Cryptography
{
    interface IAsymmetricProvider
    {
        string Encrypt(string text, string pem);
    }
}
