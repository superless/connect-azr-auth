using System;
using trifenix.side;
namespace trifenix.main
{
    /// <summary>
    /// Ejemplo de clase dispobible en trifenix
    /// </summary>
    public class TrifenixMain
    {

        /// <summary>
        /// Método de prueba, que usa un método de la clase que se encuentra en un proyecto referenciado
        /// </summary>
        public void SomeMethod(){
            var side = new TrifenixSide().SomeMethodwithAstring();
            Console.WriteLine(side);

        }
    }
}
