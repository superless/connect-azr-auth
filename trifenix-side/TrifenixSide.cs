namespace trifenix.side
{
    /// <summary>
    /// Ejemplo de clase referenciada desde un objeto nuget.
    /// </summary>
    public class TrifenixSide
    {
        private const string Value = "some test method to side";


        /// <summary>
        /// metodo test para probar referencias en nuget
        /// </summary>
        /// <returns>un string cualquiera</returns>
        public string SomeMethodwithAstring(){
            return Value;
        }
    }
}
