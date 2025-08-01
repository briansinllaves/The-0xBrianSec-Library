https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Insecure%20Deserialization/DotNET.md
Detection

    AAEAAD (Hex) = .NET deserialization BinaryFormatter
    FF01 (Hex) / /w (Base64) = .NET ViewState

Example: AAEAAAD/////AQAAAAAAAAAMAgAAAF9TeXN0ZW0u[...]0KPC9PYmpzPgs

ysoserial - Deserialization payload generator for a variety of .NET formatters 

![[Pasted image 20230605121831.png]]
.NET Native Formatters from pwntester/attacking-net-serialization


### XmlSerializer

- In C# source code, look for `XmlSerializer(typeof(<TYPE>));`.
- The attacker must control the **type** of the XmlSerializer.

### DataContractSerializer

> The DataContractSerializer deserializes in a loosely coupled way. It never reads common language runtime (CLR) type and assembly nes from the incoming data. The security model for the XmlSerializer is similar to that of the DataContractSerializer, and differs mostly in details. For example, the XmlIncludeAttribute attribute is used for type inclusion instead of the KnownTypeAttribute attribute.

- In C# source code, look for `DataContractSerializer(typeof(<TYPE>))`.
- Payload output: **XML**
- Data **Type** must be user-controlled to be exploitable

### NetDataContractSerializer

> It extends the `System.Runtime.Serialization.XmlObjectSerializer` class and is capable of serializing any type annotated with serializable attribute as `BinaryFormatter`.

- In C# source code, look for `NetDataContractSerializer().ReadObject()`.
- Payload output: **XML**

### LosFormatter 

- Use `BinaryFormatter` internally.


### JSON.NET

- In C# source code, look for `JsonConvert.DeserializeObject<Expected>(json, new JsonSerializerSettings`.
- Payload output: **JSON**

### BinaryFormatter

> The BinaryFormatter type is dangerous and is not recommended for data processing. Applications should stop using BinaryFormatter as soon as possible, even if they believe the data they're processing to be trustworthy. BinaryFormatter is insecure and can’t be made secure.

- In C# source code, look for `System.Runtime.Serialization.Binary.BinaryFormatter`.
- Exploitation requires `[Serializable]` or `ISerializable` interface.
- Payload output: **Binary**