/* DO NOT EDIT THIS FILE - it is machine generated */
#include "include/jni.h"

#include <stdio.h>
#include <stdlib.h>
#include <iostream>
#include <fstream>
#include <cstdlib>
#include <syslog.h>
#include <stdarg.h>
#include<string>
#include<vector>
#include<functional>
#include<map>
#include<string.h>
#include<pthread.h>
#include <fcntl.h>
#include <unistd.h>
#include <signal.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <errno.h>
#include <pwd.h>
#include "CommClass.h"

#include "../../../../code/agents/include/auth/bsidEncryption.h"
#include "../../../../code/agents/include/auth/LinuxXMLDoc.h"
#include "../../../../code/agents/include/auth/IniFile.h"


//#include "../../../../code/agents/include/auth/Semaphore.h"
#include "../../../../code/agents/include/auth/Log.h"
#include "../../../../code/agents/include/auth/SimpleDate.h"
#include "../../../../code/agents/include/auth/DateSplittingFileLogger.h"


#ifndef LOG_PERROR
#define	LOG_PERROR	0x20	/* log to stderr as well */
#endif

#define INI_FILE	"JCryptoWrapper.ini"
#define DAEMON_NAME     "JCryptoWrapper"

// Web Service Return Codes
#define AUTH_FAILURE                        0
#define AUTH_SUCCESS                        1
#define AUTH_CHALLENGE                      2
#define	AUTH_SERVER_PIN_PROVIDED            3
#define AUTH_USER_PIN_CHANGE                4
#define AUTH_OUTER_WINDOW_AUTH              5
#define AUTH_CHANGE_STATIC_PASSWORD         6
#define AUTH_STATIC_CHANGE_FAILED           7
#define AUTH_PIN_CHANGE_FAILED              8


static Encryption *m_Encryption                 = NULL;
static CIniFile *m_iniFile                      = NULL;
static std::string m_iniPath                    = "";
static DateSplittingFileLogger *m_Logger        = NULL;
//static Semaphore *m_Semaphore                 = NULL;

static std::string m_EncryptionKeyFile          = "";
static std::string m_KeyDecryptionPassword      = "0";
static std::string m_DecryptedKey               = "";
static std::string m_LogFile                    = "";
static int m_LogLevel                           = 3;
static std::string m_AgentId                    = "14";




//Primary BSID Server Data
static std::string m_PrimaryProtocol                    = "";
static std::string m_PrimaryServer                      = "";
static std::string m_PrimaryServerPort                  = "";
static std::string m_PrimaryWebServiceRelativePath      = "";

//Secondary BSID Server Data
static std::string m_SecondaryProtocol                  = "";
static std::string m_SecondaryServer                    = "";
static std::string m_SecondaryServerPort                = "";
static std::string m_SecondaryWebServiceRelativePath    = "";

static int m_CallTimeout                                = 30;
static std::string m_SendClientIP                       = "";

static std::string m_UseProxy                           = "";
static std::string m_ProxyServer                        = "";
static std::string m_ProxyPort                          = "";
static std::string m_ProxyUser                          = "";
static std::string m_ProxyPassword                      = "";
static int m_SWITCH_OVER_COUNT                          = 10;


static CommClass *m_AuthCommon=NULL;


static void logtosys(int err, const char *format, ...);
bool FileExists(const std::string FilePath);
std::string ExecuteScriptCommand(const std::string Script);
std::string FindAndReplace(const std::string &p_SearchHere, const std::string &p_FindThis, const std::string &p_Replacement);
void setFailure(JNIEnv *env, jobjectArray &arrData, const char* Message);
std::string GetCurrentPath();
std::string lowercase(const std::string& s );
std::string uppercase(const std::string& s );
void getString(JNIEnv *env, const jstring Value, std::string & pszOut);
std::string int2string(int value);
std::string getUserMessage(const int retValue, const std::string retMessage);
void _setFailure(vector<std::string> &arrData, const char* Message);
static int check_os_64bit(void);

//Java Package Name
//edu.internet2.middleware.shibboleth.idp.authn.provider

#ifndef _Included_JCryptoWrapper
#define _Included_JCryptoWrapper
#ifdef __cplusplus
extern "C" {
#endif
/*
 * Class:     edu_internet2_middleware_shibboleth_idp_authn_provider_JCryptoWrapper
 * Method:    Initialize
 * Signature: ()I
 */
JNIEXPORT jint JNICALL Java_edu_internet2_middleware_shibboleth_idp_authn_provider_JCryptoWrapper_Initialize(JNIEnv * env,jclass cls, jint PluginID, jstring IniPath);

/*
 * Class:     edu_internet2_middleware_shibboleth_idp_authn_provider_JCryptoWrapper
 * Method:    Encrypt
 * Signature: (Ljava/lang/String;)Ljava/lang/String;
 */
JNIEXPORT jstring JNICALL Java_edu_internet2_middleware_shibboleth_idp_authn_provider_JCryptoWrapper_Encrypt(JNIEnv * env,jclass cls, jstring PlainText);

/*
 * Class:     edu_internet2_middleware_shibboleth_idp_authn_provider_JCryptoWrapper
 * Method:    Decrypt
 * Signature: (Ljava/lang/String;)Ljava/lang/String;
 */
JNIEXPORT jstring JNICALL Java_edu_internet2_middleware_shibboleth_idp_authn_provider_JCryptoWrapper_Decrypt(JNIEnv * env,jclass cls, jstring EncryptedTextBase64);



/*
 * Class:     edu_internet2_middleware_shibboleth_idp_authn_provider_JCryptoWrapper
 * Method:    Authenticate
 * Signature: (Ljava/lang/String;)Lvoid;
 */
JNIEXPORT void JNICALL Java_edu_internet2_middleware_shibboleth_idp_authn_provider_JCryptoWrapper_Authenticate(JNIEnv * env, jclass cls, jobjectArray arrData);


/*
 * Class:     edu_internet2_middleware_shibboleth_idp_authn_provider_JCryptoWrapper
 * Method:    getValue
 * Signature: (Ljava/lang/String;,Ljava/lang/String;)Ljava/lang/String;
 */
JNIEXPORT jstring JNICALL Java_edu_internet2_middleware_shibboleth_idp_authn_provider_JCryptoWrapper_getValue(JNIEnv * env,jclass cls, jstring Section, jstring Key);

/*
 * Class:     edu_internet2_middleware_shibboleth_idp_authn_provider_JCryptoWrapper
 * Method:    setValue
 * Signature: (Ljava/lang/String;,Ljava/lang/String;,Ljava/lang/String;)I;
 */
JNIEXPORT jint JNICALL Java_edu_internet2_middleware_shibboleth_idp_authn_provider_JCryptoWrapper_setValue(JNIEnv * env,jclass cls, jstring Section, jstring Key, jstring Value);

/*
 * Class:     edu_internet2_middleware_shibboleth_idp_authn_provider_JCryptoWrapper
 * Method:    deleteValue
 * Signature: (Ljava/lang/String;,Ljava/lang/String;)I;
 */
JNIEXPORT jint JNICALL Java_edu_internet2_middleware_shibboleth_idp_authn_provider_JCryptoWrapper_deleteValue(JNIEnv * env,jclass cls, jstring Section, jstring Key);

/*
 * Class:     edu_internet2_middleware_shibboleth_idp_authn_provider_JCryptoWrapper
 * Method:    deleteSection
 * Signature: (Ljava/lang/String;)I;
 */
JNIEXPORT jint JNICALL Java_edu_internet2_middleware_shibboleth_idp_authn_provider_JCryptoWrapper_deleteSection(JNIEnv * env,jclass cls, jstring Section);

/*
 * Class:     edu_internet2_middleware_shibboleth_idp_authn_provider_JCryptoWrapper
 * Method:    LogMessage
 * Signature: (Ljava/lang/int;,Ljava/lang/String;)I;
 */
JNIEXPORT void JNICALL Java_edu_internet2_middleware_shibboleth_idp_authn_provider_JCryptoWrapper_LogMessage(JNIEnv * env,jclass cls, jint Level, jstring Message);

//non JNI exports
int _Initialize(int PluginID=0, const std::string JavaIniPath="");//plugin 0=javaapi, 1=shibboleth, 2=OAM
std::string _Encrypt(const std::string PlainText);
std::string _Decrypt(const std::string EncryptedTextBase64);
void _Authenticate(vector<std::string>&arrData, const int DataSize);




// -------------------- For Java API -------------------------//

/*
 * Class:     Java_CRYPTOCard_API_JCryptoWrapper
 * Method:    Initialize
 * Signature: ()I
 */
JNIEXPORT jint JNICALL Java_CRYPTOCard_API_CRYPTOCardAPI_Initialize(JNIEnv * env,jclass cls, jstring IniPath);

/*
 * Class:     Java_CRYPTOCard_API_JCryptoWrapper
 * Method:    Authenticate
 * Signature: (Ljava/lang/String;)Lvoid;
 */
JNIEXPORT void JNICALL Java_CRYPTOCard_API_CRYPTOCardAPI_Authenticate(JNIEnv * env, jclass cls, jobjectArray arrData);

/*
 * Class:     Java_CRYPTOCard_API_JCryptoWrapper
 * Method:    Authenticate
 * Signature: (Ljava/lang/String;)Lvoid;
 */
JNIEXPORT void JNICALL Java_CRYPTOCard_API_CRYPTOCardAPI_VerifySignature(JNIEnv * env, jclass cls, jobjectArray arrData);

	// -------------------- For Java API -------------------------//


#ifdef __cplusplus
}
#endif
#endif



