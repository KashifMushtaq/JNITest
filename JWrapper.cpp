#include "JCryptoWrapper.h"
#include "CommClass.h"

static bool m_bLastSuccessPrimary = true;
static int m_TryShiftCount = 0;
static int m_TryTimes = 10;

/* some syslogging */
static void logtosys(int err, const char *format, ...)
{
    setlogmask(LOG_UPTO (LOG_WARNING));

    va_list args;

    va_start(args, format);
    openlog(DAEMON_NAME, LOG_PID, LOG_SYSLOG);
    vsyslog(err, format, args);
    va_end(args);
    closelog();
}

bool FileExists(const std::string FilePath)
{
    bool bR = false;
    fstream fin;
    fin.open(FilePath.c_str());
    if (fin.is_open())
    {
        bR = true;
        fin.close();
    }
    return bR;
}

std::string ExecuteScriptCommand(const std::string Script)
{

    std::string psResult;

    std::string psBinary = Script;

    FILE* fpipe;
    char line[256];

    if (!(fpipe = (FILE*) popen(psBinary.c_str(), "r")))
    {
        // If fpipe is NULL
        return psResult;
    }


    while (fgets(line, sizeof line, fpipe))
    {
        if (line)
        {
            psResult.append(line);
        }
    }

    pclose(fpipe);

    if (psResult.length() > 0)
    {
        psResult = FindAndReplace(psResult, "\n", "");
    }

    return psResult;
}

//Searches the container 'SearchHere' for 'FindThis' and replaces it with 'Replacement'
//The predicate 'Pred' is used to compare elements in the container for equality,
//   and impose an equivalence relation between its operands.

std::string FindAndReplace(const std::string &p_SearchHere, const std::string &p_FindThis, const std::string &p_Replacement)
{
    if (p_SearchHere.length() == 0 || p_FindThis.length()==0)
    {
        return p_SearchHere;
    }

    //Constants to store various boundaries
    const std::string::size_type FindThisSize = p_FindThis.size();
    const std::string::const_iterator FindThisBegin = p_FindThis.begin();
    const std::string::const_iterator FindThisEnd = p_FindThis.end();
    const std::string::const_iterator ReplacementBegin = p_Replacement.begin();
    const std::string::const_iterator ReplacementEnd = p_Replacement.end();
    const std::string::const_iterator SearchHereBegin = p_SearchHere.begin();
    const std::string::const_iterator SearchHereEnd = p_SearchHere.end();

    //Iterators to step through the 'SearchHere' string
    std::string::const_iterator SearchStart = SearchHereBegin;
    std::string::const_iterator FoundPosition = SearchStart;

    //Container to store the original container with replacements
    std::string Result="";

    try
    {
        //Back Inserter Iterator to append elements to Result
        std::back_insert_iterator<std::string> ResultInserter = std::back_inserter(Result);

        do
        {
            //Find the next match in 'SearchHere'
            FoundPosition = std::search(SearchStart, SearchHereEnd, FindThisBegin, FindThisEnd, std::equal_to<std::string::value_type > ());

            //Copy the text between the last match and this match
            std::copy(SearchStart, FoundPosition, ResultInserter);

            //Advance the start position to this match
            SearchStart = FoundPosition;
            //If there was a match,
            if (SearchStart != SearchHereEnd)
            {
                //Copy the replacement string instead of the match
                std::copy(ReplacementBegin, ReplacementEnd, ResultInserter);
                //Advance past this match so it won't be found again
                std::advance(SearchStart, FindThisSize);
            }
            //Otherwise, exit loop
        }
        while (FoundPosition != SearchHereEnd);
        //Return original container with replacements made
    }
    catch(...){}

    return Result;
}

JNIEXPORT jint JNICALL Java_edu_internet2_middleware_shibboleth_idp_authn_provider_JCryptoWrapper_Initialize(JNIEnv * env, jclass cls, jint PluginID, jstring IniPath)
{
    std::string pszIniPath;

    getString(env, IniPath, pszIniPath);

    jint jR = _Initialize(PluginID, pszIniPath);
    pszIniPath.clear();

    return jR;
}

JNIEXPORT jstring JNICALL Java_edu_internet2_middleware_shibboleth_idp_authn_provider_JCryptoWrapper_Encrypt(JNIEnv * env, jclass cls, jstring PlainText)
{

    std::string sR;
    std::string pszText;

    getString(env, PlainText, pszText);

    //logtosys(LOG_NOTICE, "Java_edu_internet2_middleware_shibboleth_idp_authn_provider_JCryptoWrapper_Encrypt -> Entring. PlainText [%s]", pszText.c_str());

    if (pszText.length() > 0)
    {
        sR = m_Encryption->Encrypt(pszText);
        if (sR.length() == 0)
        {
            m_Logger->log(Log::PS_ERROR, "Java_edu_internet2_middleware_shibboleth_idp_authn_provider_Encrypt -> FAILED");
        }
    }

    //logtosys(LOG_NOTICE, "Java_edu_internet2_middleware_shibboleth_idp_authn_provider_JCryptoWrapper_Encrypt -> Encrypted. Return Text [%s]", sR.c_str());

    pszText.clear();

    char buffer[8192] = {0};
    strncpy(buffer, sR.c_str(), sR.size());
    sR.clear();

    //logtosys(LOG_NOTICE, "Java_edu_internet2_middleware_shibboleth_idp_authn_provider_Encrypt -> jstring created");

    return env->NewStringUTF(buffer);
}

JNIEXPORT jstring JNICALL Java_edu_internet2_middleware_shibboleth_idp_authn_provider_JCryptoWrapper_Decrypt(JNIEnv * env, jclass cls, jstring EncryptedTextBase64)
{
    std::string sR;
    std::string pszText;

    getString(env, EncryptedTextBase64, pszText);

    //logtosys(LOG_NOTICE, "Java_edu_internet2_middleware_shibboleth_idp_authn_provider_Decrypt -> Entring. EncryptedTextBase64 [%s]", pszText.c_str());

    if (pszText.length() > 0)
    {
        sR = m_Encryption->Decrypt(pszText);
        if (sR.length() == 0)
        {
            m_Logger->log(Log::PS_ERROR, "Java_edu_internet2_middleware_shibboleth_idp_authn_provider_Decrypt -> FAILED");
        }
    }

    //logtosys(LOG_NOTICE, "Java_edu_internet2_middleware_shibboleth_idp_authn_provider_Decrypt -> Decrypted. Return Text [%s]", sR.c_str());


    pszText.clear();

    char buffer[8192] = {0};
    strncpy(buffer, sR.c_str(), sR.size());

    sR.clear();

    //logtosys(LOG_NOTICE, "Java_edu_internet2_middleware_shibboleth_idp_authn_provider_Decrypt -> jstring created");

    return env->NewStringUTF(buffer);
}

JNIEXPORT void JNICALL Java_edu_internet2_middleware_shibboleth_idp_authn_provider_JCryptoWrapper_Authenticate(JNIEnv * env, jclass cls, jobjectArray arrData)
{

    std::string pszInComingContext;
    std::string pszEncryptedXML;
    std::string pszEncryptedResponse;
    std::string pszErrorMessage;
    std::string pszDecryptedXML;

    m_Logger->log(Log::PS_DEBUG, "Entring Java_edu_internet2_middleware_shibboleth_idp_authn_provider_Authenticate");

    jsize arraySize = env->GetArrayLength(arrData);

	m_Logger->log(Log::PS_DEBUG, "SafeNet -> ..... _Authenticate -> incoming data array size [%d]", arraySize);

    //jstring UserName = (jstring) env->GetObjectArrayElement(arrData, 0);
    //jstring Organization = (jstring) env->GetObjectArrayElement(arrData, 1);
    //jstring OTP = (jstring) env->GetObjectArrayElement(arrData, 2);
    //jstring Challenge = (jstring) env->GetObjectArrayElement(arrData, 3);
    //jstring State = (jstring) env->GetObjectArrayElement(arrData, 4);
    //jstring ChallengeData = (jstring) env->GetObjectArrayElement(arrData, 5);
    //jstring ChallengeMessage = (jstring) env->GetObjectArrayElement(arrData, 6);
    //jstring ReturndResult = (jstring) env->GetObjectArrayElement(arrData, 7); // Normal BSID return results
    //jstring BothServersDown = (jstring) env->GetObjectArrayElement(arrData, 8); // 1 or 0 (1 if down)
    //jstring ErrorMessage = (jstring) env->GetObjectArrayElement(arrData, 9); // Error Message for Log or client
    //jstring ClientIP = (jstring) env->GetObjectArrayElement(arrData, 10); //Incoming client IP address - Service Provider IP address
    //jstring ContextXML = (jstring) env->GetObjectArrayElement(arrData, 11); //Incoming context xml base64 encoded


	if(arraySize>11) //context is in cell 11 total size 12
	{
		getString(env, (const jstring)env->GetObjectArrayElement(arrData, (jsize)11), pszInComingContext); //incoming context in array element 11
		m_Logger->log(Log::PS_DEBUG, "SafeNet -> ..... _Authenticate -> incoming context data[%s]", pszInComingContext.c_str());
	}
	else
	{
		m_Logger->log(Log::PS_DEBUG, "SafeNet -> ..... _Authenticate -> No context data passed");
	}


    if (m_UseProxy == "1" && m_ProxyServer.length()>0 && m_ProxyPort.length()>0)
    {
        m_Logger->log(Log::PS_INFORMATIONAL, "Proxy Enabled. Proxy Server [%s], Port [%s]. Will try to use proxy server with basic authentication.", m_ProxyServer.c_str(), m_ProxyPort.c_str());
    }

    m_Logger->log(Log::PS_INFORMATIONAL, "Primary BSID URL [%s://%s:%s%s]", m_PrimaryProtocol.c_str(), m_PrimaryServer.c_str(), m_PrimaryServerPort.c_str(), m_PrimaryWebServiceRelativePath.c_str());

    if (m_SecondaryServer.length() > 0)
    {
        m_Logger->log(Log::PS_INFORMATIONAL, "Secondary BSID URL [%s://%s:%s%s]", m_SecondaryProtocol.c_str(), m_SecondaryServer.c_str(), m_SecondaryServerPort.c_str(), m_SecondaryWebServiceRelativePath.c_str());
    }

    m_Logger->log(Log::PS_INFORMATIONAL, "Call timeout [%i]", m_CallTimeout);


    LinuxXMLDoc *doc = new LinuxXMLDoc();



    std::string pszUserName;
    getString(env, (const jstring) env->GetObjectArrayElement(arrData, (jsize)0), pszUserName);
    std::string pszPasscode;
    getString(env, (const jstring) env->GetObjectArrayElement(arrData, (jsize)2), pszPasscode);
    std::string pszOrganization;
    getString(env, (const jstring) env->GetObjectArrayElement(arrData, (jsize)1), pszOrganization);
    std::string pszInState;
    getString(env, (const jstring) env->GetObjectArrayElement(arrData, (jsize)4), pszInState);

    std::string pszInIPAddress;
    getString(env, (const jstring) env->GetObjectArrayElement(arrData, (jsize)10), pszInIPAddress);

    //Challenge call should not accompany state
    if(pszPasscode.length()<2)
    {
        pszInState.clear();
    }

    doc->setUserName(pszUserName);
    doc->setOTP(pszPasscode);
    doc->setOTP(pszOrganization);
    doc->setState(pszInState);
    doc->setAgentId(m_AgentId); //14 for Shibboleth and 8 for API

    if(pszInComingContext.length()>0)
    {
        //Received context data, pass it to SAS
        doc->setDEVICE_FINGERPRINTING(pszInComingContext);
        doc->setUSER_IP_ADDRESS(pszInIPAddress);
    }

    if(m_SendClientIP=="1")
    {
        doc->setIP(pszInIPAddress);
    }

    if(m_AgentId=="14")
    {
        doc->setAttributes("SAML-ID"); //SAML User ID will be returned as attribute
    }

    m_Logger->log(Log::PS_INFORMATIONAL, "Received Parameters User[%s], OTP[%s], Organization [%s], State[%s], IP[%s]", pszUserName.c_str(), pszPasscode.c_str(), pszOrganization.c_str(), pszInState.c_str(), pszInIPAddress.c_str());


    m_Logger->log(Log::PS_DEBUG, "Sending XML [%s]", doc->getXML().c_str());

    pszEncryptedXML = m_Encryption->Encrypt(doc->getXML());

    m_Logger->log(Log::PS_DEBUG, "Encrypted XML [%s]", pszEncryptedXML.c_str());

    //set return value to failure by default and clean incoming array of data
    env->SetObjectArrayElement(arrData, 1, env->NewStringUTF((const char*) "")); //Organization
    env->SetObjectArrayElement(arrData, 2, env->NewStringUTF((const char*) "")); //OTP
    env->SetObjectArrayElement(arrData, 3, env->NewStringUTF((const char*) "")); //Challenge
    env->SetObjectArrayElement(arrData, 4, env->NewStringUTF((const char*) "")); //State
    env->SetObjectArrayElement(arrData, 5, env->NewStringUTF((const char*) "")); //ChallengeData
    env->SetObjectArrayElement(arrData, 6, env->NewStringUTF((const char*) "")); //Challenge Message

    env->SetObjectArrayElement(arrData, 7, env->NewStringUTF((const char*) "0")); //Return Result
    env->SetObjectArrayElement(arrData, 8, env->NewStringUTF((const char*) "0")); //Server Down Bit
    env->SetObjectArrayElement(arrData, 9, env->NewStringUTF((const char*) "")); // Error Message for Log
    env->SetObjectArrayElement(arrData, 10, env->NewStringUTF((const char*) "")); // Incoming IP address


    if(pszInComingContext.length()>0)
    {
        env->SetObjectArrayElement(arrData, 11, env->NewStringUTF((const char*) "")); // Incoming context data
    }

    //No need to make call if user name is empty. Just return Failure
    if(pszUserName.length()>0)
    {
        int iR = m_AuthCommon->Authenticate(pszEncryptedXML, pszEncryptedResponse);
        m_AuthCommon->getErrorMessage(pszErrorMessage);


        if(pszErrorMessage.length()>0)
        {
            m_Logger->log(Log::PS_ERROR, "Communication Log Messages \n%s", pszErrorMessage.c_str());
            env->SetObjectArrayElement(arrData, 9, env->NewStringUTF((const char*) pszErrorMessage.c_str())); // Error Message for Log
        }

        if(m_AuthCommon->isBothServersDown() && iR==0)
        {
            m_Logger->log(Log::PS_ERROR, "Primary and/or Secondary Server Down");
            env->SetObjectArrayElement(arrData, 8, env->NewStringUTF((const char*) "1")); //Server Down Bit
        }

        m_Logger->log(Log::PS_DEBUG, "Returned Payload [%s]", pszEncryptedResponse.c_str());

        if (pszEncryptedResponse.length()> 0)
        {

            delete doc;
            doc = new LinuxXMLDoc();

            pszDecryptedXML = m_Encryption->Decrypt(pszEncryptedResponse);

            m_Logger->log(Log::PS_DEBUG, "Returned XML Len [%i]", pszDecryptedXML.length());
            m_Logger->log(Log::PS_DEBUG, "Returned XML [%s]", pszDecryptedXML.c_str());

            if (pszDecryptedXML.length() > 0)
            {
                if (doc->loadXML(pszDecryptedXML))
                {

                    std::string STATE = doc->getState();
                    std::string CHALLENGE = doc->getChallenge();
                    std::string CHALLENGE_DATA = doc->getChallengeData();
                    std::string RET_VALUE = doc->getReturnValue();
                    std::string SAML_ID = doc->getAttributes();

                    if (RET_VALUE.length() == 0) RET_VALUE = "0";

                    //return other values
                    if(m_AgentId=="14")
                    {
                        env->SetObjectArrayElement(arrData, 0, env->NewStringUTF(SAML_ID.c_str())); // SAML_ID -> Returned User ID
                        m_Logger->log(Log::PS_DEBUG, "Returned SAML-ID [%s]", SAML_ID.c_str());
                    }

                    env->SetObjectArrayElement(arrData, 3, env->NewStringUTF(CHALLENGE.c_str())); // challenge
                    env->SetObjectArrayElement(arrData, 4, env->NewStringUTF(STATE.c_str())); //state
                    env->SetObjectArrayElement(arrData, 5, env->NewStringUTF(CHALLENGE_DATA.c_str())); //challenge data
                    env->SetObjectArrayElement(arrData, 6, env->NewStringUTF(getUserMessage(atoi(RET_VALUE.c_str()), CHALLENGE).c_str())); //challenge message (will be in challenge itself)

                    int returnResult = atoi(RET_VALUE.c_str());
                    m_Logger->log(Log::PS_DEBUG, "State [%s], Challenge[%s], Returned Authentication Code[%d]", STATE.c_str(), CHALLENGE.c_str(), returnResult);

                    // return result
                    env->SetObjectArrayElement(arrData, 7, env->NewStringUTF(int2string(returnResult).c_str())); //Authentication Result

                    SAML_ID.clear();
                    STATE.clear();
                    CHALLENGE.clear();
                    CHALLENGE_DATA.clear();
                    RET_VALUE.clear();
                }
                else
                {
                    m_Logger->log(Log::PS_ERROR, "Failed to load XML document");
                }
            }
            else
            {
                m_Logger->log(Log::PS_ERROR, "Failed to decrypt returned data");
            }

        }
        else
        {
            m_Logger->log(Log::PS_ERROR, "Call to SAS Server Returned no data");
        }
    }
    else
    {
        m_Logger->log(Log::PS_ERROR, "Cannot make authentication call when user name is empty.");
        env->SetObjectArrayElement(arrData, 9, env->NewStringUTF((const char*) "Cannot make authentication call when user name is empty.")); // Error Message for Log
    }

    pszUserName.clear();
    pszPasscode.clear();
    pszOrganization.clear();
    pszInState.clear();
    pszInIPAddress.clear();

    if (doc) delete doc;
    pszInComingContext.clear();
    pszEncryptedXML.clear();
    pszEncryptedResponse.clear();
    pszErrorMessage.clear();
    pszDecryptedXML.clear();

    m_Logger->log(Log::PS_DEBUG, "Leaving Java_edu_internet2_middleware_shibboleth_idp_authn_provider_Authenticate");


}


/*
 * Class:     edu_internet2_middleware_shibboleth_idp_authn_provider_JCryptoWrapper
 * Method:    getValue
 * Signature: (Ljava/lang/String;,Ljava/lang/String;)Ljava/lang/String;
 */
JNIEXPORT jstring JNICALL Java_edu_internet2_middleware_shibboleth_idp_authn_provider_JCryptoWrapper_getValue(JNIEnv * env,jclass cls, jstring Section, jstring Key)
{
    std::string pszSection;
    std::string pszKey;
    jstring jR;
    std::string sR;

    //m_Semaphore->Acquire();

    getString(env, Section, pszSection);
    getString(env, Key, pszKey);

    if(pszKey.length()>0)
    {
        sR = m_iniFile->GetKeyValue(pszSection, pszKey);
        if(sR.c_str())
        {
            jR = env->NewStringUTF(sR.c_str());
        }
    }

    //m_Semaphore->Release();

    pszSection.clear();
    pszKey.clear();
    sR.clear();

    return jR;
}

/*
 * Class:     edu_internet2_middleware_shibboleth_idp_authn_provider_JCryptoWrapper
 * Method:    setValue
 * Signature: (Ljava/lang/String;,Ljava/lang/String;,Ljava/lang/String;)I;
 */
JNIEXPORT jint JNICALL Java_edu_internet2_middleware_shibboleth_idp_authn_provider_JCryptoWrapper_setValue(JNIEnv * env,jclass cls, jstring Section, jstring Key, jstring Value)
{
    std::string pszSection;
    std::string pszKey;
    std::string pszValue;
    jint jR=0;

    //m_Semaphore->Acquire();

    getString(env, Section, pszSection);
    getString(env, Key, pszKey);
    getString(env, Value, pszValue);

    if(pszKey.length()>0)
    {
        m_iniFile->SetKeyValue(pszSection, pszKey, pszValue);
        if(m_iniFile->Save(m_iniPath))
        {
            jR=1;
            m_iniFile->Load(m_iniPath, false);
        }
    }

    //m_Semaphore->Release();

    pszSection.clear();
    pszKey.clear();
    pszValue.clear();

    return jR;
}

/*
 * Class:     edu_internet2_middleware_shibboleth_idp_authn_provider_JCryptoWrapper
 * Method:    setValue
 * Signature: (Ljava/lang/String;,Ljava/lang/String;)I;
 */
JNIEXPORT jint JNICALL Java_edu_internet2_middleware_shibboleth_idp_authn_provider_JCryptoWrapper_deleteValue(JNIEnv * env,jclass cls, jstring Section, jstring Key)
{
    std::string pszSection;
    std::string pszKey;
    std::string pszValue;
    jint jR=0;

    //m_Semaphore->Acquire();

    getString(env, Section, pszSection);
    getString(env, Key, pszKey);

    if(pszKey.length()>0)
    {
        m_iniFile->RemoveKey(pszSection, pszKey);
        if(m_iniFile->Save(m_iniPath))
        {
            jR=1;
            m_iniFile->Load(m_iniPath, false);
        }
    }

    //m_Semaphore->Release();

    pszSection.clear();
    pszKey.clear();
    pszValue.clear();

    return jR;
}

/*
 * Class:     edu_internet2_middleware_shibboleth_idp_authn_provider_JCryptoWrapper
 * Method:    setValue
 * Signature: (Ljava/lang/String;)I;
 */
JNIEXPORT jint JNICALL Java_edu_internet2_middleware_shibboleth_idp_authn_provider_JCryptoWrapper_deleteSection(JNIEnv * env,jclass cls, jstring Section)
{
    std::string pszSection;
    jint jR=0;

    //m_Semaphore->Acquire();

    getString(env, Section, pszSection);

    if(pszSection.length()>0)
    {
        m_iniFile->RemoveSection(pszSection);
        if(m_iniFile->Save(m_iniPath))
        {
            jR=1;
            m_iniFile->Load(m_iniPath, false);
        }
    }

    //m_Semaphore->Release();

    pszSection.clear();

    return jR;
}

/*
 * Class:     edu_internet2_middleware_shibboleth_idp_authn_provider_JCryptoWrapper
 * Method:    setValue
 * Signature: (Ljava/lang/String;)I;
 */
JNIEXPORT void JNICALL Java_edu_internet2_middleware_shibboleth_idp_authn_provider_JCryptoWrapper_LogMessage(JNIEnv *env, jclass cls, jint Level, jstring Message)
{
	if(!m_Logger) return;

	std::string pszMessage;
    getString(env, Message, pszMessage);

	if(pszMessage.length()>0)
	{
		int LogLevel = (int)Level;
		switch (Level)
		{
		case 1:
			m_Logger->log(Log::PS_CATASTROPHE, pszMessage.c_str());
			break;
		case 2:
			m_Logger->log(Log::PS_ERROR, pszMessage.c_str());
			break;
		case 3:
			m_Logger->log(Log::PS_WARNING, pszMessage.c_str());
			break;
		case 4:
			m_Logger->log(Log::PS_INFORMATIONAL, pszMessage.c_str());
			break;
		case 5:
			m_Logger->log(Log::PS_DEBUG, pszMessage.c_str());
			break;
		default:
			m_Logger->log(Log::PS_INFORMATIONAL, pszMessage.c_str());
			break;
		}
	}

	pszMessage.clear();
}

// -------------------- For Java API -------------------------//

/*
 * Class:     Java_CRYPTOCard_API_JCryptoWrapper
 * Method:    Initialize
 * Signature: ()I
 */
JNIEXPORT jint JNICALL Java_CRYPTOCard_API_CRYPTOCardAPI_Initialize(JNIEnv * env,jclass cls, jstring IniPath)
{
    return Java_edu_internet2_middleware_shibboleth_idp_authn_provider_JCryptoWrapper_Initialize(env, cls, (jint)0, IniPath);
}

/*
 * Class:     Java_CRYPTOCard_API_JCryptoWrapper
 * Method:    Authenticate
 * Signature: (Ljava/lang/String;)Lvoid;
 */
JNIEXPORT void JNICALL Java_CRYPTOCard_API_CRYPTOCardAPI_Authenticate(JNIEnv * env, jclass cls, jobjectArray arrData)
{
    m_AgentId = "8";
    Java_edu_internet2_middleware_shibboleth_idp_authn_provider_JCryptoWrapper_Authenticate(env, cls, arrData);
    m_AgentId = "14";
}

/*
 * Class:     Java_CRYPTOCard_API_JCryptoWrapper
 * Method:    Authenticate
 * Signature: (Ljava/lang/String;)Lvoid;
 */
JNIEXPORT void JNICALL Java_CRYPTOCard_API_CRYPTOCardAPI_VerifySignature(JNIEnv * env, jclass cls, jobjectArray arrData)
{
    m_Logger->log(Log::PS_DEBUG, "Entring Java_CRYPTOCard_API_CRYPTOCardAPI_VerifySignature");

    //jstring SerialNumber = (jstring) env->GetObjectArrayElement(arrData, 0);
    //jstring Hash = (jstring) env->GetObjectArrayElement(arrData, 1);
    //jstring Signature = (jstring) env->GetObjectArrayElement(arrData, 2);
    //jstring ReturnedResult = (jstring) env->GetObjectArrayElement(arrData, 3);


    //set return value to failure by default
    env->SetObjectArrayElement(arrData, 3, env->NewStringUTF((const char*) "0"));

    if (m_UseProxy == "1" && m_ProxyServer.length()>0 && m_ProxyPort.length()>0)
    {
        m_Logger->log(Log::PS_INFORMATIONAL, "Proxy Enabled. Proxy Server [%s], Port [%s]. Will try to use proxy server with basic authentication.", m_ProxyServer.c_str(), m_ProxyPort.c_str());
    }


    m_Logger->log(Log::PS_INFORMATIONAL, "Primary BSID URL [%s://%s:%s%s]", m_PrimaryProtocol.c_str(), m_PrimaryServer.c_str(), m_PrimaryServerPort.c_str(), m_PrimaryWebServiceRelativePath.c_str());


    if (m_SecondaryServer.length() > 0)
    {
        m_Logger->log(Log::PS_INFORMATIONAL, "Secondary BSID URL [%s://%s:%s%s]", m_SecondaryProtocol.c_str(), m_SecondaryServer.c_str(), m_SecondaryServerPort.c_str(), m_SecondaryWebServiceRelativePath.c_str());
    }

    m_Logger->log(Log::PS_INFORMATIONAL, "Call timeout [%i]", m_CallTimeout);


    LinuxXMLDoc *doc = new LinuxXMLDoc();
    std::string pszSerialNumber;
    getString(env, (const jstring) env->GetObjectArrayElement(arrData, 0), pszSerialNumber);
    std::string pszHash;
    getString(env, (const jstring) env->GetObjectArrayElement(arrData, 1), pszHash);
    std::string pszSignatures;
    getString(env, (const jstring) env->GetObjectArrayElement(arrData, 2), pszSignatures);
    std::string pszRequestType=(const char*)"verifysignature";

    doc->setSerialNumber(pszSerialNumber);
    doc->setHash(pszHash);
    doc->setSignature(pszSignatures);
    doc->setRequestType(pszRequestType);
    doc->setAgentId("8"); //8 for API

    m_Logger->log(Log::PS_INFORMATIONAL, "Received Parameters SerialNumber [%s], Hash [%s], Signature [%s]", pszSerialNumber.c_str(), pszHash.c_str(), pszSignatures.c_str());

    m_Logger->log(Log::PS_DEBUG, "Sending XML [%s]", doc->getXML().c_str());

    std::string pszEncryptedXML = m_Encryption->Encrypt(doc->getXML());

    m_Logger->log(Log::PS_DEBUG, "Encrypted XML [%s]", pszEncryptedXML.c_str());


    pszSerialNumber.clear();
    pszHash.clear();
    pszSignatures.clear();
    pszRequestType.clear();


    //jstring SerialNumber = (jstring) env->GetObjectArrayElement(arrData, 0);
    //jstring Hash = (jstring) env->GetObjectArrayElement(arrData, 1);
    //jstring Signature = (jstring) env->GetObjectArrayElement(arrData, 2);
    //jstring ReturnedResult = (jstring) env->GetObjectArrayElement(arrData, 3);

    //set return value to failure by default and clean incoming array of data
    env->SetObjectArrayElement(arrData, 0, env->NewStringUTF((const char*) "")); //Serial Number
    env->SetObjectArrayElement(arrData, 1, env->NewStringUTF((const char*) "")); //Hash
    env->SetObjectArrayElement(arrData, 2, env->NewStringUTF((const char*) "")); //Signature
    env->SetObjectArrayElement(arrData, 3, env->NewStringUTF((const char*) "0")); //Return Result




    std::string pszErrorMessage;
    std::string pszEncryptedResponse;
    std::string pszDecryptedXML;

    m_AuthCommon->Authenticate(pszEncryptedXML, pszEncryptedResponse);
    m_AuthCommon->getErrorMessage(pszErrorMessage);

    if(pszErrorMessage.length()>0)
    {
        m_Logger->log(Log::PS_ERROR, "Communication Log Messages \n%s", pszErrorMessage.c_str());
    }

    if(m_AuthCommon->isBothServersDown())
    {
        m_Logger->log(Log::PS_ERROR, "Primary and/or Secondary Server Down");
    }


    m_Logger->log(Log::PS_DEBUG, "Returned Payload [%s]", pszEncryptedResponse.c_str());

    if (pszEncryptedResponse.length()> 0)
    {

        delete doc;
        doc = new LinuxXMLDoc();

        pszDecryptedXML = m_Encryption->Decrypt(pszEncryptedResponse);

        m_Logger->log(Log::PS_DEBUG, "Returned XML Len [%i]", pszDecryptedXML.length());
        m_Logger->log(Log::PS_DEBUG, "Returned XML [%s]", pszDecryptedXML.c_str());

        if (pszDecryptedXML.length() > 0)
        {
            if (doc->loadXML(pszDecryptedXML))
            {
                std::string RET_VALUE = doc->getReturnValue();

                if (RET_VALUE.length() == 0) RET_VALUE = "0";

                m_Logger->log(Log::PS_DEBUG, "Verify Signature -> Returned Authentication Code[%s]", RET_VALUE.c_str());

                int returnResult = atoi(RET_VALUE.c_str());
                m_Logger->log(Log::PS_DEBUG, "Verify Signature -> Returned Code[%d]", returnResult);

                env->SetObjectArrayElement(arrData, 3, env->NewStringUTF((const char*) int2string(returnResult).c_str())); //Return Result

                RET_VALUE.clear();
            }
            else
            {
                m_Logger->log(Log::PS_ERROR, "Failed to load XML document");
            }
        }
        else
        {
            m_Logger->log(Log::PS_ERROR, "Failed to decrypt returned data");
        }

    }
    else
    {
        m_Logger->log(Log::PS_ERROR, "Call to SAS Server Returned no data");
    }


    if (doc) delete doc;
    pszEncryptedXML.clear();
    pszEncryptedResponse.clear();
    pszErrorMessage.clear();
    pszDecryptedXML.clear();

    m_Logger->log(Log::PS_DEBUG, "Leaving Java_CRYPTOCard_API_CRYPTOCardAPI_VerifySignature");
}

// -------------------- For Java API -------------------------//



void setFailure(JNIEnv *env, jobjectArray &arrData, const char* Message)
{
    env->SetObjectArrayElement(arrData, 6, env->NewStringUTF((const char*) "0"));
    env->SetObjectArrayElement(arrData, 8, env->NewStringUTF(Message));
    m_Logger->log(Log::PS_ERROR, Message);
}

void _setFailure(vector<std::string> &arrData, const char* Message)
{
    arrData[6] = (const char*) "0";
    arrData[8] = Message;
    m_Logger->log(Log::PS_ERROR, Message);
}

std::string GetCurrentPath()
{
    int MAX_PATH = 256;
    char buffer[MAX_PATH];
    std::string psPath;

    getcwd(buffer, MAX_PATH);
    psPath.append(buffer);

    if (psPath.substr(psPath.length() - 1, 1) != "/")
    {
        psPath.append("/");
    }

    return psPath;
}

std::string lowercase(const std::string& s)
{
    std::string result;
    result.assign(s.c_str());

    std::transform(result.begin(), result.end(), result.begin(), std::ptr_fun <int, int>(tolower));
    return result;
}

std::string uppercase(const std::string& s)
{
    std::string result;
    result.append(s);

    std::transform(result.begin(), result.end(), result.begin(), std::ptr_fun <int, int>(toupper));
    return result;
}

void getString(JNIEnv *env, const jstring Value, std::string & pszOut)
{
    if(!Value)
    {
        pszOut = (const char*)"";// return empty string if the value in array is NULL
        return;
    }

    const char* unicodeStr = env->GetStringUTFChars(Value, 0);
    if(unicodeStr)
    {
        pszOut.append(unicodeStr);
    }
    else
    {
        pszOut = (const char*)"";// return empty string if the value in array is NULL
    }
    env->ReleaseStringUTFChars(Value, unicodeStr);
}

std::string int2string(int value)
{
    string sR;
    char buffer[128] = {0};
    sprintf(buffer, (const char*) "%i", value);
    sR.append(buffer);
    return sR;
}

std::string getUserMessage(const int retValue, const std::string retMessage)
{

    //
    //                    CHALLENGE=Please respond to the challenge:
    //                    SERVER_PIN_PROVIDED=Please re-authenticate, using the next response.  Your new PIN is:
    //                    USER_PIN_CHANGE=Please enter a new PIN.
    //                    OUTER_WINDOW_AUTH=Please re-authenticate, using the next response.
    //                    CHANGE_STATIC_PASSWORD=Your password has expired.  Please select a new password.
    //                    STATIC_CHANGE_FAILED=Password change failed.  Please select a new password.
    //                    PIN_CHANGE_FAILED=PIN change failed.  Please select a new PIN.

    std::string sR;
    if (retValue == AUTH_FAILURE)
    {
        sR = m_iniFile->GetKeyValue("SETTINGS", "FAILURE");
    }
    else if (retValue == AUTH_SUCCESS)
    {
        sR = "";
    }
    else if (retValue == AUTH_CHALLENGE)
    {
        sR = m_iniFile->GetKeyValue("SETTINGS", "CHALLENGE");
        sR.append(retMessage);
    }
    else if (retValue == AUTH_SERVER_PIN_PROVIDED)
    {
        sR = m_iniFile->GetKeyValue("SETTINGS", "SERVER_PIN_PROVIDED");
        sR.append(retMessage);
    }
    else if (retValue == AUTH_USER_PIN_CHANGE)
    {
        sR = m_iniFile->GetKeyValue("SETTINGS", "USER_PIN_CHANGE");
    }
    else if (retValue == AUTH_OUTER_WINDOW_AUTH)
    {
        sR = m_iniFile->GetKeyValue("SETTINGS", "OUTER_WINDOW_AUTH");
    }
    else if (retValue == AUTH_CHANGE_STATIC_PASSWORD)
    {
        sR = m_iniFile->GetKeyValue("SETTINGS", "CHANGE_STATIC_PASSWORD");
    }
    else if (retValue == AUTH_STATIC_CHANGE_FAILED)
    {
        sR = m_iniFile->GetKeyValue("SETTINGS", "STATIC_CHANGE_FAILED");
    }
    else if (retValue == AUTH_PIN_CHANGE_FAILED)
    {
        sR = m_iniFile->GetKeyValue("SETTINGS", "PIN_CHANGE_FAILED");
    }
    return sR;
}

/*
 *
 * check_os_64bit
 *
 * Returns integer:
 *   1 = it is a 64-bit OS
 *   0 = it is NOT a 64-bit OS (probably 32-bit)
 *   < 0 = failure
 *   -1 = popen failed
 *   -2 = fgets failed
 *
 * **WARNING**
 * Be CAREFUL! Just testing for a boolean return may not cut it
 * with this (trivial) implementation! (Think of when it fails,
 * returning -ve; this could be seen as non-zero & therefore true!)
 * Suggestions?
 */
static int check_os_64bit(void)
{
    FILE *fp = NULL;
    char cb64[3];

    fp = popen("getconf LONG_BIT", "r");
    if (!fp)
        return -1;

    if (!fgets(cb64, 3, fp))
        return -2;

    if (!strncmp(cb64, "64", 3))
    {
        return 1;
    }
    else
    {
        return 0;
    }
}



#ifdef __cplusplus
extern "C"
{
#endif

/* *************************************** Non JNI Exported Functions  ******************************************** */
int _Initialize(int PluginID, const std::string JavaIniPath)
{
    int isx64 = check_os_64bit();

    //logtosys(LOG_NOTICE, "JCryptoWrapper -> _Initialize -> Process bitness [%s]. Call to check_os_64bit returned [%i] 1=64, 0=x86, value<0 error in finding", (isx64==1?"x64":"x86"), isx64);

    int jInt = 0;
    std::string INI_DEPLOYMET_PATH;
    std::string RUNNING_DIR;
    std::string RUNNING_DIR_BIN;
    bool isSPARC = false;
    std::string pszUName = ExecuteScriptCommand("uname -a");
    if(pszUName.find("sparc")!=std::string::npos)
    {
        isSPARC = true;
    }


    if(FileExists(JavaIniPath))
    {
        INI_DEPLOYMET_PATH = JavaIniPath;
        logtosys(LOG_INFO, "JCryptoWrapper -> _Initialize -> INI File is present at [%s]. Passed by Java", JavaIniPath.c_str());
    }
    else
    {
        RUNNING_DIR = ExecuteScriptCommand("pwd");
        RUNNING_DIR_BIN = GetCurrentPath();
        if (RUNNING_DIR.substr(RUNNING_DIR.length() - 1, 1) != "/")
        {
            RUNNING_DIR.append("/");
        }

        //lets go back to our bin dir
        chdir(RUNNING_DIR.c_str());

        logtosys(LOG_NOTICE, "JCryptoWrapper -> _Initialize -> Current Java Execution Path [%s]", RUNNING_DIR.c_str());
        logtosys(LOG_NOTICE, "JCryptoWrapper -> _Initialize -> Current Bin Path [%s]", RUNNING_DIR_BIN.c_str());

        RUNNING_DIR.append(INI_FILE);
        RUNNING_DIR_BIN.append(INI_FILE);

        if(FileExists(RUNNING_DIR))
        {
            INI_DEPLOYMET_PATH = RUNNING_DIR;
        }
        else if(FileExists(RUNNING_DIR_BIN))
        {
            INI_DEPLOYMET_PATH = RUNNING_DIR;
        }
        else
        {
            if(PluginID==0)
            {
                if(FileExists("/usr/local/cryptocard/javaapi/ini/JCryptoWrapper.ini"))
                {
                    INI_DEPLOYMET_PATH = "/usr/local/cryptocard/javaapi/ini/JCryptoWrapper.ini";
                }

            }
            else if(PluginID==1)
            {
                if(FileExists("/usr/local/cryptocard/shibboleth/ini/JCryptoWrapper.ini"))
                {
                    INI_DEPLOYMET_PATH = "/usr/local/cryptocard/shibboleth/ini/JCryptoWrapper.ini";
                }
            }
            else if(PluginID==2)
            {
                if(FileExists("/usr/local/cryptocard/oam/ini/JCryptoWrapper.ini"))
                {
                    INI_DEPLOYMET_PATH = "/usr/local/cryptocard/oam/ini/JCryptoWrapper.ini";
                }

            }
            else if(PluginID==3)
            {
                if(FileExists("/usr/local/safenet/webseal/ini/JCryptoWrapper.ini"))
                {
                    INI_DEPLOYMET_PATH = "/usr/local/safenet/webseal/ini/JCryptoWrapper.ini";
                }
            }
        }
    }

    if(INI_DEPLOYMET_PATH.length()==0)
    {
        logtosys(LOG_ERR, "JCryptoWrapper -> _Initialize -> INI File is NOT present at [%s] , [%s] and [%s]", JavaIniPath.c_str(), RUNNING_DIR.c_str(), RUNNING_DIR_BIN.c_str());
        logtosys(LOG_ERR, "JCryptoWrapper -> _Initialize -> Can not proceed further. Please place INI file at one of locations mentioned in previous message with read/write permissions for current processor owner");
        return jInt;
    }


    // its deamon now lets do our stuff now
    try
    {
        std::string iniPath;
        iniPath = INI_DEPLOYMET_PATH;
        logtosys(LOG_INFO, "JCryptoWrapper -> _Initialize -> Will use INI File present at [%s]", iniPath.c_str());

        if (FileExists(iniPath))
        {
            m_iniFile = new CIniFile();
            m_iniFile->Load(iniPath, false);

            m_iniPath.append(iniPath);

            m_LogFile = m_iniFile->GetKeyValue("SETTINGS", "LogFile");
            m_LogLevel = atoi(m_iniFile->GetKeyValue("SETTINGS", "LogLevel").c_str());

            if (m_LogLevel <= 0 || m_LogLevel > 5) m_LogLevel = 3;


            m_Logger = new DateSplittingFileLogger(m_LogFile);

            switch (m_LogLevel)
            {
            case 1:
                m_Logger->setLogLevel(Log::PS_CATASTROPHE);
                break;
            case 2:
                m_Logger->setLogLevel(Log::PS_ERROR);
                break;
            case 3:
                m_Logger->setLogLevel(Log::PS_WARNING);
                break;
            case 4:
                m_Logger->setLogLevel(Log::PS_INFORMATIONAL);
                break;
            case 5:
                m_Logger->setLogLevel(Log::PS_DEBUG);
                break;
            default:
                m_Logger->setLogLevel(Log::PS_DEBUG);
                break;
            }

            m_Logger->log_x(Log::PS_INFORMATIONAL, "JCryptoWrapper -> _Initialize -> Log file initialized at [%s]. Log level [%i]", m_Logger->getDatedFilename().c_str(), m_LogLevel);

            //m_Semaphore = new Semaphore();
            //m_Semaphore->Create();

            m_Encryption = new Encryption();

            m_EncryptionKeyFile = m_iniFile->GetKeyValue("SETTINGS", "EncryptionKeyFile");
            m_KeyDecryptionPassword = m_iniFile->GetKeyValue("SETTINGS", "KeyDecryptionPassword");
            if (m_KeyDecryptionPassword == "0") m_KeyDecryptionPassword = "";

            int iKeyLen = 0;

            m_DecryptedKey = m_Encryption->GetDecryptedKeyFromFile(m_EncryptionKeyFile.c_str(), m_KeyDecryptionPassword.c_str(), iKeyLen);

            if (iKeyLen > 0)
            {
                if (m_DecryptedKey.length() > 0)
                {
                    m_Encryption->setDevryptedKey(m_DecryptedKey); // set for later use in RSA encryption / decryption

                    logtosys(LOG_NOTICE, "JCryptoWrapper -> _Initialize -> Key Successfully Decrypted from file [%s]", m_EncryptionKeyFile.c_str());
                    m_Logger->log_x(Log::PS_INFORMATIONAL, "JCryptoWrapper -> _Initialize -> Key Successfully Decrypted from file [%s]", m_EncryptionKeyFile.c_str());

                    m_TryTimes = atoi(m_iniFile->GetKeyValue("SETTINGS", "SWITCH_OVER_COUNT").c_str());
                    if (m_TryTimes == 0) m_TryTimes = 10;

                    jInt = 1;

                    //Primary BSID Server Data
                    m_PrimaryProtocol = m_iniFile->GetKeyValue("SETTINGS", "PrimaryProtocol");
                    m_PrimaryServer = m_iniFile->GetKeyValue("SETTINGS", "PrimaryServer");
                    m_PrimaryServerPort = m_iniFile->GetKeyValue("SETTINGS", "PrimaryServerPort");
                    m_PrimaryWebServiceRelativePath = m_iniFile->GetKeyValue("SETTINGS", "PrimaryWebServiceRelativePath");

                    //Secondary BSID Server Data
                    m_SecondaryProtocol = m_iniFile->GetKeyValue("SETTINGS", "SecondaryProtocol");
                    m_SecondaryServer = m_iniFile->GetKeyValue("SETTINGS", "SecondaryServer");
                    m_SecondaryServerPort = m_iniFile->GetKeyValue("SETTINGS", "SecondaryServerPort");
                    m_SecondaryWebServiceRelativePath = m_iniFile->GetKeyValue("SETTINGS", "SecondaryWebServiceRelativePath");

                    std::string pszCallTimeout = m_iniFile->GetKeyValue("SETTINGS", "CallTimeout");
                    if(pszCallTimeout=="")pszCallTimeout="30";
                    m_CallTimeout = atoi(pszCallTimeout.c_str());
                    pszCallTimeout.clear();

                    if(isSPARC)
                    {
                        int callTimeout = (m_CallTimeout* 1000); //in Milli Seconds
                        std::string pszCmd= "/usr/sbin/ndd -set /dev/tcp tcp_ip_abort_cinterval ";
                        pszCmd.append(int2string(callTimeout));
                        ExecuteScriptCommand(pszCmd);
                        pszCmd.clear();
                    }


                    m_SendClientIP = m_iniFile->GetKeyValue("SETTINGS", "SendClientIP");

                    m_UseProxy = m_iniFile->GetKeyValue("SETTINGS", "USE_PROXY");
                    m_ProxyServer = m_iniFile->GetKeyValue("SETTINGS", "PROXY_SERVER");
                    m_ProxyPort = m_iniFile->GetKeyValue("SETTINGS", "PROXY_PORT");
                    m_ProxyUser = m_iniFile->GetKeyValue("SETTINGS", "PROXY_USER");
                    m_ProxyPassword = m_iniFile->GetKeyValue("SETTINGS", "PROXY_PASSWORD");

                    m_PrimaryProtocol = lowercase(m_PrimaryProtocol);


                    if (m_PrimaryProtocol.length() == 0)
                    {
                        m_Logger->log(Log::PS_WARNING, "Primary Protocol is empty. Will use http");
                        m_PrimaryProtocol = "http";
                    }

                    if (m_PrimaryServerPort.length() == 0)
                    {
                        m_Logger->log(Log::PS_WARNING, "Primary Server Port is empty. Will use 80");
                        m_PrimaryServerPort = "80";
                    }


                    if (m_PrimaryWebServiceRelativePath.length() == 0)
                    {
                        m_Logger->log(Log::PS_WARNING, "Primary Web Service Relative Path is empty. Will use /TokenValidator/TokenValidator.asmx");
                        m_PrimaryWebServiceRelativePath = "/TokenValidator/TokenValidator.asmx";
                    }

                    if (m_SecondaryProtocol.length() == 0)
                    {
                        m_Logger->log(Log::PS_INFORMATIONAL, "Secondary Protocol is empty. Will use http");
                        m_SecondaryProtocol = "http";
                    }

                    if (m_SecondaryServer.length() == 0)
                    {
                        m_Logger->log(Log::PS_INFORMATIONAL, "Secondary Server IP/Host Name is empty. No failover switching");
                    }

                    if (m_SecondaryServerPort.length() == 0)
                    {
                        m_Logger->log(Log::PS_INFORMATIONAL, "Secondary Server Port is empty. Will use 80");
                        m_SecondaryServerPort = "80";
                    }


                    if (m_SecondaryWebServiceRelativePath.length() == 0)
                    {
                        m_Logger->log(Log::PS_WARNING, "Secondary Web Service Relative Path is empty. Will use /TokenValidator/TokenValidator.asmx");
                        m_SecondaryWebServiceRelativePath = "/TokenValidator/TokenValidator.asmx";
                    }

                    std::string pszSWITCH_OVER_COUNT = m_iniFile->GetKeyValue("SETTINGS", "SWITCH_OVER_COUNT");
                    if(pszSWITCH_OVER_COUNT.length()>0)
                    {
                        m_SWITCH_OVER_COUNT = atoi(pszSWITCH_OVER_COUNT.c_str());
                    }


                    //----------------------------------- Create commonication class and initialize -------------------------------------------
                    m_AuthCommon = new CommClass();
                    m_AuthCommon->setPrimaryServer(m_PrimaryServer, atoi(m_PrimaryServerPort.c_str()), ((m_PrimaryProtocol == "https")?true:false));
                    m_AuthCommon->setSecondaryServer(m_SecondaryServer, atoi(m_SecondaryServerPort.c_str()), ((m_SecondaryProtocol == "https")?true:false));


                    m_AuthCommon->setProxyFlag(m_UseProxy=="1"?true:false);
                    m_AuthCommon->setProxyServer(m_ProxyServer);
                    m_AuthCommon->setProxyPort(atoi(m_ProxyPort.c_str()));
                    m_AuthCommon->setProxyUser(m_ProxyUser);
                    m_AuthCommon->setProxyPassword(m_ProxyPassword);
                    m_AuthCommon->setCallTimeout(m_CallTimeout);
                    m_AuthCommon->setRevertToPrimaryAfterTries(m_SWITCH_OVER_COUNT);
                    //----------------------------------- Create commonication class and initialize -------------------------------------------
                }
            }
        }
        else
        {
            logtosys(LOG_ERR, "JCryptoWrapper -> _Initialize -> Can not find INI file at [%s]. Can not proceed further. Aborting execution.", iniPath.c_str());
        }
    }
    catch (...)
    {
        jInt = 0;
    }

    return jInt;
}

std::string _Encrypt(const std::string PlainText)
{
    std::string sR;

    //logtosys(LOG_NOTICE, "_Encrypt -> Entring. PlainText [%s]", PlainText.c_str());

    if (PlainText.length() > 0)
    {
        sR = m_Encryption->Encrypt(PlainText);
        if (sR.length() == 0)
        {
            m_Logger->log(Log::PS_ERROR, "_Encrypt -> FAILED");
        }
    }

    //logtosys(LOG_NOTICE, "_Encrypt -> Encrypted. Return Text [%s]", sR.c_str());

    return sR;
}

std::string _Decrypt(const std::string EncryptedTextBase64)
{
    std::string sR;

    //logtosys(LOG_NOTICE, "_Decrypt -> Entering. EncryptedTextBase64 [%s]", pszText.c_str());

    if (EncryptedTextBase64.length() > 0)
    {
        sR = m_Encryption->Decrypt(EncryptedTextBase64);
        if (sR.length() == 0)
        {
            m_Logger->log(Log::PS_ERROR, "_Decrypt -> Failed");
        }
    }

    //logtosys(LOG_NOTICE, "_Decrypt -> Decrypted. Return Text [%s]", sR.c_str());

    return sR;
}
static std::string string_formatJ(const char *fmt, ...)
{
    char *ret=(char*)malloc(1024);
    memset(ret, '\0', 1024);

    va_list ap;

    va_start(ap, fmt);
    int i = vsprintf(ret, fmt, ap);
    va_end(ap);

    ret[i]='\0';
    std::string str;
    str.append(ret);

    free(ret);
    ret=NULL;
    return str;
}

static void append_formatJ(std::string& str, const char *fmt, ...)
{
    char *ret=(char*)malloc(1024);
    memset(ret, '\0', 1024);

    va_list ap;

    va_start(ap, fmt);
    int i = vsprintf(ret, fmt, ap);
    va_end(ap);
    ret[i]='\0';

    if(str.length()>0) str.append("\n");
    str.append(ret);

    free(ret);
    ret=NULL;

}

void _Authenticate(vector<std::string> &arrData, const int DataSize)
{
    std::string pszInComingContext;
    std::string pszEncryptedXML;
    std::string pszEncryptedResponse;
    std::string pszErrorMessage;
    std::string pszDecryptedXML;

    m_Logger->log(Log::PS_DEBUG, "Entring _Authenticate");

    int arraySize = (int)arrData.size();

	m_Logger->log(Log::PS_DEBUG, "SafeNet -> _Authenticate -> incoming data array size [%d]", arraySize);

    //jstring UserName = (jstring) env->GetObjectArrayElement(arrData, 0);
    //jstring Organization = (jstring) env->GetObjectArrayElement(arrData, 1);
    //jstring OTP = (jstring) env->GetObjectArrayElement(arrData, 2);
    //jstring Challenge = (jstring) env->GetObjectArrayElement(arrData, 3);
    //jstring State = (jstring) env->GetObjectArrayElement(arrData, 4);
    //jstring ChallengeData = (jstring) env->GetObjectArrayElement(arrData, 5);
    //jstring ChallengeMessage = (jstring) env->GetObjectArrayElement(arrData, 6);
    //jstring ReturndResult = (jstring) env->GetObjectArrayElement(arrData, 7); // Normal BSID return results
    //jstring BothServersDown = (jstring) env->GetObjectArrayElement(arrData, 8); // 1 or 0 (1 if down)
    //jstring ErrorMessage = (jstring) env->GetObjectArrayElement(arrData, 9); // Error Message for Log or client
    //jstring ClientIP = (jstring) env->GetObjectArrayElement(arrData, 10); //Incoming client IP address - Service Provider IP address
    //jstring ContextXML = (jstring) env->GetObjectArrayElement(arrData, 11); //Incoming context xml base64 encoded


	if(arraySize>11) //context is in cell 11 total size 12
	{
		pszInComingContext=arrData[11]; //incoming context in array element 11
		m_Logger->log(Log::PS_DEBUG, "SafeNet -> ..... _Authenticate -> incoming context data[%s]", pszInComingContext.c_str());
	}
	else
	{
		m_Logger->log(Log::PS_DEBUG, "SafeNet -> ..... _Authenticate -> No context data passed");
	}


    if (m_UseProxy == "1" && m_ProxyServer.length()>0 && m_ProxyPort.length()>0)
    {
        m_Logger->log(Log::PS_INFORMATIONAL, "Proxy Enabled. Proxy Server [%s], Port [%s]. Will try to use proxy server with basic authentication.", m_ProxyServer.c_str(), m_ProxyPort.c_str());
    }

    m_Logger->log(Log::PS_INFORMATIONAL, "Primary BSID URL [%s://%s:%s%s]", m_PrimaryProtocol.c_str(), m_PrimaryServer.c_str(), m_PrimaryServerPort.c_str(), m_PrimaryWebServiceRelativePath.c_str());

    if (m_SecondaryServer.length() > 0)
    {
        m_Logger->log(Log::PS_INFORMATIONAL, "Secondary BSID URL [%s://%s:%s%s]", m_SecondaryProtocol.c_str(), m_SecondaryServer.c_str(), m_SecondaryServerPort.c_str(), m_SecondaryWebServiceRelativePath.c_str());
    }

    m_Logger->log(Log::PS_INFORMATIONAL, "Call timeout [%i]", m_CallTimeout);


    LinuxXMLDoc *doc = new LinuxXMLDoc();



    std::string pszUserName;
    pszUserName=arrData[0];
    std::string pszPasscode;
    pszPasscode=arrData[2];
    std::string pszOrganization;
    pszOrganization=arrData[1];
    std::string pszInState;
    pszInState=arrData[4];

    std::string pszInIPAddress;
    pszInIPAddress=arrData[10];

    //challenge call should not accompany state
    if(pszPasscode.length()<2)
    {
        pszInState.clear();
    }

    doc->setUserName(pszUserName);
    doc->setOTP(pszPasscode);
    doc->setOTP(pszOrganization);
    doc->setState(pszInState);
    doc->setAgentId(m_AgentId); //14 for Shibboleth and 8 for API

    if(pszInComingContext.length()>0)
    {
        //Received context data, pass it to SAS
        doc->setDEVICE_FINGERPRINTING(pszInComingContext);
        doc->setUSER_IP_ADDRESS(pszInIPAddress);
    }

    if(m_SendClientIP=="1")
    {
        doc->setIP(pszInIPAddress);
    }

    if(m_AgentId=="14")
    {
        doc->setAttributes("SAML-ID"); //SAML User ID will be returned as attribute
    }

    m_Logger->log(Log::PS_DEBUG, "Received Parameters User[%s], OTP[%s], Organization [%s], State[%s], IP[%s]", pszUserName.c_str(), pszPasscode.c_str(), pszOrganization.c_str(), pszInState.c_str(), pszInIPAddress.c_str());


    m_Logger->log(Log::PS_DEBUG, "Sending XML [%s]", doc->getXML().c_str());

    pszEncryptedXML = m_Encryption->Encrypt(doc->getXML());

    m_Logger->log(Log::PS_DEBUG, "Encrypted XML [%s]", pszEncryptedXML.c_str());


    //set return value to failure by default and clean incoming array of data
    arrData[2]="";//env->SetObjectArrayElement(arrData, 2, env->NewStringUTF((const char*) "")); //OTP
    arrData[3]="";//env->SetObjectArrayElement(arrData, 3, env->NewStringUTF((const char*) "")); //Challenge
    arrData[4]="";//env->SetObjectArrayElement(arrData, 4, env->NewStringUTF((const char*) "")); //state
    arrData[5]="";//env->SetObjectArrayElement(arrData, 5, env->NewStringUTF((const char*) "")); //ChallengeData
    arrData[6]="";//env->SetObjectArrayElement(arrData, 6, env->NewStringUTF((const char*) "")); //Challenge Message

    arrData[7]="0";//env->SetObjectArrayElement(arrData, 7, env->NewStringUTF((const char*) "0")); //Return Result
    arrData[8]="0";//env->SetObjectArrayElement(arrData, 8, env->NewStringUTF((const char*) "0")); //Server Down Bit
    arrData[9]="";//env->SetObjectArrayElement(arrData, 9, env->NewStringUTF((const char*) "")); // Error Message for Log
    arrData[10]="";//env->SetObjectArrayElement(arrData, 10, env->NewStringUTF((const char*) "")); // Incoming IP address

    if(pszInComingContext.length()>0)
    {
        arrData[11]="";//env->SetObjectArrayElement(arrData, 11, env->NewStringUTF((const char*) "")); // Incoming context data
    }

    //no need to make call is there is no user name
    if(pszUserName.length()>0)
    {
        int iR = m_AuthCommon->Authenticate(pszEncryptedXML, pszEncryptedResponse);
        m_AuthCommon->getErrorMessage(pszErrorMessage);

        if(pszErrorMessage.length()>0)
        {
            m_Logger->log(Log::PS_ERROR, "Communication Log Messages \n%s", pszErrorMessage.c_str());
            arrData[9]=pszErrorMessage;//env->SetObjectArrayElement(arrData, 9, env->NewStringUTF((const char*) pszErrorMessage.c_str())); // Error Message for Log
        }

        if(m_AuthCommon->isBothServersDown() && iR==0)
        {
            m_Logger->log(Log::PS_ERROR, "Primary and/or Secondary Server Down");
            arrData[8]="1";//env->SetObjectArrayElement(arrData, 8, env->NewStringUTF((const char*) "1")); //Server Down Bit
        }


        m_Logger->log(Log::PS_DEBUG, "Returned Payload [%s]", pszEncryptedResponse.c_str());

        if (pszEncryptedResponse.length()> 0)
        {

            delete doc;
            doc = new LinuxXMLDoc();

            pszDecryptedXML = m_Encryption->Decrypt(pszEncryptedResponse);

            m_Logger->log(Log::PS_DEBUG, "Returned XML Len [%i]", pszDecryptedXML.length());
            m_Logger->log(Log::PS_DEBUG, "Returned XML [%s]", pszDecryptedXML.c_str());

            if (pszDecryptedXML.length() > 0)
            {
                if (doc->loadXML(pszDecryptedXML))
                {


                    std::string STATE = doc->getState();
                    std::string CHALLENGE = doc->getChallenge();
                    std::string CHALLENGE_DATA = doc->getChallengeData();
                    std::string RET_VALUE = doc->getReturnValue();
                    std::string SAML_ID = doc->getAttributes();

                    if (RET_VALUE.length() == 0) RET_VALUE = "0";

                    //return other values
                    if(m_AgentId=="14")
                    {
                        arrData[0]=SAML_ID;//env->SetObjectArrayElement(arrData, 0, env->NewStringUTF(SAML_ID.c_str())); // SAML_ID -> Returned User ID
                        m_Logger->log(Log::PS_DEBUG, "Returned SAML-ID [%s]", SAML_ID.c_str());
                    }

                    arrData[3]=CHALLENGE;//env->SetObjectArrayElement(arrData, 3, env->NewStringUTF(CHALLENGE.c_str())); // challenge
                    arrData[4]=STATE;//env->SetObjectArrayElement(arrData, 4, env->NewStringUTF(STATE.c_str())); //state
                    arrData[5]=CHALLENGE_DATA;//env->SetObjectArrayElement(arrData, 5, env->NewStringUTF(CHALLENGE_DATA.c_str())); //challenge data
                    arrData[6]=getUserMessage(atoi(RET_VALUE.c_str()), CHALLENGE);//env->SetObjectArrayElement(arrData, 6, env->NewStringUTF(getUserMessage(atoi(RET_VALUE.c_str()), CHALLENGE).c_str())); //challenge message (will be in challenge itself)

                    int returnResult = atoi(RET_VALUE.c_str());

                    m_Logger->log(Log::PS_DEBUG, "State [%s], Challenge[%s], Returned Authentication Code[%d]", STATE.c_str(), CHALLENGE.c_str(), returnResult);

                    // return result
                    arrData[7] = IntToString(returnResult);

                    SAML_ID.clear();
                    STATE.clear();
                    CHALLENGE.clear();
                    CHALLENGE_DATA.clear();
                    RET_VALUE.clear();
                }
                else
                {
                    m_Logger->log(Log::PS_ERROR, "Failed to load XML document");
                }
            }
            else
            {
                m_Logger->log(Log::PS_ERROR, "Failed to decrypt returned data");
            }

        }
        else
        {
            m_Logger->log(Log::PS_ERROR, "Call to SAS Server Returned no data");
        }
    }
    else
    {
        m_Logger->log(Log::PS_ERROR, "Cannot make authentication call when user name is empty.");
        arrData[9]=(const char*) "Cannot make authentication call when user name is empty."; // Error Message for Log
    }

    pszUserName.clear();
    pszPasscode.clear();
    pszOrganization.clear();
    pszInState.clear();
    pszInIPAddress.clear();

    if (doc) delete doc;
    pszInComingContext.clear();
    pszEncryptedXML.clear();
    pszEncryptedResponse.clear();
    pszErrorMessage.clear();
    pszDecryptedXML.clear();

    m_Logger->log(Log::PS_DEBUG, "Leaving _Authenticate");
}


#ifdef __cplusplus
}
#endif
/* *************************************** Non JNI Exported Functions  ******************************************** */

/*

static void* myThread(void * Data);
struct threadData
{
    std::vector<std::string> arrData;
    int DataSize;
    int threadNumber;
    int count;
};
threadData getData(int thId);
std::vector<std::string> getVect();

int main(int argc, char **argv)
{
    int iR = _Initialize(8, "/usr/local/safenet/siebel/ini/JCryptoWrapper.ini");

    if(iR==1)
    {
        //jstring UserName = (jstring) env->GetObjectArrayElement(arrData, 0);
        //jstring Organization = (jstring) env->GetObjectArrayElement(arrData, 1);
        //jstring OTP = (jstring) env->GetObjectArrayElement(arrData, 2);
        //jstring Challenge = (jstring) env->GetObjectArrayElement(arrData, 3);
        //jstring State = (jstring) env->GetObjectArrayElement(arrData, 4);
        //jstring ChallengeData = (jstring) env->GetObjectArrayElement(arrData, 5);
        //jstring ChallengeMessage = (jstring) env->GetObjectArrayElement(arrData, 6);
        //jstring ReturndResult = (jstring) env->GetObjectArrayElement(arrData, 7); // Normal BSID return results
        //jstring BothServersDown = (jstring) env->GetObjectArrayElement(arrData, 8); // 1 or 0 (1 if down)
        //jstring ErrorMessage = (jstring) env->GetObjectArrayElement(arrData, 9); // Error Message for Log or client
        //jstring ClientIP = (jstring) env->GetObjectArrayElement(arrData, 10); //Incoming client IP address - Service Provider IP address
        //jstring ContextXML = (jstring) env->GetObjectArrayElement(arrData, 11); //Incoming context xml base64 encoded

        std::vector<std::string> arrData;
        for(int i=0; i<11; i++)
        {
            arrData.push_back("");
        }

        arrData[0]="kmushtaq";  //user Name
        arrData[1]="";          //Organization
        arrData[2]="";//env->SetObjectArrayElement(arrData, 2, env->NewStringUTF((const char*) "")); //OTP
        arrData[3]="";//env->SetObjectArrayElement(arrData, 3, env->NewStringUTF((const char*) "")); //challenge
        arrData[4]="";//env->SetObjectArrayElement(arrData, 4, env->NewStringUTF((const char*) "")); //State
        arrData[5]="";//env->SetObjectArrayElement(arrData, 5, env->NewStringUTF((const char*) "")); //ChallengeData
        arrData[6]="";//env->SetObjectArrayElement(arrData, 6, env->NewStringUTF((const char*) "")); //Challenge Message

        arrData[7]="0";//env->SetObjectArrayElement(arrData, 7, env->NewStringUTF((const char*) "0")); //Return Result
        arrData[8]="0";//env->SetObjectArrayElement(arrData, 8, env->NewStringUTF((const char*) "0")); //Server Down Bit
        arrData[9]="";//env->SetObjectArrayElement(arrData, 9, env->NewStringUTF((const char*) "")); // Error Message for Log
        arrData[10]="";//env->SetObjectArrayElement(arrData, 10, env->NewStringUTF((const char*) "")); // Incoming IP address

       for(int count=0; count<10; count++)
       {


//            arrData[0]="kmushtaq";  //user Name
//            arrData[1]="";          //Organization
//            arrData[2]="";//env->SetObjectArrayElement(arrData, 2, env->NewStringUTF((const char*) "")); //OTP
//            arrData[3]="";//env->SetObjectArrayElement(arrData, 3, env->NewStringUTF((const char*) "")); //challenge
//            arrData[4]="";//env->SetObjectArrayElement(arrData, 4, env->NewStringUTF((const char*) "")); //State
//            arrData[5]="";//env->SetObjectArrayElement(arrData, 5, env->NewStringUTF((const char*) "")); //ChallengeData
//            arrData[6]="";//env->SetObjectArrayElement(arrData, 6, env->NewStringUTF((const char*) "")); //Challenge Message
//
//            arrData[7]="0";//env->SetObjectArrayElement(arrData, 7, env->NewStringUTF((const char*) "0")); //Return Result
//            arrData[8]="0";//env->SetObjectArrayElement(arrData, 8, env->NewStringUTF((const char*) "0")); //Server Down Bit
//            arrData[9]="";//env->SetObjectArrayElement(arrData, 9, env->NewStringUTF((const char*) "")); // Error Message for Log
//            arrData[10]="";//env->SetObjectArrayElement(arrData, 10, env->NewStringUTF((const char*) "")); // Incoming IP address
//
//            _Authenticate(arrData, arrData.size());
//
//            printf("Call No %i Result[%s]\r\n", count, arrData[7].c_str());
//            printf("Message Log:\r\n%s", arrData[9].c_str());




            pthread_t thread1;
            pthread_t thread2;
            pthread_t thread3;
            pthread_t thread4;
            pthread_t thread5;
            pthread_t thread6;

            struct threadData td = getData(1);
            int iret = pthread_create( &thread1, NULL, myThread, (void*)&td);

//            struct threadData td2 = getData(2);
//            iret = pthread_create( &thread2, NULL, myThread, (void*)&td2);
//
//
//            struct threadData td3 = getData(3);
//            iret = pthread_create( &thread3, NULL, myThread, (void*)&td3);
//
//            struct threadData td4 = getData(4);
//            iret = pthread_create( &thread4, NULL, myThread, (void*)&td4);


            pthread_join( thread1, NULL);
//            pthread_join( thread2, NULL);
//            pthread_join( thread3, NULL);
//            pthread_join( thread4, NULL);

       }
    }

    return 0;
}

static void* myThread(void * Data)
{
    threadData *td = (threadData*)Data;

    for(int c=0; c<10; c++)
    {
        _Authenticate(td->arrData, td->DataSize);

        printf("Thread No %d - Count %d - Result[%s]\n%s", td->threadNumber, td->count, td->arrData[7].c_str(), td->arrData[9].c_str());

        //printf("Message Log:\n%s", td->arrData[9].c_str());
        td->arrData[0]="kmushtaq";  //user Name
        td->arrData[1]="";          //Organization
        td->arrData[2]="";//env->SetObjectArrayElement(arrData, 2, env->NewStringUTF((const char*) "")); //OTP
        td->arrData[3]="";//env->SetObjectArrayElement(arrData, 3, env->NewStringUTF((const char*) "")); //challenge
        td->arrData[4]="";//env->SetObjectArrayElement(arrData, 4, env->NewStringUTF((const char*) "")); //State
        td->arrData[5]="";//env->SetObjectArrayElement(arrData, 5, env->NewStringUTF((const char*) "")); //ChallengeData
        td->arrData[6]="";//env->SetObjectArrayElement(arrData, 6, env->NewStringUTF((const char*) "")); //Challenge Message

        td->arrData[7]="0";//env->SetObjectArrayElement(arrData, 7, env->NewStringUTF((const char*) "0")); //Return Result
        td->arrData[8]="0";//env->SetObjectArrayElement(arrData, 8, env->NewStringUTF((const char*) "0")); //Server Down Bit
        td->arrData[9]="";//env->SetObjectArrayElement(arrData, 9, env->NewStringUTF((const char*) "")); // Error Message for Log
        td->arrData[10]="";//env->SetObjectArrayElement(arrData, 10, env->NewStringUTF((const char*) "")); // Incoming IP address

        //usleep(200);

        td->count++;

    }
    return 0;
}

threadData getData(int thId)
{
        std::vector<std::string> arrData = getVect();

        struct threadData td;
        td.arrData = arrData;
        td.DataSize = arrData.size();
        td.threadNumber = thId;
        td.count = 0;

        return td;
}
std::vector<std::string> getVect()
{
        std::vector<std::string> arrData;
        for(int i=0; i<11; i++)
        {
            arrData.push_back("");
        }

        arrData[0]="kmushtaq";  //user Name
        arrData[1]="";          //Organization
        arrData[2]="";//env->SetObjectArrayElement(arrData, 2, env->NewStringUTF((const char*) "")); //OTP
        arrData[3]="";//env->SetObjectArrayElement(arrData, 3, env->NewStringUTF((const char*) "")); //challenge
        arrData[4]="";//env->SetObjectArrayElement(arrData, 4, env->NewStringUTF((const char*) "")); //State
        arrData[5]="";//env->SetObjectArrayElement(arrData, 5, env->NewStringUTF((const char*) "")); //ChallengeData
        arrData[6]="";//env->SetObjectArrayElement(arrData, 6, env->NewStringUTF((const char*) "")); //Challenge Message

        arrData[7]="0";//env->SetObjectArrayElement(arrData, 7, env->NewStringUTF((const char*) "0")); //Return Result
        arrData[8]="0";//env->SetObjectArrayElement(arrData, 8, env->NewStringUTF((const char*) "0")); //Server Down Bit
        arrData[9]="";//env->SetObjectArrayElement(arrData, 9, env->NewStringUTF((const char*) "")); // Error Message for Log
        arrData[10]="";//env->SetObjectArrayElement(arrData, 10, env->NewStringUTF((const char*) "")); // Incoming IP address

        return arrData;
}

*/


